#!/usr/bin/env python3
"""
Attribution Pipeline 

Usage:
    from src.pipeline import AttributionPipeline

    pipeline = AttributionPipeline()
    result = pipeline.process(input_data)

    # Or process file
    pipeline.process_file(input_file, output_file)
"""

import csv
import json
import os
import re
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.cdn_detector import CNDDetector
from utils.cert_validator import CertificateValidator
from utils.html_processor import HTMLProcessor
from utils.llm_api import LLMAPI
from utils.as2org_parser import AS2OrgParser

# Maximum attempts for domain scanning
MAX_DOMAIN_ATTEMPTS = 5


class AttributionPipeline:
    """
    Attribution pipeline for organizational analysis.
    
    """

    # LLM Prompts (defined in pipeline, not in llm_api.py)
    SYSTEM_PROMPT = """You are a Cybersecurity Intelligence Analyst and an expert in Network Asset Attribution.
Your task is to determine the "Operating Organization" (the entity that owns or manages the service running on the IP) based on the provided SSL Certificate details and the HTML content of the web page.

### INPUT DATA:
1. **subject_cn**: The Common Name from a TRUSTED SSL certificate.
2. **san**: The Subject Alternative Name list from the same certificate.
3. **html_content**: The cleaned text content derived from the service's HTML (Port 443).

### ANALYSIS LOGIC (Priority Order):
1. **Analyze Certificate Domains (CN & SAN)**:
   - Since the certificate is TRUSTED, the domains are valid indicators of ownership.
   - Extract the root domain (e.g., from `mail.google.com` -> `google.com`).
   - Associate the root domain with a known organization.
   - **WARNING**: If the domains indicate a Shared Hosting Provider, CDN, or Cloud Service (e.g., `*.herokuapp.com`, `*.cloudfront.net`, `*.squarespace.com`, `kubernetes.default.svc`), do NOT assume the provider is the organization. Look at the HTML.

2. **Analyze HTML Content**:
   - Look for "Copyright" statements (e.g., "© 2024 Acme Corp").
   - Look for Company Names in titles, headers, or footers.
   - Look for specific product names associated with a single company.
   - **Default Pages**: If the HTML contains generic text like "Welcome to Nginx", "IIS Windows Server", "404 Not Found", or "Error", the HTML provides NO attribution value. Fall back to the Certificate Domain owner.

3. **Conflict Resolution**:
   - **Case A (Content identified)**: If HTML clearly identifies "Company X", but Cert is "Cloudflare", the answer is **Company X**.
   - **Case B (No Content)**: If HTML is empty/generic/error, and Cert is "vpn.company-x.com", the answer is **Company X**.
   - **Case C (Hosting + No Content)**: If HTML is generic AND Cert is generic hosting (e.g., `localhost` or `*.amazonaws.com`), the answer is **Unknown**.

### OUTPUT FORMAT:
Return the result in a strictly valid JSON format:
{
  "reasoning": "Brief explanation of how you derived the organization, citing specific evidence from HTML or Cert.",
  "organization": "The English name of the organization. Use 'Unknown' if no clear evidence exists."
}"""

    def __init__(self,
                 asn_db_path: str = None,
                 cdn_asn_file: str = None,
                 zgrab_executable: str = None,
                 intermediate_dir: str = './output/intermediate',
                 as_org_file: str = None):
        """
        Initialize the attribution pipeline.

        Args:
            asn_db_path: Path to pyasn database
            cdn_asn_file: Path to CDN ASN mapping JSON
            zgrab_executable: Path to zgrab2 executable
            intermediate_dir: Directory for intermediate JSONL files
            as_org_file: Path to as-org2info.txt file for AS name lookup
        """
        # Set default paths
        project_root = Path(__file__).parent.parent

        if asn_db_path is None:
            asn_db_path = str(project_root / "data" / "asn_db")
        if cdn_asn_file is None:
            cdn_asn_file = str(project_root / "data" / "cdn_asn.json")
        if zgrab_executable is None:
            zgrab_executable = str(project_root / "utils" / "zgrab2")
        if as_org_file is None:
            as_org_file = str(project_root / "data" / "as-org2info.txt")
        if intermediate_dir == './output/intermediate':
            intermediate_dir = str(project_root / "output" / "intermediate")

        # Initialize components
        self.cdn_detector = CNDDetector(asn_db_path, Path(cdn_asn_file))
        self.cert_validator = CertificateValidator(enable_revocation_check=False)
        self.html_processor = HTMLProcessor()
        self.llm_api = LLMAPI()
        self.as2org_parser = AS2OrgParser(as_org_file) if Path(as_org_file).exists() else None

        # Zgrab executable path
        self.zgrab_executable = zgrab_executable if Path(zgrab_executable).exists() else None

        # Intermediate file directory
        self.intermediate_dir = Path(intermediate_dir)
        self.intermediate_dir.mkdir(parents=True, exist_ok=True)

        # Statistics
        self.stats = {
            'total_processed': 0,
            'untrusted_cert_count': 0,
            'cdn_count': 0,
            'cert_org_direct_count': 0,
            'needs_stage2_count': 0,
            'html_fetch_success': 0,
            'html_fetch_failed': 0,
            'llm_analysis_count': 0,
            'unknown_count': 0
        }

    # ========================================================================
    # Stage 0: Active Scanning (zgrab2)
    # ========================================================================

    def stage_0_active_scan(self,
                            ip_file: str,
                            output_jsonl: str,
                            concurrency: int = 500) -> str:
        """
        Stage 0: Active scanning module.

        Read an IP list file, invoke zgrab2 for HTTPS scanning, and produce
        scan results in the same JSONL format that Stage 1 expects.

        Args:
            ip_file: Path to input file, one IP address per line (IPv4/IPv6).
            output_jsonl: Path to output JSONL file (zgrab2 scan results).
            concurrency: zgrab2 concurrent connections (default 500).

        Returns:
            Path to the output JSONL file.
        """
        import ipaddress
        import subprocess

        ip_path = Path(ip_file)
        output_path = Path(output_jsonl)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not ip_path.exists():
            raise FileNotFoundError(f"IP file not found: {ip_file}")

        if not self.zgrab_executable:
            raise RuntimeError("zgrab2 executable not found. Set zgrab_executable path.")

        # Step 1: Read, validate, and deduplicate IPs
        ips = []
        seen = set()
        skipped = 0

        with open(ip_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Handle CSV format: take first field
                ip = line.split(',')[0].strip()
                if ip in seen:
                    skipped += 1
                    continue
                # Validate IP format
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    skipped += 1
                    continue
                seen.add(ip)
                ips.append(ip)

        print(f"  [Stage 0] Loaded {len(ips)} unique IPs (skipped {skipped} invalid/duplicate)")

        if not ips:
            raise ValueError("No valid IP addresses found in input file")

        # Step 2: Write IPs to temp file for zgrab2
        fd, target_file = tempfile.mkstemp(suffix='.txt', text=True)
        try:
            with open(fd, 'w') as f:
                for ip in ips:
                    f.write(f"{ip}\n")

            # Step 3: Run zgrab2
            cmd = [
                self.zgrab_executable,
                'http',
                '--use-https',
                '-p', '443',
                '-f', target_file,
                '-o', str(output_path),
                '-s', str(concurrency),
                '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            ]

            print(f"  [Stage 0] Running zgrab2 scan ({len(ips)} IPs, concurrency={concurrency})...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(300, len(ips))  # Scale timeout with IP count
            )

            if result.returncode != 0:
                raise RuntimeError(f"zgrab2 scan failed (exit code {result.returncode}): {result.stderr[:500]}")

            # Step 4: Validate output
            success_count = 0
            fail_count = 0
            with open(output_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        scan = json.loads(line)
                        data = scan.get('data', {})
                        # Check for successful response in any http/https key
                        found_success = False
                        for key in data.keys():
                            if key.startswith('http'):
                                status = data[key].get('status', '')
                                if status == 'success':
                                    found_success = True
                                    break
                        if found_success:
                            success_count += 1
                        else:
                            fail_count += 1
                    except json.JSONDecodeError:
                        fail_count += 1

            print(f"  [Stage 0] Scan complete: {success_count} success, {fail_count} failed, {len(ips)} total")
            print(f"  [Stage 0] Output: {output_path}")

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"zgrab2 scan timed out after {max(300, len(ips))}s")
        finally:
            try:
                os.unlink(target_file)
            except OSError:
                pass

        return str(output_path)

    def process_from_ip_list(self,
                             ip_file: str,
                             output_jsonl: str,
                             output_csv: str = None,
                             scan_concurrency: int = 500) -> Dict[str, Any]:
        """
        Full pipeline from an IP list file: Stage 0 → 1 → 2A → 2B.

        Args:
            ip_file: Path to input file, one IP per line.
            output_jsonl: Path to final output JSONL file.
            output_csv: Optional path to output CSV file.
            scan_concurrency: zgrab2 concurrent connections (default 500).

        Returns:
            Statistics dictionary.
        """
        output_path = Path(output_jsonl)

        # Stage 0: Active scan
        print("=" * 80)
        print("Stage 0: Active Scanning (zgrab2)")
        print("=" * 80)
        scan_output = self.stage_0_active_scan(
            ip_file=ip_file,
            output_jsonl=str(self.intermediate_dir / (output_path.stem + '_scan.jsonl')),
            concurrency=scan_concurrency
        )

        # Stage 1 + 2A + 2B: Full pipeline
        print("\n" + "=" * 80)
        print("Stage 1 + 2A + 2B: Attribution Pipeline")
        print("=" * 80)
        stats = self.process_file(
            input_file=scan_output,
            output_jsonl=output_jsonl
        )

        # Save CSV if requested
        if output_csv:
            csv_path = Path(output_csv)
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'org'])
                with open(output_jsonl, 'r') as fin:
                    for line in fin:
                        if not line.strip():
                            continue
                        d = json.loads(line)
                        writer.writerow([d.get('ip', ''), d.get('org', 'unknown')])

        return stats

    # ========================================================================
    # Data Extraction Methods
    # ========================================================================

    def _extract_scan_data(self, input_data: Dict[str, Any]) -> Tuple[int, str, Dict, int, str]:
        """
        Extract scan data from input.

        Returns:
            (port, asn, headers, http_code, raw_html)
        """
        port = 443
        asn = ''
        headers = {}
        http_code = 0
        raw_html = ''

        # Find HTTP data key (prefer https over http)
        data = input_data.get('data', {})
        http_key = None
        for key in data.keys():
            if key.startswith('https'):
                http_key = key
                port = int(key.replace('https', ''))
                break

        # If no https key found, look for http key
        if http_key is None:
            for key in data.keys():
                if key.startswith('http'):
                    http_key = key
                    port = 443
                    break

        if http_key:
            http_data = data[http_key]
            response = http_data.get('result', {}).get('response', {})

            http_code = response.get('status_code', 0)
            headers = response.get('headers', {})

            # Extract body
            body = response.get('body', '')
            if body:
                raw_html = body

        return port, asn, headers, http_code, raw_html

    def _extract_cert_data(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract certificate data from input.

        Returns:
            Dict with cert_org, cert_san, cert_cn, cert_raw, cert_chain, issuer_dn
        """
        cert_data = {
            'cert_org': '',
            'cert_san': [],
            'cert_cn': '',
            'cert_raw': '',
            'cert_chain': [],
            'issuer_dn': ''
        }

        data = input_data.get('data', {})
        http_key = None
        for key in data.keys():
            if key.startswith('https'):
                http_key = key
                break

        # If no https key found, look for http key
        if http_key is None:
            for key in data.keys():
                if key.startswith('http'):
                    http_key = key
                    break

        if http_key:
            try:
                http_data = data[http_key]
                request = http_data.get('result', {}).get('response', {}).get('request', {})
                tls_log = request.get('tls_log', {})
                handshake = tls_log.get('handshake_log', {})
                server_certs = handshake.get('server_certificates', {})

                # Get certificate
                cert = server_certs.get('certificate', {})
                cert_raw_base64 = cert.get('raw', '')
                parsed = cert.get('parsed', {})

                # Convert to PEM if available
                if cert_raw_base64:
                    cert_data['cert_raw'] = self.cert_validator.base64_to_pem(cert_raw_base64)

                # Extract certificate chain
                chain_data = server_certs.get('chain', [])
                cert_chain_pems = []
                for chain_cert in chain_data:
                    chain_raw = chain_cert.get('raw', '')
                    if chain_raw:
                        cert_chain_pems.append(self.cert_validator.base64_to_pem(chain_raw))
                cert_data['cert_chain'] = cert_chain_pems

                # Extract subject organization
                subject = parsed.get('subject', {})
                org_list = subject.get('organization', [])
                if org_list:
                    cert_data['cert_org'] = org_list[0] if isinstance(org_list, list) else org_list

                # Extract CN
                cn_list = subject.get('common_name', [])
                if cn_list:
                    cert_data['cert_cn'] = cn_list[0] if isinstance(cn_list, list) else cn_list

                # Extract SAN
                extensions = parsed.get('extensions', {})
                san_data = extensions.get('subject_alt_name', {})
                dns_names = san_data.get('dns_names', [])
                cert_data['cert_san'] = dns_names

                # Extract issuer DN
                cert_data['issuer_dn'] = parsed.get('issuer_dn', '')

            except (KeyError, TypeError):
                pass

        return cert_data

    def _extract_asn(self, ip: str) -> Tuple[str, str]:
        """
        Extract ASN and AS name for an IP.

        Returns:
            (asn, as_name) tuple
        """
        asn_number = self.cdn_detector.lookup_asn(ip)
        asn = f'AS{asn_number}' if asn_number else ''

        as_name = 'unknown'
        if asn_number and self.as2org_parser:
            as_name_lookup = self.as2org_parser.get_as_name(asn_number)
            if as_name_lookup:
                as_name = as_name_lookup

        return asn, as_name

    # ========================================================================
    # Stage 1: Certificate Validation + Early Termination
    # ========================================================================

    def stage_1_process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 1: Extract and validate certificate, determine AS, early termination checks.

        Pipeline logic:
            1. Extract certificate and validate, determine AS and mark as_name
            2. IF untrusted cert -> org: unknown -> STOP
            3. IF CDN -> is_cdn: True, org: unknown -> STOP
            4. IF cert has subject_org -> org: subject_org -> STOP
            5. ELSE -> save for Stage 2

        Args:
            input_data: Input data dict from zgrab2 scan

        Returns:
            Dict with extracted and validated data, including 'org' if determined
        """
        ip = input_data.get('ip', '')

        # Extract scan data
        port, asn, headers, http_code, raw_html = self._extract_scan_data(input_data)

        # Extract certificate data
        cert_data = self._extract_cert_data(input_data)
        cert_org = cert_data.get('cert_org', '')
        cert_san = cert_data.get('cert_san', [])
        cert_cn = cert_data.get('cert_cn', '')
        cert_raw = cert_data.get('cert_raw', '')
        cert_chain = cert_data.get('cert_chain', [])
        issuer_dn = cert_data.get('issuer_dn', '')

        # Extract AS name
        asn, as_name = self._extract_asn(ip)

        # Validate certificate using root certificate store
        cert_valid = False
        if cert_raw:
            if cert_chain:
                cert_valid, _ = self.cert_validator.verify_certificate(cert_raw, cert_chain)

        # Build result structure
        result = {
            'ip': ip,
            'port': port,
            'asn': asn,
            'as_name': as_name,
            'is_cdn': False,
            'cert_info': {
                'cert_valid': cert_valid,
                'cert_org': cert_org,
                'cert_san': cert_san,
                'cert_cn': cert_cn,
                'issuer_dn': issuer_dn
            }
        }

        # Step 1: Untrusted certificate -> org: unknown -> STOP
        if not cert_valid:
            self.stats['untrusted_cert_count'] += 1
            result['org'] = 'unknown'
            result['stop_reason'] = 'untrusted_cert'
            return result

        # Step 2: CDN Detection -> is_cdn: True, org: unknown -> STOP
        cdn_result = self.cdn_detector.detect(ip, headers)
        is_cdn = cdn_result.get('is_cdn', False)
        result['is_cdn'] = is_cdn

        if is_cdn:
            self.stats['cdn_count'] += 1
            result['org'] = 'unknown'
            result['stop_reason'] = 'cdn'
            return result

        # Step 3: If cert has subject_org -> org: subject_org -> STOP
        if cert_org:
            self.stats['cert_org_direct_count'] += 1
            result['org'] = cert_org
            result['stop_reason'] = 'cert_org_found'
            return result

        # Step 4: No early termination - save for Stage 2
        self.stats['needs_stage2_count'] += 1
        result['stop_reason'] = 'needs_stage2'
        return result

    # ========================================================================
    # Stage 2: Domain-Based HTML Fetching + LLM Analysis
    # ========================================================================

    def _batch_fetch_html_for_domains(self, ip_domain_pairs: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        """
        Batch fetch HTML for multiple (IP, domain) pairs using zgrab2.

        Uses domain-only format (,domain,,443) to let DNS resolution handle IP mapping.

        Args:
            ip_domain_pairs: List of (ip, domain, port) tuples

        Returns:
            Dict mapping IP to list of successful fetch results
            Format: {ip: [{'domain': domain, 'raw_html': html, 'http_code': code}, ...]}
        """
        if not ip_domain_pairs or not self.zgrab_executable:
            return {}

        # Build IP -> list of domains mapping for reverse lookup
        # Since we're using domain-only format, we need to track which IPs want which domains
        ip_to_domains: Dict[str, List[str]] = {}
        unique_domains = set()

        for ip, domain, _ in ip_domain_pairs:
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            ip_to_domains[ip].append(domain)
            unique_domains.add(domain)

        # Create temporary files
        fd, target_file = tempfile.mkstemp(suffix='.csv', text=True)
        fd_out, output_file = tempfile.mkstemp(suffix='.jsonl', text=True)
        os.close(fd_out)

        results = {ip: [] for ip, _, _ in ip_domain_pairs}

        try:
            # Write targets (format: ,domain,,443) - domain-only, no IP specified
            # This lets zgrab2 handle DNS resolution
            with open(fd, 'w') as f:
                for domain in unique_domains:
                    f.write(f"{domain}\n")

            # Run zgrab2 batch scan
            import subprocess
            cmd = [
                self.zgrab_executable,
                'http',
                '--use-https',
                '-p', '443',
                '-f', target_file,
                '-o', output_file,
                '-s', '2000',  # High concurrency for batch
                '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            ]

            print(f"  Running zgrab2 batch scan ({len(unique_domains)} unique domains for {len(ip_domain_pairs)} IP-domain pairs)...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout for batch
            )

            if result.returncode != 0:
                print(f"  Warning: zgrab2 batch scan failed: {result.stderr}")
                return results

            # Parse results
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        scan_result = json.loads(line)
                        data = scan_result.get('data', {})

                        # Find the http key
                        http_key = None
                        for key in data.keys():
                            if key.startswith('http') and '_ tls' not in key:
                                http_key = key
                                break

                        if not http_key:
                            for key in data.keys():
                                if key.startswith('https'):
                                    http_key = key
                                    break

                        if http_key:
                            http_data = data[http_key]
                            response = http_data.get('result', {}).get('response', {})

                            # Get the domain from the top level (zgrab2 puts it there for domain-only format)
                            domain = scan_result.get('domain', '')
                            # Get the actual IP that responded (zgrab2 resolves DNS)
                            # Note: when using domain-only format, ip field may be null
                            actual_ip = scan_result.get('ip', '')

                            http_code = response.get('status_code', 0)
                            body = response.get('body', '')

                            # Check if response is successful and has meaningful content
                            if http_code == 200 and body and len(body) > 100:
                                # Quick validation check
                                body_lower = body.lower()
                                invalid_patterns = [
                                    '404 not found',
                                    'page not found',
                                    'default page',
                                    'it works!',
                                    'welcome to nginx',
                                    'apache2 default',
                                    'iis windows server',
                                    '403 forbidden'
                                ]

                                is_valid = True
                                for pattern in invalid_patterns:
                                    if pattern in body_lower[:500]:
                                        is_valid = False
                                        break

                                if is_valid:
                                    # Find all IPs that requested this domain and add result to each
                                    for ip, domains in ip_to_domains.items():
                                        if domain in domains:
                                            results[ip].append({
                                                'domain': domain,
                                                'raw_html': body,
                                                'http_code': http_code,
                                                'resolved_ip': actual_ip  # Track the actual IP that responded
                                            })

                    except json.JSONDecodeError:
                        continue

            return results

        except subprocess.TimeoutExpired:
            print(f"  Warning: zgrab2 batch scan timeout")
            return results
        except Exception as e:
            print(f"  Warning: zgrab2 batch scan error: {e}")
            return results
        finally:
            # Clean up temporary files
            try:
                os.unlink(target_file)
                os.unlink(output_file)
            except:
                pass

    def _build_candidate_domains(self, cert_cn: str, cert_san: List[str]) -> List[str]:
        """
        Build candidate domain list from CN and SAN.

        Strategy:
        Step 1: Extract CN
        Step 2: Extract SAN list
        Step 3: Wildcard processing: *.abc.com -> www.abc.com and abc.com
        Step 4: Quick deduplication and sorting (CN first, then by length)

        Args:
            cert_cn: Certificate Common Name
            cert_san: Certificate Subject Alternative Names

        Returns:
            List of candidate domains (max MAX_DOMAIN_ATTEMPTS)
        """
        candidates = []
        seen = set()

        # Priority 1: CN
        if cert_cn:
            cn_clean = cert_cn.lstrip('*.')
            if cn_clean and '.' in cn_clean and cn_clean not in seen:
                candidates.append(cn_clean)
                seen.add(cn_clean)

                # Add www variant if CN was wildcard
                if cert_cn.startswith('*.'):
                    www_variant = cert_cn.replace('*.', 'www.')
                    if www_variant not in seen:
                        candidates.append(www_variant)
                        seen.add(www_variant)

        # Priority 2: SAN (sorted by length, shorter first)
        san_domains = []
        for san_entry in cert_san:
            if not san_entry or san_entry in seen:
                continue

            # Wildcard processing
            if san_entry.startswith('*.'):
                # Generate both www.abc.com and abc.com
                www_variant = san_entry.replace('*.', 'www.')
                base_variant = san_entry.lstrip('*.')

                if base_variant and '.' in base_variant:
                    if base_variant not in seen:
                        san_domains.append((len(base_variant), base_variant))
                        seen.add(base_variant)
                    if www_variant not in seen:
                        san_domains.append((len(www_variant), www_variant))
                        seen.add(www_variant)
            else:
                if san_entry not in seen:
                    san_domains.append((len(san_entry), san_entry))
                    seen.add(san_entry)

        # Sort by length and add
        san_domains.sort(key=lambda x: x[0])
        for _, domain in san_domains:
            candidates.append(domain)

        # Limit to max attempts
        return candidates[:MAX_DOMAIN_ATTEMPTS]

    def _fetch_html_for_domain(self, ip: str, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Fetch HTML for a specific domain using zgrab2 with SNI.

        Uses domain-only format (,domain,,443) to let DNS resolution handle IP.

        Args:
            ip: Target IP address (for tracking/record-keeping, DNS resolution is handled by zgrab2)
            domain: Domain name for SNI
            port: HTTPS port (fixed at 443, kept for interface compatibility)

        Returns:
            Dict with http_code, raw_html, success, error, resolved_ip
        """
        # Note: ip and port parameters are kept for interface compatibility and tracking
        # The actual connection uses DNS resolution via domain-only format
        _ = ip  # Used for tracking, not in zgrab2 input
        _ = port  # Fixed at 443 for HTTPS

        if not self.zgrab_executable:
            return {'success': False, 'error': 'zgrab2 not available', 'http_code': 0, 'raw_html': ''}

        # Create temporary files
        fd, target_file = tempfile.mkstemp(suffix='.csv', text=True)
        fd_out, output_file = tempfile.mkstemp(suffix='.jsonl', text=True)
        os.close(fd_out)

        try:
            # Write target (format: ,domain,,443) - domain-only, no IP specified
            with open(fd, 'w') as f:
                f.write(f"{domain}\n")

            # Run zgrab2
            import subprocess
            cmd = [
                self.zgrab_executable,
                'http',
                '-f', target_file,
                '-o', output_file,
                '--use-https',
                '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # 30 seconds timeout per request
            )

            if result.returncode != 0:
                return {'success': False, 'error': 'zgrab2 failed', 'http_code': 0, 'raw_html': ''}

            # Parse result
            with open(output_file, 'r') as f:
                line = f.readline()
                if not line:
                    return {'success': False, 'error': 'no output', 'http_code': 0, 'raw_html': ''}

                scan_result = json.loads(line)
                data = scan_result.get('data', {})

                # Find the http key
                http_key = None
                for key in data.keys():
                    if key.startswith('http') and '_ tls' not in key:
                        http_key = key
                        break

                if not http_key:
                    # Try https key
                    for key in data.keys():
                        if key.startswith('https'):
                            http_key = key
                            break

                if http_key:
                    http_data = data[http_key]
                    response = http_data.get('result', {}).get('response', {})
                    http_code = response.get('status_code', 0)
                    body = response.get('body', '')

                    # Check if response is successful and has meaningful content
                    # Circuit breaker: stop on first success with valid content
                    if http_code == 200:
                        # Check for valid content (not 403/404/Default Page)
                        if body and len(body) > 100:
                            # Quick check for default/empty pages
                            body_lower = body.lower()
                            invalid_patterns = [
                                '404 not found',
                                'page not found',
                                'default page',
                                'it works!',
                                'welcome to nginx',
                                'apache2 default',
                                'iis windows server',
                                '403 forbidden'
                            ]

                            is_valid = True
                            for pattern in invalid_patterns:
                                if pattern in body_lower[:500]:  # Check first 500 chars
                                    is_valid = False
                                    break

                            if is_valid:
                                return {
                                    'success': True,
                                    'http_code': http_code,
                                    'raw_html': body,
                                    'domain': domain,
                                    'resolved_ip': scan_result.get('ip', '')  # Track actual resolved IP
                                }

                    return {
                        'success': False,
                        'error': f'HTTP {http_code}',
                        'http_code': http_code,
                        'raw_html': body if body else ''
                    }

            return {'success': False, 'error': 'no http data', 'http_code': 0, 'raw_html': ''}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'timeout', 'http_code': 0, 'raw_html': ''}
        except Exception as e:
            return {'success': False, 'error': str(e), 'http_code': 0, 'raw_html': ''}
        finally:
            # Clean up temporary files
            try:
                os.unlink(target_file)
                os.unlink(output_file)
            except:
                pass

    def stage_2a_fetch_html(self, stage1_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 2A: Domain-based HTML fetching.

        Pipeline logic:
            1. Extract cert subject_cn and SAN domains
            2. Build candidate domain list (CN + SAN, wildcard processing)
            3. Sequentially try domains (max 5 attempts) with circuit breaker
            4. For successful response -> clean HTML -> save intermediate results

        Args:
            stage1_data: Data from stage 1

        Returns:
            Dict with HTML fetch results (intermediate - saved to file)
        """
        result = stage1_data.copy()

        # If org already determined in stage 1, return as is
        if 'org' in result:
            return result

        ip = result.get('ip', '')
        cert_info = result.get('cert_info', {})
        cert_cn = cert_info.get('cert_cn', '')
        cert_san = cert_info.get('cert_san', [])

        # Step 1: Build candidate domain list
        candidates = self._build_candidate_domains(cert_cn, cert_san)

        result['html_fetch_info'] = {
            'candidates': candidates,
            'successful_domain': '',
            'raw_html': '',
            'cleaned_html': '',
            'success': False
        }

        if not candidates:
            self.stats['unknown_count'] += 1
            result['org'] = 'unknown'
            result['stop_reason'] = 'no_valid_domains'
            return result

        # Step 2 & 3: Sequentially try domains with circuit breaker
        cleaned_html = ''
        successful_domain = ''
        raw_html = ''

        for domain in candidates:
            fetch_result = self._fetch_html_for_domain(ip, domain)

            if fetch_result.get('success'):
                raw_html = fetch_result.get('raw_html', '')
                cleaned_html = self.html_processor.extract_text(raw_html)
                successful_domain = domain
                self.stats['html_fetch_success'] += 1

                # Circuit breaker: stop on first success
                break
            else:
                self.stats['html_fetch_failed'] += 1

        result['html_fetch_info']['successful_domain'] = successful_domain
        result['html_fetch_info']['raw_html'] = raw_html
        result['html_fetch_info']['cleaned_html'] = cleaned_html
        result['html_fetch_info']['success'] = bool(cleaned_html)

        if not cleaned_html:
            self.stats['unknown_count'] += 1
            result['org'] = 'unknown'
            result['stop_reason'] = 'html_fetch_failed'
            return result

        # HTML fetch successful - ready for Stage 2B (LLM analysis)
        result['stop_reason'] = 'needs_llm'
        return result

    def stage_2b_llm_analysis(self, stage2a_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 2B: LLM analysis for final attribution.

        Pipeline logic:
            1. Read cleaned HTML from Stage 2A results
            2. Use cert subject_cn, san, cleaned_html -> LLM inference
            3. org: label

        Args:
            stage2a_data: Data from stage 2A (HTML fetch results)

        Returns:
            Final result with attribution
        """
        result = stage2a_data.copy()

        # If org already determined, return as is
        if 'org' in result and result.get('stop_reason') != 'needs_llm':
            return result

        # Check if we have HTML data
        html_fetch_info = result.get('html_fetch_info', {})
        cleaned_html = html_fetch_info.get('cleaned_html', '')

        if not cleaned_html:
            self.stats['unknown_count'] += 1
            result['org'] = 'unknown'
            result['stop_reason'] = 'no_html_for_llm'
            return result

        cert_info = result.get('cert_info', {})
        cert_cn = cert_info.get('cert_cn', '')
        cert_san = cert_info.get('cert_san', [])

        # LLM inference
        self.stats['llm_analysis_count'] += 1

        user_prompt = self._build_llm_prompt(cert_cn, cert_san, cleaned_html)
        llm_result = self.llm_api.call(
            system_prompt=self.SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1,
            json_mode=True
        )

        result['llm_analysis'] = {
            'raw_response': llm_result.get('content', ''),
            'parsed': llm_result.get('parsed', {}),
            'error': llm_result.get('error', ''),
            'success': llm_result.get('success', False)
        }

        if llm_result.get('success') and llm_result.get('parsed'):
            parsed = llm_result['parsed']
            attribution = parsed.get('organization', 'unknown')
            result['org'] = self._normalize_org_name(attribution)
            result['stop_reason'] = 'llm_success'
        else:
            self.stats['unknown_count'] += 1
            result['org'] = 'unknown'
            result['stop_reason'] = 'llm_failed'

        return result

    def _build_llm_prompt(self, cert_cn: str, cert_san: List[str], cleaned_html: str) -> str:
        """Build user prompt for LLM analysis."""
        prompt = f"""Please analyze the following information and determine the operating organization:

**Certificate Common Name (CN):**
{cert_cn if cert_cn else 'N/A'}

**Subject Alternative Names (SAN):**
{', '.join(cert_san) if cert_san else 'N/A'}

**HTML Content (cleaned):**
{cleaned_html[:5000] if cleaned_html else 'N/A'}

Based on the above information, what is the operating organization?"""

        return prompt

    def _normalize_org_name(self, org: str) -> str:
        """Normalize organization name."""
        if not org:
            return 'unknown'

        org = org.strip()

        # Convert to title case
        org = org.title()

        return org if org else 'unknown'

    # ========================================================================
    # File Processing Methods
    # ========================================================================

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single input data through all stages.

        Args:
            input_data: Input data dict from zgrab2 scan

        Returns:
            Final result with attribution
        """
        self.stats['total_processed'] += 1

        # Stage 1
        stage1_result = self.stage_1_process(input_data)

        # Stage 2A (if needed)
        if stage1_result.get('stop_reason') == 'needs_stage2':
            stage2a_result = self.stage_2a_fetch_html(stage1_result)

            # Stage 2B (if HTML fetch successful)
            if stage2a_result.get('stop_reason') == 'needs_llm':
                return self.stage_2b_llm_analysis(stage2a_result)

            return stage2a_result

        return stage1_result

    def process_file(self,
                     input_file: str,
                     output_jsonl: str,
                     stop_at_stage1: bool = False) -> Dict[str, Any]:
        """
        Process a file of zgrab2 scan results.

        Args:
            input_file: Path to input JSONL file
            output_jsonl: Path to output JSONL file
            stop_at_stage1: If True, stop after Stage 1

        Returns:
            Statistics dictionary
        """
        input_path = Path(input_file)
        output_path = Path(output_jsonl)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Reset statistics
        self.stats = {
            'total_processed': 0,
            'untrusted_cert_count': 0,
            'cdn_count': 0,
            'cert_org_direct_count': 0,
            'needs_stage2_count': 0,
            'html_fetch_success': 0,
            'html_fetch_failed': 0,
            'llm_analysis_count': 0,
            'unknown_count': 0
        }

        stage1_results = []

        # Process input file
        with open(input_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    input_data = json.loads(line)
                    self.stats['total_processed'] += 1

                    # Stage 1
                    stage1_result = self.stage_1_process(input_data)
                    stage1_results.append(stage1_result)

                    # Print progress
                    if self.stats['total_processed'] % 100 == 0:
                        print(f"  Processed {self.stats['total_processed']} records...")

                except json.JSONDecodeError:
                    continue

        # Save Stage 1 results
        # If output path already ends with _stage1, use it directly; otherwise add suffix
        if output_path.stem.endswith('_stage1'):
            stage1_file = output_path
        else:
            stage1_file = output_path.parent / (output_path.stem + '_stage1.jsonl')
        with open(stage1_file, 'w') as f:
            for result in stage1_results:
                f.write(json.dumps(result) + '\n')

        print(f"  Stage 1 complete: {len(stage1_results)} records")
        print(f"    - Untrusted cert: {self.stats['untrusted_cert_count']}")
        print(f"    - CDN: {self.stats['cdn_count']}")
        print(f"    - Cert org found: {self.stats['cert_org_direct_count']}")
        print(f"    - Needs Stage 2: {self.stats['needs_stage2_count']}")

        if stop_at_stage1:
            return self.stats

        # Stage 2A: HTML Fetching (BATCH MODE)
        print("\n  Starting Stage 2A: HTML Fetching (BATCH MODE)...")
        stage2a_results = []
        ip_domain_pairs = []
        ip_to_stage1 = {}

        # Collect all results and build batch scan list
        for stage1_result in stage1_results:
            if stage1_result.get('stop_reason') == 'needs_stage2':
                ip = stage1_result.get('ip', '')
                cert_info = stage1_result.get('cert_info', {})
                cert_cn = cert_info.get('cert_cn', '')
                cert_san = cert_info.get('cert_san', [])
                port = stage1_result.get('port', 443)

                ip_to_stage1[ip] = stage1_result

                # Build candidate domains and add to batch list
                candidates = self._build_candidate_domains(cert_cn, cert_san)
                for domain in candidates:
                    ip_domain_pairs.append((ip, domain, port))
            else:
                stage2a_results.append(stage1_result)

        print(f"  Total (IP, domain) pairs to scan: {len(ip_domain_pairs)}")

        if ip_domain_pairs:
            # Batch fetch HTML
            batch_results = self._batch_fetch_html_for_domains(ip_domain_pairs)

            # Update stage1 results with fetched HTML
            for ip, fetched_list in batch_results.items():
                if ip in ip_to_stage1:
                    stage1_result = ip_to_stage1[ip]

                    cert_info = stage1_result.get('cert_info', {})
                    cert_cn = cert_info.get('cert_cn', '')
                    cert_san = cert_info.get('cert_san', [])
                    candidates = self._build_candidate_domains(cert_cn, cert_san)

                    # Select the first valid result
                    selected = None
                    if fetched_list:
                        for fetch_result in fetched_list:
                            selected = fetch_result
                            self.stats['html_fetch_success'] += 1
                            break

                    if not selected:
                        self.stats['html_fetch_failed'] += 1
                        stage1_result['html_fetch_info'] = {
                            'candidates': candidates,
                            'successful_domain': '',
                            'raw_html': '',
                            'cleaned_html': '',
                            'success': False
                        }
                        stage1_result['org'] = 'unknown'
                        stage1_result['stop_reason'] = 'html_fetch_failed'
                    else:
                        raw_html = selected['raw_html']
                        cleaned_html = self.html_processor.extract_text(raw_html)
                        successful_domain = selected['domain']

                        stage1_result['html_fetch_info'] = {
                            'candidates': candidates,
                            'successful_domain': successful_domain,
                            'raw_html': raw_html,
                            'cleaned_html': cleaned_html,
                            'success': True
                        }
                        stage1_result['stop_reason'] = 'needs_llm'

                    stage2a_results.append(stage1_result)

        # Save Stage 2A results
        stage2a_file = output_path.parent / (output_path.stem + '_stage2a.jsonl')
        with open(stage2a_file, 'w') as f:
            for result in stage2a_results:
                f.write(json.dumps(result) + '\n')

        print(f"\n  Stage 2A complete:")
        print(f"    - HTML fetch success: {self.stats['html_fetch_success']}")
        print(f"    - HTML fetch failed: {self.stats['html_fetch_failed']}")

        # Stage 2B: LLM Analysis (CONCURRENT)
        print("\n  Starting Stage 2B: LLM Analysis (CONCURRENT)...")
        final_results = []

        # Separate tasks: needs LLM vs already complete
        llm_tasks = []
        for stage2a_result in stage2a_results:
            if stage2a_result.get('stop_reason') == 'needs_llm':
                llm_tasks.append(stage2a_result)
            else:
                final_results.append(stage2a_result)

        if llm_tasks:
            print(f"  Processing {len(llm_tasks)} records with concurrent LLM analysis...")
            completed_count = 0

            with ThreadPoolExecutor(max_workers=10) as executor:
                # Submit all tasks
                future_to_task = {
                    executor.submit(self.stage_2b_llm_analysis, task): task
                    for task in llm_tasks
                }

                # Process completed tasks
                for future in as_completed(future_to_task):
                    try:
                        result = future.result()
                        final_results.append(result)
                        completed_count += 1

                        # Print progress
                        if completed_count % 10 == 0:
                            print(f"  LLM analysis: {completed_count}/{len(llm_tasks)} records completed...")

                    except Exception as e:
                        print(f"  Error processing LLM task: {e}")

        # Save final results
        with open(output_path, 'w') as f:
            for result in final_results:
                f.write(json.dumps(result) + '\n')

        print(f"\n  Stage 2B complete:")
        print(f"    - LLM analysis: {self.stats['llm_analysis_count']}")
        print(f"    - Unknown: {self.stats['unknown_count']}")

        return self.stats

    def process_stage2a_from_stage1(self,
                                    intermediate_file: str,
                                    output_jsonl: str) -> Dict[str, Any]:
        """
        Process Stage 2A (HTML Fetching) from Stage 1 intermediate results.
        Uses BATCH concurrent scanning for efficiency.

        Args:
            intermediate_file: Path to Stage 1 JSONL file
            output_jsonl: Path to output Stage 2A JSONL file

        Returns:
            Statistics dictionary
        """
        intermediate_path = Path(intermediate_file)
        output_path = Path(output_jsonl)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Reset stage 2a statistics
        self.stats['html_fetch_success'] = 0
        self.stats['html_fetch_failed'] = 0
        self.stats['unknown_count'] = 0

        stage2a_results = []
        ip_to_stage1 = {}  # Map IP to stage1 result for updating

        # Step 1: Load Stage 1 results and collect all (IP, domain) pairs
        print(f"  Loading Stage 1 results from {intermediate_file}...")
        ip_domain_pairs = []  # List of (ip, domain, port)
        needs_stage2_count = 0  # Count of records that need Stage 2

        with open(intermediate_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    stage1_result = json.loads(line)

                    # Check if needs Stage 2
                    if stage1_result.get('stop_reason') == 'needs_stage2':
                        ip = stage1_result.get('ip', '')
                        needs_stage2_count += 1

                        # Store for later update (only for IPs that need Stage 2)
                        if ip:
                            ip_to_stage1[ip] = stage1_result

                        cert_info = stage1_result.get('cert_info', {})
                        cert_cn = cert_info.get('cert_cn', '')
                        cert_san = cert_info.get('cert_san', [])

                        # Build candidate domains for this IP
                        candidates = self._build_candidate_domains(cert_cn, cert_san)

                        # Add to batch list
                        port = stage1_result.get('port', 443)
                        for domain in candidates:
                            ip_domain_pairs.append((ip, domain, port))
                    else:
                        stage2a_results.append(stage1_result)

                except json.JSONDecodeError:
                    continue

        print(f"  Found {needs_stage2_count} IPs needing Stage 2")
        print(f"  Total (IP, domain) pairs to scan: {len(ip_domain_pairs)}")

        if not ip_domain_pairs:
            # No HTML fetching needed, save and return
            with open(output_path, 'w') as f:
                for result in stage2a_results:
                    f.write(json.dumps(result) + '\n')

            print(f"\n  Stage 2A (HTML Fetching) complete:")
            print(f"    - No HTML fetching needed")
            print(f"    - Output: {output_path}")
            return self.stats

        # Step 2: Batch fetch HTML for all domains
        batch_results = self._batch_fetch_html_for_domains(ip_domain_pairs)

        # Step 3: Update stage1 results with fetched HTML
        for ip, fetched_list in batch_results.items():
            if ip in ip_to_stage1:
                stage1_result = ip_to_stage1[ip]

                # Prepare html_fetch_info structure
                cert_info = stage1_result.get('cert_info', {})
                cert_cn = cert_info.get('cert_cn', '')
                cert_san = cert_info.get('cert_san', [])
                candidates = self._build_candidate_domains(cert_cn, cert_san)

                # Select the first valid result (circuit breaker effect)
                selected = None
                if fetched_list:
                    for fetch_result in fetched_list:
                        # Use the first successful result
                        selected = fetch_result
                        self.stats['html_fetch_success'] += 1
                        break

                if not selected:
                    self.stats['html_fetch_failed'] += 1
                    stage1_result['html_fetch_info'] = {
                        'candidates': candidates,
                        'successful_domain': '',
                        'raw_html': '',
                        'cleaned_html': '',
                        'success': False
                    }
                    stage1_result['org'] = 'unknown'
                    stage1_result['stop_reason'] = 'html_fetch_failed'
                else:
                    # Process successful fetch
                    raw_html = selected['raw_html']
                    cleaned_html = self.html_processor.extract_text(raw_html)
                    successful_domain = selected['domain']

                    stage1_result['html_fetch_info'] = {
                        'candidates': candidates,
                        'successful_domain': successful_domain,
                        'raw_html': raw_html,
                        'cleaned_html': cleaned_html,
                        'success': True
                    }
                    stage1_result['stop_reason'] = 'needs_llm'

                stage2a_results.append(stage1_result)

        # Step 4: Save Stage 2A results
        with open(output_path, 'w') as f:
            for result in stage2a_results:
                f.write(json.dumps(result) + '\n')

        print(f"\n  Stage 2A (HTML Fetching) complete:")
        print(f"    - HTML fetch success: {self.stats['html_fetch_success']}")
        print(f"    - HTML fetch failed: {self.stats['html_fetch_failed']}")
        print(f"    - Unknown: {self.stats['unknown_count']}")
        print(f"    - Output: {output_path}")

        return self.stats

    def process_from_stage1(self,
                           intermediate_file: str,
                           output_jsonl: str,
                           output_csv: str = None) -> Dict[str, Any]:
        """
        Process from Stage 1 intermediate results.

        Args:
            intermediate_file: Path to Stage 1 JSONL file
            output_jsonl: Path to output JSONL file
            output_csv: Optional path to output CSV file

        Returns:
            Statistics dictionary
        """
        intermediate_path = Path(intermediate_file)
        output_path = Path(output_jsonl)

        if output_csv:
            csv_path = Path(output_csv)
        else:
            csv_path = None

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Reset stage 2 statistics
        self.stats['needs_stage2_count'] = 0
        self.stats['html_fetch_success'] = 0
        self.stats['html_fetch_failed'] = 0
        self.stats['llm_analysis_count'] = 0
        self.stats['unknown_count'] = 0

        final_results = []
        ip_domain_pairs = []
        ip_to_stage1 = {}
        stage2a_results = []

        # Load Stage 1 results and process through Stage 2A + Stage 2B
        print(f"  Loading Stage 1 results from {intermediate_file}...")
        with open(intermediate_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    stage1_result = json.loads(line)

                    # Check if needs Stage 2
                    if stage1_result.get('stop_reason') == 'needs_stage2':
                        self.stats['needs_stage2_count'] += 1

                        ip = stage1_result.get('ip', '')
                        cert_info = stage1_result.get('cert_info', {})
                        cert_cn = cert_info.get('cert_cn', '')
                        cert_san = cert_info.get('cert_san', [])
                        port = stage1_result.get('port', 443)

                        ip_to_stage1[ip] = stage1_result

                        # Build candidate domains and add to batch list
                        candidates = self._build_candidate_domains(cert_cn, cert_san)
                        for domain in candidates:
                            ip_domain_pairs.append((ip, domain, port))
                    else:
                        final_results.append(stage1_result)

                except json.JSONDecodeError:
                    continue

        print(f"  Found {self.stats['needs_stage2_count']} IPs needing Stage 2")
        print(f"  Total (IP, domain) pairs to scan: {len(ip_domain_pairs)}")

        # Stage 2A: Batch HTML Fetching
        if ip_domain_pairs:
            print(f"\n  Stage 2A: Batch HTML Fetching...")
            batch_results = self._batch_fetch_html_for_domains(ip_domain_pairs)

            # Update stage1 results with fetched HTML
            for ip, fetched_list in batch_results.items():
                if ip in ip_to_stage1:
                    stage1_result = ip_to_stage1[ip]

                    cert_info = stage1_result.get('cert_info', {})
                    cert_cn = cert_info.get('cert_cn', '')
                    cert_san = cert_info.get('cert_san', [])
                    candidates = self._build_candidate_domains(cert_cn, cert_san)

                    # Select the first valid result
                    selected = None
                    if fetched_list:
                        for fetch_result in fetched_list:
                            selected = fetch_result
                            self.stats['html_fetch_success'] += 1
                            break

                    if not selected:
                        self.stats['html_fetch_failed'] += 1
                        stage1_result['html_fetch_info'] = {
                            'candidates': candidates,
                            'successful_domain': '',
                            'raw_html': '',
                            'cleaned_html': '',
                            'success': False
                        }
                        stage1_result['org'] = 'unknown'
                        stage1_result['stop_reason'] = 'html_fetch_failed'
                    else:
                        raw_html = selected['raw_html']
                        cleaned_html = self.html_processor.extract_text(raw_html)
                        successful_domain = selected['domain']

                        stage1_result['html_fetch_info'] = {
                            'candidates': candidates,
                            'successful_domain': successful_domain,
                            'raw_html': raw_html,
                            'cleaned_html': cleaned_html,
                            'success': True
                        }
                        stage1_result['stop_reason'] = 'needs_llm'

                    stage2a_results.append(stage1_result)

        # Stage 2B: LLM Analysis (CONCURRENT)
        print(f"\n  Stage 2B: LLM Analysis (CONCURRENT)...")

        # Separate tasks: needs LLM vs already complete
        llm_tasks = []
        for stage2a_result in stage2a_results:
            if stage2a_result.get('stop_reason') == 'needs_llm':
                llm_tasks.append(stage2a_result)
            else:
                final_results.append(stage2a_result)

        if llm_tasks:
            print(f"  Processing {len(llm_tasks)} records with concurrent LLM analysis...")
            completed_count = 0

            with ThreadPoolExecutor(max_workers=10) as executor:
                # Submit all tasks
                future_to_task = {
                    executor.submit(self.stage_2b_llm_analysis, task): task
                    for task in llm_tasks
                }

                # Process completed tasks
                for future in as_completed(future_to_task):
                    try:
                        result = future.result()
                        final_results.append(result)
                        completed_count += 1

                        # Print progress
                        if completed_count % 10 == 0:
                            print(f"  LLM analysis: {completed_count}/{len(llm_tasks)} records completed...")

                    except Exception as e:
                        print(f"  Error processing LLM task: {e}")

        # Save final results
        with open(output_path, 'w') as f:
            for result in final_results:
                f.write(json.dumps(result) + '\n')

        # Save CSV if requested
        if csv_path:
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'org'])

                for result in final_results:
                    writer.writerow([result.get('ip', ''), result.get('org', 'unknown')])

        print(f"\n  Stage 2 (2A + 2B) complete:")
        print(f"    - Needs Stage 2: {self.stats['needs_stage2_count']}")
        print(f"    - HTML fetch success: {self.stats['html_fetch_success']}")
        print(f"    - HTML fetch failed: {self.stats['html_fetch_failed']}")
        print(f"    - LLM analysis: {self.stats['llm_analysis_count']}")
        print(f"    - Unknown: {self.stats['unknown_count']}")

        return self.stats

    def process_stage2b_from_stage2a(self,
                                     stage2a_file: str,
                                     output_jsonl: str,
                                     output_csv: str = None,
                                     max_workers: int = 10,
                                     save_interval: int = 50) -> Dict[str, Any]:
        """
        Process Stage 2B (LLM Analysis) from Stage 2A intermediate results.

        Uses CONCURRENT processing for improved performance.

        Args:
            stage2a_file: Path to Stage 2A JSONL file (with HTML fetch results)
            output_jsonl: Path to output JSONL file
            output_csv: Optional path to output CSV file
            max_workers: Number of concurrent LLM requests (default: 10)
            save_interval: Save intermediate results every N records (default: 50)

        Returns:
            Statistics dictionary
        """
        stage2a_path = Path(stage2a_file)
        output_path = Path(output_jsonl)

        if output_csv:
            csv_path = Path(output_csv)
        else:
            csv_path = None

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Reset stage 2b statistics
        self.stats['llm_analysis_count'] = 0
        self.stats['unknown_count'] = 0

        # Thread-safe counters and locks
        self._stats_lock = Lock()
        self._progress_count = 0

        # Load Stage 2A results and separate tasks
        print(f"  Loading Stage 2A results from {stage2a_file}...")
        stage2a_results = []
        llm_tasks = []

        with open(stage2a_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    stage2a_result = json.loads(line)

                    # Check if needs LLM analysis
                    if stage2a_result.get('stop_reason') == 'needs_llm':
                        llm_tasks.append(stage2a_result)
                    else:
                        stage2a_results.append(stage2a_result)

                except json.JSONDecodeError:
                    continue

        print(f"  Found {len(llm_tasks)} records needing LLM analysis")
        print(f"  Found {len(stage2a_results)} records already complete")

        if not llm_tasks:
            # No LLM analysis needed, just save results
            with open(output_path, 'w') as f:
                for result in stage2a_results:
                    f.write(json.dumps(result) + '\n')

            print(f"\n  Stage 2B (LLM Analysis) complete:")
            print(f"    - No LLM analysis needed")
            print(f"    - Output: {output_path}")
            return self.stats

        # Process LLM tasks concurrently
        print(f"\n  Starting concurrent LLM analysis (max_workers={max_workers})...")
        completed_count = 0
        llm_results = []

        # Temporary file for incremental saving
        temp_output_path = output_path.with_suffix('.tmp')

        with open(temp_output_path, 'w') as tmp_f:
            # Save non-LLM results first
            for result in stage2a_results:
                tmp_f.write(json.dumps(result) + '\n')

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(self.stage_2b_llm_analysis, task): task
                for task in llm_tasks
            }

            # Process completed tasks
            with open(temp_output_path, 'a') as tmp_f:
                for future in as_completed(future_to_task):
                    try:
                        result = future.result()
                        llm_results.append(result)

                        # Increment completed count (thread-safe)
                        with self._stats_lock:
                            completed_count += 1
                            self._progress_count += 1

                        # Write result immediately
                        tmp_f.write(json.dumps(result) + '\n')
                        tmp_f.flush()

                        # Print progress
                        if completed_count % 10 == 0:
                            print(f"  LLM analysis: {completed_count}/{len(llm_tasks)} records completed...")

                        # Save checkpoint periodically
                        if completed_count % save_interval == 0:
                            print(f"  Checkpoint: {completed_count} records saved to {temp_output_path}")

                    except Exception as e:
                        print(f"  Error processing task: {e}")
                        with self._stats_lock:
                            self.stats['unknown_count'] += 1

        # Rename temp file to final output
        temp_output_path.replace(output_path)

        # Save CSV if requested
        if csv_path:
            print(f"  Saving CSV to {csv_path}...")
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'org'])

                # Write from non-LLM results
                for result in stage2a_results:
                    writer.writerow([result.get('ip', ''), result.get('org', 'unknown')])

                # Write from LLM results
                for result in llm_results:
                    writer.writerow([result.get('ip', ''), result.get('org', 'unknown')])

        print(f"\n  Stage 2B (LLM Analysis) complete:")
        print(f"    - LLM analysis: {self.stats['llm_analysis_count']}")
        print(f"    - Unknown: {self.stats['unknown_count']}")
        print(f"    - Output: {output_path}")

        return self.stats


if __name__ == '__main__':
    # Test the pipeline
    pipeline = AttributionPipeline()

    # Test with a sample input
    sample_input = {
        'ip': '1.1.1.1',
        'data': {
            'https': {
                'result': {
                    'response': {
                        'status_code': 200,
                        'headers': {'Server': 'cloudflare'},
                        'body': '<html><body>Test</body></html>'
                    },
                    'request': {
                        'tls_log': {
                            'handshake_log': {
                                'server_certificates': {
                                    'certificate': {
                                        'parsed': {
                                            'subject': {
                                                'organization': ['Example Inc'],
                                                'common_name': ['example.com']
                                            },
                                            'issuer_dn': 'CN=Test CA'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = pipeline.process(sample_input)
    print(json.dumps(result, indent=2))
