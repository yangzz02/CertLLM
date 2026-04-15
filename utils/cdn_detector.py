#!/usr/bin/env python3
"""
CDN/Cloud Provider Detection Module

Detects CDN and cloud providers via:
1. ASN lookup using pyasn
2. HTTP response header patterns

Usage:
    detector = CNDDetector(asn_db_path='data/asn_db', cdn_asn_file='cdn_asn.json')
    result = detector.detect(ip='1.1.1.1', headers={'server': 'cloudflare'})
"""

import json
import re
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# CDN header patterns (case-insensitive)
# CDN_HEADER_PATTERNS = [
#     (r'^x-cache:\s*(hit|miss|refreshhit)$', 'X-Cache'),
#     (r'^via:\s.*(\bvarnish\b|\bsquid\b|\bcloudflare\b)', 'Via'),
#     (r'^server:\s.*(\bcloudflare\b|\bawselb\b|\bgws\b|nginx.*cloudflare)', 'Server'),
#     (r'^cf-ray:', 'CF-RAY'),
#     (r'^cf-cache-status:', 'CF-Cache-Status'),
#     (r'^x-akamai-', 'X-Akamai'),
#     (r'^x-cdn:\s.*(cloudflare|akamai|fastly)', 'X-CDN'),
#     (r'^x-amz-cf-id:', 'X-Amz-CF-ID'),  # CloudFront
#     (r'^x-edge-location:', 'X-Edge-Location'),  # CloudFront
#     (r'^x-served-by:', 'X-Served-By'),  # Fastly
#     (r'^x-fastly-request-id:', 'X-Fastly-Request-ID'),
# ]
 
CDN_HEADER_PATTERNS = [
    # 1. Server 字段: 明确的 CDN 厂商标识
    (re.compile(r'^server:\s.*(cloudflare|akamai|gse|sffe|gws|edgecast|netdna|sucuri)', re.IGNORECASE), 'Server-Vendor'),
    
    # 2. Via 字段: 代理路径
    # 这里的 '1.1 google' 通常是 GCLB 的前端，'1.1 varnish' 太通用容易误伤，所以只杀带厂商名的
    (re.compile(r'^via:\s.*(cloudfront|akamai|bitgravity|zenedge)', re.IGNORECASE), 'Via-Vendor'),
    
    # 3. Cloudflare 特有
    (re.compile(r'^cf-ray:', re.IGNORECASE), 'Cloudflare-Ray'),
    (re.compile(r'^cf-cache-status:', re.IGNORECASE), 'Cloudflare-Status'),
    
    # 4. Amazon CloudFront 特有 (注意区分 ELB 和 CloudFront)
    (re.compile(r'^x-amz-cf-id:', re.IGNORECASE), 'CloudFront-ID'),
    
    # 5. Akamai 特有
    (re.compile(r'^x-akamai-', re.IGNORECASE), 'Akamai-Tag'),
    
    # 6. Fastly 特有
    (re.compile(r'^x-fastly-', re.IGNORECASE), 'Fastly-Tag'),
    (re.compile(r'^x-served-by:\s.*cache-', re.IGNORECASE), 'Fastly-Served'),
    
    # 7. EdgeCast / Verizon
    (re.compile(r'^x-ec-custom-error:', re.IGNORECASE), 'EdgeCast-Error'),
    
    # 8. 通用 CDN 边缘位置标识 (云主机通常没有这个，CDN 才有)
    (re.compile(r'^x-edge-location:', re.IGNORECASE), 'CDN-Edge-Loc'),
    (re.compile(r'^x-cdn:', re.IGNORECASE), 'Generic-X-CDN')
]


 

class CNDDetector:
    """CDN/Cloud provider detector."""

    # AWS ASNs (Amazon)
    AWS_ASNS = {
        16509,  # Amazon.com, Inc.
        14618,  # Amazon EC2
        7224,   # Amazon
        16702,  # Amazon
        36884,  # Amazon
        38895,  # Amazon
        24112,  # Amazon
        23275,  # Amazon
        27728,  # Amazon
        # Add more as needed
    }

    # Azure ASNs (Microsoft)
    AZURE_ASNS = {
        8075,   # Microsoft Corporation
        8068,   # Microsoft-Europe
        12076,  # Microsoft Corporation (Azure)
        26606,  # Microsoft Azure
        20473,  # Microsoft Azure
        # Add more as needed
    }

    def __init__(self, asn_db_path: str = None, cdn_asn_file: Path = None,
                 aws_ranges_file: Path = None, azure_ranges_file: Path = None):
        """
        Initialize CDN detector.

        Args:
            asn_db_path: Path to pyasn IPASN database file
            cdn_asn_file: Path to CDN ASN mapping JSON file
            aws_ranges_file: Path to AWS IP ranges JSON file
            azure_ranges_file: Path to Azure Service Tags JSON file
        """
        self.asn_db = None
        if asn_db_path:
            try:
                import pyasn
                self.asn_db = pyasn.pyasn(asn_db_path)
            except (ImportError, FileNotFoundError):
                pass

        self.cdn_asns = {}
        if cdn_asn_file and cdn_asn_file.exists():
            self.cdn_asns = self._load_cdn_asns(cdn_asn_file)

        # Pre-compiled AWS CDN prefixes (only CDN services)
        self.aws_cdn_networks = []
        if aws_ranges_file and aws_ranges_file.exists():
            self.aws_cdn_networks = self._load_aws_cdn_networks(aws_ranges_file)

        # Pre-compiled Azure CDN prefixes (only CDN services)
        self.azure_cdn_networks = []
        if azure_ranges_file and azure_ranges_file.exists():
            self.azure_cdn_networks = self._load_azure_cdn_networks(azure_ranges_file)

        # Statistics
        self.cdn_by_asn_count = 0
        self.cdn_by_header_count = 0
        self.cdn_by_aws_prefix_count = 0
        self.cdn_by_azure_prefix_count = 0
        self.asn_skip_count = 0  # Track how many IPs skipped by ASN check

    def _load_cdn_asns(self, asn_file: Path) -> Dict[int, str]:
        """Load CDN ASN mappings from JSON file."""
        with open(asn_file, 'r') as f:
            data = json.load(f)

        cdn_asns = {}
        for provider, asns in data.items():
            for asn in asns:
                cdn_asns[asn] = provider
        return cdn_asns

    def _load_aws_cdn_networks(self, aws_file: Path) -> List:
        """Load and pre-compile AWS CDN IP ranges."""
        with open(aws_file, 'r') as f:
            data = json.load(f)

        cdn_services = {'CLOUDFRONT', 'S3', 'ROUTE53_HEALTH_CHECKS', 'GLOBALACCELERATOR'}
        networks = []

        for prefix in data.get('prefixes', []):
            service = prefix.get('service', '')
            if service in cdn_services:
                try:
                    net = ipaddress.ip_network(prefix['ip_prefix'])
                    networks.append((net, service))
                except (ValueError, KeyError):
                    continue

        print(f"[*] Pre-compiled {len(networks)} AWS CDN network prefixes")
        return networks

    def _load_azure_cdn_networks(self, azure_file: Path) -> List:
        """Load and pre-compile Azure CDN IP ranges."""
        with open(azure_file, 'r') as f:
            data = json.load(f)

        networks = []

        for item in data.get('values', []):
            name = item.get('name', '')
            # Check if this is a CDN service
            if any(cdnn in name for cdnn in ['AzureFrontDoor', 'AzureCDN', 'TrafficManager']):
                properties = item.get('properties', {})
                for prefix_str in properties.get('addressPrefixes', []):
                    try:
                        net = ipaddress.ip_network(prefix_str)
                        networks.append((net, name))
                    except ValueError:
                        continue

        print(f"[*] Pre-compiled {len(networks)} Azure CDN network prefixes")
        return networks

    def check_aws(self, ip: str) -> Optional[str]:
        """
        AWS 策略 - ASN预过滤 + 前缀匹配:
        1. 先检查ASN是否属于AWS
        2. 只有AWS IP才进行前缀匹配
        3. 排除: CLOUDFRONT, ROUTE53_HEALTH_CHECKS, GLOBALACCELERATOR, S3

        Returns:
            'DROP_CDN' if CDN service, None otherwise
        """
        # Fast path: no ASN DB or no pre-compiled networks
        if not self.asn_db or not self.aws_cdn_networks:
            return None

        # Step 1: Check if IP belongs to AWS ASN
        asn, _ = self.asn_db.lookup(ip)
        if asn not in self.AWS_ASNS:
            self.asn_skip_count += 1
            return None  # Not AWS IP, skip prefix check

        # Step 2: IP belongs to AWS, check if it's in CDN prefixes
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for net, service in self.aws_cdn_networks:
            if ip_obj in net:
                return 'DROP_CDN'

        return None

    def check_azure(self, ip: str) -> Optional[str]:
        """
        Azure 策略 - ASN预过滤 + 前缀匹配:
        1. 先检查ASN是否属于Azure
        2. 只有Azure IP才进行前缀匹配
        3. 排除: AzureFrontDoor, AzureCDN, TrafficManager

        Returns:
            'DROP_CDN' if CDN service, None otherwise
        """
        # Fast path: no ASN DB or no pre-compiled networks
        if not self.asn_db or not self.azure_cdn_networks:
            return None

        # Step 1: Check if IP belongs to Azure ASN
        asn, _ = self.asn_db.lookup(ip)
        if asn not in self.AZURE_ASNS:
            self.asn_skip_count += 1
            return None  # Not Azure IP, skip prefix check

        # Step 2: IP belongs to Azure, check if it's in CDN prefixes
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for net, name in self.azure_cdn_networks:
            if ip_obj in net:
                return 'DROP_CDN'

        return None

    def check_asn(self, ip: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Check if IP belongs to a known CDN provider via ASN lookup.

        Args:
            ip: IP address to check

        Returns:
            Tuple of (asn_number, provider_name) or (None, None)
        """
        if not self.asn_db:
            return None, None

        asn, prefix = self.asn_db.lookup(ip)
        if asn and asn in self.cdn_asns:
            return asn, self.cdn_asns[asn]

        return None, None

    def lookup_asn(self, ip: str) -> Optional[int]:
        """
        Look up ASN for any IP address.

        Args:
            ip: IP address to check

        Returns:
            ASN number or None
        """
        if not self.asn_db:
            return None

        asn, prefix = self.asn_db.lookup(ip)
        return asn

    def check_headers(self, headers: Dict[str, List[str]]) -> Tuple[bool, Optional[str]]:
        """
        Check if HTTP headers indicate CDN usage.

        Args:
            headers: HTTP headers dict (key -> list of values)

        Returns:
            Tuple of (is_cdn, header_pattern_name)
        """
        if not headers:
            return False, None

        # Normalize headers to lowercase keys
        header_lower = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if isinstance(value, list):
                header_lower[key_lower] = ' '.join(str(v) for v in value)
            else:
                header_lower[key_lower] = str(value)

        # Check each CDN pattern
        for pattern, name in CDN_HEADER_PATTERNS:
            for key, value in header_lower.items():
                if pattern.match(f"{key}: {value}"):
                    return True, name

        return False, None

    def detect(self, ip: str, headers: Dict[str, List[str]] = None) -> Dict:
        """
        Detect CDN/Cloud provider for an IP.

        Args:
            ip: IP address to check
            headers: HTTP response headers (optional)

        Returns:
            Dict with detection results:
            {
                'is_cdn': bool,
                'method': 'ASN' | 'AWS-Prefix' | 'Azure-Prefix' | 'Header' | None,
                'asn': int | None,
                'provider': str | None,
                'header_pattern': str | None,
                'aws_service': str | None,
                'azure_service': str | None
            }
        """
        result = {
            'is_cdn': False,
            'method': None,
            'asn': None,
            'provider': None,
            'header_pattern': None,
            'aws_service': None,
            'azure_service': None
        }

        # 1. Check ASN first
        asn, provider = self.check_asn(ip)
        if asn:
            result['is_cdn'] = True
            result['method'] = 'ASN'
            result['asn'] = asn
            result['provider'] = provider
            self.cdn_by_asn_count += 1
            return result

        # 2. Check AWS prefix (between ASN and Header)
        aws_result = self.check_aws(ip)
        if aws_result == 'DROP_CDN':
            result['is_cdn'] = True
            result['method'] = 'AWS-Prefix'
            result['provider'] = 'Amazon'
            self.cdn_by_aws_prefix_count += 1
            return result

        # 3. Check Azure prefix (between ASN and Header)
        azure_result = self.check_azure(ip)
        if azure_result == 'DROP_CDN':
            result['is_cdn'] = True
            result['method'] = 'Azure-Prefix'
            result['provider'] = 'Microsoft'
            self.cdn_by_azure_prefix_count += 1
            return result

        # 4. Check headers
        if headers:
            is_cdn, header_pattern = self.check_headers(headers)
            if is_cdn:
                result['is_cdn'] = True
                result['method'] = 'Header'
                result['header_pattern'] = header_pattern
                self.cdn_by_header_count += 1
                return result

        return result

    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        return {
            'cdn_by_asn': self.cdn_by_asn_count,
            'cdn_by_header': self.cdn_by_header_count,
            'cdn_by_aws_prefix': self.cdn_by_aws_prefix_count,
            'cdn_by_azure_prefix': self.cdn_by_azure_prefix_count,
            'asn_skip_count': self.asn_skip_count,  # IPs skipped by ASN pre-filter
            'total_cdn': self.cdn_by_asn_count + self.cdn_by_header_count +
                         self.cdn_by_aws_prefix_count + self.cdn_by_azure_prefix_count
        }


# Convenience function for quick detection
def detect_cdn(ip: str, headers: Dict[str, List[str]] = None,
               asn_db_path: str = None, cdn_asn_file: Path = None,
               aws_ranges_file: Path = None, azure_ranges_file: Path = None) -> Dict:
    """
    Quick CDN detection function.

    Args:
        ip: IP address to check
        headers: HTTP response headers (optional)
        asn_db_path: Path to pyasn database
        cdn_asn_file: Path to CDN ASN mapping JSON
        aws_ranges_file: Path to AWS IP ranges JSON
        azure_ranges_file: Path to Azure Service Tags JSON

    Returns:
        Detection result dict
    """
    detector = CNDDetector(asn_db_path, cdn_asn_file, aws_ranges_file, azure_ranges_file)
    return detector.detect(ip, headers)
