#!/usr/bin/env python3
"""TLS Certificate Validator with chain verification and revocation checking."""

import hashlib
import json
import re
import warnings
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

warnings.filterwarnings("ignore", category=DeprecationWarning)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509.oid import ExtensionOID

import requests
from asn1crypto import ocsp


class CRLCache:

    def __init__(self, cache_dir: str = None):
        if cache_dir is None:
            cache_dir = Path(__file__).parent.parent / "crl_cache"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, url: str) -> Path:
        return self.cache_dir / f"{hashlib.sha256(url.encode()).hexdigest()}.crl"

    def get(self, url: str) -> Optional[bytes]:
        cache_path = self._get_cache_path(url)
        meta_path = cache_path.with_suffix('.meta')

        if not cache_path.exists() or not meta_path.exists():
            return None

        try:
            with open(meta_path, 'r') as f:
                meta = json.loads(f.read())
            next_update = datetime.fromisoformat(meta.get('next_update'))
            if datetime.now(timezone.utc) > next_update - timedelta(hours=1):
                return None
            with open(cache_path, 'rb') as f:
                return f.read()
        except Exception:
            return None

    def set(self, url: str, crl_data: bytes, next_update: datetime):
        cache_path = self._get_cache_path(url)
        meta_path = cache_path.with_suffix('.meta')
        try:
            with open(cache_path, 'wb') as f:
                f.write(crl_data)
            with open(meta_path, 'w') as f:
                json.dump({
                    'url': url,
                    'next_update': next_update.isoformat(),
                    'cached_at': datetime.now(timezone.utc).isoformat()
                }, f)
        except Exception:
            pass

    def clear_expired(self):
        for meta_file in self.cache_dir.glob("*.meta"):
            try:
                with open(meta_file, 'r') as f:
                    meta = json.loads(f.read())
                next_update = datetime.fromisoformat(meta.get('next_update'))
                if datetime.now(timezone.utc) > next_update:
                    crl_file = meta_file.with_suffix('.crl')
                    if crl_file.exists():
                        crl_file.unlink()
                    meta_file.unlink()
            except Exception:
                pass


class CertificateValidator:
    """TLS certificate trust validator with OCSP/CRL revocation checking."""

    def __init__(self, root_ca_path: Optional[str] = None,
                 crl_cache_dir: Optional[str] = None,
                 enable_revocation_check: bool = True):
        self.enable_revocation_check = enable_revocation_check
        self.crl_cache = CRLCache(crl_cache_dir) if crl_cache_dir else CRLCache()
        self.root_ca_path = root_ca_path or self._find_system_ca_bundle()
        self._load_root_certs()

    def _find_system_ca_bundle(self) -> str:
        common_paths = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/usr/lib/ssl/certs/ca-certificates.crt",
            "/etc/ssl/cert.pem",
        ]
        for path in common_paths:
            try:
                with open(path, "r"):
                    return path
            except FileNotFoundError:
                continue
        try:
            import certifi
            return certifi.where()
        except ImportError:
            raise RuntimeError("No system CA bundle found and certifi not installed")

    def _load_root_certs(self):
        self.root_certs = []
        try:
            with open(self.root_ca_path, "rb") as f:
                cert_data = f.read()
                for pem_match in re.finditer(
                    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                    cert_data, re.DOTALL
                ):
                    try:
                        cert = x509.load_pem_x509_certificate(pem_match.group(), default_backend())
                        self.root_certs.append(cert)
                    except Exception:
                        pass
        except Exception:
            pass

    def verify_certificate(self, cert_pem: str, chain_pems: List[str] = None) -> Tuple[bool, str]:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            cert_chain = [cert]
            if chain_pems:
                for chain_pem in chain_pems:
                    try:
                        cert_chain.append(x509.load_pem_x509_certificate(chain_pem.encode(), default_backend()))
                    except Exception:
                        pass
            return self._verify_with_cryptography(cert, cert_chain if chain_pems else [cert])
        except Exception as e:
            return False, str(e)

    def _verify_with_cryptography(self, cert, cert_chain) -> Tuple[bool, str]:
        is_trusted, error = self._simple_verify(cert, cert_chain)
        if not is_trusted:
            return False, error
        if self.enable_revocation_check:
            return self._check_revocation(cert, cert_chain)
        return True, ""

    def _check_revocation(self, cert: x509.Certificate, cert_chain: List) -> Tuple[bool, str]:
        issuer_cert = None
        if len(cert_chain) > 1:
            issuer_cert = cert_chain[1]
        else:
            for root_cert in self.root_certs:
                if cert.issuer == root_cert.subject:
                    issuer_cert = root_cert
                    break

        if issuer_cert is None:
            return False, "Issuer certificate not found for revocation check"

        ocsp_result, ocsp_error = self._check_ocsp(cert, issuer_cert)
        if ocsp_result:
            return True, ""
        elif "no OCSP URL" not in ocsp_error and "failed" not in ocsp_error:
            return False, ocsp_error

        crl_result, crl_error = self._check_crl(cert, issuer_cert)
        if crl_result:
            return True, ""
        if "no CRL" in crl_error:
            return True, ""
        return False, f"Revocation check failed: OCSP({ocsp_error}), CRL({crl_error})"

    def _check_ocsp(self, cert: x509.Certificate, issuer_cert: x509.Certificate) -> Tuple[bool, str]:
        try:
            aia_extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            ocsp_urls = [
                desc.access_location.value
                for desc in aia_extension.value
                if desc.access_method == x509.AuthorityInformationAccessAccessType.OCSP
            ]
            if not ocsp_urls:
                return False, "no OCSP URL"

            ocsp_url = ocsp_urls[0]
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            issuer_der = issuer_cert.public_bytes(serialization.Encoding.DER)

            from asn1crypto.x509 import Certificate as Asn1Certificate

            asn1_cert = Asn1Certificate.load(cert_der)
            asn1_issuer = Asn1Certificate.load(issuer_der)

            ocsp_request = {
                'tbs_request': {
                    'request_list': [{
                        'req_cert': {
                            'hash_algorithm': {'algorithm': 'sha1', 'parameters': None},
                            'issuer_name_hash': hashlib.sha1(asn1_issuer.issuer.dump()).digest(),
                            'issuer_key_hash': hashlib.sha1(asn1_issuer.public_key.dump()).digest(),
                            'serial_number': asn1_cert.serial_number
                        }
                    }]
                }
            }

            request_data = ocsp.OCSPRequest(ocsp_request).dump()
            headers = {
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response',
            }

            response = requests.post(ocsp_url, data=request_data, headers=headers, timeout=10)
            if response.status_code != 200:
                return False, f"OCSP request failed: HTTP {response.status_code}"

            ocsp_response = ocsp.OCSPResponse.load(response.content)
            response_status = ocsp_response['response_status'].native
            if response_status != 'successful':
                return False, f"OCSP status: {response_status}"

            responses = ocsp_response['response_bytes']['response'].native
            if not responses:
                return False, "Empty OCSP response"

            cert_status = responses[0]['cert_status'].native
            if cert_status == 'good':
                return True, ""
            elif cert_status == 'revoked':
                return False, "Certificate revoked"
            return False, "OCSP status: unknown"
        except Exception as e:
            return False, f"OCSP check failed: {str(e)}"

    def _check_crl(self, cert: x509.Certificate, issuer_cert: x509.Certificate) -> Tuple[bool, str]:
        try:
            crl_dp_extension = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_urls = [uri.value for dp in crl_dp_extension.value for uri in dp.full_name]
            if not crl_urls:
                return False, "no CRL distribution points"

            for crl_url in crl_urls:
                is_valid, error = self._check_single_crl(cert, crl_url)
                if is_valid:
                    return True, ""
                if "revoked" in error:
                    return False, error
            return False, "All CRL checks failed"
        except x509.ExtensionNotFound:
            return False, "no CRL extension"
        except Exception as e:
            return False, f"CRL check failed: {str(e)}"

    def _check_single_crl(self, cert: x509.Certificate, crl_url: str) -> Tuple[bool, str]:
        try:
            crl_data = self.crl_cache.get(crl_url)
            if crl_data is None:
                response = requests.get(crl_url, timeout=30)
                response.raise_for_status()
                crl_data = response.content

            crl = x509.load_der_x509_crl(crl_data, default_backend())
            self.crl_cache.set(crl_url, crl_data, crl.next_update_utc)

            for revoked_cert in crl:
                if revoked_cert.serial_number == cert.serial_number:
                    return False, f"Certificate revoked (date: {revoked_cert.revocation_date_utc})"

            if datetime.now(timezone.utc) > crl.next_update_utc:
                return False, "CRL expired"
            return True, ""
        except requests.RequestException as e:
            return False, f"CRL download failed: {str(e)}"
        except Exception as e:
            return False, f"CRL parse failed: {str(e)}"

    def _simple_verify(self, cert, cert_chain) -> Tuple[bool, str]:
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            return False, f"Certificate not yet valid (not before: {cert.not_valid_before_utc})"
        if now > cert.not_valid_after_utc:
            return False, f"Certificate expired (not after: {cert.not_valid_after_utc})"

        from cryptography.hazmat.primitives.asymmetric import ec

        def verify_sig(public_key, signature, tbs_bytes, hash_algo):
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, tbs_bytes, ec.ECDSA(hash_algo))
            else:
                public_key.verify(signature, tbs_bytes, asym_padding.PKCS1v15(), hash_algo)

        current_cert = cert
        for i, chain_cert in enumerate(cert_chain[1:], 1):
            try:
                verify_sig(chain_cert.public_key(), current_cert.signature,
                           current_cert.tbs_certificate_bytes, current_cert.signature_hash_algorithm)
                current_cert = chain_cert
            except Exception as e:
                return False, f"Chain signature verification failed at position {i}: {str(e)}"

        # Check self-signed root
        last_cert = current_cert
        try:
            verify_sig(last_cert.public_key(), last_cert.signature,
                       last_cert.tbs_certificate_bytes, last_cert.signature_hash_algorithm)
            last_fp = last_cert.fingerprint(hashes.SHA256())
            for root_cert in self.root_certs:
                if last_fp == root_cert.fingerprint(hashes.SHA256()):
                    return True, ""
            return False, "Self-signed root not in trust store"
        except Exception:
            pass

        # Check signed by known root
        for root_cert in self.root_certs:
            try:
                if last_cert.issuer == root_cert.subject:
                    verify_sig(root_cert.public_key(), last_cert.signature,
                               last_cert.tbs_certificate_bytes, last_cert.signature_hash_algorithm)
                    return True, ""
            except Exception:
                continue
        return False, "Cannot verify to trusted root"

    @staticmethod
    def base64_to_pem(base64_cert: str) -> str:
        clean = base64_cert.replace("\n", "").replace(" ", "").strip()
        lines = [clean[i:i+64] for i in range(0, len(clean), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"

    @staticmethod
    def extract_sans(cert_data: Dict[str, Any]) -> List[str]:
        try:
            return cert_data.get("extensions", {}).get("subject_alt_name", {}).get("dns_names", []) or []
        except Exception:
            return []

    @staticmethod
    def extract_subject_dn(cert_data: Dict[str, Any]) -> str:
        return cert_data.get("subject_dn", "")

    @staticmethod
    def extract_issuer_dn(cert_data: Dict[str, Any]) -> str:
        return cert_data.get("issuer_dn", "")


def validate_certificate(cert_pem: str, chain_pems: List[str] = None,
                        root_ca_path: str = None,
                        enable_revocation_check: bool = False) -> Tuple[bool, str]:
    validator = CertificateValidator(root_ca_path, enable_revocation_check=enable_revocation_check)
    return validator.verify_certificate(cert_pem, chain_pems)
