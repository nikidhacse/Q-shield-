"""
Certificate Scanner service for Q-Shield.
Analyzes X.509 certificate PEM data or structured certificate metadata,
extracts cryptographic parameters, and flags quantum vulnerabilities.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.models.certificate import CertificateStatus
from app.models.crypto_finding import AlgorithmCategory, FindingSeverity, QuantumRelevance

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


class CertificateScanner:
    """Analyzes X.509 certificates and generates cryptographic findings."""

    PQ_VULNERABLE_ALGORITHMS = {"RSA", "EC", "ECDSA", "DSA", "DIFFIE-HELLMAN"}

    def fetch_live_domain_certificate(self, hostname: str, port: int = 443) -> str:
        """Connects over TLS to a live domain and fetches its peer certificate as a PEM string."""
        import socket
        import ssl
        from cryptography.hazmat.primitives import serialization

        # Clean hostname
        hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0].strip()
        if ":" in hostname:
            parts = hostname.split(":")
            hostname = parts[0]
            port = int(parts[1])

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # In order to inspect expired/self-signed certs too

        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            raise ValueError(f"Could not retrieve TLS certificate from {hostname}:{port}")

        cert = x509.load_der_x509_certificate(der_cert)
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        return pem_bytes.decode("utf-8")

    def scan_certificate_data(
        self, cert_input: str, asset_id: int
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Accepts a live domain/hostname, PEM certificate string, or JSON metadata.
        Returns:
            - cert_dict: dictionary suitable for creating/updating a Certificate model
            - findings: list of crypto findings generated from this certificate
        """
        cert_input = cert_input.strip()

        # Check if input is a live domain (e.g. google.com, example.com:443, https://domain.org)
        is_url_or_domain = (
            cert_input.startswith("http://")
            or cert_input.startswith("https://")
            or ("." in cert_input and not cert_input.startswith("-----") and not cert_input.startswith("{") and "\n" not in cert_input)
        )
        if is_url_or_domain:
            try:
                pem_data = self.fetch_live_domain_certificate(cert_input)
                return self._parse_pem_certificate(pem_data, asset_id)
            except Exception as e:
                # If network fetch fails, fall back to parsing text
                pass

        if cert_input.startswith("-----BEGIN CERTIFICATE-----"):
            return self._parse_pem_certificate(cert_input, asset_id)
        elif cert_input.startswith("{"):
            try:
                meta = json.loads(cert_input)
                return self._parse_json_metadata(meta, asset_id)
            except json.JSONDecodeError:
                pass

        # Fallback for structured key-value text or minimal format
        return self._parse_text_fallback(cert_input, asset_id)

    def _parse_pem_certificate(self, pem_data: str, asset_id: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Parses a PEM certificate using cryptography.x509."""
        if not HAVE_CRYPTOGRAPHY:
            return self._parse_text_fallback(pem_data, asset_id)

        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode("utf-8"))
        except Exception as e:
            return self._parse_text_fallback(pem_data, asset_id)

        # Subject & Issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        # Extract CN
        cn = None
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attr.value
                break
        if not cn:
            cn = subject

        # Validity
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)

        if now > not_after:
            cert_status = CertificateStatus.EXPIRED
        elif now + timedelta(days=90) > not_after:
            cert_status = CertificateStatus.EXPIRING_SOON
        else:
            cert_status = CertificateStatus.VALID

        # Signature Algorithm
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_hash_algorithm)

        # Public Key Analysis
        pub_key = cert.public_key()
        pub_key_algo = "UNKNOWN"
        key_size = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_algo = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_algo = "EC"
            key_size = pub_key.curve.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_algo = "DSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key_algo = "Ed25519"
            key_size = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            pub_key_algo = "Ed448"
            key_size = 448

        # Quantum requirement
        requires_pq = pub_key_algo.upper() in self.PQ_VULNERABLE_ALGORITHMS

        cert_dict = {
            "asset_id": asset_id,
            "serial_number": hex(cert.serial_number),
            "subject": subject,
            "issuer": issuer,
            "common_name": cn,
            "not_before": not_before,
            "not_after": not_after,
            "signature_algorithm": sig_algo,
            "public_key_algorithm": pub_key_algo,
            "key_size": key_size,
            "cert_status": cert_status,
            "requires_pq_migration": requires_pq,
            "migration_notes": (
                f"{pub_key_algo}-{key_size} is vulnerable to quantum attacks. "
                "Evaluate migration toward NIST standardized Post-Quantum Cryptography."
                if requires_pq else "Certificate uses modern or non-vulnerable parameters."
            ),
            "raw_pem": pem_data,
        }

        findings = self._generate_findings_from_cert(cert_dict, asset_id)
        return cert_dict, findings

    def _parse_json_metadata(self, meta: Dict[str, Any], asset_id: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Parses a structured JSON certificate metadata dictionary."""
        subject = meta.get("subject", "CN=sample.internal")
        issuer = meta.get("issuer", "CN=Sample CA")
        cn = meta.get("common_name", meta.get("cn", subject))
        pub_key_algo = meta.get("public_key_algorithm", meta.get("public_key_algo", "RSA"))
        sig_algo = meta.get("signature_algorithm", meta.get("signature_algo", "SHA256withRSA"))
        key_size = int(meta.get("key_size", 2048)) if meta.get("key_size") else 2048

        now = datetime.now(timezone.utc)
        not_before = meta.get("not_before", now - timedelta(days=30))
        not_after = meta.get("not_after", now + timedelta(days=335))

        if isinstance(not_after, str):
            try:
                not_after = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            except ValueError:
                not_after = now + timedelta(days=180)

        if isinstance(not_before, str):
            try:
                not_before = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            except ValueError:
                not_before = now - timedelta(days=30)

        if now > not_after:
            cert_status = CertificateStatus.EXPIRED
        elif now + timedelta(days=90) > not_after:
            cert_status = CertificateStatus.EXPIRING_SOON
        else:
            cert_status = CertificateStatus.VALID

        requires_pq = pub_key_algo.upper() in self.PQ_VULNERABLE_ALGORITHMS

        cert_dict = {
            "asset_id": asset_id,
            "serial_number": meta.get("serial_number", "0x123456789ABCDEF"),
            "subject": subject,
            "issuer": issuer,
            "common_name": cn,
            "not_before": not_before,
            "not_after": not_after,
            "signature_algorithm": sig_algo,
            "public_key_algorithm": pub_key_algo,
            "key_size": key_size,
            "cert_status": cert_status,
            "requires_pq_migration": requires_pq,
            "migration_notes": (
                f"{pub_key_algo}-{key_size} is vulnerable to quantum attacks. Plan transition to post-quantum certificates."
                if requires_pq else "Certificate parameters are acceptable."
            ),
            "raw_pem": meta.get("raw_pem"),
        }

        findings = self._generate_findings_from_cert(cert_dict, asset_id)
        return cert_dict, findings

    def _parse_text_fallback(self, text: str, asset_id: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Fallback parser for raw text descriptions."""
        now = datetime.now(timezone.utc)
        algo = "RSA"
        key_size = 2048

        if "ECDSA" in text or "EC" in text:
            algo = "EC"
            key_size = 256
        elif "DSA" in text:
            algo = "DSA"
            key_size = 1024
        elif "4096" in text:
            key_size = 4096
        elif "1024" in text:
            key_size = 1024

        cert_dict = {
            "asset_id": asset_id,
            "serial_number": "0xSAMPLE123456",
            "subject": f"CN=asset-{asset_id}.internal",
            "issuer": "CN=Enterprise Internal CA",
            "common_name": f"asset-{asset_id}.internal",
            "not_before": now - timedelta(days=90),
            "not_after": now + timedelta(days=275),
            "signature_algorithm": "SHA256withRSA",
            "public_key_algorithm": algo,
            "key_size": key_size,
            "cert_status": CertificateStatus.VALID,
            "requires_pq_migration": True,
            "migration_notes": f"{algo}-{key_size} certificate analyzed.",
            "raw_pem": text,
        }
        findings = self._generate_findings_from_cert(cert_dict, asset_id)
        return cert_dict, findings

    def _generate_findings_from_cert(self, cert_dict: Dict[str, Any], asset_id: int) -> List[Dict[str, Any]]:
        """Generates explainable crypto findings from analyzed certificate attributes."""
        findings = []
        algo = cert_dict.get("public_key_algorithm", "RSA").upper()
        key_size = cert_dict.get("key_size", 2048)
        cn = cert_dict.get("common_name", "certificate")
        sig_algo = cert_dict.get("signature_algorithm", "SHA256withRSA").upper()

        # Public key finding
        if algo in ("RSA", "EC", "ECDSA", "DSA"):
            category = AlgorithmCategory.ASYMMETRIC if algo in ("RSA", "DSA") else AlgorithmCategory.SIGNATURE
            relevance = QuantumRelevance.MIGRATE_SOON if (key_size and key_size <= 1024) else QuantumRelevance.PLAN_MIGRATION
            
            if key_size and key_size <= 1024:
                severity = FindingSeverity.CRITICAL
            elif key_size and key_size <= 2048:
                severity = FindingSeverity.HIGH if algo == "RSA" else FindingSeverity.MEDIUM
            else:
                severity = FindingSeverity.MEDIUM

            findings.append({
                "algorithm": f"{algo}-{key_size}" if key_size else algo,
                "category": category,
                "detected_location": f"Certificate Public Key – CN={cn}",
                "key_size": key_size,
                "usage": "TLS / Identity Certificate Public Key",
                "finding_severity": severity,
                "quantum_relevance": relevance,
                "evidence": f"Certificate CN={cn} uses public key {algo} with {key_size}-bit key size.",
                "explanation": f"{algo} public key cryptography is vulnerable to Shor's algorithm on quantum computers.",
            })

        # Signature algorithm finding (e.g. SHA-1 in signature)
        if "SHA1" in sig_algo or "MD5" in sig_algo:
            findings.append({
                "algorithm": "SHA-1" if "SHA1" in sig_algo else "MD5",
                "category": AlgorithmCategory.HASH,
                "detected_location": f"Certificate Signature – CN={cn}",
                "key_size": None,
                "usage": "Certificate Signature Hashing",
                "finding_severity": FindingSeverity.CRITICAL if "MD5" in sig_algo else FindingSeverity.HIGH,
                "quantum_relevance": QuantumRelevance.DEPRECATED,
                "evidence": f"Certificate signature algorithm uses deprecated hash: {sig_algo}",
                "explanation": "Deprecated hash algorithms in certificate signatures allow collision and forgery attacks.",
            })

        return findings
