"""
Network Metadata Analyzer for Q-Shield.
Safely evaluates controlled network traffic metadata / cipher suite recordings.
Does NOT execute active network attacks, unauthorized port scans, or exploitation.
"""

import json
import re
from typing import Any, Dict, List
from app.models.crypto_finding import AlgorithmCategory, FindingSeverity, QuantumRelevance


class NetworkAnalyzer:
    """Evaluates passive/controlled network metadata records to extract cryptographic findings."""

    CIPHER_SUITE_PATTERNS = [
        # Insecure / Broken Ciphers
        (r"(?:^|[^a-zA-Z0-9])RC4(?:$|[^a-zA-Z0-9])", "RC4", AlgorithmCategory.SYMMETRIC, 128, FindingSeverity.CRITICAL, QuantumRelevance.DEPRECATED, "RC4 stream cipher is broken and insecure (RFC 7465)."),
        (r"(?:^|[^a-zA-Z0-9])(?:DES-CBC3|3DES|DES_EDE|DESEDE|TRIPLEDES)(?:$|[^a-zA-Z0-9])", "3DES", AlgorithmCategory.SYMMETRIC, 112, FindingSeverity.HIGH, QuantumRelevance.MIGRATE_SOON, "3DES is deprecated due to 64-bit block size vulnerabilities (Sweet32)."),
        (r"(?:^|[^a-zA-Z0-9])DES(?:$|[^a-zA-Z0-93])", "DES", AlgorithmCategory.SYMMETRIC, 56, FindingSeverity.CRITICAL, QuantumRelevance.DEPRECATED, "Single DES 56-bit is completely insecure."),
        # Modern Symmetric Ciphers
        (r"AES[_-]?256", "AES-256", AlgorithmCategory.SYMMETRIC, 256, FindingSeverity.INFORMATIONAL, QuantumRelevance.MONITOR, "AES-256 provides strong post-quantum symmetric encryption (128-bit quantum security)."),
        (r"AES[_-]?128", "AES-128", AlgorithmCategory.SYMMETRIC, 128, FindingSeverity.MEDIUM, QuantumRelevance.MONITOR, "AES-128 provides 64 bits of security against Grover's algorithm; consider upgrading to AES-256."),
        (r"CHACHA20", "ChaCha20", AlgorithmCategory.SYMMETRIC, 256, FindingSeverity.INFORMATIONAL, QuantumRelevance.MONITOR, "ChaCha20-Poly1305 is modern and quantum-resistant for symmetric encryption."),
    ]

    KEY_EXCHANGE_PATTERNS = [
        (r"(?:ECDHE|ECDH|X25519|X448)", "ECDH", AlgorithmCategory.KEY_EXCHANGE, 256, FindingSeverity.MEDIUM, QuantumRelevance.PLAN_MIGRATION, "ECDH key exchange is susceptible to Harvest-Now-Decrypt-Later (HNDL); prepare migration to ML-KEM/hybrid."),
        (r"(?:DHE|DH)(?:$|[^a-zA-Z0-9]|_)", "DH", AlgorithmCategory.KEY_EXCHANGE, 1024, FindingSeverity.HIGH, QuantumRelevance.MIGRATE_SOON, "Finite-field Diffie-Hellman key exchange is weak and vulnerable to quantum discrete logarithm attacks."),
        (r"(?:^|[^a-zA-Z0-9])RSA(?:$|[^a-zA-Z0-9])", "RSA", AlgorithmCategory.ASYMMETRIC, 2048, FindingSeverity.HIGH, QuantumRelevance.PLAN_MIGRATION, "Static RSA key transport lacks forward secrecy and is vulnerable to Shor's algorithm."),
    ]

    HASH_PATTERNS = [
        (r"(?:^|[^a-zA-Z0-9])MD5(?:$|[^a-zA-Z0-9])", "MD5", AlgorithmCategory.HASH, None, FindingSeverity.CRITICAL, QuantumRelevance.DEPRECATED, "MD5 in network MAC / handshake is cryptographically broken."),
        (r"SHA384|SHA-384", "SHA-384", AlgorithmCategory.HASH, 384, FindingSeverity.INFORMATIONAL, QuantumRelevance.MONITOR, "SHA-384 provides high quantum collision resistance."),
        (r"SHA256|SHA-256", "SHA-256", AlgorithmCategory.HASH, 256, FindingSeverity.INFORMATIONAL, QuantumRelevance.MONITOR, "SHA-256 HMAC/handshake hash is currently secure."),
        (r"SHA1|SHA-1|(?:^|[^a-zA-Z0-9])SHA(?:$|[^a-zA-Z0-9])", "SHA-1", AlgorithmCategory.HASH, None, FindingSeverity.HIGH, QuantumRelevance.DEPRECATED, "SHA-1 in TLS integrity/MAC is deprecated."),
    ]

    def analyze_metadata(self, metadata_input: str, asset_id: int) -> List[Dict[str, Any]]:
        """
        Parses controlled network metadata records (JSON or text) and returns crypto findings.
        """
        records: List[Dict[str, Any]] = []
        metadata_input = metadata_input.strip()

        if metadata_input.startswith("{"):
            try:
                parsed = json.loads(metadata_input)
                records.append(parsed)
            except json.JSONDecodeError:
                pass
        elif metadata_input.startswith("["):
            try:
                parsed = json.loads(metadata_input)
                if isinstance(parsed, list):
                    records.extend(parsed)
            except json.JSONDecodeError:
                pass

        if not records:
            # Treat raw text string as a sample cipher suite or flow description
            records.append({
                "source": f"asset-{asset_id}",
                "destination": "internal-service",
                "protocol": "TLS",
                "cipher": metadata_input,
                "key_exchange": metadata_input,
            })

        findings: List[Dict[str, Any]] = []
        seen_keys = set()

        for rec in records:
            source = rec.get("source", "unknown-source")
            dest = rec.get("destination", "unknown-destination")
            proto = rec.get("protocol", "TLS")
            cipher = rec.get("cipher", "")
            kex = rec.get("key_exchange", "")
            combined_text = f"{proto} {cipher} {kex}".upper()
            location = f"Network Traffic [{source} -> {dest}]"

            # Check protocol version
            if "TLS 1.0" in combined_text or "TLS 1.1" in combined_text or "SSLV3" in combined_text:
                dedup_key = (location, "TLS-Legacy")
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append({
                        "algorithm": "TLS 1.0/1.1",
                        "category": AlgorithmCategory.OTHER,
                        "detected_location": location,
                        "key_size": None,
                        "usage": "Transport Layer Security",
                        "finding_severity": FindingSeverity.HIGH,
                        "quantum_relevance": QuantumRelevance.DEPRECATED,
                        "evidence": f"Deprecated protocol detected: {combined_text}",
                        "explanation": "TLS 1.0 and 1.1 are deprecated by RFC 8996 due to lack of modern cipher suites.",
                    })

            # Check Key Exchange
            for pat, algo, cat, ksize, sev, qrel, expl in self.KEY_EXCHANGE_PATTERNS:
                if re.search(pat, combined_text):
                    dedup_key = (location, algo, "KEYX")
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append({
                            "algorithm": algo,
                            "category": cat,
                            "detected_location": location,
                            "key_size": ksize,
                            "usage": f"Network session key establishment ({proto})",
                            "finding_severity": sev,
                            "quantum_relevance": qrel,
                            "evidence": f"Key exchange '{algo}' observed in flow: {cipher or kex}",
                            "explanation": expl,
                        })

            # Check Symmetric Ciphers
            for pat, algo, cat, ksize, sev, qrel, expl in self.CIPHER_SUITE_PATTERNS:
                if re.search(pat, combined_text):
                    dedup_key = (location, algo, "SYM")
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append({
                            "algorithm": algo,
                            "category": cat,
                            "detected_location": location,
                            "key_size": ksize,
                            "usage": f"In-transit payload encryption ({proto})",
                            "finding_severity": sev,
                            "quantum_relevance": qrel,
                            "evidence": f"Symmetric cipher '{algo}' observed in cipher suite: {cipher}",
                            "explanation": expl,
                        })

            # Check Hash / MAC algorithms
            for pat, algo, cat, ksize, sev, qrel, expl in self.HASH_PATTERNS:
                if re.search(pat, combined_text):
                    dedup_key = (location, algo, "HASH")
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        findings.append({
                            "algorithm": algo,
                            "category": cat,
                            "detected_location": location,
                            "key_size": ksize,
                            "usage": f"Network integrity / HMAC verification ({proto})",
                            "finding_severity": sev,
                            "quantum_relevance": qrel,
                            "evidence": f"Hash algorithm '{algo}' observed in cipher suite: {cipher}",
                            "explanation": expl,
                        })

        return findings
