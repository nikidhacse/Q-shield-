"""
Crypto Detection Engine for Q-Shield.
Analyzes source code and sample configuration files for cryptographic usage
using explainable rule-based patterns and AST heuristics.
"""

import re
from typing import Any, Dict, List, Optional
from app.models.crypto_finding import AlgorithmCategory, FindingSeverity, QuantumRelevance


class CryptoDetectionEngine:
    """Rule-based, explainable cryptographic algorithm detector for source code and configurations."""

    RULES: List[Dict[str, Any]] = [
        # --- Asymmetric Algorithms (Quantum Vulnerable to Shor's Algorithm) ---
        {
            "id": "RULE-ASYM-RSA",
            "algorithm": "RSA",
            "category": AlgorithmCategory.ASYMMETRIC,
            "patterns": [
                r"\bRSA(?:\.generate|\.new|_PKCS1|KeyPairGenerator\.getInstance\([\"']RSA[\"']|\.import_key)\b",
                r"[\"']RSA(?:-OAEP|-PSS|/ECB/PKCS1Padding|/None/OAEPWithSHA1AndMGF1Padding)?[\"']",
                r"\brsa\.GenerateKey\b",
                r"\bRSAPrivateKey\b|\bRSAPublicKey\b",
                r"\bfrom cryptography\.hazmat\.primitives\.asymmetric import rsa\b",
            ],
            "key_size_patterns": [
                r"(?:generate|GenerateKey|key_size|keysize|bits)\s*\(?\s*(?:bits\s*=\s*)?(\d{3,4})",
                r"RSA-(\d{3,4})",
                r"(\d{3,4})\s*-?\s*bit",
            ],
            "default_key_size": 2048,
            "default_usage": "Asymmetric encryption / Digital signatures / Key wrapping",
            "quantum_relevance": QuantumRelevance.PLAN_MIGRATION,
            "severity_calculator": lambda key_size: (
                FindingSeverity.CRITICAL if key_size and key_size < 2048
                else FindingSeverity.HIGH if key_size and key_size <= 2048
                else FindingSeverity.MEDIUM
            ),
            "explanation": "RSA reliance on integer factorization makes it vulnerable to Shor's algorithm on a cryptographically relevant quantum computer.",
        },
        {
            "id": "RULE-ASYM-ECC",
            "algorithm": "ECC",
            "category": AlgorithmCategory.ASYMMETRIC,
            "patterns": [
                r"\bECC\.generate\b|\bEllipticCurve\b|\bECPrivateKey\b|\bECPublicKey\b",
                r"\bSECP(?:256r1|384r1|521r1|256k1)\b",
                r"\bfrom cryptography\.hazmat\.primitives\.asymmetric import ec\b",
                r"[\"'](?:secp256r1|prime256v1|secp384r1|secp521r1)[\"']",
            ],
            "key_size_patterns": [
                r"(?:secp|SECP|P-?)(\d{3})",
                r"(\d{3})\s*-?\s*bit",
            ],
            "default_key_size": 256,
            "default_usage": "Elliptic Curve Cryptography",
            "quantum_relevance": QuantumRelevance.PLAN_MIGRATION,
            "severity_calculator": lambda key_size: FindingSeverity.HIGH,
            "explanation": "Elliptic Curve Cryptography depends on the discrete logarithm problem over elliptic curves, vulnerable to Shor's algorithm.",
        },
        {
            "id": "RULE-SIGN-ECDSA",
            "algorithm": "ECDSA",
            "category": AlgorithmCategory.SIGNATURE,
            "patterns": [
                r"\bECDSA\b|\bSigningKey\.generate\b|\bVerifyingKey\.from_pem\b",
                r"[\"'](?:SHA256withECDSA|SHA384withECDSA|SHA512withECDSA|ES256|ES384|ES512)[\"']",
                r"\bec\.ECDSA\b",
            ],
            "key_size_patterns": [
                r"(?:ES|P-)(\d{3})",
                r"(\d{3})\s*-?\s*bit",
            ],
            "default_key_size": 256,
            "default_usage": "Digital Signature Generation / Verification",
            "quantum_relevance": QuantumRelevance.PLAN_MIGRATION,
            "severity_calculator": lambda key_size: FindingSeverity.MEDIUM,
            "explanation": "ECDSA digital signatures are breakable by Shor's algorithm; recommend planning transition to NIST PQC signature standards (ML-DSA, SLH-DSA).",
        },
        {
            "id": "RULE-KEYX-ECDH",
            "algorithm": "ECDH",
            "category": AlgorithmCategory.KEY_EXCHANGE,
            "patterns": [
                r"\bECDH\b|\bECDHE\b|\bX25519\b|\bX448\b",
                r"\bec\.ECDH\b|\bKeyAgreement\.getInstance\([\"']ECDH[\"']\)",
                r"[\"'](?:TLS_ECDHE_|ECDHE-RSA-|ECDHE-ECDSA-)[\"']",
            ],
            "key_size_patterns": [
                r"(?:X|P-)(\d{3,4})",
            ],
            "default_key_size": 256,
            "default_usage": "Elliptic Curve Diffie-Hellman Key Exchange",
            "quantum_relevance": QuantumRelevance.PLAN_MIGRATION,
            "severity_calculator": lambda key_size: FindingSeverity.MEDIUM,
            "explanation": "ECDH key exchanges are susceptible to Harvest-Now-Decrypt-Later (HNDL) attacks and future quantum decryption; transition to ML-KEM/hybrid.",
        },
        {
            "id": "RULE-ASYM-DSA",
            "algorithm": "DSA",
            "category": AlgorithmCategory.ASYMMETRIC,
            "patterns": [
                r"\bDSA(?:\.generate|\.new|_PKCS1|KeyPairGenerator\.getInstance\([\"']DSA[\"'])\b",
                r"[\"'](?:DSA|SHA1withDSA|SHA256withDSA)[\"']",
                r"\bfrom cryptography\.hazmat\.primitives\.asymmetric import dsa\b",
            ],
            "key_size_patterns": [
                r"(?:generate|bits|key_size)\s*\(?\s*(\d{3,4})",
            ],
            "default_key_size": 1024,
            "default_usage": "Digital Signature Algorithm (Legacy)",
            "quantum_relevance": QuantumRelevance.DEPRECATED,
            "severity_calculator": lambda key_size: FindingSeverity.CRITICAL if (key_size and key_size <= 1024) else FindingSeverity.HIGH,
            "explanation": "DSA is classically deprecated by NIST (SP 800-131A) and vulnerable to quantum discrete log attacks.",
        },
        {
            "id": "RULE-KEYX-DH",
            "algorithm": "DH",
            "category": AlgorithmCategory.KEY_EXCHANGE,
            "patterns": [
                r"\bDiffieHellman\b|\bDiffie-Hellman\b|\bDHE\b|\bDHParameters\b",
                r"[\"'](?:DH|DHE-RSA|TLS_DHE_)[\"']",
                r"\/etc\/openvpn\/dh(\d{3,4})\.pem",
            ],
            "key_size_patterns": [
                r"(?:dh|DH|bits|size)[-_]?(\d{3,4})",
                r"(\d{3,4})\s*-?\s*bit",
            ],
            "default_key_size": 1024,
            "default_usage": "Diffie-Hellman Key Exchange",
            "quantum_relevance": QuantumRelevance.MIGRATE_SOON,
            "severity_calculator": lambda key_size: FindingSeverity.CRITICAL if (key_size and key_size < 2048) else FindingSeverity.HIGH,
            "explanation": "Finite-field Diffie-Hellman (especially <2048 bits) is weak classically and completely broken by Shor's algorithm.",
        },

        # --- Symmetric Encryption Algorithms ---
        {
            "id": "RULE-SYM-AES",
            "algorithm": "AES",
            "category": AlgorithmCategory.SYMMETRIC,
            "patterns": [
                r"\bAES(?:\.new|_GCM|_CBC|_CTR|Cipher\.getInstance\([\"']AES[\"']|\.AESCipher)\b",
                r"[\"'](?:AES|AES-128-GCM|AES-256-GCM|AES-128-CBC|AES-256-CBC|AES/GCM/NoPadding|AES/CBC/PKCS5Padding)[\"']",
                r"\bciphers\.AES\b|\bAESGCM\b|\bAESCCM\b",
            ],
            "key_size_patterns": [
                r"AES[-_]?(\d{3})",
                r"key_size\s*=\s*(\d{3})",
                r"(\d{3})\s*-?\s*bit",
            ],
            "default_key_size": 256,
            "default_usage": "Symmetric Payload / Storage Encryption",
            "quantum_relevance": QuantumRelevance.MONITOR,
            "severity_calculator": lambda key_size: (
                FindingSeverity.MEDIUM if key_size and key_size < 256
                else FindingSeverity.INFORMATIONAL
            ),
            "explanation": "AES-256 provides 128 bits of security against Grover's quantum search algorithm and remains post-quantum resilient. AES-128 provides 64-bit quantum security.",
        },
        {
            "id": "RULE-SYM-3DES",
            "algorithm": "3DES",
            "category": AlgorithmCategory.SYMMETRIC,
            "patterns": [
                r"\b(?:DES3|TripleDES|3DES)\b",
                r"[\"'](?:DESede|TripleDES|3DES|DES-EDE3-CBC|3DES_EDE_CBC|DESede/CBC/PKCS5Padding)[\"']",
                r"\bTripleDESCipher\b",
            ],
            "key_size_patterns": [
                r"(\d{2,3})\s*-?\s*bit",
            ],
            "default_key_size": 112,
            "default_usage": "Legacy Symmetric Encryption",
            "quantum_relevance": QuantumRelevance.MIGRATE_SOON,
            "severity_calculator": lambda key_size: FindingSeverity.HIGH,
            "explanation": "3DES is deprecated by NIST due to Sweet32 64-bit block collisions and short effective key length.",
        },
        {
            "id": "RULE-SYM-DES",
            "algorithm": "DES",
            "category": AlgorithmCategory.SYMMETRIC,
            "patterns": [
                r"\bDES(?:\.new|Cipher\.getInstance\([\"']DES[\"'])\b",
                r"[\"'](?:DES|DES/CBC/PKCS5Padding|DES-CBC)[\"']",
                r"\bciphers\.algorithms\.DES\b",
            ],
            "key_size_patterns": [],
            "default_key_size": 56,
            "default_usage": "Obsolete Symmetric Encryption",
            "quantum_relevance": QuantumRelevance.DEPRECATED,
            "severity_calculator": lambda key_size: FindingSeverity.CRITICAL,
            "explanation": "Single DES with 56-bit key is cryptographically broken and vulnerable to practical exhaustive search.",
        },
        {
            "id": "RULE-SYM-CHACHA20",
            "algorithm": "ChaCha20",
            "category": AlgorithmCategory.SYMMETRIC,
            "patterns": [
                r"\bChaCha20\b|\bChaCha20Poly1305\b",
                r"[\"'](?:ChaCha20|ChaCha20-Poly1305|TLS_CHACHA20_POLY1305_SHA256)[\"']",
            ],
            "key_size_patterns": [],
            "default_key_size": 256,
            "default_usage": "Modern Stream Cipher / Authenticated Encryption",
            "quantum_relevance": QuantumRelevance.MONITOR,
            "severity_calculator": lambda key_size: FindingSeverity.INFORMATIONAL,
            "explanation": "ChaCha20 provides 256-bit symmetric security, resilient against Grover's algorithm.",
        },

        # --- Hash Functions ---
        {
            "id": "RULE-HASH-MD5",
            "algorithm": "MD5",
            "category": AlgorithmCategory.HASH,
            "patterns": [
                r"\bhashlib\.md5\b|\bMessageDigest\.getInstance\([\"']MD5[\"']\)|\bCryptoJS\.MD5\b",
                r"[\"'](?:MD5|HmacMD5|HMAC-MD5)[\"']",
                r"\bmd5\([^\)]+\)",
            ],
            "key_size_patterns": [],
            "default_key_size": None,
            "default_usage": "Data Integrity / Hashing",
            "quantum_relevance": QuantumRelevance.DEPRECATED,
            "severity_calculator": lambda key_size: FindingSeverity.CRITICAL,
            "explanation": "MD5 has severe collision vulnerabilities and is cryptographically broken. Not acceptable for security contexts.",
        },
        {
            "id": "RULE-HASH-SHA1",
            "algorithm": "SHA-1",
            "category": AlgorithmCategory.HASH,
            "patterns": [
                r"\bhashlib\.sha1\b|\bMessageDigest\.getInstance\([\"']SHA-?1[\"']\)|\bCryptoJS\.SHA1\b",
                r"[\"'](?:SHA-1|SHA1|HmacSHA1|HMAC-SHA1)[\"']",
                r"\bsha1\([^\)]+\)",
            ],
            "key_size_patterns": [],
            "default_key_size": None,
            "default_usage": "Data Integrity / Legacy Signature Hashing",
            "quantum_relevance": QuantumRelevance.DEPRECATED,
            "severity_calculator": lambda key_size: FindingSeverity.HIGH,
            "explanation": "SHA-1 is formally retired by NIST due to collision attacks (SHAttered). Replace with SHA-2 or SHA-3.",
        },
        {
            "id": "RULE-HASH-SHA256",
            "algorithm": "SHA-256",
            "category": AlgorithmCategory.HASH,
            "patterns": [
                r"\bhashlib\.sha256\b|\bMessageDigest\.getInstance\([\"']SHA-?256[\"']\)|\bCryptoJS\.SHA256\b",
                r"[\"'](?:SHA-256|SHA256|HmacSHA256|HMAC-SHA256)[\"']",
                r"\bhashes\.SHA256\(\)",
            ],
            "key_size_patterns": [],
            "default_key_size": 256,
            "default_usage": "Cryptographic Hash / Integrity / HMAC",
            "quantum_relevance": QuantumRelevance.MONITOR,
            "severity_calculator": lambda key_size: FindingSeverity.INFORMATIONAL,
            "explanation": "SHA-256 provides 128-bit quantum collision resistance against Grover search and remains secure.",
        },
        {
            "id": "RULE-HASH-SHA384",
            "algorithm": "SHA-384",
            "category": AlgorithmCategory.HASH,
            "patterns": [
                r"\bhashlib\.sha384\b|\bMessageDigest\.getInstance\([\"']SHA-?384[\"']\)",
                r"[\"'](?:SHA-384|SHA384|HmacSHA384|HMAC-SHA384)[\"']",
                r"\bhashes\.SHA384\(\)",
            ],
            "key_size_patterns": [],
            "default_key_size": 384,
            "default_usage": "Cryptographic Hash / High-Security HMAC",
            "quantum_relevance": QuantumRelevance.MONITOR,
            "severity_calculator": lambda key_size: FindingSeverity.INFORMATIONAL,
            "explanation": "SHA-384 provides 192-bit quantum collision resistance, recommended for high-assurance environments.",
        },
        {
            "id": "RULE-HASH-SHA512",
            "algorithm": "SHA-512",
            "category": AlgorithmCategory.HASH,
            "patterns": [
                r"\bhashlib\.sha512\b|\bMessageDigest\.getInstance\([\"']SHA-?512[\"']\)|\bCryptoJS\.SHA512\b",
                r"[\"'](?:SHA-512|SHA512|HmacSHA512|HMAC-SHA512)[\"']",
                r"\bhashes\.SHA512\(\)",
            ],
            "key_size_patterns": [],
            "default_key_size": 512,
            "default_usage": "Cryptographic Hash / HMAC",
            "quantum_relevance": QuantumRelevance.MONITOR,
            "severity_calculator": lambda key_size: FindingSeverity.INFORMATIONAL,
            "explanation": "SHA-512 provides 256-bit quantum collision resistance, post-quantum safe.",
        },
    ]

    def scan_source_code(self, content: str, filename: str = "source_file") -> List[Dict[str, Any]]:
        """
        Scans a source code string and returns a list of detected cryptographic findings.
        """
        findings: List[Dict[str, Any]] = []
        lines = content.splitlines()

        for rule in self.RULES:
            matched_locations: set = set()

            for pattern_str in rule["patterns"]:
                regex = re.compile(pattern_str, re.IGNORECASE)

                for line_idx, line in enumerate(lines):
                    line_num = line_idx + 1
                    match = regex.search(line)

                    if match and line_num not in matched_locations:
                        matched_locations.add(line_num)
                        evidence_text = line.strip()

                        # Check key size in surrounding context (up to 3 lines)
                        context_window = "\n".join(lines[max(0, line_idx - 2):min(len(lines), line_idx + 3)])
                        detected_key_size = self._extract_key_size(context_window, rule)

                        severity = rule["severity_calculator"](detected_key_size)

                        findings.append({
                            "algorithm": rule["algorithm"],
                            "category": rule["category"],
                            "detected_location": f"{filename}:{line_num}",
                            "key_size": detected_key_size,
                            "usage": rule["default_usage"],
                            "finding_severity": severity,
                            "quantum_relevance": rule["quantum_relevance"],
                            "evidence": evidence_text[:300],
                            "explanation": rule["explanation"],
                        })

        return findings

    def _extract_key_size(self, text: str, rule: Dict[str, Any]) -> Optional[int]:
        """Attempts to extract key size from context using key size patterns."""
        for pattern_str in rule.get("key_size_patterns", []):
            match = re.search(pattern_str, text, re.IGNORECASE)
            if match and match.group(1):
                try:
                    val = int(match.group(1))
                    if 32 <= val <= 8192:
                        return val
                except ValueError:
                    pass
        return rule.get("default_key_size")
