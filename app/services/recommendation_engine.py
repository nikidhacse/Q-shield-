"""
Recommendation Engine for Q-Shield.
Generates explainable, advisory cryptographic migration recommendations.
Recommendations provide migration directions requiring organizational validation.
"""

from typing import Any, Dict, List, Optional
from app.models.asset import Asset
from app.models.crypto_finding import CryptoFinding, FindingSeverity, QuantumRelevance
from app.models.migration import MigrationPriority
from app.models.risk_score import RiskScore


class RecommendationEngine:
    """Generates advisory, explainable cryptographic migration recommendations."""

    # Knowledge base for cryptographic migration paths
    ALGORITHM_GUIDANCE = {
        "RSA": {
            "concern": "RSA relies on the integer factorization problem, which Shor's algorithm on a cryptographically relevant quantum computer (CRQC) can solve in polynomial time.",
            "target_options": ["ML-KEM (FIPS 203)", "ML-DSA (FIPS 204)", "SLH-DSA (FIPS 205)", "Hybrid Classical-PQC", "RSA-3072+ (Interim)"],
            "suggested_target": "ML-KEM / ML-DSA (or Hybrid)",
            "direction": "Plan migration toward NIST Post-Quantum Cryptography standards (FIPS 203 ML-KEM for key encapsulation, FIPS 204 ML-DSA for digital signatures). As an interim measure, ensure minimum 3072-bit keys and crypto-agile abstraction layers.",
        },
        "ECC": {
            "concern": "Elliptic Curve Cryptography is vulnerable to quantum discrete logarithm attacks via Shor's algorithm.",
            "target_options": ["ML-KEM (FIPS 203)", "ML-DSA (FIPS 204)", "SLH-DSA (FIPS 205)", "Hybrid X25519+ML-KEM-768"],
            "suggested_target": "Hybrid X25519 + ML-KEM-768",
            "direction": "Adopt hybrid key exchange (combining classical ECC with NIST ML-KEM) for in-transit communication, and plan digital signature migration to ML-DSA or SLH-DSA.",
        },
        "ECDSA": {
            "concern": "ECDSA signature schemes (P-256, P-384, secp256k1) are broken by Shor's quantum algorithm.",
            "target_options": ["ML-DSA (FIPS 204)", "SLH-DSA (FIPS 205)", "LMS/HSS (RFC 8554 - Firmware)", "XMSS (RFC 8391)"],
            "suggested_target": "ML-DSA (FIPS 204)",
            "direction": "Transition digital signature generation and verification to NIST standardized ML-DSA or SLH-DSA. Validate software stack support for larger signature sizes.",
        },
        "ECDH": {
            "concern": "ECDH key exchanges allow adversaries to capture ciphertext today and decrypt once a quantum computer is available (Harvest-Now-Decrypt-Later).",
            "target_options": ["X25519MLKEM768 (Hybrid)", "ML-KEM-768 (FIPS 203)", "ML-KEM-1024 (FIPS 203)"],
            "suggested_target": "Hybrid X25519 + ML-KEM-768",
            "direction": "Enable hybrid post-quantum key exchange mechanisms in TLS 1.3 / SSH configurations to protect against retrospective decryption.",
        },
        "DH": {
            "concern": "Finite-field Diffie-Hellman with small parameters (<2048-bit) is weak classically and fully broken by quantum algorithms.",
            "target_options": ["ECDHE (P-384)", "Hybrid ECDHE+ML-KEM", "ML-KEM-768 (FIPS 203)"],
            "suggested_target": "ECDHE P-384 (Interim) / Hybrid ML-KEM",
            "direction": "Immediately deprecate DHE parameters below 2048 bits. Transition to ECDHE or post-quantum hybrid key encapsulation.",
        },
        "DSA": {
            "concern": "DSA is deprecated by NIST (SP 800-131A Rev 2) and vulnerable to classical and quantum discrete logarithm attacks.",
            "target_options": ["ECDSA P-384 (Interim)", "ML-DSA (FIPS 204)", "Ed25519"],
            "suggested_target": "ML-DSA (FIPS 204) / Ed25519",
            "direction": "Phase out DSA keys and signatures immediately in favor of modern standard algorithms.",
        },
        "3DES": {
            "concern": "3DES has been retired by NIST due to Sweet32 64-bit block collision vulnerabilities.",
            "target_options": ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"],
            "suggested_target": "AES-256-GCM",
            "direction": "Migrate data encryption routines to AES-256 in Galois/Counter Mode (GCM) for authenticated encryption. Verify protocol compatibility.",
        },
        "DES": {
            "concern": "Single DES uses a 56-bit key which is broken and vulnerable to brute-force attacks within hours.",
            "target_options": ["AES-256-GCM", "AES-256-CBC"],
            "suggested_target": "AES-256-GCM",
            "direction": "Decommission DES usage immediately. Replace with AES-256 authenticated encryption.",
        },
        "SHA-1": {
            "concern": "SHA-1 has demonstrated practical hash collision attacks (SHAttered) and is retired by NIST.",
            "target_options": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256"],
            "suggested_target": "SHA-256",
            "direction": "Replace SHA-1 in hashing, HMAC, and digital signatures with SHA-256 or SHA-3.",
        },
        "MD5": {
            "concern": "MD5 suffers from catastrophic collision and preimage weaknesses.",
            "target_options": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256"],
            "suggested_target": "SHA-256",
            "direction": "Eliminate MD5 across all security contexts and replace with SHA-256 or SHA-3.",
        },
        "AES-128": {
            "concern": "Grover's algorithm reduces effective symmetric key strength by half (128-bit key -> 64 bits of quantum security).",
            "target_options": ["AES-256-GCM", "ChaCha20-Poly1305"],
            "suggested_target": "AES-256-GCM",
            "direction": "Upgrade from AES-128 to AES-256 to guarantee 128-bit security against Grover's quantum search algorithm.",
        },
    }

    def generate_recommendations(
        self, asset: Asset, findings: List[CryptoFinding], risk: Optional[RiskScore] = None
    ) -> List[Dict[str, Any]]:
        """
        Generates structured advisory migration recommendations for all detected algorithms on an asset.
        """
        recommendations: List[Dict[str, Any]] = []
        processed_algos = set()

        for f in findings:
            if f.is_false_positive:
                continue

            base_algo = self._normalize_algo_name(f.algorithm)
            if base_algo in processed_algos:
                continue
            processed_algos.add(base_algo)

            guidance = self._lookup_guidance(base_algo)
            if not guidance:
                continue

            priority = self._determine_migration_priority(f, asset, risk)

            rec_text = (
                f"[{priority.value} Priority] {f.algorithm}: {guidance['concern']} "
                f"Recommended Direction: {guidance['direction']} "
                f"(Note: Guidance is advisory and requires organizational compatibility validation)."
            )

            recommendations.append({
                "asset_id": asset.id,
                "current_algorithm": f.algorithm,
                "target_algorithm": guidance["suggested_target"],
                "target_options": guidance["target_options"],
                "reason_for_concern": guidance["concern"],
                "recommended_direction": guidance["direction"],
                "migration_priority": priority,
                "recommendation_text": rec_text,
            })

        return recommendations

    def _normalize_algo_name(self, algo_str: str) -> str:
        """Normalizes algorithm names (e.g. 'RSA-2048' -> 'RSA', 'AES-128' -> 'AES-128')."""
        algo_upper = algo_str.upper()
        if "3DES" in algo_upper or "TRIPLEDES" in algo_upper or "DES3" in algo_upper:
            return "3DES"
        elif "DES" in algo_upper and "3DES" not in algo_upper and "TRIPLE" not in algo_upper:
            return "DES"
        elif "MD5" in algo_upper:
            return "MD5"
        elif "SHA-1" in algo_upper or "SHA1" in algo_upper:
            return "SHA-1"
        elif "ECDSA" in algo_upper:
            return "ECDSA"
        elif "ECDH" in algo_upper or "X25519" in algo_upper:
            return "ECDH"
        elif "ECC" in algo_upper or "SECP" in algo_upper:
            return "ECC"
        elif "RSA" in algo_upper:
            return "RSA"
        elif "DH" in algo_upper or "DIFFIE" in algo_upper:
            return "DH"
        elif "DSA" in algo_upper and "ECDSA" not in algo_upper:
            return "DSA"
        elif "AES-128" in algo_upper:
            return "AES-128"
        elif "AES" in algo_upper:
            return "AES-128" if "128" in algo_upper else "AES-256"
        return algo_str

    def _lookup_guidance(self, base_algo: str) -> Optional[Dict[str, Any]]:
        return self.ALGORITHM_GUIDANCE.get(base_algo)

    def _determine_migration_priority(
        self, finding: CryptoFinding, asset: Asset, risk: Optional[RiskScore]
    ) -> MigrationPriority:
        # Broken/deprecated classical algorithms require IMMEDIATE remediation
        if finding.quantum_relevance == QuantumRelevance.DEPRECATED or finding.algorithm in ("DES", "MD5", "SHA-1", "3DES"):
            return MigrationPriority.IMMEDIATE
        if finding.key_size and finding.key_size <= 1024 and finding.algorithm in ("RSA", "DH", "DSA"):
            return MigrationPriority.IMMEDIATE

        # High risk or critical asset with quantum-vulnerable algorithms
        if risk and risk.risk_score >= 75.0:
            return MigrationPriority.IMMEDIATE
        elif risk and risk.risk_score >= 50.0:
            return MigrationPriority.HIGH
        elif finding.quantum_relevance in (QuantumRelevance.MIGRATE_SOON, QuantumRelevance.PLAN_MIGRATION):
            return MigrationPriority.HIGH if asset.criticality.value in ("HIGH", "CRITICAL") else MigrationPriority.MEDIUM

        return MigrationPriority.MEDIUM
