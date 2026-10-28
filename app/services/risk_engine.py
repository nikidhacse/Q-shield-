"""
Risk Engine for Q-Shield.
Calculates a transparent, deterministic, factor-based 0-100 quantum risk score.
Exposes all contributing factor scores and plain-language explanations.
"""

import json
from typing import Any, Dict, List, Optional

from app.models.asset import Asset, AssetEnvironment, Criticality
from app.models.crypto_finding import CryptoFinding, FindingSeverity, QuantumRelevance
from app.models.risk_score import DataSensitivity, RiskLevel, RiskScore
from app.services.data_classifier import DataClassifier


class RiskEngine:
    """Calculates explainable risk scores based on cryptographic findings, criticality, and data sensitivity."""

    CRITICALITY_WEIGHTS = {
        Criticality.CRITICAL: 100.0,
        Criticality.HIGH: 75.0,
        Criticality.MEDIUM: 50.0,
        Criticality.LOW: 25.0,
    }

    def __init__(self):
        self.classifier = DataClassifier()

    def calculate_asset_risk(
        self,
        asset: Asset,
        findings: List[CryptoFinding],
        data_sensitivity: Optional[DataSensitivity] = None,
    ) -> Dict[str, Any]:
        """
        Computes the deterministic composite risk score and factor breakdown for an asset.
        """
        # 1. Determine Data Sensitivity
        if data_sensitivity is None:
            suggested_sens, _ = self.classifier.suggest_classification(asset)
            data_sensitivity = suggested_sens
        data_sens_score = self.classifier.get_sensitivity_score(data_sensitivity)

        # 2. Asset Criticality Score
        crit_score = self.CRITICALITY_WEIGHTS.get(asset.criticality, 50.0)

        # 3. Exposure Score
        exposure_score = self._compute_exposure_score(asset)

        # 4. Cryptographic Vulnerability & Algorithm Strength Scores
        crypto_vuln_score, algo_strength_score, factors = self._evaluate_findings(findings)

        # 5. Harvest-Now-Decrypt-Later (HNDL) Relevance Score
        harvest_now_score = self._compute_harvest_now_score(findings, data_sens_score, exposure_score)

        # 6. Migration Difficulty Score
        migration_difficulty_score = self._compute_migration_difficulty(asset, findings)

        # 7. Weighted Composite Score (0-100)
        # Weights:
        # Crypto Vulnerability: 30%
        # Data Sensitivity: 20%
        # Asset Criticality: 20%
        # Harvest-Now Relevance: 15%
        # Exposure: 15%
        raw_composite = (
            (crypto_vuln_score * 0.30)
            + (data_sens_score * 0.20)
            + (crit_score * 0.20)
            + (harvest_now_score * 0.15)
            + (exposure_score * 0.15)
        )

        composite_score = round(max(0.0, min(100.0, raw_composite)), 1)
        risk_level = self._get_risk_level(composite_score)

        explanation = self._build_explanation(
            composite_score, risk_level, factors, data_sensitivity, asset.criticality
        )

        return {
            "asset_id": asset.id,
            "risk_score": composite_score,
            "risk_level": risk_level,
            "crypto_vulnerability_score": round(crypto_vuln_score, 1),
            "asset_criticality_score": round(crit_score, 1),
            "data_sensitivity_score": round(data_sens_score, 1),
            "exposure_score": round(exposure_score, 1),
            "algorithm_strength_score": round(algo_strength_score, 1),
            "migration_difficulty_score": round(migration_difficulty_score, 1),
            "harvest_now_score": round(harvest_now_score, 1),
            "data_sensitivity": data_sensitivity,
            "risk_factors": json.dumps(factors),
            "explanation": explanation,
        }

    def _get_risk_level(self, score: float) -> RiskLevel:
        if score >= 75.0:
            return RiskLevel.CRITICAL
        elif score >= 50.0:
            return RiskLevel.HIGH
        elif score >= 25.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _compute_exposure_score(self, asset: Asset) -> float:
        """Calculates exposure based on environment and network accessibility hints."""
        score = 40.0  # baseline internal
        if asset.environment == AssetEnvironment.PRODUCTION:
            score += 25.0
        elif asset.environment == AssetEnvironment.STAGING:
            score += 10.0

        loc_or_tags = f"{asset.location or ''} {asset.tags or ''}".lower()
        if any(kw in loc_or_tags for kw in ["https://", "public", "api.", "portal.", "internet", "customer"]):
            score += 25.0
        elif "vpn" in loc_or_tags or "gateway" in loc_or_tags:
            score += 20.0
        elif "internal" in loc_or_tags or "isolated" in loc_or_tags:
            score -= 10.0

        return max(10.0, min(100.0, score))

    def _evaluate_findings(self, findings: List[CryptoFinding]) -> Tuple[float, float, List[str]]:
        """Evaluates findings to return crypto_vulnerability_score, algo_strength_score, and risk_factors."""
        factors: List[str] = []
        if not findings:
            return 20.0, 80.0, ["No cryptographic findings recorded (baseline assessment)."]

        max_severity_weight = 0.0
        has_deprecated = False
        has_quantum_vulnerable = False
        has_weak_key = False

        for f in findings:
            if f.is_false_positive:
                continue

            sev = f.finding_severity
            qrel = f.quantum_relevance
            algo_name = f.algorithm

            if sev == FindingSeverity.CRITICAL:
                max_severity_weight = max(max_severity_weight, 95.0)
                factors.append(f"Critical severity finding: {algo_name} ({f.detected_location or 'general'})")
            elif sev == FindingSeverity.HIGH:
                max_severity_weight = max(max_severity_weight, 75.0)
                factors.append(f"High severity finding: {algo_name}")
            elif sev == FindingSeverity.MEDIUM:
                max_severity_weight = max(max_severity_weight, 50.0)
            elif sev == FindingSeverity.LOW:
                max_severity_weight = max(max_severity_weight, 25.0)

            if qrel in (QuantumRelevance.DEPRECATED, QuantumRelevance.MIGRATE_SOON):
                has_deprecated = True
                factors.append(f"Cryptographically weak or deprecated algorithm detected: {algo_name}")
            elif qrel == QuantumRelevance.PLAN_MIGRATION:
                has_quantum_vulnerable = True

            if f.key_size and f.key_size < 2048 and algo_name in ("RSA", "DH", "DSA"):
                has_weak_key = True
                factors.append(f"Sub-standard key length ({f.key_size}-bit) detected for {algo_name}")

        vuln_score = max_severity_weight
        if has_deprecated:
            vuln_score = max(vuln_score, 85.0)
        elif has_weak_key:
            vuln_score = max(vuln_score, 80.0)
        elif has_quantum_vulnerable:
            vuln_score = max(vuln_score, 60.0)

        # Strength score is inversely related to vulnerability
        algo_strength_score = max(10.0, 100.0 - vuln_score)

        # Deduplicate factor strings
        unique_factors = list(dict.fromkeys(factors))
        return vuln_score, algo_strength_score, unique_factors

    def _compute_harvest_now_score(
        self, findings: List[CryptoFinding], data_sens_score: float, exposure_score: float
    ) -> float:
        """
        Harvest-Now-Decrypt-Later (HNDL) is high when long-lived sensitive data is protected
        by asymmetric or key-exchange algorithms breakable by quantum computers.
        """
        has_asym_or_kex = any(
            f.quantum_relevance in (QuantumRelevance.PLAN_MIGRATION, QuantumRelevance.MIGRATE_SOON)
            and not f.is_false_positive
            for f in findings
        )
        if not has_asym_or_kex:
            return 20.0

        # High data sensitivity + public/production exposure + quantum vulnerable = high HNDL risk
        hndl_base = (data_sens_score * 0.6) + (exposure_score * 0.4)
        return round(max(20.0, min(100.0, hndl_base)), 1)

    def _compute_migration_difficulty(self, asset: Asset, findings: List[CryptoFinding]) -> float:
        """Estimates migration difficulty based on asset type, criticality, and legacy findings."""
        score = 40.0
        if asset.criticality == Criticality.CRITICAL:
            score += 25.0
        if any("legacy" in (f.evidence or "").lower() or f.algorithm in ("3DES", "DES", "DSA") for f in findings):
            score += 20.0
        return min(100.0, score)

    def _build_explanation(
        self,
        score: float,
        level: RiskLevel,
        factors: List[str],
        sensitivity: DataSensitivity,
        criticality: Criticality,
    ) -> str:
        top_factors = factors[:3] if factors else ["Standard operational parameters"]
        factor_summary = "; ".join(top_factors)
        return (
            f"Asset assessed at {score}/100 ({level.value} Risk). "
            f"Criticality is {criticality.value} with {sensitivity.value} data classification. "
            f"Key contributing factors: {factor_summary}."
        )
