"""
Priority Engine for Q-Shield.
Calculates normalized migration priority scores and ranks assets for cryptographic migration.
Levels: IMMEDIATE, HIGH, MEDIUM, LOW.
"""

from typing import Any, Dict, List, Optional
from app.models.asset import Asset, Criticality
from app.models.migration import MigrationPriority
from app.models.risk_score import RiskScore, DataSensitivity


class PriorityEngine:
    """Calculates migration urgency and prioritization ranks across audited assets."""

    CRITICALITY_MULTIPLIERS = {
        Criticality.CRITICAL: 1.25,
        Criticality.HIGH: 1.10,
        Criticality.MEDIUM: 1.00,
        Criticality.LOW: 0.85,
    }

    SENSITIVITY_MULTIPLIERS = {
        DataSensitivity.CRITICAL: 1.25,
        DataSensitivity.RESTRICTED: 1.15,
        DataSensitivity.CONFIDENTIAL: 1.05,
        DataSensitivity.INTERNAL: 0.95,
        DataSensitivity.PUBLIC: 0.80,
    }

    def calculate_priority(self, asset: Asset, risk_score_record: RiskScore) -> Dict[str, Any]:
        """
        Calculates normalized 0-100 priority score and urgency level for a single asset.
        """
        base_risk = risk_score_record.risk_score

        crit_mult = self.CRITICALITY_MULTIPLIERS.get(asset.criticality, 1.0)
        sens_mult = self.SENSITIVITY_MULTIPLIERS.get(risk_score_record.data_sensitivity, 1.0)

        # Exposure bonus
        exposure_factor = (risk_score_record.exposure_score / 100.0) * 0.15
        # Harvest-now bonus
        harvest_factor = (risk_score_record.harvest_now_score / 100.0) * 0.15

        raw_priority = (base_risk * 0.70 * crit_mult * sens_mult) + (base_risk * exposure_factor) + (base_risk * harvest_factor)
        priority_score = round(max(0.0, min(100.0, raw_priority)), 1)

        priority_level = self._get_priority_level(priority_score)
        reason = self._build_reason(asset, risk_score_record, priority_score, priority_level)
        action = self._build_recommended_action(priority_level, risk_score_record)

        return {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "risk_score": base_risk,
            "priority_score": priority_score,
            "priority_level": priority_level,
            "reason": reason,
            "recommended_action": action,
        }

    def rank_assets(self, evaluated_assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes a list of priority evaluation dicts and assigns 1-based priority ranks.
        """
        sorted_assets = sorted(evaluated_assets, key=lambda x: x["priority_score"], reverse=True)
        for rank_idx, item in enumerate(sorted_assets, start=1):
            item["priority_rank"] = rank_idx
        return sorted_assets

    def _get_priority_level(self, score: float) -> MigrationPriority:
        if score >= 80.0:
            return MigrationPriority.IMMEDIATE
        elif score >= 60.0:
            return MigrationPriority.HIGH
        elif score >= 35.0:
            return MigrationPriority.MEDIUM
        return MigrationPriority.LOW

    def _build_reason(
        self, asset: Asset, risk: RiskScore, score: float, level: MigrationPriority
    ) -> str:
        urgency_text = {
            MigrationPriority.IMMEDIATE: "Critical quantum exposure on sensitive/critical infrastructure requiring immediate roadmap execution.",
            MigrationPriority.HIGH: "Significant cryptographic risk with high business impact. Prioritize in upcoming sprint cycle.",
            MigrationPriority.MEDIUM: "Standard post-quantum migration schedule recommended. Monitor NIST standards progress.",
            MigrationPriority.LOW: "Low exposure asset. Cryptographic migration can be deferred to standard maintenance windows.",
        }.get(level, "")

        return (
            f"Priority Score {score}/100 ({level.value}). "
            f"Asset criticality '{asset.criticality.value}', Data sensitivity '{risk.data_sensitivity.value}'. "
            f"{urgency_text}"
        )

    def _build_recommended_action(self, level: MigrationPriority, risk: RiskScore) -> str:
        if level == MigrationPriority.IMMEDIATE:
            return "Formulate migration plan immediately, replace broken ciphers, and establish PQC pilot testing."
        elif level == MigrationPriority.HIGH:
            return "Incorporate cryptographic agility upgrades into near-term engineering roadmap."
        elif level == MigrationPriority.MEDIUM:
            return "Catalog crypto dependencies and evaluate vendor PQC compatibility."
        return "Periodic review during standard release cycles."
