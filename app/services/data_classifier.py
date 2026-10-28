"""
Data Classifier service for Q-Shield.
Suggests data sensitivity levels for assets and supports analyst overrides.
Levels: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, CRITICAL.
"""

from typing import Dict, List, Tuple
from app.models.risk_score import DataSensitivity
from app.models.asset import Asset, AssetType, Criticality


class DataClassifier:
    """Classifies asset data sensitivity based on metadata heuristics and analyst overrides."""

    CRITICAL_KEYWORDS = {
        "payment", "card", "pci", "banking", "financial", "secret", "private-key",
        "hsm", "root-ca", "biometric", "password", "master", "core-banking", "ssn",
    }

    RESTRICTED_KEYWORDS = {
        "pii", "hr", "payroll", "salary", "medical", "phi", "health", "identity",
        "customer-data", "restricted", "compliance", "gdpr", "hipaa",
    }

    CONFIDENTIAL_KEYWORDS = {
        "auth", "jwt", "api-key", "token", "credential", "database", "analytics",
        "customer", "internal-api", "warehouse", "proprietary", "confidential",
    }

    PUBLIC_KEYWORDS = {
        "public", "marketing", "static", "cdn", "docs", "documentation", "blog",
        "landing", "open-source", "guest",
    }

    SENSITIVITY_SCORES: Dict[DataSensitivity, float] = {
        DataSensitivity.PUBLIC: 15.0,
        DataSensitivity.INTERNAL: 40.0,
        DataSensitivity.CONFIDENTIAL: 65.0,
        DataSensitivity.RESTRICTED: 85.0,
        DataSensitivity.CRITICAL: 100.0,
    }

    def suggest_classification(self, asset: Asset) -> Tuple[DataSensitivity, List[str]]:
        """
        Analyzes an asset's name, description, tags, type, and criticality to suggest a sensitivity level.
        Returns:
            - suggested_level: DataSensitivity enum value
            - reasons: list of explanation strings for why this classification was chosen
        """
        reasons: List[str] = []
        text_corpus = f"{asset.name} {asset.description or ''} {asset.tags or ''}".lower()

        # Check criticality direct hints
        if asset.criticality == Criticality.CRITICAL:
            reasons.append("Asset criticality is marked as CRITICAL")

        # Check keywords
        for kw in self.CRITICAL_KEYWORDS:
            if kw in text_corpus:
                reasons.append(f"Identified critical keyword '{kw}' in asset metadata")
                return DataSensitivity.CRITICAL, reasons

        for kw in self.RESTRICTED_KEYWORDS:
            if kw in text_corpus:
                reasons.append(f"Identified restricted keyword '{kw}' (PII/compliance)")
                return DataSensitivity.RESTRICTED, reasons

        for kw in self.CONFIDENTIAL_KEYWORDS:
            if kw in text_corpus:
                reasons.append(f"Identified confidential keyword '{kw}'")
                return DataSensitivity.CONFIDENTIAL, reasons

        for kw in self.PUBLIC_KEYWORDS:
            if kw in text_corpus:
                reasons.append(f"Identified public-facing keyword '{kw}'")
                return DataSensitivity.PUBLIC, reasons

        # Fallback based on asset type and environment
        if asset.asset_type in (AssetType.DATABASE, AssetType.SERVICE) and asset.criticality in (Criticality.HIGH, Criticality.CRITICAL):
            reasons.append("High criticality backend service/database defaults to CONFIDENTIAL")
            return DataSensitivity.CONFIDENTIAL, reasons

        reasons.append("Default internal baseline sensitivity applied")
        return DataSensitivity.INTERNAL, reasons

    def get_sensitivity_score(self, sensitivity: DataSensitivity) -> float:
        """Returns the 0-100 numerical score associated with a sensitivity level."""
        return self.SENSITIVITY_SCORES.get(sensitivity, 40.0)
