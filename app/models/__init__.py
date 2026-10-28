"""
Convenience re-export of all SQLAlchemy models.
Import from here in Alembic env.py so Alembic sees every table.
"""

from app.models.user import User, UserRole  # noqa: F401
from app.models.asset import Asset, AssetType, Criticality, AssetEnvironment, AssetStatus  # noqa: F401
from app.models.scan import Scan, ScanType, ScanStatus  # noqa: F401
from app.models.crypto_finding import CryptoFinding, AlgorithmCategory, FindingSeverity, QuantumRelevance  # noqa: F401
from app.models.certificate import Certificate, CertificateStatus  # noqa: F401
from app.models.risk_score import RiskScore, RiskLevel, DataSensitivity  # noqa: F401
from app.models.migration import MigrationPlan, MigrationStatus, MigrationPriority  # noqa: F401

__all__ = [
    "User", "UserRole",
    "Asset", "AssetType", "Criticality", "AssetEnvironment", "AssetStatus",
    "Scan", "ScanType", "ScanStatus",
    "CryptoFinding", "AlgorithmCategory", "FindingSeverity", "QuantumRelevance",
    "Certificate", "CertificateStatus",
    "RiskScore", "RiskLevel", "DataSensitivity",
    "MigrationPlan", "MigrationStatus", "MigrationPriority",
]
