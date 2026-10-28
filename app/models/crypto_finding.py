"""
CryptoFinding SQLAlchemy model.
Records a single detected cryptographic algorithm usage within an asset scan.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class AlgorithmCategory(str, enum.Enum):
    ASYMMETRIC = "ASYMMETRIC"
    SYMMETRIC = "SYMMETRIC"
    HASH = "HASH"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    SIGNATURE = "SIGNATURE"
    OTHER = "OTHER"


class FindingSeverity(str, enum.Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QuantumRelevance(str, enum.Enum):
    NOT_RELEVANT = "NOT_RELEVANT"       # Algorithm not affected by known quantum threats
    MONITOR = "MONITOR"                 # Keep an eye on developments
    PLAN_MIGRATION = "PLAN_MIGRATION"   # Should plan migration timeline
    MIGRATE_SOON = "MIGRATE_SOON"       # Priority migration recommended
    DEPRECATED = "DEPRECATED"          # Already weak regardless of quantum threats


class CryptoFinding(Base):
    __tablename__ = "crypto_findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    algorithm = Column(String(100), nullable=False, index=True)
    category = Column(Enum(AlgorithmCategory), nullable=False)
    detected_location = Column(String(1000), nullable=True)  # File path, line number, config key, etc.
    key_size = Column(Integer, nullable=True)                 # Key size in bits if known
    usage = Column(String(500), nullable=True)               # e.g., "TLS handshake", "file encryption"
    finding_severity = Column(Enum(FindingSeverity), default=FindingSeverity.MEDIUM, nullable=False)
    quantum_relevance = Column(Enum(QuantumRelevance), default=QuantumRelevance.MONITOR, nullable=False)
    evidence = Column(Text, nullable=True)                   # Supporting evidence or excerpt
    is_false_positive = Column(Boolean, default=False, nullable=False)
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="crypto_findings")
    scan = relationship("Scan", back_populates="crypto_findings")

    def __repr__(self) -> str:
        return f"<CryptoFinding id={self.id} algorithm={self.algorithm} severity={self.finding_severity}>"
