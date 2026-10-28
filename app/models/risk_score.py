"""
RiskScore SQLAlchemy model.
Stores the transparent, factor-based risk score for an asset.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class RiskLevel(str, enum.Enum):
    LOW = "LOW"         # 0–24
    MEDIUM = "MEDIUM"   # 25–49
    HIGH = "HIGH"       # 50–74
    CRITICAL = "CRITICAL"  # 75–100


class DataSensitivity(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL = "CRITICAL"


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)

    # Composite score (0-100)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(Enum(RiskLevel), nullable=False, default=RiskLevel.LOW)

    # Individual factor scores (each 0-100) – stored to ensure transparency
    crypto_vulnerability_score = Column(Float, default=0.0)     # Based on detected weak algorithms
    asset_criticality_score = Column(Float, default=0.0)        # Derived from asset.criticality
    data_sensitivity_score = Column(Float, default=0.0)         # How sensitive is the data handled
    exposure_score = Column(Float, default=0.0)                 # Internet-facing, internal, air-gapped
    algorithm_strength_score = Column(Float, default=0.0)       # Key length and algorithm modernity
    migration_difficulty_score = Column(Float, default=0.0)     # How hard is it to migrate
    harvest_now_score = Column(Float, default=0.0)              # Harvest-now-decrypt-later relevance

    # Classification of data handled by the asset
    data_sensitivity = Column(Enum(DataSensitivity), default=DataSensitivity.INTERNAL, nullable=False)

    # Human-readable explanation components
    risk_factors = Column(Text, nullable=True)   # JSON list of contributing risk factors
    explanation = Column(Text, nullable=True)     # Plain-language summary

    calculated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="risk_scores")

    def __repr__(self) -> str:
        return f"<RiskScore id={self.id} asset_id={self.asset_id} score={self.risk_score} level={self.risk_level}>"
