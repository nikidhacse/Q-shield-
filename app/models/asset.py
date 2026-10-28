"""
Asset SQLAlchemy model.
Represents a system, application, server, service, repository, certificate,
or other infrastructure component to be audited.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class AssetType(str, enum.Enum):
    SERVER = "server"
    APPLICATION = "application"
    SERVICE = "service"
    DATABASE = "database"
    REPOSITORY = "repository"
    CERTIFICATE = "certificate"
    NETWORK_DEVICE = "network_device"
    CLOUD_RESOURCE = "cloud_resource"
    API = "api"
    OTHER = "other"


class Criticality(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetEnvironment(str, enum.Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    DR = "dr"


class AssetStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    UNDER_REVIEW = "under_review"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    asset_type = Column(Enum(AssetType), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    environment = Column(Enum(AssetEnvironment), default=AssetEnvironment.PRODUCTION, nullable=False)
    criticality = Column(Enum(Criticality), default=Criticality.MEDIUM, nullable=False)
    description = Column(Text, nullable=True)
    location = Column(String(500), nullable=True)   # IP, hostname, URL, or physical location
    status = Column(Enum(AssetStatus), default=AssetStatus.ACTIVE, nullable=False)
    tags = Column(String(1000), nullable=True)       # Comma-separated tags
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    owner_user = relationship("User", back_populates="assets", foreign_keys=[owner_id])
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")
    crypto_findings = relationship("CryptoFinding", back_populates="asset", cascade="all, delete-orphan")
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")
    risk_scores = relationship("RiskScore", back_populates="asset", cascade="all, delete-orphan")
    migration_plans = relationship("MigrationPlan", back_populates="asset", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Asset id={self.id} name={self.name} type={self.asset_type}>"
