"""
Scan SQLAlchemy model.
Tracks the lifecycle of a cryptographic audit scan against an asset.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class ScanType(str, enum.Enum):
    SOURCE_CODE = "SOURCE_CODE"
    CERTIFICATE = "CERTIFICATE"
    NETWORK_METADATA = "NETWORK_METADATA"
    SAMPLE_DATA = "SAMPLE_DATA"


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    findings_count = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    scan_metadata = Column(Text, nullable=True)   # JSON string for flexible scan config
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="scans")
    created_by_user = relationship("User", back_populates="scans", foreign_keys=[created_by])
    crypto_findings = relationship("CryptoFinding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} asset_id={self.asset_id} type={self.scan_type} status={self.status}>"
