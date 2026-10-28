"""
Certificate SQLAlchemy model.
Stores analyzed certificate metadata, validity, and quantum-migration flags.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class CertificateStatus(str, enum.Enum):
    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"   # Within 90 days
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    serial_number = Column(String(255), nullable=True, index=True)
    subject = Column(String(1000), nullable=True)
    issuer = Column(String(1000), nullable=True)
    common_name = Column(String(500), nullable=True)
    san = Column(Text, nullable=True)                         # Subject Alternative Names (JSON)
    not_before = Column(DateTime(timezone=True), nullable=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    signature_algorithm = Column(String(200), nullable=True)
    public_key_algorithm = Column(String(200), nullable=True)
    key_size = Column(Integer, nullable=True)
    fingerprint_sha256 = Column(String(64), nullable=True)
    cert_status = Column(Enum(CertificateStatus), default=CertificateStatus.UNKNOWN, nullable=False)
    requires_pq_migration = Column(Boolean, default=False, nullable=False)
    migration_notes = Column(Text, nullable=True)
    raw_pem = Column(Text, nullable=True)                     # Optional stored PEM (no private keys)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    asset = relationship("Asset", back_populates="certificates")

    def __repr__(self) -> str:
        return f"<Certificate id={self.id} cn={self.common_name} algo={self.public_key_algorithm}>"
