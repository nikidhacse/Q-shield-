"""
MigrationPlan SQLAlchemy model.
Tracks the migration status of each cryptographic algorithm usage
identified in an asset.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class MigrationStatus(str, enum.Enum):
    NOT_STARTED = "NOT_STARTED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    TESTING = "TESTING"
    COMPLETED = "COMPLETED"
    DEFERRED = "DEFERRED"


class MigrationPriority(str, enum.Enum):
    IMMEDIATE = "IMMEDIATE"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MigrationPlan(Base):
    __tablename__ = "migration_plans"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    current_algorithm = Column(String(200), nullable=False)
    target_algorithm = Column(String(200), nullable=True)       # Nullable – may not be decided yet
    status = Column(Enum(MigrationStatus), default=MigrationStatus.NOT_STARTED, nullable=False)
    priority = Column(Enum(MigrationPriority), default=MigrationPriority.MEDIUM, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    planned_date = Column(DateTime(timezone=True), nullable=True)
    completion_date = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)                # Copied from recommendation engine
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    asset = relationship("Asset", back_populates="migration_plans")
    owner = relationship("User", foreign_keys=[owner_id])

    def __repr__(self) -> str:
        return (
            f"<MigrationPlan id={self.id} asset_id={self.asset_id} "
            f"algo={self.current_algorithm} status={self.status}>"
        )
