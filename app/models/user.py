"""
User SQLAlchemy model.
Stores authentication credentials and role assignments.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    assets = relationship("Asset", back_populates="owner_user", foreign_keys="Asset.owner_id")
    scans = relationship("Scan", back_populates="created_by_user", foreign_keys="Scan.created_by")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"
