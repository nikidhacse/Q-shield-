"""
Database engine, session factory, and base declarative model setup.
All SQLAlchemy models inherit from Base defined here.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
engine_args = {
    "pool_pre_ping": True,
    "echo": settings.DEBUG,
}
if "sqlite" not in settings.DATABASE_URL:
    engine_args["pool_size"] = 10
    engine_args["max_overflow"] = 20

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    **engine_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base shared across all SQLAlchemy models."""
    pass


def get_db():
    """
    FastAPI dependency that provides a database session per request.
    Ensures the session is always closed after the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
