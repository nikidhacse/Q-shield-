"""
Utility helpers used across the Q-Shield backend.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utcnow() -> datetime:
    """Return the current UTC timestamp (timezone-aware)."""
    return datetime.now(timezone.utc)


def paginate(query, skip: int, limit: int):
    """Apply offset/limit pagination to a SQLAlchemy query and return results."""
    return query.offset(skip).limit(limit).all()


def sanitize_string(value: str, max_length: int = 500) -> str:
    """Strip leading/trailing whitespace and truncate to max_length."""
    if not value:
        return value
    return value.strip()[:max_length]


def to_enum_value(enum_obj: Any) -> str:
    """Safely extract the string value from an enum or return the value as-is."""
    return enum_obj.value if hasattr(enum_obj, "value") else str(enum_obj)


def build_error_response(detail: str, status_code: int = 400) -> Dict[str, Any]:
    """Build a standard error response dict."""
    return {"detail": detail, "status_code": status_code}
