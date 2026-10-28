"""
Pydantic schemas for Scan endpoints.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ScanCreateRequest(BaseModel):
    asset_id: int
    scan_type: str
    scan_metadata: Optional[str] = None


class ScanResponse(BaseModel):
    id: int
    asset_id: int
    scan_type: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    findings_count: int
    error_message: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    total: int
    scans: list[ScanResponse]
