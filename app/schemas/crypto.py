"""
Pydantic schemas for Crypto Finding endpoints.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class CryptoFindingResponse(BaseModel):
    id: int
    asset_id: int
    scan_id: int
    algorithm: str
    category: str
    detected_location: Optional[str]
    key_size: Optional[int]
    usage: Optional[str]
    finding_severity: str
    quantum_relevance: str
    evidence: Optional[str]
    is_false_positive: bool
    analyst_notes: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class CryptoFindingListResponse(BaseModel):
    total: int
    findings: list[CryptoFindingResponse]


class CryptoFindingUpdateRequest(BaseModel):
    is_false_positive: Optional[bool] = None
    analyst_notes: Optional[str] = None
