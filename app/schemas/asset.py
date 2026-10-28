"""
Pydantic schemas for Asset endpoints.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AssetCreateRequest(BaseModel):
    name: str
    asset_type: str
    environment: Optional[str] = "production"
    criticality: Optional[str] = "MEDIUM"
    description: Optional[str] = None
    location: Optional[str] = None
    tags: Optional[str] = None
    status: Optional[str] = "active"


class AssetUpdateRequest(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    tags: Optional[str] = None
    status: Optional[str] = None


class AssetResponse(BaseModel):
    id: int
    name: str
    asset_type: str
    owner_id: Optional[int]
    environment: str
    criticality: str
    description: Optional[str]
    location: Optional[str]
    tags: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssetListResponse(BaseModel):
    total: int
    assets: list[AssetResponse]
