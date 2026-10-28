"""
Pydantic schemas for Migration Plan endpoints.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class MigrationPlanCreateRequest(BaseModel):
    asset_id: int
    current_algorithm: str
    target_algorithm: Optional[str] = None
    priority: Optional[str] = "MEDIUM"
    planned_date: Optional[datetime] = None
    notes: Optional[str] = None
    recommendation: Optional[str] = None


class MigrationPlanUpdateRequest(BaseModel):
    target_algorithm: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    planned_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    notes: Optional[str] = None


class MigrationPlanResponse(BaseModel):
    id: int
    asset_id: int
    current_algorithm: str
    target_algorithm: Optional[str]
    status: str
    priority: str
    owner_id: Optional[int]
    planned_date: Optional[datetime]
    completion_date: Optional[datetime]
    notes: Optional[str]
    recommendation: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class MigrationRoadmapResponse(BaseModel):
    total_plans: int
    plans_by_status: dict
    plans_by_priority: dict
    plans: list[MigrationPlanResponse]
