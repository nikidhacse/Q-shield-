"""
Pydantic schemas for Risk endpoints.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class RiskScoreResponse(BaseModel):
    id: int
    asset_id: int
    risk_score: float
    risk_level: str
    crypto_vulnerability_score: float
    asset_criticality_score: float
    data_sensitivity_score: float
    exposure_score: float
    algorithm_strength_score: float
    migration_difficulty_score: float
    harvest_now_score: float
    data_sensitivity: str
    risk_factors: Optional[str]
    explanation: Optional[str]
    calculated_at: datetime

    model_config = {"from_attributes": True}


class RiskSummaryResponse(BaseModel):
    total_assets: int
    risk_distribution: Dict[str, int]
    average_risk_score: float
    highest_risk_assets: List[Dict[str, Any]]
    quantum_vulnerable_count: int


class DataClassificationOverrideRequest(BaseModel):
    data_sensitivity: str  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, CRITICAL


class PriorityAssetResponse(BaseModel):
    asset_id: int
    asset_name: str
    risk_score: float
    priority_score: float
    priority_level: str
    priority_rank: Optional[int] = None
    reason: str
    recommended_action: str
