"""
Risk assessment routes: per-asset risk scores and portfolio summary.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Any, Dict, List

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.asset import Asset
from app.models.crypto_finding import CryptoFinding
from app.models.risk_score import RiskScore, DataSensitivity
from app.models.user import User
from app.schemas.risk import (
    DataClassificationOverrideRequest,
    PriorityAssetResponse,
    RiskScoreResponse,
    RiskSummaryResponse,
)
from app.services.priority_engine import PriorityEngine
from app.services.recommendation_engine import RecommendationEngine
from app.services.risk_engine import RiskEngine

router = APIRouter(prefix="/risk", tags=["Risk Assessment"])


@router.get("/summary", response_model=RiskSummaryResponse)
def risk_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return a portfolio-level risk summary.
    Distribution and average are calculated from stored risk scores.
    """
    scores = db.query(RiskScore).all()
    total_assets = db.query(Asset).count()

    distribution: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    quantum_vulnerable = 0
    total_score = 0.0
    highest: List[Dict[str, Any]] = []

    for rs in scores:
        level = str(rs.risk_level.value if hasattr(rs.risk_level, "value") else rs.risk_level)
        distribution[level] = distribution.get(level, 0) + 1
        total_score += rs.risk_score
        if rs.risk_score >= 50:
            quantum_vulnerable += 1

    # Build top 5 highest risk assets for summary
    top_scores = (
        db.query(RiskScore).order_by(RiskScore.risk_score.desc()).limit(5).all()
    )
    for rs in top_scores:
        asset = db.query(Asset).filter(Asset.id == rs.asset_id).first()
        if asset:
            highest.append({
                "asset_id": asset.id,
                "asset_name": asset.name,
                "risk_score": rs.risk_score,
                "risk_level": str(rs.risk_level.value if hasattr(rs.risk_level, "value") else rs.risk_level),
            })

    avg = round(total_score / len(scores), 2) if scores else 0.0

    return RiskSummaryResponse(
        total_assets=total_assets,
        risk_distribution=distribution,
        average_risk_score=avg,
        highest_risk_assets=highest,
        quantum_vulnerable_count=quantum_vulnerable,
    )


@router.get("/priorities", response_model=List[PriorityAssetResponse])
def get_prioritized_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns all assets evaluated and ranked by the Priority Engine.
    """
    priority_engine = PriorityEngine()
    risk_scores = db.query(RiskScore).all()
    evaluated_list = []

    for rs in risk_scores:
        asset = db.query(Asset).filter(Asset.id == rs.asset_id).first()
        if asset:
            eval_dict = priority_engine.calculate_priority(asset, rs)
            eval_dict["priority_level"] = str(eval_dict["priority_level"].value if hasattr(eval_dict["priority_level"], "value") else eval_dict["priority_level"])
            evaluated_list.append(eval_dict)

    return priority_engine.rank_assets(evaluated_list)


@router.get("/assets", response_model=List[RiskScoreResponse])
def list_risk_scores(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    risk_level: str = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List risk scores for all assets."""
    query = db.query(RiskScore)
    if risk_level:
        query = query.filter(RiskScore.risk_level == risk_level)
    return query.order_by(RiskScore.risk_score.desc()).offset(skip).limit(limit).all()


@router.get("/assets/{asset_id}", response_model=RiskScoreResponse)
def get_asset_risk(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve the most recent risk score for a specific asset."""
    risk = (
        db.query(RiskScore)
        .filter(RiskScore.asset_id == asset_id)
        .order_by(RiskScore.calculated_at.desc())
        .first()
    )
    if not risk:
        raise HTTPException(status_code=404, detail="No risk score found for this asset")
    return risk


@router.post("/assets/{asset_id}/classify", response_model=RiskScoreResponse)
def override_data_classification(
    asset_id: int,
    payload: DataClassificationOverrideRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """
    Allows an analyst to override the data sensitivity classification for an asset
    and automatically recalculate the risk score.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        new_sensitivity = DataSensitivity(payload.data_sensitivity.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid data sensitivity. Valid values: {[e.value for e in DataSensitivity]}",
        )

    findings = (
        db.query(CryptoFinding)
        .filter(CryptoFinding.asset_id == asset_id, CryptoFinding.is_false_positive == False)  # noqa: E712
        .all()
    )

    risk_engine = RiskEngine()
    risk_calc = risk_engine.calculate_asset_risk(asset, findings, new_sensitivity)

    existing_risk = db.query(RiskScore).filter(RiskScore.asset_id == asset_id).first()
    if existing_risk:
        for k, v in risk_calc.items():
            setattr(existing_risk, k, v)
        risk_record = existing_risk
    else:
        risk_record = RiskScore(**risk_calc)
        db.add(risk_record)

    db.commit()
    db.refresh(risk_record)
    return risk_record
