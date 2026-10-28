"""
Dashboard route: returns a structured overview for the Q-Shield frontend.
All numbers are computed from live database records – no hardcoded fake values.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import Any, Dict

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.asset import Asset, Criticality
from app.models.crypto_finding import CryptoFinding, QuantumRelevance
from app.models.migration import MigrationPlan, MigrationStatus
from app.models.risk_score import RiskScore, RiskLevel
from app.models.scan import Scan, ScanStatus
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview")
def dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Structured dashboard overview consumed by the Q-Shield frontend.
    Returns real counts from the database.
    """
    total_assets = db.query(Asset).count()

    # Assets that have at least one completed scan
    scanned_asset_ids = (
        db.query(Scan.asset_id)
        .filter(Scan.status == ScanStatus.COMPLETED)
        .distinct()
        .subquery()
    )
    scanned_assets = db.query(Asset).filter(Asset.id.in_(scanned_asset_ids)).count()

    critical_assets = db.query(Asset).filter(Asset.criticality == Criticality.CRITICAL).count()

    # High-risk = score >= 50 (HIGH or CRITICAL)
    high_risk_asset_ids = (
        db.query(RiskScore.asset_id)
        .filter(RiskScore.risk_score >= 50)
        .distinct()
        .subquery()
    )
    high_risk_assets = db.query(Asset).filter(Asset.id.in_(high_risk_asset_ids)).count()

    crypto_findings = (
        db.query(CryptoFinding)
        .filter(CryptoFinding.is_false_positive == False)  # noqa: E712
        .count()
    )

    # Assets with MIGRATE_SOON or DEPRECATED quantum relevance findings
    quantum_vuln_asset_ids = (
        db.query(CryptoFinding.asset_id)
        .filter(
            CryptoFinding.quantum_relevance.in_(
                [QuantumRelevance.MIGRATE_SOON, QuantumRelevance.PLAN_MIGRATION]
            ),
            CryptoFinding.is_false_positive == False,  # noqa: E712
        )
        .distinct()
        .subquery()
    )
    quantum_vulnerable_assets = db.query(Asset).filter(Asset.id.in_(quantum_vuln_asset_ids)).count()

    migration_in_progress = (
        db.query(MigrationPlan)
        .filter(MigrationPlan.status == MigrationStatus.IN_PROGRESS)
        .count()
    )

    # Risk distribution from stored risk scores
    risk_distribution: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for rs in db.query(RiskScore).all():
        level = str(rs.risk_level.value if hasattr(rs.risk_level, "value") else rs.risk_level)
        risk_distribution[level] = risk_distribution.get(level, 0) + 1

    # Top 5 priority assets by risk score
    top_risk = (
        db.query(RiskScore)
        .order_by(RiskScore.risk_score.desc())
        .limit(5)
        .all()
    )
    top_priority_assets = []
    for rs in top_risk:
        asset = db.query(Asset).filter(Asset.id == rs.asset_id).first()
        if asset:
            top_priority_assets.append({
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_type": str(asset.asset_type.value if hasattr(asset.asset_type, "value") else asset.asset_type),
                "criticality": str(asset.criticality.value if hasattr(asset.criticality, "value") else asset.criticality),
                "risk_score": rs.risk_score,
                "risk_level": str(rs.risk_level.value if hasattr(rs.risk_level, "value") else rs.risk_level),
            })

    return {
        "total_assets": total_assets,
        "scanned_assets": scanned_assets,
        "critical_assets": critical_assets,
        "high_risk_assets": high_risk_assets,
        "crypto_findings": crypto_findings,
        "quantum_vulnerable_assets": quantum_vulnerable_assets,
        "migration_in_progress": migration_in_progress,
        "risk_distribution": risk_distribution,
        "top_priority_assets": top_priority_assets,
    }
