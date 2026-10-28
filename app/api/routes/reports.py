"""
Reports route: portfolio summary report endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Any, Dict

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.asset import Asset, Criticality
from app.models.crypto_finding import CryptoFinding
from app.models.migration import MigrationPlan, MigrationStatus
from app.models.risk_score import RiskScore, RiskLevel
from app.models.scan import Scan, ScanStatus
from app.models.user import User

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/summary")
def get_summary_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Return a comprehensive portfolio summary report.
    All numbers are calculated from live database records.
    """
    total_assets = db.query(Asset).count()
    critical_assets = db.query(Asset).filter(Asset.criticality == Criticality.CRITICAL).count()
    total_scans = db.query(Scan).count()
    completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
    total_findings = db.query(CryptoFinding).filter(CryptoFinding.is_false_positive == False).count()  # noqa: E712

    # Risk distribution from stored scores
    risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for rs in db.query(RiskScore).all():
        level = str(rs.risk_level.value if hasattr(rs.risk_level, "value") else rs.risk_level)
        risk_distribution[level] = risk_distribution.get(level, 0) + 1

    # Migration stats
    migration_in_progress = db.query(MigrationPlan).filter(
        MigrationPlan.status == MigrationStatus.IN_PROGRESS
    ).count()
    migration_completed = db.query(MigrationPlan).filter(
        MigrationPlan.status == MigrationStatus.COMPLETED
    ).count()

    # Algorithm frequency distribution
    from sqlalchemy import func
    algo_dist = (
        db.query(CryptoFinding.algorithm, func.count(CryptoFinding.id))
        .filter(CryptoFinding.is_false_positive == False)  # noqa: E712
        .group_by(CryptoFinding.algorithm)
        .order_by(func.count(CryptoFinding.id).desc())
        .limit(10)
        .all()
    )

    return {
        "report_type": "Portfolio Summary",
        "total_assets": total_assets,
        "critical_assets": critical_assets,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_crypto_findings": total_findings,
        "risk_distribution": risk_distribution,
        "migration_in_progress": migration_in_progress,
        "migration_completed": migration_completed,
        "top_algorithms_detected": [
            {"algorithm": row[0], "count": row[1]} for row in algo_dist
        ],
    }
