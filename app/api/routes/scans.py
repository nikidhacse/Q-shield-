"""
Scan management routes: create scans, list, and trigger execution.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User
from app.schemas.scan import ScanCreateRequest, ScanListResponse, ScanResponse
from app.services.scan_manager import ScanManager

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """Create a new scan record in QUEUED state."""
    # Verify asset exists
    asset = db.query(Asset).filter(Asset.id == payload.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {payload.asset_id} not found")

    try:
        scan_type = ScanType(payload.scan_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scan_type: {payload.scan_type}")

    scan = Scan(
        asset_id=payload.asset_id,
        scan_type=scan_type,
        status=ScanStatus.QUEUED,
        scan_metadata=payload.scan_metadata,
        created_by=current_user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=ScanListResponse)
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    asset_id: int = Query(None),
    scan_status: str = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scans with optional filters."""
    query = db.query(Scan)
    if asset_id:
        query = query.filter(Scan.asset_id == asset_id)
    if scan_status:
        query = query.filter(Scan.status == scan_status)
    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return ScanListResponse(total=total, scans=scans)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve scan details by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/start", response_model=ScanResponse)
def start_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """
    Trigger execution of a queued scan.
    The scan manager runs synchronously for the initial implementation
    (async job queue will be added in a future phase).
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in (ScanStatus.QUEUED, ScanStatus.FAILED):
        raise HTTPException(
            status_code=400,
            detail=f"Scan cannot be started from status '{scan.status}'. Must be QUEUED or FAILED.",
        )

    manager = ScanManager(db)
    updated_scan = manager.run_scan(scan)
    return updated_scan


@router.post("/execute-instant", response_model=ScanResponse)
def execute_instant_scan(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """
    Creates an asset if needed, creates a scan with user-provided code/domain/file metadata,
    and runs the intelligence pipeline instantly.
    """
    from app.models.asset import AssetType, Criticality, AssetEnvironment, AssetStatus

    name = payload.get("name") or "Live Target Asset"
    scan_type_str = payload.get("scan_type") or "CERTIFICATE"
    raw_content = payload.get("content") or payload.get("metadata") or ""
    target_scope = payload.get("target") or name

    try:
        scan_type = ScanType(scan_type_str)
    except ValueError:
        scan_type = ScanType.CERTIFICATE

    # Find existing asset or create new one
    asset = db.query(Asset).filter(Asset.name == name).first()
    if not asset:
        asset = Asset(
            name=name,
            asset_type=AssetType.CERTIFICATE if scan_type == ScanType.CERTIFICATE else AssetType.APPLICATION,
            environment=AssetEnvironment.PRODUCTION,
            criticality=Criticality.HIGH,
            location=target_scope,
            description=f"Auto-registered from live {scan_type.value} scan.",
            status=AssetStatus.ACTIVE,
            owner_id=current_user.id,
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

    scan = Scan(
        asset_id=asset.id,
        scan_type=scan_type,
        status=ScanStatus.QUEUED,
        scan_metadata=raw_content or target_scope,
        created_by=current_user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    manager = ScanManager(db)
    return manager.run_scan(scan)


@router.post("/reset-database")
def reset_database(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    """
    Purges demo assets, scans, findings, certificates, risk scores, and migration plans.
    Retains user accounts so login persists.
    """
    from app.models.certificate import Certificate
    from app.models.crypto_finding import CryptoFinding
    from app.models.migration import MigrationPlan
    from app.models.risk_score import RiskScore

    db.query(CryptoFinding).delete()
    db.query(Certificate).delete()
    db.query(RiskScore).delete()
    db.query(MigrationPlan).delete()
    db.query(Scan).delete()
    db.query(Asset).delete()
    db.commit()

    return {"success": True, "message": "Demo data cleared successfully. Database is now clean."}
