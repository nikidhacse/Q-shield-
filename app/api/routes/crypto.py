"""
Crypto findings routes: read-only access to detected cryptographic algorithms.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.crypto_finding import CryptoFinding
from app.models.user import User
from app.schemas.crypto import CryptoFindingListResponse, CryptoFindingResponse, CryptoFindingUpdateRequest

router = APIRouter(prefix="/crypto", tags=["Crypto Findings"])


@router.get("/findings", response_model=CryptoFindingListResponse)
def list_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    asset_id: Optional[int] = None,
    algorithm: Optional[str] = None,
    severity: Optional[str] = None,
    quantum_relevance: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all crypto findings with optional filtering."""
    query = db.query(CryptoFinding).filter(CryptoFinding.is_false_positive == False)  # noqa: E712
    if asset_id:
        query = query.filter(CryptoFinding.asset_id == asset_id)
    if algorithm:
        query = query.filter(CryptoFinding.algorithm.ilike(f"%{algorithm}%"))
    if severity:
        query = query.filter(CryptoFinding.finding_severity == severity)
    if quantum_relevance:
        query = query.filter(CryptoFinding.quantum_relevance == quantum_relevance)

    total = query.count()
    findings = query.order_by(CryptoFinding.created_at.desc()).offset(skip).limit(limit).all()
    return CryptoFindingListResponse(total=total, findings=findings)


@router.get("/findings/{finding_id}", response_model=CryptoFindingResponse)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a specific crypto finding by ID."""
    finding = db.query(CryptoFinding).filter(CryptoFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=CryptoFindingResponse)
def update_finding(
    finding_id: int,
    payload: CryptoFindingUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """Allow analysts to mark a finding as false-positive or add notes."""
    finding = db.query(CryptoFinding).filter(CryptoFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if payload.is_false_positive is not None:
        finding.is_false_positive = payload.is_false_positive
    if payload.analyst_notes is not None:
        finding.analyst_notes = payload.analyst_notes
    db.commit()
    db.refresh(finding)
    return finding
