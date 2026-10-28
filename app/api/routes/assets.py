"""
Asset management routes: CRUD for infrastructure assets.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.asset import Asset, AssetType, Criticality, AssetEnvironment, AssetStatus
from app.models.user import User
from app.schemas.asset import AssetCreateRequest, AssetUpdateRequest, AssetResponse, AssetListResponse

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """Create a new infrastructure asset record."""
    asset = Asset(
        name=payload.name,
        asset_type=AssetType(payload.asset_type),
        owner_id=current_user.id,
        environment=AssetEnvironment(payload.environment or "production"),
        criticality=Criticality(payload.criticality or "MEDIUM"),
        description=payload.description,
        location=payload.location,
        tags=payload.tags,
        status=AssetStatus(payload.status or "active"),
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=AssetListResponse)
def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    asset_type: Optional[str] = None,
    criticality: Optional[str] = None,
    environment: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all assets with optional filters and pagination."""
    query = db.query(Asset)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if environment:
        query = query.filter(Asset.environment == environment)
    if status:
        query = query.filter(Asset.status == status)
    total = query.count()
    assets = query.order_by(Asset.created_at.desc()).offset(skip).limit(limit).all()
    return AssetListResponse(total=total, assets=assets)


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a single asset by ID."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    payload: AssetUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """Update an existing asset record."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if value is not None:
            # Convert string enums
            if field == "asset_type":
                value = AssetType(value)
            elif field == "criticality":
                value = Criticality(value)
            elif field == "environment":
                value = AssetEnvironment(value)
            elif field == "status":
                value = AssetStatus(value)
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    """Permanently delete an asset (admin only). Cascades to scans, findings, etc."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
