"""
Migration plan routes: roadmap view, plan creation, and status updates.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, require_roles
from app.models.migration import MigrationPlan, MigrationPriority, MigrationStatus
from app.models.user import User
from app.schemas.migration import (
    MigrationPlanCreateRequest,
    MigrationPlanResponse,
    MigrationPlanUpdateRequest,
    MigrationRoadmapResponse,
)

router = APIRouter(prefix="/migration", tags=["Migration"])


@router.get("/roadmap", response_model=MigrationRoadmapResponse)
def get_roadmap(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return a roadmap view of all migration plans grouped by status and priority."""
    plans = db.query(MigrationPlan).order_by(MigrationPlan.created_at.desc()).all()

    by_status: dict = {}
    by_priority: dict = {}
    for plan in plans:
        s = str(plan.status.value if hasattr(plan.status, "value") else plan.status)
        p = str(plan.priority.value if hasattr(plan.priority, "value") else plan.priority)
        by_status[s] = by_status.get(s, 0) + 1
        by_priority[p] = by_priority.get(p, 0) + 1

    return MigrationRoadmapResponse(
        total_plans=len(plans),
        plans_by_status=by_status,
        plans_by_priority=by_priority,
        plans=plans,
    )


@router.post("/plans", response_model=MigrationPlanResponse, status_code=status.HTTP_201_CREATED)
def create_plan(
    payload: MigrationPlanCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """Create a new migration plan for a cryptographic algorithm on an asset."""
    plan = MigrationPlan(
        asset_id=payload.asset_id,
        current_algorithm=payload.current_algorithm,
        target_algorithm=payload.target_algorithm,
        priority=MigrationPriority(payload.priority or "MEDIUM"),
        status=MigrationStatus.NOT_STARTED,
        owner_id=current_user.id,
        planned_date=payload.planned_date,
        notes=payload.notes,
        recommendation=payload.recommendation,
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


@router.put("/plans/{plan_id}", response_model=MigrationPlanResponse)
def update_plan(
    plan_id: int,
    payload: MigrationPlanUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "security_analyst")),
):
    """Update migration plan status, target algorithm, or scheduling information."""
    plan = db.query(MigrationPlan).filter(MigrationPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Migration plan not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if value is not None:
            if field == "status":
                value = MigrationStatus(value)
            elif field == "priority":
                value = MigrationPriority(value)
        setattr(plan, field, value)

    db.commit()
    db.refresh(plan)
    return plan
