from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db

from backend.schemas.risk import (
    RiskCreate,
    RiskResponse,
    RiskUpdate,
)

from backend.services.audit_service import write_audit_log

from backend.services.risk_service import (
    RiskError,
    create_risk,
    get_risk,
    list_risks,
    update_risk,
)


router = APIRouter(
    prefix="/api/risk",
    tags=["Risk Management"],
)


@router.post(
    "",
    response_model=RiskResponse,
)
def create(
    payload: RiskCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        risk = create_risk(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="risk_created",
            user_id=current_user.id,
            resource_type="risk",
            resource_id=risk.id,
            description=(
                f"Created risk {risk.risk_uid}"
            ),
        )

        db.commit()

        return risk

    except RiskError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=list[RiskResponse],
)
def list_all(
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_risks(
        db,
        severity=severity,
        status=status,
    )


@router.get(
    "/{risk_id}",
    response_model=RiskResponse,
)
def get(
    risk_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_risk(
            db,
            risk_id,
        )

    except RiskError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.patch(
    "/{risk_id}",
    response_model=RiskResponse,
)
def update(
    risk_id: int,
    payload: RiskUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        risk = update_risk(
            db,
            risk_id,
            payload,
        )

        write_audit_log(
            db,
            action="risk_updated",
            user_id=current_user.id,
            resource_type="risk",
            resource_id=risk.id,
            description=(
                f"Updated risk {risk.risk_uid}"
            ),
        )

        db.commit()

        return risk

    except RiskError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
