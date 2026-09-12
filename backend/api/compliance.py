from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db

from backend.schemas.compliance import (
    ComplianceAssessmentUpdate,
    ComplianceControlCreate,
    ComplianceControlResponse,
)

from backend.services.audit_service import write_audit_log

from backend.services.compliance_service import (
    ComplianceError,
    assess_control,
    create_control,
    get_control,
    get_summary,
    list_controls,
)


router = APIRouter(
    prefix="/api/compliance",
    tags=["Compliance"],
)


@router.post(
    "/controls",
    response_model=ComplianceControlResponse,
)
def create_compliance_control(
    payload: ComplianceControlCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        control = create_control(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="compliance_control_created",
            user_id=current_user.id,
            resource_type="compliance_control",
            resource_id=control.id,
            description=(
                f"Created compliance control "
                f"{control.control_uid}"
            ),
        )

        db.commit()

        return control

    except ComplianceError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/controls",
    response_model=list[ComplianceControlResponse],
)
def get_controls(
    framework: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_controls(
        db,
        framework=framework,
        status=status,
    )


@router.get(
    "/controls/{control_id}",
    response_model=ComplianceControlResponse,
)
def get_single_control(
    control_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_control(
            db,
            control_id,
        )

    except ComplianceError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.patch(
    "/controls/{control_id}/assessment",
    response_model=ComplianceControlResponse,
)
def assess_compliance_control(
    control_id: int,
    payload: ComplianceAssessmentUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        control = assess_control(
            db,
            control_id,
            payload,
        )

        write_audit_log(
            db,
            action="compliance_control_assessed",
            user_id=current_user.id,
            resource_type="compliance_control",
            resource_id=control.id,
            description=(
                f"Assessed {control.control_uid}: "
                f"{control.status}"
            ),
            metadata={
                "status": control.status,
                "framework": control.framework,
                "control_id": control.control_id,
            },
        )

        db.commit()

        return control

    except ComplianceError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/summary",
)
def compliance_summary(
    framework: str | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return get_summary(
        db,
        framework=framework,
    )
