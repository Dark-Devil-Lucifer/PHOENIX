from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.schemas.case import (
    CaseEvidenceCreate,
    CaseEvidenceResponse,
    CaseResponse,
    CaseUpdate,
)

from backend.services.audit_service import write_audit_log

from backend.services.case_service import (
    CaseError,
    add_evidence,
    create_case_from_incident,
    get_case,
    list_cases,
    update_case,
)


router = APIRouter(
    prefix="/api/cases",
    tags=["Cases"],
)


@router.post(
    "/from-incident/{incident_id}",
    response_model=CaseResponse,
)
def create_from_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        case = create_case_from_incident(
            db,
            incident_id,
            current_user.id,
        )

        write_audit_log(
            db,
            action="case_created_from_incident",
            user_id=current_user.id,
            resource_type="case",
            resource_id=case.id,
            description=(
                f"Created case {case.case_uid} "
                f"from incident {incident_id}"
            ),
        )

        db.commit()

        return case

    except CaseError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=list[CaseResponse],
)
def get_cases(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_cases(db)


@router.get(
    "/{case_id}",
    response_model=CaseResponse,
)
def get_single_case(
    case_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_case(
            db,
            case_id,
        )

    except CaseError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.post(
    "/{case_id}/evidence",
    response_model=CaseEvidenceResponse,
)
def create_evidence(
    case_id: int,
    payload: CaseEvidenceCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        evidence = add_evidence(
            db,
            case_id,
            payload.evidence_type,
            payload.reference_type,
            payload.reference_id,
            payload.description,
            current_user.id,
        )

        write_audit_log(
            db,
            action="case_evidence_added",
            user_id=current_user.id,
            resource_type="case_evidence",
            resource_id=evidence.id,
            description=(
                f"Added evidence to case {case_id}"
            ),
        )

        db.commit()

        return evidence

    except CaseError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.patch(
    "/{case_id}",
    response_model=CaseResponse,
)
def update_case_endpoint(
    case_id: int,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        case = update_case(
            db,
            case_id,
            status=payload.status,
            priority=payload.priority,
            assigned_to=payload.assigned_to,
            description=payload.description,
        )

        write_audit_log(
            db,
            action="case_updated",
            user_id=current_user.id,
            resource_type="case",
            resource_id=case.id,
            description=(
                f"Updated case {case.case_uid}"
            ),
        )

        db.commit()

        return case

    except CaseError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
