from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db

from backend.schemas.dlp import (
    DLPAssessmentResponse,
    DLPEventCreate,
    DLPEventResponse,
    SensitiveResourceCreate,
    SensitiveResourceResponse,
)

from backend.services.audit_service import write_audit_log

from backend.services.dlp_service import (
    DLPError,
    assess_dlp_event,
    create_sensitive_resource,
    get_dlp_event,
    get_sensitive_resource,
    list_dlp_events,
    list_sensitive_resources,
    record_dlp_event,
)


router = APIRouter(
    prefix="/api/dlp",
    tags=["DLP"],
)


@router.post(
    "/resources",
    response_model=SensitiveResourceResponse,
)
def create_resource(
    payload: SensitiveResourceCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        resource = create_sensitive_resource(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="dlp_resource_created",
            user_id=current_user.id,
            resource_type="sensitive_resource",
            resource_id=resource.id,
            description=(
                f"Created sensitive resource "
                f"{resource.resource_uid}"
            ),
        )

        db.commit()

        return resource

    except DLPError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/resources",
    response_model=list[SensitiveResourceResponse],
)
def get_resources(
    classification: str | None = None,
    enabled_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_sensitive_resources(
        db,
        classification=classification,
        enabled_only=enabled_only,
    )


@router.get(
    "/resources/{resource_id}",
    response_model=SensitiveResourceResponse,
)
def get_resource(
    resource_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_sensitive_resource(
            db,
            resource_id,
        )

    except DLPError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.post(
    "/events",
    response_model=DLPEventResponse,
)
def create_event(
    payload: DLPEventCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        event = record_dlp_event(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="dlp_event_recorded",
            user_id=current_user.id,
            resource_type="dlp_event",
            resource_id=event.id,
            description=(
                f"Recorded DLP event "
                f"{event.event_uid}"
            ),
        )

        db.commit()

        return event

    except DLPError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/events",
    response_model=list[DLPEventResponse],
)
def get_events(
    resource_id: int | None = None,
    username: str | None = None,
    severity: str | None = None,
    limit: int = Query(
        100,
        ge=1,
        le=500,
    ),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_dlp_events(
        db,
        resource_id=resource_id,
        username=username,
        severity=severity,
        limit=limit,
    )


@router.get(
    "/events/{event_id}",
    response_model=DLPEventResponse,
)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_dlp_event(
            db,
            event_id,
        )

    except DLPError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.post(
    "/events/{event_id}/assess",
    response_model=DLPAssessmentResponse,
)
def assess_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        assessment = assess_dlp_event(
            db,
            event_id,
        )

        write_audit_log(
            db,
            action="dlp_event_assessed",
            user_id=current_user.id,
            resource_type="dlp_event",
            resource_id=event_id,
            description=(
                f"Assessed DLP event {event_id}; "
                f"risk={assessment['risk_level']}"
            ),
            metadata={
                "risk_score": assessment["risk_score"],
                "triggered": assessment["triggered"],
            },
        )

        db.commit()

        return assessment

    except DLPError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
