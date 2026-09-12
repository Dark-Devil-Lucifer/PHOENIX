from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.auth import get_current_user
from backend.schemas.incident import IncidentResponse
from backend.services.incident_service import (
    create_incident_from_alert,
    get_incident,
    list_incidents,
)
from backend.services.investigation_service import (
    get_incident_investigation,
)
from backend.services.incident_service import (
    acknowledge_incident,
    contain_incident,
    create_incident_from_alert,
    get_incident,
    list_incidents,
    resolve_incident,
)

router = APIRouter(
    prefix="/api/incidents",
    tags=["Incidents"],
)


@router.get(
    "",
    response_model=list[IncidentResponse],
)
def get_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
    db: Session = Depends(get_db),
):
    return list_incidents(
        db,
        status=status,
        severity=severity,
        limit=limit,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def get_single_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = get_incident(
        db,
        incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident


@router.post(
    "/from-alert/{alert_id}",
    response_model=IncidentResponse,
)
def create_from_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    try:
        return create_incident_from_alert(
            db,
            alert_id=alert_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
@router.get(
    "/{incident_id}/investigation",
)
def investigation(
    incident_id: int,
    db: Session = Depends(get_db),
):
    result = get_incident_investigation(
        db,
        incident_id,
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return result
@router.post("/{incident_id}/acknowledge", response_model=IncidentResponse)
def acknowledge(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return acknowledge_incident(
            db,
            incident_id=incident_id,
            actor_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.post("/{incident_id}/contain", response_model=IncidentResponse)
def contain(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return contain_incident(
            db,
            incident_id=incident_id,
            actor_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
def resolve(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return resolve_incident(
            db,
            incident_id=incident_id,
            actor_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
