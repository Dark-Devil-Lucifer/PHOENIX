from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.models.user import User
from backend.schemas.endpoint import (
    EndpointCreate,
    EndpointEventCreate,
    EndpointIsolationRequest,
)
from backend.services.audit_service import write_audit_log
from backend.services.endpoint_service import (
    create_endpoint,
    get_endpoint,
    isolate_endpoint,
    list_endpoint_events,
    list_endpoints,
    record_endpoint_event,
    release_endpoint,
)


router = APIRouter(
    prefix="/api/endpoints",
    tags=["Endpoint Security / EDR"],
)


def get_source_ip(request: Request):
    return request.client.host if request.client else None


@router.post("")
def create(
    payload: EndpointCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    endpoint = create_endpoint(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="endpoint_registered",
        user_id=current_user.id,
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        description=f"Registered endpoint {endpoint.endpoint_uid}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(endpoint)

    return endpoint


@router.get("")
def list_all(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_endpoints(db)


@router.get("/{endpoint_id}")
def get_one(
    endpoint_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    endpoint = get_endpoint(db, endpoint_id)

    if not endpoint:
        raise HTTPException(
            status_code=404,
            detail="Endpoint not found",
        )

    return endpoint


@router.post("/events")
def create_event(
    payload: EndpointEventCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    try:
        event = record_endpoint_event(
            db,
            **payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="endpoint_event_ingested",
        user_id=current_user.id,
        resource_type="endpoint_event",
        resource_id=str(event.id),
        description=(
            f"Ingested endpoint event {event.event_type}"
        ),
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(event)

    return event


@router.get("/{endpoint_id}/events")
def events(
    endpoint_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    endpoint = get_endpoint(db, endpoint_id)

    if not endpoint:
        raise HTTPException(
            status_code=404,
            detail="Endpoint not found",
        )

    return list_endpoint_events(
        db,
        endpoint_id,
    )


@router.post("/isolate")
def isolate(
    payload: EndpointIsolationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    try:
        endpoint = isolate_endpoint(
            db,
            endpoint_id=payload.endpoint_id,
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="endpoint_isolated",
        user_id=current_user.id,
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        description=payload.reason,
        source_ip=get_source_ip(request),
        metadata={
            "controlled_action": True,
            "isolation_status": endpoint.isolation_status,
        },
    )

    db.commit()

    return {
        "success": True,
        "endpoint_id": endpoint.id,
        "endpoint_uid": endpoint.endpoint_uid,
        "isolation_status": endpoint.isolation_status,
    }


@router.post("/release")
def release(
    payload: EndpointIsolationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    try:
        endpoint = release_endpoint(
            db,
            endpoint_id=payload.endpoint_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="endpoint_isolation_released",
        user_id=current_user.id,
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        description=payload.reason,
        source_ip=get_source_ip(request),
    )

    db.commit()

    return {
        "success": True,
        "endpoint_id": endpoint.id,
        "endpoint_uid": endpoint.endpoint_uid,
        "isolation_status": endpoint.isolation_status,
    }
