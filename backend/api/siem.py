from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.schemas.siem import (
    SIEMCorrelationRequest,
    SIEMCorrelationResponse,
    SIEMSearchRequest,
    SIEMSearchResponse,
)

from backend.services.audit_service import write_audit_log

from backend.services.siem_service import (
    SIEMError,
    correlate_events,
    search_events,
)


router = APIRouter(
    prefix="/api/siem",
    tags=["SIEM"],
)


@router.post(
    "/search",
    response_model=SIEMSearchResponse,
)
def search(
    payload: SIEMSearchRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return search_events(
        db,
        query=payload.query,
        event_type=payload.event_type,
        category=payload.category,
        action=payload.action,
        severity=payload.severity,
        username=payload.username,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        hostname=payload.hostname,
        start_time=payload.start_time,
        end_time=payload.end_time,
        limit=payload.limit,
    )


@router.post(
    "/correlate",
    response_model=SIEMCorrelationResponse,
)
def correlate(
    payload: SIEMCorrelationRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        result = correlate_events(
            db,
            payload.event_ids,
            payload.correlation_name,
        )

        write_audit_log(
            db,
            action="siem_events_correlated",
            user_id=current_user.id,
            resource_type="siem_correlation",
            description=(
                f"Correlated {len(payload.event_ids)} "
                f"security events"
            ),
            metadata={
                "correlation_name": payload.correlation_name,
                "event_ids": payload.event_ids,
                "confidence": result["confidence"],
            },
        )

        db.commit()

        return result

    except SIEMError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
