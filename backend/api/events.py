from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
)
from backend.services.event_service import (
    ingest_event,
    list_events,
)

router = APIRouter(
    prefix="/api/events",
    tags=["SIEM Events"],
)


@router.post(
    "",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest(
    data: SecurityEventCreate,
    db: Session = Depends(get_db),
):
    return ingest_event(db, data)


@router.get(
    "",
    response_model=list[SecurityEventResponse],
)
def search(
    limit: int = Query(default=100, ge=1, le=1000),
    event_type: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    return list_events(
        db=db,
        limit=limit,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        severity=severity,
    )
