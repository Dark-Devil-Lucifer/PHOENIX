from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models.alert import Alert
from backend.schemas.alert import AlertResponse

router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    query = select(Alert)

    if status:
        query = query.where(Alert.status == status)

    if severity:
        query = query.where(Alert.severity == severity)

    query = (
        query
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )

    return list(db.scalars(query).all())


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert
