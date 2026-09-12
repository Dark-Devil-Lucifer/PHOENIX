from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.services.alert_enrichment_service import (
    enrich_alert,
)


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alert Investigation"],
)


@router.get(
    "/{alert_id}/context",
)
def alert_context(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return enrich_alert(
            db,
            alert_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
