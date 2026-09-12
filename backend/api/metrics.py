from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.services.metrics_service import (
    get_security_health,
    get_soc_metrics,
)


router = APIRouter(
    prefix="/api/metrics",
    tags=["SOC Metrics"],
)


@router.get(
    "/soc",
)
def soc_metrics(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return get_soc_metrics(db)


@router.get(
    "/health",
)
def security_health(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return get_security_health(db)
