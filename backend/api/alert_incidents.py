from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.services.alert_incident_service import (
    create_incident_from_alert,
)

from backend.services.audit_service import write_audit_log


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alert Incident Automation"],
)


@router.post(
    "/{alert_id}/create-incident",
)
def create_incident(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        incident = create_incident_from_alert(
            db,
            alert_id,
        )

        write_audit_log(
            db,
            action="incident_auto_created",
            user_id=current_user.id,
            resource_type="incident",
            resource_id=incident.id,
            description=(
                f"Created incident "
                f"{incident.incident_uid} "
                f"from alert {alert_id}"
            ),
            metadata={
                "alert_id": alert_id,
                "automation": True,
            },
        )

        db.commit()

        return {
            "created": True,
            "incident_id": incident.id,
            "incident_uid": incident.incident_uid,
            "severity": incident.severity,
            "priority": incident.priority,
            "status": incident.status,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
