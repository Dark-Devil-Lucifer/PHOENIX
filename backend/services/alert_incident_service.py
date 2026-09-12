from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.alert_event import AlertEvent
from backend.models.incident import Incident
from backend.models.incident_alert import IncidentAlert
from backend.models.incident_timeline import IncidentTimeline


SEVERITY_PRIORITY = {
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 30,
    "informational": 10,
}


def create_incident_from_alert(
    db: Session,
    alert_id: int,
):
    alert = db.get(
        Alert,
        alert_id,
    )

    if not alert:
        raise ValueError(
            "Alert not found"
        )

    existing_link = db.scalar(
        select(IncidentAlert).where(
            IncidentAlert.alert_id == alert.id
        )
    )

    if existing_link:
        existing_incident = db.get(
            Incident,
            existing_link.incident_id,
        )

        return existing_incident

    priority = SEVERITY_PRIORITY.get(
        alert.severity,
        10,
    )

    incident = Incident(
        incident_uid=(
            f"PHX-INC-{alert.alert_uid}"
        ),
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status="open",
        priority=priority,
        detected_at=alert.first_seen_at,
    )

    db.add(incident)
    db.flush()

    link = IncidentAlert(
        incident_id=incident.id,
        alert_id=alert.id,
    )

    db.add(link)

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_created",
        description=(
            f"Incident automatically created "
            f"from alert {alert.alert_uid}"
        ),
        metadata={
            "source": "automatic_alert_to_incident",
            "alert_id": alert.id,
            "alert_uid": alert.alert_uid,
        },
    )

    db.add(timeline)

    db.commit()
    db.refresh(incident)

    return incident


def auto_create_incident_for_alert(
    db: Session,
    alert_id: int,
):
    return create_incident_from_alert(
        db,
        alert_id,
    )
