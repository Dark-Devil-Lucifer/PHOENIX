from datetime import datetime
import json

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.incident import Incident


SEVERITY_PRIORITY = {
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 30,
    "informational": 10,
}


def create_incident_from_alert(
    db: Session,
    *,
    alert_id: int,
) -> Incident:

    alert = db.get(Alert, alert_id)

    if not alert:
        raise ValueError("Alert not found")

    existing_incident = db.execute(
        text(
            """
            SELECT i.id
            FROM incidents i
            INNER JOIN incident_alerts ia
                ON ia.incident_id = i.id
            WHERE ia.alert_id = :alert_id
            LIMIT 1
            """
        ),
        {"alert_id": alert_id},
    ).scalar()

    if existing_incident:
        incident = db.get(Incident, existing_incident)

        if incident:
            return incident

    now = datetime.utcnow()

    priority = SEVERITY_PRIORITY.get(
        alert.severity.lower(),
        50,
    )

    incident_uid = f"PHX-INC-{alert.alert_uid}"

    incident = Incident(
        incident_uid=incident_uid,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status="open",
        priority=priority,
        detected_at=alert.first_seen_at or now,
    )

    db.add(incident)
    db.flush()

    db.execute(
        text(
            """
            INSERT INTO incident_alerts
                (incident_id, alert_id)
            VALUES
                (:incident_id, :alert_id)
            """
        ),
        {
            "incident_id": incident.id,
            "alert_id": alert.id,
        },
    )

    add_timeline_entry(
        db,
        incident.id,
        "incident_created",
        f"Incident created from alert {alert.alert_uid}.",
        actor_type="system",
        metadata={
            "source": "phoenix_detection_engine",
            "alert_id": alert.id,
            "alert_uid": alert.alert_uid,
        },
        occurred_at=now,
    )

    db.commit()
    db.refresh(incident)

    return incident


def add_timeline_entry(
    db: Session,
    incident_id: int,
    event_type: str,
    description: str,
    *,
    actor_type: str = "system",
    actor_id: int | None = None,
    metadata: dict | None = None,
    occurred_at: datetime | None = None,
):
    db.execute(
        text(
            """
            INSERT INTO incident_timeline
                (
                    incident_id,
                    event_type,
                    description,
                    actor_type,
                    actor_id,
                    occurred_at,
                    metadata
                )
            VALUES
                (
                    :incident_id,
                    :event_type,
                    :description,
                    :actor_type,
                    :actor_id,
                    :occurred_at,
                    :metadata
                )
            """
        ),
        {
            "incident_id": incident_id,
            "event_type": event_type,
            "description": description,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "occurred_at": occurred_at or datetime.utcnow(),
            "metadata": (
                json.dumps(metadata)
                if metadata is not None
                else None
            ),
        },
    )


def acknowledge_incident(
    db: Session,
    *,
    incident_id: int,
    actor_id: int | None = None,
) -> Incident:

    incident = db.get(Incident, incident_id)

    if not incident:
        raise ValueError("Incident not found")

    if incident.status != "open":
        raise ValueError(
            f"Incident cannot be acknowledged from status '{incident.status}'"
        )

    incident.status = "acknowledged"

    add_timeline_entry(
        db,
        incident.id,
        "incident_acknowledged",
        "Incident acknowledged by analyst.",
        actor_type="analyst",
        actor_id=actor_id,
    )

    db.commit()
    db.refresh(incident)

    return incident


def contain_incident(
    db: Session,
    *,
    incident_id: int,
    actor_id: int | None = None,
) -> Incident:

    incident = db.get(Incident, incident_id)

    if not incident:
        raise ValueError("Incident not found")

    if incident.status not in {"open", "acknowledged"}:
        raise ValueError(
            f"Incident cannot be contained from status '{incident.status}'"
        )

    now = datetime.utcnow()

    incident.status = "contained"
    incident.contained_at = now

    add_timeline_entry(
        db,
        incident.id,
        "incident_contained",
        "Incident marked as contained.",
        actor_type="analyst",
        actor_id=actor_id,
        occurred_at=now,
    )

    db.commit()
    db.refresh(incident)

    return incident


def resolve_incident(
    db: Session,
    *,
    incident_id: int,
    actor_id: int | None = None,
) -> Incident:

    incident = db.get(Incident, incident_id)

    if not incident:
        raise ValueError("Incident not found")

    if incident.status != "contained":
        raise ValueError(
            f"Incident cannot be resolved from status '{incident.status}'"
        )

    now = datetime.utcnow()

    incident.status = "resolved"
    incident.resolved_at = now

    add_timeline_entry(
        db,
        incident.id,
        "incident_resolved",
        "Incident marked as resolved.",
        actor_type="analyst",
        actor_id=actor_id,
        occurred_at=now,
    )

    db.commit()
    db.refresh(incident)

    return incident


def get_incident(
    db: Session,
    incident_id: int,
) -> Incident | None:

    return db.scalar(
        select(Incident).where(
            Incident.id == incident_id
        )
    )


def list_incidents(
    db: Session,
    *,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[Incident]:

    query = select(Incident)

    if status:
        query = query.where(
            Incident.status == status
        )

    if severity:
        query = query.where(
            Incident.severity == severity
        )

    query = (
        query
        .order_by(
            Incident.priority.desc(),
            Incident.created_at.desc(),
        )
        .limit(limit)
    )

    return list(db.scalars(query).all())
