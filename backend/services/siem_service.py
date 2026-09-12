from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.models.security_event import SecurityEvent


class SIEMError(Exception):
    pass


def search_events(
    db: Session,
    *,
    query: str | None = None,
    event_type: str | None = None,
    category: str | None = None,
    action: str | None = None,
    severity: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    hostname: str | None = None,
    start_time=None,
    end_time=None,
    limit: int = 100,
):
    stmt = select(SecurityEvent).order_by(
        SecurityEvent.event_time.desc()
    )

    filters = []

    if query:
        search_value = f"%{query}%"

        filters.append(
            or_(
                SecurityEvent.event_uid.like(search_value),
                SecurityEvent.event_type.like(search_value),
                SecurityEvent.category.like(search_value),
                SecurityEvent.action.like(search_value),
                SecurityEvent.username.like(search_value),
                SecurityEvent.source_ip.like(search_value),
                SecurityEvent.destination_ip.like(search_value),
                SecurityEvent.message.like(search_value),
            )
        )

    if event_type:
        filters.append(
            SecurityEvent.event_type == event_type
        )

    if category:
        filters.append(
            SecurityEvent.category == category
        )

    if action:
        filters.append(
            SecurityEvent.action == action
        )

    if severity:
        filters.append(
            SecurityEvent.severity == severity
        )

    if username:
        filters.append(
            SecurityEvent.username == username
        )

    if source_ip:
        filters.append(
            SecurityEvent.source_ip == source_ip
        )

    if destination_ip:
        filters.append(
            SecurityEvent.destination_ip == destination_ip
        )

    if start_time:
        filters.append(
            SecurityEvent.event_time >= start_time
        )

    if end_time:
        filters.append(
            SecurityEvent.event_time <= end_time
        )

    if filters:
        stmt = stmt.where(*filters)

    events = list(
        db.scalars(
            stmt.limit(min(limit, 500))
        ).all()
    )

    output = []

    for event in events:
        normalized = event.normalized_data or {}

        output.append(
            {
                "id": event.id,
                "event_uid": event.event_uid,
                "event_time": event.event_time,
                "event_type": event.event_type,
                "category": event.category,
                "action": event.action,
                "severity": event.severity,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "username": event.username,
                "process_name": event.process_name,
                "message": event.message,
                "outcome": normalized.get("outcome"),
                "hostname": normalized.get("hostname"),
                "normalized_data": normalized,
            }
        )

    return {
        "total": len(output),
        "events": output,
    }


def correlate_events(
    db: Session,
    event_ids: list[int],
    correlation_name: str,
):
    unique_ids = list(dict.fromkeys(event_ids))

    events = list(
        db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.id.in_(unique_ids)
            )
            .order_by(
                SecurityEvent.event_time.asc()
            )
        ).all()
    )

    if not events:
        raise SIEMError(
            "No matching security events found"
        )

    findings = []
    highest_severity = "informational"

    severity_rank = {
        "informational": 10,
        "low": 30,
        "medium": 60,
        "high": 80,
        "critical": 100,
    }

    for event in events:
        if (
            severity_rank.get(
                event.severity,
                10,
            )
            > severity_rank.get(
                highest_severity,
                10,
            )
        ):
            highest_severity = event.severity

        normalized = event.normalized_data or {}

        if normalized.get("outcome") == "failure":
            findings.append(
                f"Failed action detected in {event.event_uid}"
            )

        if normalized.get("outcome") == "success":
            findings.append(
                f"Successful action detected in {event.event_uid}"
            )

        if event.action in {
            "add_role",
            "remove_role",
            "modify_privilege",
        }:
            findings.append(
                f"Privilege-related activity in {event.event_uid}"
            )

        if event.destination_ip:
            findings.append(
                f"Outbound destination observed: "
                f"{event.destination_ip}"
            )

    timeline = [
        {
            "event_id": event.id,
            "event_uid": event.event_uid,
            "event_time": event.event_time,
            "event_type": event.event_type,
            "action": event.action,
            "severity": event.severity,
            "username": event.username,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
        }
        for event in events
    ]

    confidence = min(
        95,
        50 + (len(events) * 10),
    )

    if len(events) >= 3:
        confidence += 5
        confidence = min(confidence, 100)

    return {
        "correlation_name": correlation_name,
        "matched": len(events) > 0,
        "event_count": len(events),
        "severity": highest_severity,
        "confidence": confidence,
        "timeline": timeline,
        "findings": list(dict.fromkeys(findings)),
    }
