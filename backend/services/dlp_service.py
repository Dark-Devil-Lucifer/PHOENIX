from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.dlp import DLPEvent, SensitiveResource


class DLPError(Exception):
    pass


CLASSIFICATION_SCORE = {
    "public": 5,
    "internal": 20,
    "confidential": 45,
    "restricted": 70,
    "secret": 90,
    "top_secret": 100,
}


ACTION_SCORE = {
    "view": 5,
    "read": 5,
    "download": 20,
    "copy": 25,
    "export": 40,
    "share": 50,
    "upload": 55,
    "email": 60,
    "transfer": 65,
    "delete": 75,
}


def create_sensitive_resource(
    db: Session,
    data,
):
    existing = db.scalar(
        select(SensitiveResource).where(
            SensitiveResource.resource_uid == data.resource_uid
        )
    )

    if existing:
        raise DLPError(
            "Sensitive resource UID already exists"
        )

    resource = SensitiveResource(
        resource_uid=data.resource_uid,
        name=data.name,
        resource_type=data.resource_type,
        location=data.location,
        classification=data.classification,
        owner=data.owner,
        description=data.description,
        enabled=data.enabled,
    )

    db.add(resource)
    db.commit()
    db.refresh(resource)

    return resource


def list_sensitive_resources(
    db: Session,
    classification: str | None = None,
    enabled_only: bool = False,
):
    stmt = select(SensitiveResource).order_by(
        SensitiveResource.created_at.desc()
    )

    if classification:
        stmt = stmt.where(
            SensitiveResource.classification == classification
        )

    if enabled_only:
        stmt = stmt.where(
            SensitiveResource.enabled.is_(True)
        )

    return list(db.scalars(stmt).all())


def get_sensitive_resource(
    db: Session,
    resource_id: int,
):
    resource = db.get(
        SensitiveResource,
        resource_id,
    )

    if not resource:
        raise DLPError(
            "Sensitive resource not found"
        )

    return resource


def record_dlp_event(
    db: Session,
    data,
):
    existing = db.scalar(
        select(DLPEvent).where(
            DLPEvent.event_uid == data.event_uid
        )
    )

    if existing:
        raise DLPError(
            "DLP event UID already exists"
        )

    if data.resource_id:
        resource = get_sensitive_resource(
            db,
            data.resource_id,
        )

        if not resource.enabled:
            raise DLPError(
                "Sensitive resource is disabled"
            )

    event = DLPEvent(
        event_uid=data.event_uid,
        resource_id=data.resource_id,
        event_type=data.event_type,
        action=data.action,
        username=data.username,
        source_ip=data.source_ip,
        destination=data.destination,
        data_classification=data.data_classification,
        bytes_transferred=data.bytes_transferred,
        policy_result=data.policy_result,
        severity=data.severity,
        event_time=data.event_time,
        description=data.description,
        event_metadata=data.metadata,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def get_dlp_event(
    db: Session,
    event_id: int,
):
    event = db.get(
        DLPEvent,
        event_id,
    )

    if not event:
        raise DLPError(
            "DLP event not found"
        )

    return event


def list_dlp_events(
    db: Session,
    resource_id: int | None = None,
    username: str | None = None,
    severity: str | None = None,
    limit: int = 100,
):
    stmt = select(DLPEvent).order_by(
        DLPEvent.event_time.desc()
    ).limit(min(limit, 500))

    if resource_id:
        stmt = stmt.where(
            DLPEvent.resource_id == resource_id
        )

    if username:
        stmt = stmt.where(
            DLPEvent.username == username
        )

    if severity:
        stmt = stmt.where(
            DLPEvent.severity == severity
        )

    return list(db.scalars(stmt).all())


def assess_dlp_event(
    db: Session,
    event_id: int,
):
    event = get_dlp_event(
        db,
        event_id,
    )

    risk_score = 0
    reasons = []

    classification = (
        event.data_classification or "internal"
    ).lower()

    classification_score = CLASSIFICATION_SCORE.get(
        classification,
        20,
    )

    action = (
        event.action or ""
    ).lower()

    action_score = ACTION_SCORE.get(
        action,
        10,
    )

    risk_score += int(
        classification_score * 0.5
    )

    risk_score += int(
        action_score * 0.35
    )

    if event.bytes_transferred:
        if event.bytes_transferred >= 100_000_000:
            risk_score += 30
            reasons.append(
                "Large data transfer detected"
            )
        elif event.bytes_transferred >= 10_000_000:
            risk_score += 15
            reasons.append(
                "Elevated data transfer volume"
            )

    if event.destination:
        destination = event.destination.lower()

        external_markers = (
            "external",
            "internet",
            "public",
            "unknown",
        )

        if any(
            marker in destination
            for marker in external_markers
        ):
            risk_score += 25
            reasons.append(
                "Data movement toward an external destination"
            )

    if event.policy_result.lower() in {
        "blocked",
        "denied",
        "violation",
    }:
        risk_score += 35
        reasons.append(
            "DLP policy violation or blocked action"
        )

    if classification in {
        "restricted",
        "secret",
        "top_secret",
    }:
        reasons.append(
            f"High-sensitivity classification: {classification}"
        )

    if action in {
        "export",
        "share",
        "upload",
        "email",
        "transfer",
    }:
        reasons.append(
            f"Sensitive data movement action: {action}"
        )

    risk_score = min(
        risk_score,
        100,
    )

    if risk_score >= 80:
        risk_level = "critical"
        triggered = True
        recommended_action = (
            "Contain the affected identity or endpoint, "
            "preserve evidence, and investigate the transfer."
        )
    elif risk_score >= 60:
        risk_level = "high"
        triggered = True
        recommended_action = (
            "Review authorization, destination, and "
            "data classification; escalate if unauthorized."
        )
    elif risk_score >= 35:
        risk_level = "medium"
        triggered = False
        recommended_action = (
            "Review the event and tune monitoring if required."
        )
    else:
        risk_level = "low"
        triggered = False
        recommended_action = (
            "Record the event for audit and monitoring."
        )

    if not reasons:
        reasons.append(
            "No high-risk DLP condition identified"
        )

    return {
        "event_id": event.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "triggered": triggered,
        "reasons": reasons,
        "recommended_action": recommended_action,
    }
