from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.intelligence.extractor import extract_indicators_from_event
from backend.models.indicator_match import IndicatorMatch
from backend.models.security_event import SecurityEvent
from backend.schemas.security_event import SecurityEventCreate
from backend.services.threat_intelligence_service import lookup_indicator


def enrich_ingested_event(
    db: Session,
    event: SecurityEvent,
) -> list[dict]:
    """
    Automatically extract and match supported IOCs
    after an event has been persisted.
    """

    candidates = extract_indicators_from_event(event)
    matches = []

    for candidate in candidates:
        result = lookup_indicator(
            db,
            indicator_type=candidate["indicator_type"],
            value=candidate["value"],
        )

        if not result["matched"]:
            continue

        existing_match = db.scalar(
            select(IndicatorMatch).where(
                IndicatorMatch.indicator_id == result["indicator_id"],
                IndicatorMatch.event_id == event.id,
            )
        )

        if not existing_match:
            match = IndicatorMatch(
                indicator_id=result["indicator_id"],
                event_id=event.id,
                matched_value=candidate["value"],
                match_type=f"exact_{candidate['field']}",
                confidence=result["confidence"],
                matched_at=datetime.utcnow(),
                match_metadata={
                    "field": candidate["field"],
                    "indicator_type": candidate["indicator_type"],
                    "normalized_value": candidate["normalized_value"],
                    "source_id": result["source_id"],
                },
            )

            db.add(match)

        matches.append({
            **result,
            "field": candidate["field"],
        })

    db.flush()

    return matches


def ingest_event(
    db: Session,
    data: SecurityEventCreate,
) -> SecurityEvent:

    existing = db.scalar(
        select(SecurityEvent).where(
            SecurityEvent.event_uid == data.event_uid
        )
    )

    if existing:
        return existing

    event_time = data.timestamp or datetime.utcnow()

    normalized = {
        "timestamp": event_time.isoformat(),
        "source": data.source_type,
        "event_type": data.event_type,
        "source_ip": data.source_ip,
        "destination_ip": data.destination_ip,
        "username": data.username,
        "hostname": data.hostname,
        "action": data.action,
        "outcome": data.outcome,
        "severity": data.severity,
        **data.normalized_data,
    }

    event = SecurityEvent(
        event_uid=data.event_uid,
        event_time=event_time,
        event_type=data.event_type,
        category=data.source_type,
        action=data.action,
        severity=data.severity,
        source_ip=data.source_ip,
        destination_ip=data.destination_ip,
        source_port=data.source_port,
        destination_port=data.destination_port,
        username=data.username,
        message=data.raw_event.get("message"),
        raw_event=data.raw_event,
        normalized_data=normalized,
    )

    db.add(event)
    db.flush()

    # Automatic Threat Intelligence enrichment.
    enrich_ingested_event(
        db,
        event,
    )

    db.commit()
    db.refresh(event)

    return event


def get_event(
    db: Session,
    event_id: int,
) -> SecurityEvent | None:

    return db.scalar(
        select(SecurityEvent).where(
            SecurityEvent.id == event_id
        )
    )


def list_events(
    db: Session,
    limit=100,
    event_type=None,
    username=None,
    source_ip=None,
    severity=None,
):

    query = select(SecurityEvent)

    if event_type:
        query = query.where(
            SecurityEvent.event_type == event_type
        )

    if username:
        query = query.where(
            SecurityEvent.username == username
        )

    if source_ip:
        query = query.where(
            SecurityEvent.source_ip == source_ip
        )

    if severity:
        query = query.where(
            SecurityEvent.severity == severity
        )

    query = (
        query
        .order_by(SecurityEvent.event_time.desc())
        .limit(limit)
    )

    return list(db.scalars(query).all())
