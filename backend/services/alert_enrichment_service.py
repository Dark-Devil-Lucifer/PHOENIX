from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.alert_event import AlertEvent
from backend.models.asset import Asset
from backend.models.security_event import SecurityEvent
from backend.models.threat_indicator import ThreatIndicator
from backend.models.indicator_match import IndicatorMatch


def enrich_alert(
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

    asset = None

    if alert.asset_id:
        asset = db.get(
            Asset,
            alert.asset_id,
        )

    links = list(
        db.scalars(
            select(AlertEvent).where(
                AlertEvent.alert_id == alert.id
            )
        ).all()
    )

    event_ids = [
        link.event_id
        for link in links
    ]

    events = []

    if event_ids:
        events = list(
            db.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.id.in_(event_ids)
                )
                .order_by(
                    SecurityEvent.event_time.asc()
                )
            ).all()
        )

    intelligence = []

    for event in events:
        indicators = db.execute(
            select(
                ThreatIndicator,
                IndicatorMatch,
            )
            .join(
                IndicatorMatch,
                IndicatorMatch.indicator_id
                == ThreatIndicator.id,
            )
            .where(
                IndicatorMatch.event_id == event.id
            )
        ).all()

        for indicator, match in indicators:
            intelligence.append(
                {
                    "indicator": indicator.indicator_value,
                    "indicator_type": indicator.indicator_type,
                    "confidence": indicator.confidence,
                    "severity": indicator.severity,
                    "source_id": indicator.source_id,
                    "match_id": match.id,
                }
            )

    return {
        "alert": {
            "id": alert.id,
            "alert_uid": alert.alert_uid,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "status": alert.status,
            "first_seen_at": alert.first_seen_at,
            "last_seen_at": alert.last_seen_at,
        },
        "asset": (
            {
                "id": asset.id,
                "asset_uid": asset.asset_uid,
                "hostname": asset.hostname,
                "asset_type": asset.asset_type,
                "ip_address": asset.ip_address,
                "criticality": asset.criticality,
                "environment": asset.environment,
                "status": asset.status,
            }
            if asset
            else None
        ),
        "events": [
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
                "normalized_data": event.normalized_data,
            }
            for event in events
        ],
        "threat_intelligence": intelligence,
        "event_count": len(events),
        "intelligence_match_count": len(intelligence),
    }
