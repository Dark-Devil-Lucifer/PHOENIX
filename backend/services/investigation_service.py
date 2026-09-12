from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.models.incident import Incident


def get_incident_investigation(
    db: Session,
    incident_id: int,
):
    incident = db.get(Incident, incident_id)

    if not incident:
        return None

    alerts = db.execute(
        text(
            """
            SELECT
                a.id,
                a.alert_uid,
                a.title,
                a.description,
                a.severity,
                a.confidence,
                a.status,
                a.asset_id,
                a.detection_rule_id,
                a.first_seen_at,
                a.last_seen_at
            FROM alerts a
            INNER JOIN incident_alerts ia
                ON ia.alert_id = a.id
            WHERE ia.incident_id = :incident_id
            ORDER BY a.created_at ASC
            """
        ),
        {"incident_id": incident_id},
    ).mappings().all()

    events = db.execute(
        text(
            """
            SELECT DISTINCT
                se.id,
                se.event_uid,
                se.event_time,
                se.event_type,
                se.category,
                se.action,
                se.severity,
                se.source_ip,
                se.destination_ip,
                se.source_port,
                se.destination_port,
                se.username,
                se.process_name,
                se.message,
                se.normalized_data
            FROM security_events se
            INNER JOIN alert_events ae
                ON ae.event_id = se.id
            INNER JOIN incident_alerts ia
                ON ia.alert_id = ae.alert_id
            WHERE ia.incident_id = :incident_id
            ORDER BY se.event_time ASC
            """
        ),
        {"incident_id": incident_id},
    ).mappings().all()

    event_ids = [event["id"] for event in events]

    intelligence_matches = []

    if event_ids:
        intelligence_matches = db.execute(
            text(
                """
                SELECT
                    im.id,
                    im.event_id,
                    im.alert_id,
                    im.matched_value,
                    im.match_type,
                    im.confidence,
                    im.matched_at,

                    ti.id AS indicator_id,
                    ti.indicator_uid,
                    ti.indicator_type,
                    ti.normalized_value,
                    ti.threat_type,
                    ti.malware_family,
                    ti.severity AS indicator_severity,
                    ti.status AS indicator_status,

                    tis.id AS source_id,
                    tis.source_uid,
                    tis.name AS source_name,
                    tis.source_type,
                    tis.reliability AS source_reliability,
                    tis.confidence AS source_confidence

                FROM indicator_matches im

                INNER JOIN threat_indicators ti
                    ON ti.id = im.indicator_id

                LEFT JOIN threat_intelligence_sources tis
                    ON tis.id = ti.source_id

                WHERE im.event_id IN (
                    SELECT id
                    FROM security_events
                    WHERE id IN :event_ids
                )

                ORDER BY im.matched_at ASC
                """
            ).bindparams(
                event_ids=tuple(event_ids)
            ),
        ).mappings().all()

    timeline = db.execute(
        text(
            """
            SELECT
                id,
                event_type,
                description,
                actor_type,
                actor_id,
                occurred_at,
                metadata
            FROM incident_timeline
            WHERE incident_id = :incident_id
            ORDER BY occurred_at ASC, id ASC
            """
        ),
        {"incident_id": incident_id},
    ).mappings().all()

    return {
        "incident": incident,
        "alerts": [dict(row) for row in alerts],
        "events": [dict(row) for row in events],
        "intelligence_matches": [
            dict(row)
            for row in intelligence_matches
        ],
        "timeline": [
            {
                **dict(row),
                "metadata": (
                    row["metadata"]
                    if isinstance(row["metadata"], dict)
                    else None
                ),
            }
            for row in timeline
        ],
    }
