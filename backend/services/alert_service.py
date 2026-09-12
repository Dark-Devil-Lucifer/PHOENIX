from datetime import datetime

from sqlalchemy import text, select
from sqlalchemy.orm import Session

from backend.models.alert import Alert


def create_or_update_alert(
    db: Session,
    *,
    detection_id: str,
    title: str,
    description: str,
    severity: str,
    confidence: int,
    event_ids: list[int],
    asset_id: int | None = None,
    detection_rule_id: int | None = None,
) -> Alert:
    """
    Persist a detection result as an analyst-facing alert.

    Alerts are idempotent by detection_id. Re-evaluating the
    same detection updates the existing alert instead of creating
    duplicate alert records.
    """

    alert_uid = f"PHX-{detection_id}"
    now = datetime.utcnow()

    alert = db.scalar(
        select(Alert).where(Alert.alert_uid == alert_uid)
    )

    if alert:
        alert.last_seen_at = now

        if confidence > alert.confidence:
            alert.confidence = confidence

        if severity != alert.severity:
            alert.severity = severity

        if alert.asset_id is None and asset_id is not None:
            alert.asset_id = asset_id

        if alert.detection_rule_id is None and detection_rule_id is not None:
            alert.detection_rule_id = detection_rule_id

        db.flush()

        for event_id in event_ids:
            db.execute(
                text(
                    """
                    INSERT INTO alert_events (alert_id, event_id)
                    VALUES (:alert_id, :event_id)
                    ON DUPLICATE KEY UPDATE alert_id = VALUES(alert_id)
                    """
                ),
                {
                    "alert_id": alert.id,
                    "event_id": event_id,
                },
            )

        db.commit()
        db.refresh(alert)
        return alert

    alert = Alert(
        alert_uid=alert_uid,
        detection_rule_id=detection_rule_id,
        asset_id=asset_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        status="new",
        first_seen_at=now,
        last_seen_at=now,
    )

    db.add(alert)
    db.flush()

    for event_id in event_ids:
        db.execute(
            text(
                """
                INSERT INTO alert_events (alert_id, event_id)
                VALUES (:alert_id, :event_id)
                """
            ),
            {
                "alert_id": alert.id,
                "event_id": event_id,
            },
        )

    db.commit()
    db.refresh(alert)

    return alert
