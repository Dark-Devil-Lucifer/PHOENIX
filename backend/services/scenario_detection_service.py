from sqlalchemy.orm import Session

from backend.models.security_event import SecurityEvent
from backend.models.detection_rule import DetectionRule

from backend.detection.engine import (
    detect_failed_then_success,
    detect_privilege_modification,
    detect_unusual_admin_activity,
    detect_unexpected_outbound,
    detect_sensitive_resource_access,
    detect_critical_config_change,
    detect_web_api_anomaly,
    detect_suspicious_process,
    detect_prohibited_segment_access,
    detect_container_vulnerability,
    detect_kubernetes_baseline_violation,
    detect_cloud_config_change,
    detect_ti_indicator_match,
    detect_containment_recovery,
)

from backend.services.alert_service import create_or_update_alert


DETECTORS = [
    detect_privilege_modification,
    detect_unusual_admin_activity,
    detect_unexpected_outbound,
    detect_sensitive_resource_access,
    detect_critical_config_change,
    detect_web_api_anomaly,
    detect_suspicious_process,
    detect_prohibited_segment_access,
    detect_container_vulnerability,
    detect_kubernetes_baseline_violation,
    detect_cloud_config_change,
    detect_ti_indicator_match,
    detect_containment_recovery,
]


def _confidence_score(value):
    if isinstance(value, int):
        return value

    return {
        "low": 40,
        "medium": 65,
        "high": 90,
    }.get(str(value).lower(), 50)


def _rule_id(db: Session, detection_id: str):
    rule = (
        db.query(DetectionRule)
        .filter(
            DetectionRule.rule_uid == detection_id,
            DetectionRule.enabled == True,
        )
        .first()
    )

    return rule.id if rule else None


def _serialize_alert(alert):
    return {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "detection_rule_id": alert.detection_rule_id,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "status": alert.status,
    }


def _create_alert(db, result, event):
    rule_id = _rule_id(
        db,
        result["detection_id"],
    )

    alert = create_or_update_alert(
        db=db,
        detection_id=result["detection_id"],
        title=result["rule_name"],
        description=result["description"],
        severity=result["severity"],
        confidence=_confidence_score(
            result["confidence"]
        ),
        event_ids=result.get(
            "evidence_event_ids",
            [event.id],
        ),
        asset_id=event.asset_id,
        detection_rule_id=rule_id,
    )

    result["detection_rule_id"] = rule_id
    result["alert"] = _serialize_alert(alert)
    result["alert_id"] = alert.id
    result["alert_uid"] = alert.alert_uid

    return result


def detect_event(
    db: Session,
    event_id: int,
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:
        return []


    detections = []

    # Authentication correlation detector needs
    # database context and the successful event timestamp.
    if (
        event.event_type == "authentication"
        and event.action == "login"
    ):
        outcome = (
            (event.normalized_data or {}).get("outcome")
            or ""
        ).lower()

        if outcome == "success":
            result = detect_failed_then_success(
                db=db,
                username=event.username,
                source_ip=event.source_ip,
                success_event_time=event.event_time,
            )

            if result:
                detections.append(
                    _create_alert(
                        db,
                        result,
                        event,
                    )
                )


    # Event-level detectors.
    for detector in DETECTORS:
        result = detector(event)

        if not result:
            continue

        detections.append(
            _create_alert(
                db,
                result,
                event,
            )
        )

    return detections
