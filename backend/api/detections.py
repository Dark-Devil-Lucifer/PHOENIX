from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.auth import get_current_user

from backend.models.detection_rule import DetectionRule
from backend.models.security_event import SecurityEvent

from backend.services.alert_service import create_or_update_alert

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
)


router = APIRouter(
    prefix="/api/detections",
    tags=["Detection Engineering"],
)


def confidence_to_score(confidence):
    mapping = {
        "low": 40,
        "medium": 65,
        "high": 90,
    }

    if isinstance(confidence, int):
        return confidence

    return mapping.get(
        str(confidence).lower(),
        50,
    )


def get_rule_id(
    db: Session,
    detection_id: str,
):
    rule = (
        db.query(DetectionRule)
        .filter(
            DetectionRule.rule_uid == detection_id,
            DetectionRule.enabled == True,
        )
        .first()
    )

    return rule.id if rule else None


def get_event_outcome(
    event: SecurityEvent,
):
    normalized = event.normalized_data or {}
    raw = event.raw_event or {}

    return (
        normalized.get("outcome")
        or raw.get("outcome")
        or raw.get("result")
        or ""
    ).lower()


def serialize_alert(alert):
    if not alert:
        return None

    return {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "detection_rule_id": alert.detection_rule_id,
        "asset_id": alert.asset_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "status": alert.status,
        "first_seen_at": (
            alert.first_seen_at.isoformat()
            if alert.first_seen_at
            else None
        ),
        "last_seen_at": (
            alert.last_seen_at.isoformat()
            if alert.last_seen_at
            else None
        ),
    }


DETECTORS = {
    "privilege_modification": detect_privilege_modification,
    "unusual_admin_activity": detect_unusual_admin_activity,
    "unexpected_outbound": detect_unexpected_outbound,
    "sensitive_resource_access": detect_sensitive_resource_access,
    "critical_config_change": detect_critical_config_change,
    "web_api_anomaly": detect_web_api_anomaly,
    "suspicious_process": detect_suspicious_process,
    "prohibited_segment_access": detect_prohibited_segment_access,
}


@router.post("/authentication/{event_id}")
def detect_authentication(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    event_type = str(
        event.event_type or ""
    ).lower()

    action = str(
        event.action or ""
    ).lower()

    outcome = get_event_outcome(event)

    if event_type not in {
        "authentication",
        "login",
    }:
        raise HTTPException(
            status_code=400,
            detail="Event is not an authentication event",
        )

    successful = (
        outcome == "success"
        or action in {
            "login_success",
            "authentication_success",
        }
    )

    if not successful:
        raise HTTPException(
            status_code=400,
            detail="Authentication event is not a successful login",
        )

    detection = detect_failed_then_success(
        db=db,
        username=event.username,
        source_ip=event.source_ip,
        success_event_time=event.event_time,
    )

    if not detection:
        return {
            "detected": False,
            "event_id": event_id,
            "detections": [],
        }

    detection_rule_id = get_rule_id(
        db,
        detection["detection_id"],
    )

    alert = create_or_update_alert(
        db=db,
        detection_id=detection["detection_id"],
        title=detection["rule_name"],
        description=detection["description"],
        severity=detection["severity"],
        confidence=confidence_to_score(
            detection["confidence"]
        ),
        event_ids=detection.get(
            "evidence_event_ids",
            [],
        ),
        asset_id=event.asset_id,
        detection_rule_id=detection_rule_id,
    )

    return {
        "detected": True,
        "event_id": event_id,
        "detection": detection,
        "detection_rule_id": detection_rule_id,
        "alert": serialize_alert(alert),
        "evidence_event_ids": detection.get(
            "evidence_event_ids",
            [],
        ),
    }


@router.post("/event/{event_id}")
def detect_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    detections = []

    for detector_name, detector in DETECTORS.items():

        detection = detector(event)

        if not detection:
            continue

        detection_rule_id = get_rule_id(
            db,
            detection["detection_id"],
        )

        alert = create_or_update_alert(
            db=db,
            detection_id=detection["detection_id"],
            title=detection["rule_name"],
            description=detection["description"],
            severity=detection["severity"],
            confidence=confidence_to_score(
                detection["confidence"]
            ),
            event_ids=detection.get(
                "evidence_event_ids",
                [event.id],
            ),
            asset_id=event.asset_id,
            detection_rule_id=detection_rule_id,
        )

        detections.append(
            {
                "detector": detector_name,
                "detection_id": detection["detection_id"],
                "rule_name": detection["rule_name"],
                "severity": detection["severity"],
                "confidence": detection["confidence"],
                "detection_rule_id": detection_rule_id,
                "alert": serialize_alert(alert),
                "evidence_event_ids": detection.get(
                    "evidence_event_ids",
                    [event.id],
                ),
                "recommended_response": detection.get(
                    "recommended_response"
                ),
            }
        )

    return {
        "event_id": event_id,
        "count": len(detections),
        "detections": detections,
    }
