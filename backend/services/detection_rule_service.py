from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.detection_rule import DetectionRule


class DetectionRuleError(Exception):
    pass


VALID_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}


def create_rule(
    db: Session,
    data,
):
    existing = db.scalar(
        select(DetectionRule).where(
            DetectionRule.rule_uid == data.rule_uid
        )
    )

    if existing:
        raise DetectionRuleError(
            "Detection rule UID already exists"
        )

    if data.severity not in VALID_SEVERITIES:
        raise DetectionRuleError(
            "Invalid detection rule severity"
        )

    rule = DetectionRule(
        rule_uid=data.rule_uid,
        name=data.name,
        description=data.description,
        rule_type=data.rule_type,
        severity=data.severity,
        confidence=data.confidence,
        query=data.query,
        recommended_response=data.recommended_response,
        enabled=data.enabled,
    )

    db.add(rule)
    db.commit()
    db.refresh(rule)

    return rule


def list_rules(
    db: Session,
    enabled_only: bool = False,
):
    stmt = select(DetectionRule).order_by(
        DetectionRule.created_at.desc()
    )

    if enabled_only:
        stmt = stmt.where(
            DetectionRule.enabled.is_(True)
        )

    return list(db.scalars(stmt).all())


def get_rule(
    db: Session,
    rule_id: int,
):
    rule = db.get(
        DetectionRule,
        rule_id,
    )

    if not rule:
        raise DetectionRuleError(
            "Detection rule not found"
        )

    return rule


def update_rule(
    db: Session,
    rule_id: int,
    data,
):
    rule = get_rule(
        db,
        rule_id,
    )

    if (
        data.severity is not None
        and data.severity not in VALID_SEVERITIES
    ):
        raise DetectionRuleError(
            "Invalid detection rule severity"
        )

    if data.name is not None:
        rule.name = data.name

    if data.description is not None:
        rule.description = data.description

    if data.severity is not None:
        rule.severity = data.severity

    if data.confidence is not None:
        rule.confidence = data.confidence

    if data.query is not None:
        rule.query = data.query

    if data.recommended_response is not None:
        rule.recommended_response = (
            data.recommended_response
        )

    if data.enabled is not None:
        rule.enabled = data.enabled

    db.commit()
    db.refresh(rule)

    return rule
