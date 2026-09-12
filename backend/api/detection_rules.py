from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db

from backend.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleResponse,
    DetectionRuleUpdate,
)

from backend.services.audit_service import write_audit_log

from backend.services.detection_rule_service import (
    DetectionRuleError,
    create_rule,
    get_rule,
    list_rules,
    update_rule,
)


router = APIRouter(
    prefix="/api/detection-rules",
    tags=["Detection Rules"],
)


@router.post(
    "",
    response_model=DetectionRuleResponse,
)
def create_detection_rule(
    payload: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        rule = create_rule(
            db,
            payload,
        )

        write_audit_log(
            db,
            action="detection_rule_created",
            user_id=current_user.id,
            resource_type="detection_rule",
            resource_id=rule.id,
            description=(
                f"Created detection rule "
                f"{rule.rule_uid}"
            ),
        )

        db.commit()

        return rule

    except DetectionRuleError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=list[DetectionRuleResponse],
)
def get_detection_rules(
    enabled_only: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_rules(
        db,
        enabled_only=enabled_only,
    )


@router.get(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
)
def get_detection_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_rule(
            db,
            rule_id,
        )

    except DetectionRuleError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.patch(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
)
def update_detection_rule(
    rule_id: int,
    payload: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        rule = update_rule(
            db,
            rule_id,
            payload,
        )

        write_audit_log(
            db,
            action="detection_rule_updated",
            user_id=current_user.id,
            resource_type="detection_rule",
            resource_id=rule.id,
            description=(
                f"Updated detection rule "
                f"{rule.rule_uid}"
            ),
        )

        db.commit()

        return rule

    except DetectionRuleError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
