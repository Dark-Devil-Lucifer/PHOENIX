from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.models.user import User
from backend.schemas.zero_trust import (
    ZeroTrustEvaluateRequest,
    ZeroTrustPolicyCreate,
)
from backend.services.audit_service import write_audit_log
from backend.services.zero_trust_service import (
    create_policy,
    evaluate_access,
    list_policies,
)


router = APIRouter(
    prefix="/api/zero-trust",
    tags=["Zero Trust"],
)


def get_source_ip(request: Request):
    return request.client.host if request.client else None


@router.post("/policies")
def create(
    payload: ZeroTrustPolicyCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    policy = create_policy(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="zero_trust_policy_created",
        user_id=current_user.id,
        resource_type="zero_trust_policy",
        resource_id=str(policy.id),
        description=f"Created Zero Trust policy {policy.policy_uid}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(policy)

    return {
        "success": True,
        "policy_id": policy.id,
        "policy_uid": policy.policy_uid,
        "action": policy.action,
    }


@router.get("/policies")
def policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_policies(db)


@router.post("/evaluate")
def evaluate(
    payload: ZeroTrustEvaluateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = evaluate_access(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="zero_trust_access_evaluated",
        user_id=current_user.id,
        resource_type="zero_trust_decision",
        resource_id=str(result.id),
        description=(
            f"Zero Trust decision: {result.decision}"
        ),
        source_ip=get_source_ip(request),
        metadata={
            "source_segment": result.source_segment,
            "destination_segment": result.destination_segment,
            "reason": result.reason,
        },
    )

    db.commit()

    return {
        "success": True,
        "decision_id": result.id,
        "decision_uid": result.decision_uid,
        "decision": result.decision,
        "reason": result.reason,
        "policy_id": result.policy_id,
    }
