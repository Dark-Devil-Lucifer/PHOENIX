from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.zero_trust import (
    ZeroTrustPolicy,
    ZeroTrustDecision,
)


def create_policy(
    db: Session,
    *,
    policy_uid: str,
    name: str,
    description: str | None = None,
    source_segment: str | None = None,
    destination_segment: str | None = None,
    action: str = "deny",
    required_role: str | None = None,
    required_device_state: str | None = None,
):
    existing = db.scalar(
        select(ZeroTrustPolicy).where(
            ZeroTrustPolicy.policy_uid == policy_uid
        )
    )

    if existing:
        return existing

    policy = ZeroTrustPolicy(
        policy_uid=policy_uid,
        name=name,
        description=description,
        source_segment=source_segment,
        destination_segment=destination_segment,
        action=action.lower(),
        required_role=required_role,
        required_device_state=required_device_state,
        enabled=True,
    )

    db.add(policy)
    db.flush()

    return policy


def list_policies(db: Session):
    return list(
        db.scalars(
            select(ZeroTrustPolicy)
            .order_by(ZeroTrustPolicy.id)
        ).all()
    )


def evaluate_access(
    db: Session,
    *,
    decision_uid: str,
    source_segment: str,
    destination_segment: str,
    user_id: int | None = None,
    asset_id: int | None = None,
    user_roles: list[str] | None = None,
    device_state: str | None = None,
):
    policies = list(
        db.scalars(
            select(ZeroTrustPolicy).where(
                ZeroTrustPolicy.enabled.is_(True)
            )
        ).all()
    )

    user_roles = user_roles or []

    matched_policy = None

    for policy in policies:
        if (
            policy.source_segment
            and policy.source_segment != source_segment
        ):
            continue

        if (
            policy.destination_segment
            and policy.destination_segment != destination_segment
        ):
            continue

        if (
            policy.required_role
            and policy.required_role not in user_roles
        ):
            continue

        if (
            policy.required_device_state
            and policy.required_device_state != device_state
        ):
            continue

        matched_policy = policy
        break

    if matched_policy:
        decision = matched_policy.action.lower()
        reason = (
            f"Matched Zero Trust policy "
            f"{matched_policy.policy_uid}"
        )
        policy_id = matched_policy.id
    else:
        # Zero Trust default-deny posture.
        decision = "deny"
        reason = "No matching policy; default deny"
        policy_id = None

    result = ZeroTrustDecision(
        decision_uid=decision_uid,
        policy_id=policy_id,
        user_id=user_id,
        asset_id=asset_id,
        source_segment=source_segment,
        destination_segment=destination_segment,
        decision=decision,
        reason=reason,
        evaluated_at=datetime.utcnow(),
    )

    db.add(result)
    db.flush()

    return result
