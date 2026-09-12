from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.models.user import User

from backend.services.audit_service import write_audit_log
from backend.services.soar_service import (
    SOARError,
    request_execution,
    approve_execution,
    execute_containment,
    get_execution,
)


router = APIRouter(
    prefix="/api/soar",
    tags=["SOAR"],
)


def get_source_ip(request: Request) -> str | None:
    """Return the requesting client's IP address."""
    return (
        request.client.host
        if request.client
        else None
    )


# ---------------------------------------------------------------------------
# REQUEST SOAR EXECUTION
# Analyst or authorized authenticated user requests a response execution.
# ---------------------------------------------------------------------------

@router.post("/incidents/{incident_id}/execute/{playbook_uid}")
def request_soar_execution(
    incident_id: int,
    playbook_uid: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        execution = request_execution(
            db,
            incident_id=incident_id,
            playbook_uid=playbook_uid,
            requested_by=current_user.id,
        )

        write_audit_log(
            db,
            action="soar_execution_requested",
            user_id=current_user.id,
            resource_type="soar_execution",
            resource_id=execution.execution_uid,
            description=(
                f"SOAR execution requested for incident "
                f"{incident_id}"
            ),
            source_ip=get_source_ip(http_request),
            metadata={
                "incident_id": incident_id,
                "playbook_uid": playbook_uid,
                "execution_uid": execution.execution_uid,
                "username": current_user.username,
                "roles": [
                    role.name
                    for role in current_user.roles
                ],
            },
        )

        db.commit()

        return {
            "success": True,
            "execution_id": execution.id,
            "execution_uid": execution.execution_uid,
            "status": execution.status,
            "approval_required": execution.status == "pending",
            "requested_by": current_user.username,
            "message": (
                "SOAR execution created and awaiting approval"
                if execution.status == "pending"
                else "SOAR execution approved"
            ),
        }

    except SOARError as exc:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# GET SOAR EXECUTION
# Any authenticated SOC user can inspect an execution.
# ---------------------------------------------------------------------------

@router.get("/executions/{execution_uid}")
def get_soar_execution(
    execution_uid: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    execution = get_execution(
        db,
        execution_uid,
    )

    if not execution:
        raise HTTPException(
            status_code=404,
            detail="Execution not found",
        )

    return {
        "id": execution.id,
        "execution_uid": execution.execution_uid,
        "playbook_id": execution.playbook_id,
        "incident_id": execution.incident_id,
        "status": execution.status,
        "requested_by": execution.requested_by,
        "approved_by": execution.approved_by,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at,
        "result": execution.result,
        "created_at": execution.created_at,
    }


# ---------------------------------------------------------------------------
# APPROVE SOAR EXECUTION
# SOC Lead only.
#
# A requester cannot approve their own response execution.
# ---------------------------------------------------------------------------

@router.post("/executions/{execution_uid}/approve")
def approve_soar_execution(
    execution_uid: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    try:
        execution = get_execution(
            db,
            execution_uid,
        )

        if not execution:
            raise HTTPException(
                status_code=404,
                detail="Execution not found",
            )

        # Prevent self-approval.
        if execution.requested_by == current_user.id:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Requesters cannot approve "
                    "their own SOAR executions"
                ),
            )

        execution = approve_execution(
            db,
            execution_uid=execution_uid,
            approved_by=current_user.id,
        )

        write_audit_log(
            db,
            action="soar_execution_approved",
            user_id=current_user.id,
            resource_type="soar_execution",
            resource_id=execution.execution_uid,
            description=(
                "SOAR execution approved by SOC lead"
            ),
            source_ip=get_source_ip(http_request),
            metadata={
                "incident_id": execution.incident_id,
                "execution_uid": execution.execution_uid,
                "requested_by": execution.requested_by,
                "approved_by": current_user.id,
                "approver_username": current_user.username,
            },
        )

        db.commit()

        return {
            "success": True,
            "execution_uid": execution.execution_uid,
            "status": execution.status,
            "approved_by": current_user.username,
            "message": "SOAR execution approved",
        }

    except SOARError as exc:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# RUN SOAR EXECUTION
# Authenticated user executes an already-approved response.
# ---------------------------------------------------------------------------

@router.post("/executions/{execution_uid}/run")
def run_soar_execution(
    execution_uid: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        execution = execute_containment(
            db,
            execution_uid=execution_uid,
            executed_by=current_user.id,
        )

        write_audit_log(
            db,
            action="soar_execution_completed",
            user_id=current_user.id,
            resource_type="soar_execution",
            resource_id=execution.execution_uid,
            description=(
                "Controlled SOAR containment execution completed"
            ),
            source_ip=get_source_ip(http_request),
            metadata={
                "incident_id": execution.incident_id,
                "execution_uid": execution.execution_uid,
                "status": execution.status,
                "mode": "controlled_lab",
                "executed_by": current_user.username,
            },
        )

        db.commit()

        return {
            "success": True,
            "execution_uid": execution.execution_uid,
            "status": execution.status,
            "started_at": execution.started_at,
            "completed_at": execution.completed_at,
            "result": execution.result,
            "executed_by": current_user.username,
        }

    except SOARError as exc:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
