from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.incident import Incident
from backend.models.incident_timeline import IncidentTimeline
from backend.models.response_playbook import ResponsePlaybook
from backend.models.response_execution import ResponseExecution

from backend.services.audit_service import write_audit_log


class SOARError(Exception):
    pass


ACTIVE_STATUSES = {
    "pending",
    "approved",
    "running",
}


def get_playbook(
    db: Session,
    playbook_uid: str,
):
    playbook = db.scalar(
        select(ResponsePlaybook).where(
            ResponsePlaybook.playbook_uid == playbook_uid
        )
    )

    if not playbook:
        raise SOARError("Response playbook not found")

    if not playbook.enabled:
        raise SOARError("Response playbook is disabled")

    return playbook


def get_execution(
    db: Session,
    execution_uid: str,
):
    execution = db.scalar(
        select(ResponseExecution).where(
            ResponseExecution.execution_uid == execution_uid
        )
    )

    if not execution:
        raise SOARError("SOAR execution not found")

    return execution


def collect_incident_context(
    db: Session,
    incident_id: int,
):
    incident = db.get(Incident, incident_id)

    if not incident:
        raise SOARError("Incident not found")

    alerts = []

    try:
        from backend.models.incident_alert import IncidentAlert
        from backend.models.alert import Alert

        links = list(
            db.scalars(
                select(IncidentAlert).where(
                    IncidentAlert.incident_id == incident.id
                )
            ).all()
        )

        alert_ids = [link.alert_id for link in links]

        if alert_ids:
            alerts = list(
                db.scalars(
                    select(Alert).where(
                        Alert.id.in_(alert_ids)
                    )
                ).all()
            )

    except Exception:
        alerts = []

    return {
        "incident": {
            "id": incident.id,
            "incident_uid": incident.incident_uid,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "priority": incident.priority,
        },
        "alerts": [
            {
                "id": alert.id,
                "alert_uid": alert.alert_uid,
                "title": alert.title,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "status": alert.status,
            }
            for alert in alerts
        ],
    }


def request_execution(
    db: Session,
    incident_id: int,
    playbook_uid: str,
    requested_by: int,
):
    incident = db.get(Incident, incident_id)

    if not incident:
        raise SOARError("Incident not found")

    playbook = get_playbook(db, playbook_uid)

    existing = db.scalar(
        select(ResponseExecution).where(
            ResponseExecution.incident_id == incident.id,
            ResponseExecution.playbook_id == playbook.id,
            ResponseExecution.status.in_(ACTIVE_STATUSES),
        )
    )

    if existing:
        return existing

    execution = ResponseExecution(
        execution_uid=f"PHX-EXEC-{uuid4().hex[:16].upper()}",
        incident_id=incident.id,
        playbook_id=playbook.id,
        status=(
            "pending"
            if playbook.requires_approval
            else "approved"
        ),
        requested_by=requested_by,
        created_at=datetime.utcnow(),
    )

    db.add(execution)
    db.flush()

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="soar_execution_requested",
        description=(
            f"SOAR playbook {playbook.playbook_uid} requested"
        ),
        metadata={
            "execution_id": execution.id,
            "execution_uid": execution.execution_uid,
            "playbook_uid": playbook.playbook_uid,
            "requires_approval": playbook.requires_approval,
        },
    )

    db.add(timeline)

    write_audit_log(
        db,
        action="soar_execution_requested",
        user_id=requested_by,
        resource_type="response_execution",
        resource_id=str(execution.id),
        description=(
            f"Requested SOAR playbook "
            f"{playbook.playbook_uid}"
        ),
        metadata={
            "incident_id": incident.id,
            "playbook_uid": playbook.playbook_uid,
            "execution_uid": execution.execution_uid,
        },
    )

    db.commit()
    db.refresh(execution)

    return execution


def approve_execution(
    db: Session,
    execution_uid: str,
    approved_by: int,
):
    execution = get_execution(db, execution_uid)

    if execution.status != "pending":
        raise SOARError(
            f"Execution cannot be approved from "
            f"status '{execution.status}'"
        )

    if execution.requested_by == approved_by:
        raise SOARError("Self-approval is not permitted")

    execution.status = "approved"
    execution.approved_by = approved_by

    # Model does not currently expose approved_at.
    # Approval time is recorded in the incident timeline/audit log.
    now = datetime.utcnow()

    timeline = IncidentTimeline(
        incident_id=execution.incident_id,
        event_type="soar_execution_approved",
        description=(
            f"SOAR execution {execution.execution_uid} approved"
        ),
        metadata={
            "execution_id": execution.id,
            "execution_uid": execution.execution_uid,
            "approved_by": approved_by,
            "approved_at": now.isoformat(),
        },
    )

    db.add(timeline)

    write_audit_log(
        db,
        action="soar_execution_approved",
        user_id=approved_by,
        resource_type="response_execution",
        resource_id=str(execution.id),
        description=(
            f"Approved SOAR execution "
            f"{execution.execution_uid}"
        ),
        metadata={
            "incident_id": execution.incident_id,
            "execution_uid": execution.execution_uid,
            "approved_at": now.isoformat(),
        },
    )

    db.commit()
    db.refresh(execution)

    return execution


def execute_containment(
    db: Session,
    execution_uid: str,
    executed_by: int,
):
    execution = get_execution(db, execution_uid)

    if execution.status != "approved":
        raise SOARError(
            "Execution must be approved before running"
        )

    playbook = db.get(
        ResponsePlaybook,
        execution.playbook_id,
    )

    if not playbook:
        raise SOARError("Playbook not found")

    execution.status = "running"
    execution.started_at = datetime.utcnow()

    db.flush()

    context = collect_incident_context(
        db,
        execution.incident_id,
    )

    actions = []

    # Actions are stored in ResponsePlaybook.definition.
    definition = (
        playbook.definition
        if isinstance(playbook.definition, dict)
        else {}
    )

    configured_actions = definition.get("actions", [])

    if not isinstance(configured_actions, list):
        configured_actions = []

    if not configured_actions:
        configured_actions = [
            "collect_context",
            "isolate_test_asset",
            "block_test_ioc",
        ]

    for configured_action in configured_actions:

        if isinstance(configured_action, dict):
            action = configured_action.get("type")
            action_description = configured_action.get("description")
        else:
            action = configured_action
            action_description = None

        if action == "collect_context":
            actions.append({
                "action": action,
                "status": "completed",
                "details": (
                    action_description
                    or "Incident context collected"
                ),
            })

        elif action == "isolate_test_asset":
            actions.append({
                "action": action,
                "status": "completed",
                "details": (
                    action_description
                    or "Controlled lab isolation state recorded"
                ),
                "external_action": False,
            })

        elif action == "block_test_ioc":
            actions.append({
                "action": action,
                "status": "completed",
                "details": (
                    action_description
                    or "Controlled test IOC block state recorded"
                ),
                "external_action": False,
            })

        elif action == "preserve_evidence":
            actions.append({
                "action": action,
                "status": "completed",
                "details": (
                    action_description
                    or "Controlled incident evidence preservation recorded"
                ),
            })

        elif action == "collect_forensics":
            actions.append({
                "action": action,
                "status": "completed",
                "details": (
                    action_description
                    or "Controlled forensic collection recorded"
                ),
            })

        else:
            actions.append({
                "action": action,
                "status": "skipped",
                "details": (
                    "Action is not enabled by the controlled "
                    "PHOENIX execution engine"
                ),
            })

    execution.result = {
        "execution_mode": "controlled_lab",
        "executed_by": executed_by,
        "incident_id": execution.incident_id,
        "execution_uid": execution.execution_uid,
        "context": context,
        "actions": actions,
        "completed_at": datetime.utcnow().isoformat(),
    }

    execution.status = "completed"
    execution.completed_at = datetime.utcnow()

    timeline = IncidentTimeline(
        incident_id=execution.incident_id,
        event_type="soar_execution_completed",
        description=(
            f"SOAR execution "
            f"{execution.execution_uid} completed"
        ),
        metadata={
            "execution_id": execution.id,
            "execution_uid": execution.execution_uid,
            "actions": actions,
            "controlled_lab": True,
        },
    )

    db.add(timeline)

    write_audit_log(
        db,
        action="soar_execution_completed",
        user_id=executed_by,
        resource_type="response_execution",
        resource_id=str(execution.id),
        description=(
            f"Completed SOAR execution "
            f"{execution.execution_uid}"
        ),
        metadata={
            "incident_id": execution.incident_id,
            "execution_uid": execution.execution_uid,
            "actions": actions,
            "controlled_lab": True,
        },
    )

    db.commit()
    db.refresh(execution)

    return execution
