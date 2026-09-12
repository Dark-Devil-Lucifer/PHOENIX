from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.case import SecurityCase, CaseEvidence
from backend.models.incident import Incident


class CaseError(Exception):
    pass


ALLOWED_CASE_STATUSES = {
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed",
}


def create_case_from_incident(
    db: Session,
    incident_id: int,
    user_id: int,
):
    incident = db.get(
        Incident,
        incident_id,
    )

    if not incident:
        raise CaseError("Incident not found")

    existing = db.scalar(
        select(SecurityCase).where(
            SecurityCase.incident_id == incident.id
        )
    )

    if existing:
        return existing

    now = datetime.utcnow()

    case = SecurityCase(
        case_uid=f"PHX-CASE-{incident.incident_uid}",
        incident_id=incident.id,
        title=incident.title,
        description=incident.description,
        status="open",
        priority=incident.priority,
        assigned_to=incident.assigned_to,
        created_at=now,
        updated_at=now,
    )

    db.add(case)
    db.flush()

    evidence = CaseEvidence(
        case_id=case.id,
        evidence_type="incident",
        reference_type="incident",
        reference_id=str(incident.id),
        description=(
            f"Source incident {incident.incident_uid}"
        ),
        added_by=user_id,
        created_at=now,
    )

    db.add(evidence)

    db.commit()
    db.refresh(case)

    return case


def get_case(
    db: Session,
    case_id: int,
):
    case = db.get(
        SecurityCase,
        case_id,
    )

    if not case:
        raise CaseError("Case not found")

    return case


def list_cases(
    db: Session,
):
    return list(
        db.scalars(
            select(SecurityCase)
            .order_by(
                SecurityCase.created_at.desc()
            )
        ).all()
    )


def update_case(
    db: Session,
    case_id: int,
    *,
    status: str | None = None,
    priority: int | None = None,
    assigned_to: int | None = None,
    description: str | None = None,
):
    case = get_case(db, case_id)

    if status is not None:
        status = status.lower()

        if status not in ALLOWED_CASE_STATUSES:
            raise CaseError(
                f"Invalid case status: {status}. "
                f"Allowed values: {sorted(ALLOWED_CASE_STATUSES)}"
            )

        case.status = status

    if priority is not None:
        case.priority = priority

    if assigned_to is not None:
        case.assigned_to = assigned_to

    if description is not None:
        case.description = description

    case.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(case)

    return case


def add_evidence(
    db: Session,
    case_id: int,
    evidence_type: str,
    reference_type: str,
    reference_id: int | None,
    description: str | None,
    user_id: int,
):
    case = get_case(
        db,
        case_id,
    )

    evidence = CaseEvidence(
        case_id=case.id,
        evidence_type=evidence_type,
        reference_type=reference_type,
        reference_id=(
            str(reference_id)
            if reference_id is not None
            else None
        ),
        description=description,
        added_by=user_id,
        created_at=datetime.utcnow(),
    )

    db.add(evidence)

    case.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(evidence)

    return evidence
