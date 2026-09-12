from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.compliance import ComplianceControl


class ComplianceError(Exception):
    pass


VALID_STATUSES = {
    "not_assessed",
    "planned",
    "in_progress",
    "compliant",
    "partially_compliant",
    "non_compliant",
    "not_applicable",
}


def create_control(
    db: Session,
    data,
):
    existing = db.scalar(
        select(ComplianceControl).where(
            ComplianceControl.control_uid == data.control_uid
        )
    )

    if existing:
        raise ComplianceError(
            "Compliance control UID already exists"
        )

    control = ComplianceControl(
        control_uid=data.control_uid,
        framework=data.framework,
        control_id=data.control_id,
        title=data.title,
        description=data.description,
        owner=data.owner,
        evidence=data.evidence,
        status="not_assessed",
    )

    db.add(control)
    db.commit()
    db.refresh(control)

    return control


def list_controls(
    db: Session,
    framework: str | None = None,
    status: str | None = None,
):
    stmt = select(ComplianceControl).order_by(
        ComplianceControl.framework.asc(),
        ComplianceControl.control_id.asc(),
    )

    if framework:
        stmt = stmt.where(
            ComplianceControl.framework == framework
        )

    if status:
        stmt = stmt.where(
            ComplianceControl.status == status
        )

    return list(db.scalars(stmt).all())


def get_control(
    db: Session,
    control_id: int,
):
    control = db.get(
        ComplianceControl,
        control_id,
    )

    if not control:
        raise ComplianceError(
            "Compliance control not found"
        )

    return control


def assess_control(
    db: Session,
    control_id: int,
    data,
):
    control = get_control(
        db,
        control_id,
    )

    if data.status not in VALID_STATUSES:
        raise ComplianceError(
            "Invalid compliance status"
        )

    control.status = data.status
    control.assessment_notes = data.assessment_notes

    if data.evidence is not None:
        control.evidence = data.evidence

    control.assessed_at = datetime.utcnow()

    db.commit()
    db.refresh(control)

    return control


def get_summary(
    db: Session,
    framework: str | None = None,
):
    controls = list_controls(
        db,
        framework=framework,
    )

    summary = {
        "total": len(controls),
        "compliant": 0,
        "partially_compliant": 0,
        "non_compliant": 0,
        "not_assessed": 0,
        "in_progress": 0,
        "planned": 0,
        "not_applicable": 0,
    }

    for control in controls:
        if control.status in summary:
            summary[control.status] += 1

    assessed = (
        summary["compliant"]
        + summary["partially_compliant"]
        + summary["non_compliant"]
    )

    if assessed:
        summary["compliance_percentage"] = round(
            (
                summary["compliant"]
                + (summary["partially_compliant"] * 0.5)
            )
            / assessed
            * 100,
            2,
        )
    else:
        summary["compliance_percentage"] = 0.0

    return summary
