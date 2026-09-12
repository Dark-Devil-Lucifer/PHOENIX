from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.risk import RiskRegister


class RiskError(Exception):
    pass


def calculate_risk(likelihood: int, impact: int):
    score = likelihood * impact * 4

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    else:
        severity = "low"

    return min(score, 100), severity


def create_risk(
    db: Session,
    data,
):
    existing = db.scalar(
        select(RiskRegister).where(
            RiskRegister.risk_uid == data.risk_uid
        )
    )

    if existing:
        raise RiskError(
            "Risk UID already exists"
        )

    score, severity = calculate_risk(
        data.likelihood,
        data.impact,
    )

    risk = RiskRegister(
        risk_uid=data.risk_uid,
        title=data.title,
        description=data.description,
        category=data.category,
        likelihood=data.likelihood,
        impact=data.impact,
        risk_score=score,
        severity=severity,
        owner=data.owner,
        treatment=data.treatment,
        status=data.status,
        due_date=data.due_date,
        metadata_json=data.metadata,
    )

    db.add(risk)
    db.commit()
    db.refresh(risk)

    return risk


def list_risks(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
):
    stmt = select(RiskRegister).order_by(
        RiskRegister.risk_score.desc()
    )

    if severity:
        stmt = stmt.where(
            RiskRegister.severity == severity
        )

    if status:
        stmt = stmt.where(
            RiskRegister.status == status
        )

    return list(db.scalars(stmt).all())


def get_risk(
    db: Session,
    risk_id: int,
):
    risk = db.get(
        RiskRegister,
        risk_id,
    )

    if not risk:
        raise RiskError(
            "Risk not found"
        )

    return risk


def update_risk(
    db: Session,
    risk_id: int,
    data,
):
    risk = get_risk(
        db,
        risk_id,
    )

    likelihood = (
        data.likelihood
        if data.likelihood is not None
        else risk.likelihood
    )

    impact = (
        data.impact
        if data.impact is not None
        else risk.impact
    )

    score, severity = calculate_risk(
        likelihood,
        impact,
    )

    risk.likelihood = likelihood
    risk.impact = impact
    risk.risk_score = score

    if data.severity is not None:
        risk.severity = data.severity
    else:
        risk.severity = severity

    if data.owner is not None:
        risk.owner = data.owner

    if data.treatment is not None:
        risk.treatment = data.treatment

    if data.status is not None:
        risk.status = data.status

    if data.due_date is not None:
        risk.due_date = data.due_date

    if data.metadata is not None:
        risk.metadata_json = data.metadata

    db.commit()
    db.refresh(risk)

    return risk
