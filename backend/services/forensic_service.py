import hashlib
import secrets
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.case import SecurityCase
from backend.models.forensic import ForensicArtifact


class ForensicError(Exception):
    pass


def generate_artifact_uid() -> str:
    return (
        "PHX-ART-"
        + secrets.token_hex(8).upper()
    )


def _validate_sha256(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.lower()

    if len(value) != 64:
        raise ForensicError(
            "SHA-256 hash must contain exactly 64 hexadecimal characters."
        )

    try:
        int(value, 16)
    except ValueError:
        raise ForensicError(
            "Invalid SHA-256 hash."
        )

    return value


def collect_artifact(
    db: Session,
    payload,
    user_id: int,
):
    case = db.get(
        SecurityCase,
        payload.case_id,
    )

    if not case:
        raise ForensicError(
            "Case not found."
        )

    existing = db.scalar(
        select(ForensicArtifact).where(
            ForensicArtifact.artifact_uid
            == payload.artifact_uid
        )
    )

    if existing:
        raise ForensicError(
            "Forensic artifact UID already exists."
        )

    hash_sha256 = _validate_sha256(
        payload.hash_sha256
    )

    now = datetime.utcnow()

    evidence = dict(
        payload.evidence or {}
    )

    # Explicitly identify this as a controlled
    # PHOENIX evidence acquisition.
    evidence.setdefault(
        "collection_mode",
        "controlled_lab",
    )

    evidence.setdefault(
        "integrity_algorithm",
        "SHA-256",
    )

    artifact = ForensicArtifact(
        artifact_uid=payload.artifact_uid,
        case_id=payload.case_id,
        artifact_type=payload.artifact_type,
        source=payload.source,
        hash_sha256=hash_sha256,
        collected_by=user_id,
        collected_at=now,
        evidence=evidence,
    )

    db.add(artifact)
    db.flush()
    db.refresh(artifact)

    return artifact


def get_artifact(
    db: Session,
    artifact_id: int,
):
    artifact = db.get(
        ForensicArtifact,
        artifact_id,
    )

    if not artifact:
        raise ForensicError(
            "Forensic artifact not found."
        )

    return artifact


def list_artifacts(
    db: Session,
    case_id: int | None = None,
):
    query = select(
        ForensicArtifact
    ).order_by(
        ForensicArtifact.collected_at.desc()
    )

    if case_id is not None:
        query = query.where(
            ForensicArtifact.case_id == case_id
        )

    return list(
        db.scalars(query).all()
    )


def get_case_artifacts(
    db: Session,
    case_id: int,
):
    case = db.get(
        SecurityCase,
        case_id,
    )

    if not case:
        raise ForensicError(
            "Case not found."
        )

    return list_artifacts(
        db,
        case_id=case_id,
    )


def verify_artifact_integrity(
    db: Session,
    artifact_id: int,
    content: bytes,
):
    artifact = get_artifact(
        db,
        artifact_id,
    )

    calculated_hash = hashlib.sha256(
        content
    ).hexdigest()

    expected_hash = artifact.hash_sha256

    if not expected_hash:
        return {
            "verified": False,
            "artifact_uid": artifact.artifact_uid,
            "message": "Artifact has no recorded SHA-256 hash.",
        }

    verified = (
        calculated_hash.lower()
        == expected_hash.lower()
    )

    return {
        "verified": verified,
        "artifact_uid": artifact.artifact_uid,
        "expected_sha256": expected_hash,
        "calculated_sha256": calculated_hash,
        "message": (
            "Artifact integrity verified."
            if verified
            else "Artifact integrity verification failed."
        ),
    }
