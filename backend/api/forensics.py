from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db

from backend.schemas.forensic import (
    ForensicArtifactCreate,
    ForensicArtifactResponse,
)

from backend.services.audit_service import write_audit_log

from backend.services.forensic_service import (
    verify_artifact_integrity,
    ForensicError,
    collect_artifact,
    generate_artifact_uid,
    get_artifact,
    get_case_artifacts,
    list_artifacts,
)


router = APIRouter(
    prefix="/api/forensics",
    tags=["Digital Forensics"],
)


@router.post(
    "/artifacts/generate-uid",
)
def generate_uid(
    current_user=Depends(get_current_user),
):
    return {
        "artifact_uid": generate_artifact_uid()
    }


@router.post(
    "/artifacts",
    response_model=ForensicArtifactResponse,
)
def create_artifact(
    payload: ForensicArtifactCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        artifact = collect_artifact(
            db,
            payload,
            current_user.id,
        )

        write_audit_log(
            db,
            action="forensic_artifact_collected",
            user_id=current_user.id,
            resource_type="forensic_artifact",
            resource_id=artifact.id,
            description=(
                f"Collected forensic artifact "
                f"{artifact.artifact_uid}"
            ),
            metadata={
                "case_id": artifact.case_id,
                "artifact_type": artifact.artifact_type,
                "source": artifact.source,
            },
        )

        db.commit()

        return artifact

    except ForensicError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/artifacts",
    response_model=list[ForensicArtifactResponse],
)
def get_artifacts(
    case_id: int | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_artifacts(
        db,
        case_id=case_id,
    )


@router.get(
    "/artifacts/{artifact_id:int}",
    response_model=ForensicArtifactResponse,
)
def get_single_artifact(
    artifact_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_artifact(
            db,
            artifact_id,
        )

    except ForensicError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.get(
    "/cases/{case_id}/artifacts",
    response_model=list[ForensicArtifactResponse],
)
def get_case_forensics(
    case_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_case_artifacts(
            db,
            case_id,
        )

    except ForensicError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# FORENSIC INTEGRITY VERIFICATION
# Controlled-lab SHA-256 verification of an evidence artifact.
# ---------------------------------------------------------------------------

@router.post("/artifacts/{artifact_id:int}/verify")
def verify_artifact(
    artifact_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    content = payload.get("content")

    if not isinstance(content, str):
        raise HTTPException(
            status_code=400,
            detail="content must be a string",
        )

    try:
        result = verify_artifact_integrity(
            db,
            artifact_id,
            content.encode("utf-8"),
        )

        audit_metadata = dict(result)

        for key, value in list(audit_metadata.items()):
            if hasattr(value, "isoformat"):
                audit_metadata[key] = value.isoformat()

        write_audit_log(
            db,
            action="forensic_integrity_verification",
            user_id=current_user.id,
            resource_type="forensic_artifact",
            resource_id=artifact_id,
            description=(
                f"Verified forensic artifact integrity: "
                f"{result.get('artifact_uid')}"
            ),
            metadata=audit_metadata,
        )

        db.commit()

        return result

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
