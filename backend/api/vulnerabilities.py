from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.models.user import User
from backend.schemas.vulnerability import (
    AssetVulnerabilityCreate,
    RemediationRequest,
    VulnerabilityCreate,
    VulnerabilityExceptionCreate,
    VulnerabilityResponse,
)
from backend.services.audit_service import write_audit_log
from backend.services.vulnerability_service import (
    create_exception,
    create_vulnerability,
    get_vulnerability,
    list_asset_vulnerabilities,
    list_vulnerabilities,
    map_vulnerability_to_asset,
    remediate_vulnerability,
    verify_remediation,
)


router = APIRouter(
    prefix="/api/vulnerabilities",
    tags=["Vulnerability Management"],
)


def source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post(
    "",
    response_model=VulnerabilityResponse,
    status_code=201,
)
def create(
    payload: VulnerabilityCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst", "soc_lead")),
):
    vulnerability = create_vulnerability(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="vulnerability_created",
        user_id=current_user.id,
        resource_type="vulnerability",
        resource_id=str(vulnerability.id),
        description=f"Created vulnerability {vulnerability.vulnerability_uid}",
        source_ip=source_ip(request),
    )

    db.commit()
    db.refresh(vulnerability)

    return vulnerability


@router.get("")
def list_all(
    status: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_vulnerabilities(
        db,
        status=status,
        severity=severity,
    )


@router.get("/{vulnerability_id}")
def get_one(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vulnerability = get_vulnerability(db, vulnerability_id)

    if not vulnerability:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found",
        )

    return vulnerability


@router.post("/map")
def map_to_asset(
    payload: AssetVulnerabilityCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_analyst", "soc_lead")
    ),
):
    try:
        mapping = map_vulnerability_to_asset(
            db,
            **payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="vulnerability_mapped",
        user_id=current_user.id,
        resource_type="asset_vulnerability",
        resource_id=f"{payload.asset_id}:{payload.vulnerability_id}",
        description="Mapped vulnerability to asset",
        source_ip=source_ip(request),
        metadata={
            "risk_score": mapping.risk_score,
        },
    )

    db.commit()

    return {
        "success": True,
        "asset_id": mapping.asset_id,
        "vulnerability_id": mapping.vulnerability_id,
        "risk_score": mapping.risk_score,
        "status": mapping.status,
    }


@router.get("/asset/{asset_id}")
def asset_findings(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_asset_vulnerabilities(
        db,
        asset_id,
    )


@router.post("/remediate")
def remediate(
    payload: RemediationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_analyst", "soc_lead")
    ),
):
    try:
        mapping = remediate_vulnerability(
            db,
            **payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="vulnerability_remediation",
        user_id=current_user.id,
        resource_type="asset_vulnerability",
        resource_id=f"{payload.asset_id}:{payload.vulnerability_id}",
        description="Vulnerability marked as remediated pending verification",
        source_ip=source_ip(request),
    )

    db.commit()

    return {
        "success": True,
        "asset_id": mapping.asset_id,
        "vulnerability_id": mapping.vulnerability_id,
        "status": mapping.status,
        "remediated_at": mapping.remediated_at,
    }


@router.post("/verify")
def verify(
    payload: RemediationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_analyst", "soc_lead")
    ),
):
    try:
        result = verify_remediation(
            db,
            **payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    audit_result = dict(result)

    if audit_result.get("verified_at") is not None:
        audit_result["verified_at"] = audit_result["verified_at"].isoformat()

    write_audit_log(
        db,
        action="vulnerability_verification",
        user_id=current_user.id,
        resource_type="asset_vulnerability",
        resource_id=f"{payload.asset_id}:{payload.vulnerability_id}",
        description="Performed authorized vulnerability remediation verification",
        source_ip=source_ip(request),
        metadata=audit_result,
    )

    db.commit()

    return result


@router.post("/exception")
def exception(
    payload: VulnerabilityExceptionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    try:
        result = create_exception(
            db,
            asset_id=payload.asset_id,
            vulnerability_id=payload.vulnerability_id,
            reason=payload.reason,
            approved_by=current_user.id,
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="vulnerability_exception_approved",
        user_id=current_user.id,
        resource_type="vulnerability_exception",
        resource_id=str(result.id),
        description="Approved vulnerability exception",
        source_ip=source_ip(request),
    )

    db.commit()

    return {
        "success": True,
        "exception_id": result.id,
        "asset_id": result.asset_id,
        "vulnerability_id": result.vulnerability_id,
        "status": result.status,
        "expires_at": result.expires_at,
    }
