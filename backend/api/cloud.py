from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.models.user import User
from backend.schemas.cloud import (
    CloudAccountCreate,
    CloudAssetCreate,
    CloudFindingCreate,
)
from backend.services.audit_service import write_audit_log
from backend.services.cloud_service import (
    create_cloud_account,
    create_cloud_asset,
    create_finding,
    list_cloud_accounts,
    list_cloud_assets,
    list_findings,
    resolve_finding,
)


router = APIRouter(
    prefix="/api/cloud",
    tags=["Cloud Security"],
)


def get_source_ip(request: Request):
    return request.client.host if request.client else None


@router.post("/accounts")
def create_account(
    payload: CloudAccountCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    account = create_cloud_account(
        db,
        **payload.model_dump(),
    )

    write_audit_log(
        db,
        action="cloud_account_created",
        user_id=current_user.id,
        resource_type="cloud_account",
        resource_id=str(account.id),
        description=f"Registered cloud account {account.account_uid}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(account)

    return account


@router.get("/accounts")
def accounts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_cloud_accounts(db)


@router.post("/assets")
def create_asset(
    payload: CloudAssetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    try:
        asset = create_cloud_asset(
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
        action="cloud_asset_registered",
        user_id=current_user.id,
        resource_type="cloud_asset",
        resource_id=str(asset.id),
        description=f"Registered cloud asset {asset.cloud_asset_uid}",
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(asset)

    return asset


@router.get("/assets")
def assets(
    cloud_account_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_cloud_assets(
        db,
        cloud_account_id=cloud_account_id,
    )


@router.post("/findings")
def finding(
    payload: CloudFindingCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead", "soc_analyst")
    ),
):
    try:
        result = create_finding(
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
        action="cloud_security_finding_created",
        user_id=current_user.id,
        resource_type="cloud_security_finding",
        resource_id=str(result.id),
        description=result.title,
        source_ip=get_source_ip(request),
    )

    db.commit()
    db.refresh(result)

    return result


@router.get("/findings")
def findings(
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_findings(
        db,
        severity=severity,
        status=status,
    )


@router.post("/findings/{finding_id}/resolve")
def resolve(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("soc_lead")
    ),
):
    try:
        finding = resolve_finding(
            db,
            finding_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    write_audit_log(
        db,
        action="cloud_security_finding_resolved",
        user_id=current_user.id,
        resource_type="cloud_security_finding",
        resource_id=str(finding.id),
        description="Resolved cloud security finding",
        source_ip=get_source_ip(request),
    )

    db.commit()

    return {
        "success": True,
        "finding_id": finding.id,
        "status": finding.status,
        "resolved_at": finding.resolved_at,
    }
