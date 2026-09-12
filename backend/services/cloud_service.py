from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.cloud import (
    CloudAccount,
    CloudAsset,
    CloudSecurityFinding,
)


def create_cloud_account(
    db: Session,
    *,
    account_uid: str,
    provider: str,
    account_name: str,
    account_identifier: str | None = None,
    environment: str = "production",
):
    existing = db.scalar(
        select(CloudAccount).where(
            CloudAccount.account_uid == account_uid
        )
    )

    if existing:
        return existing

    now = datetime.utcnow()

    account = CloudAccount(
        account_uid=account_uid,
        provider=provider,
        account_name=account_name,
        account_identifier=account_identifier,
        environment=environment,
        status="active",
        created_at=now,
        updated_at=now,
    )

    db.add(account)
    db.flush()

    return account


def list_cloud_accounts(db: Session):
    return list(
        db.scalars(
            select(CloudAccount).order_by(
                CloudAccount.created_at.desc()
            )
        ).all()
    )


def create_cloud_asset(
    db: Session,
    *,
    cloud_asset_uid: str,
    cloud_account_id: int,
    resource_type: str,
    resource_name: str | None = None,
    region: str | None = None,
    criticality: str = "medium",
    configuration: dict | None = None,
):
    account = db.get(CloudAccount, cloud_account_id)

    if not account:
        raise ValueError("Cloud account not found")

    existing = db.scalar(
        select(CloudAsset).where(
            CloudAsset.cloud_asset_uid == cloud_asset_uid
        )
    )

    if existing:
        return existing

    now = datetime.utcnow()

    asset = CloudAsset(
        cloud_asset_uid=cloud_asset_uid,
        cloud_account_id=cloud_account_id,
        resource_type=resource_type,
        resource_name=resource_name,
        region=region,
        criticality=criticality,
        configuration=configuration,
        status="active",
        created_at=now,
        updated_at=now,
    )

    db.add(asset)
    db.flush()

    return asset


def list_cloud_assets(
    db: Session,
    cloud_account_id: int | None = None,
):
    query = select(CloudAsset).order_by(
        CloudAsset.created_at.desc()
    )

    if cloud_account_id:
        query = query.where(
            CloudAsset.cloud_account_id == cloud_account_id
        )

    return list(db.scalars(query).all())


def create_finding(
    db: Session,
    *,
    finding_uid: str,
    cloud_asset_id: int,
    title: str,
    severity: str,
    description: str | None = None,
    control_id: str | None = None,
    remediation: str | None = None,
):
    asset = db.get(CloudAsset, cloud_asset_id)

    if not asset:
        raise ValueError("Cloud asset not found")

    existing = db.scalar(
        select(CloudSecurityFinding).where(
            CloudSecurityFinding.finding_uid == finding_uid
        )
    )

    if existing:
        return existing

    finding = CloudSecurityFinding(
        finding_uid=finding_uid,
        cloud_asset_id=cloud_asset_id,
        title=title,
        description=description,
        severity=severity.lower(),
        control_id=control_id,
        remediation=remediation,
        status="open",
        detected_at=datetime.utcnow(),
    )

    db.add(finding)
    db.flush()

    return finding


def list_findings(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
):
    query = select(
        CloudSecurityFinding
    ).order_by(
        CloudSecurityFinding.detected_at.desc()
    )

    if severity:
        query = query.where(
            CloudSecurityFinding.severity == severity.lower()
        )

    if status:
        query = query.where(
            CloudSecurityFinding.status == status
        )

    return list(db.scalars(query).all())


def resolve_finding(
    db: Session,
    finding_id: int,
):
    finding = db.get(
        CloudSecurityFinding,
        finding_id,
    )

    if not finding:
        raise ValueError("Cloud finding not found")

    finding.status = "resolved"
    finding.resolved_at = datetime.utcnow()

    db.flush()

    return finding
