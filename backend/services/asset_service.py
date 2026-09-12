from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.asset import Asset
from backend.schemas.asset import AssetCreate, AssetUpdate


def create_asset(
    db: Session,
    data: AssetCreate,
) -> Asset:

    existing = db.scalar(
        select(Asset).where(
            Asset.asset_uid == data.asset_uid
        )
    )

    if existing:
        raise ValueError("Asset UID already exists")

    now = datetime.utcnow()

    asset = Asset(
        asset_uid=data.asset_uid,
        hostname=data.hostname,
        asset_type=data.asset_type,
        ip_address=data.ip_address,
        operating_system=data.operating_system,
        environment=data.environment,
        criticality=data.criticality,
        owner=data.owner,
        location=data.location,
        status=data.status,
        first_seen_at=now,
        last_seen_at=now,
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


def get_asset(
    db: Session,
    asset_id: int,
) -> Asset | None:

    return db.scalar(
        select(Asset).where(
            Asset.id == asset_id
        )
    )


def list_assets(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    search: str | None = None,
    status: str | None = None,
    criticality: str | None = None,
):

    query = select(Asset)

    if search:
        search_value = f"%{search}%"

        query = query.where(
            Asset.hostname.ilike(search_value)
            | Asset.asset_uid.ilike(search_value)
            | Asset.ip_address.ilike(search_value)
        )

    if status:
        query = query.where(
            Asset.status == status
        )

    if criticality:
        query = query.where(
            Asset.criticality == criticality
        )

    query = (
        query
        .order_by(Asset.created_at.desc())
        .offset(skip)
        .limit(limit)
    )

    return list(db.scalars(query).all())


def update_asset(
    db: Session,
    asset: Asset,
    data: AssetUpdate,
) -> Asset:

    updates = data.model_dump(
        exclude_unset=True
    )

    for field, value in updates.items():
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)

    return asset


def delete_asset(
    db: Session,
    asset: Asset,
) -> None:

    db.delete(asset)
    db.commit()
