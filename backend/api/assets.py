from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetUpdate,
)
from backend.services.asset_service import (
    create_asset,
    delete_asset,
    get_asset,
    list_assets,
    update_asset,
)


router = APIRouter(
    prefix="/api/assets",
    tags=["Assets"],
)


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create(
    data: AssetCreate,
    db: Session = Depends(get_db),
):

    try:
        return create_asset(db, data)

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=list[AssetResponse],
)
def list_all(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    search: str | None = None,
    status: str | None = None,
    criticality: str | None = None,
    db: Session = Depends(get_db),
):

    return list_assets(
        db=db,
        skip=skip,
        limit=limit,
        search=search,
        status=status,
        criticality=criticality,
    )


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
)
def get_one(
    asset_id: int,
    db: Session = Depends(get_db),
):

    asset = get_asset(db, asset_id)

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    return asset


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
)
def update(
    asset_id: int,
    data: AssetUpdate,
    db: Session = Depends(get_db),
):

    asset = get_asset(db, asset_id)

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    return update_asset(
        db,
        asset,
        data,
    )


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete(
    asset_id: int,
    db: Session = Depends(get_db),
):

    asset = get_asset(db, asset_id)

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    delete_asset(db, asset)
