from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user, require_role
from backend.core.database import get_db
from backend.schemas.hunting import (
    HuntingQueryCreate,
    HuntingQueryResponse,
    HuntingRunCreate,
    HuntingRunResponse,
)
from backend.services.audit_service import write_audit_log
from backend.services.hunting_service import (
    HuntingError,
    create_query,
    execute_query,
    get_query,
    get_run,
    list_queries,
    list_runs,
)

router = APIRouter(
    prefix="/api/hunting",
    tags=["Threat Hunting"],
)


@router.post(
    "/queries",
    response_model=HuntingQueryResponse,
)
def create_hunting_query(
    payload: HuntingQueryCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("soc_lead")),
):
    try:
        query = create_query(
            db,
            payload,
            current_user.id,
        )

        write_audit_log(
            db,
            action="hunting_query_created",
            user_id=current_user.id,
            resource_type="hunting_query",
            resource_id=query.id,
            description=f"Created hunting query {query.query_uid}",
        )

        db.commit()

        return query

    except HuntingError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/queries",
    response_model=list[HuntingQueryResponse],
)
def get_hunting_queries(
    enabled_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_queries(
        db,
        enabled_only=enabled_only,
    )


@router.get(
    "/queries/{query_id}",
    response_model=HuntingQueryResponse,
)
def get_hunting_query(
    query_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_query(db, query_id)
    except HuntingError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.post(
    "/runs",
    response_model=HuntingRunResponse,
)
def run_hunting_query(
    payload: HuntingRunCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        run = execute_query(
            db,
            query_id=payload.query_id,
            user_id=current_user.id,
            start_time=payload.start_time,
            end_time=payload.end_time,
            parameters=payload.parameters,
        )

        write_audit_log(
            db,
            action="hunting_query_executed",
            user_id=current_user.id,
            resource_type="hunting_run",
            resource_id=run.id,
            description=f"Executed hunting query {payload.query_id}",
        )

        db.commit()

        return run

    except HuntingError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


@router.get(
    "/runs",
    response_model=list[HuntingRunResponse],
)
def get_hunting_runs(
    query_id: int | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return list_runs(
        db,
        query_id=query_id,
        limit=limit,
    )


@router.get(
    "/runs/{run_id}",
    response_model=HuntingRunResponse,
)
def get_hunting_run(
    run_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return get_run(db, run_id)
    except HuntingError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
