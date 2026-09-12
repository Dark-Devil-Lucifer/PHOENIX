from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.models.hunting import HuntingQuery, HuntingRun


class HuntingError(Exception):
    pass


ALLOWED_QUERY_TYPES = {
    "sql",
    "event_search",
    "endpoint_search",
    "network_search",
}


def create_query(db: Session, data, user_id: int):
    existing = db.scalar(
        select(HuntingQuery).where(
            HuntingQuery.query_uid == data.query_uid
        )
    )

    if existing:
        raise HuntingError("Hunting query UID already exists")

    query = HuntingQuery(
        query_uid=data.query_uid,
        name=data.name,
        description=data.description,
        query_type=data.query_type,
        query_text=data.query_text,
        severity=data.severity,
        enabled=data.enabled,
    )

    db.add(query)
    db.commit()
    db.refresh(query)

    return query


def list_queries(db: Session, enabled_only: bool = False):
    stmt = select(HuntingQuery).order_by(
        HuntingQuery.created_at.desc()
    )

    if enabled_only:
        stmt = stmt.where(HuntingQuery.enabled.is_(True))

    return list(db.scalars(stmt).all())


def get_query(db: Session, query_id: int):
    query = db.get(HuntingQuery, query_id)

    if not query:
        raise HuntingError("Hunting query not found")

    return query


def execute_query(
    db: Session,
    query_id: int,
    user_id: int,
    start_time=None,
    end_time=None,
    parameters=None,
):
    query = get_query(db, query_id)

    if not query.enabled:
        raise HuntingError("Hunting query is disabled")

    if query.query_type not in ALLOWED_QUERY_TYPES:
        raise HuntingError("Unsupported hunting query type")

    end = end_time or datetime.now(timezone.utc).replace(tzinfo=None)
    start = start_time or (end - timedelta(hours=24))

    run = HuntingRun(
        query_id=query.id,
        executed_by=user_id,
        start_time=start,
        end_time=end,
        result_count=0,
        status="running",
        results=None,
    )

    db.add(run)
    db.flush()

    try:
        results = []

        # PHOENIX hunting deliberately operates against normalized
        # security telemetry rather than executing arbitrary shell
        # commands or external queries.
        if query.query_type in {
            "sql",
            "event_search",
            "network_search",
        }:
            sql = text(
                """
                SELECT
                    id,
                    event_uid,
                    event_time,
                    event_type,
                    category,
                    action,
                    severity,
                    source_ip,
                    destination_ip,
                    username,
                    process_name,
                    message
                FROM security_events
                WHERE event_time BETWEEN :start_time AND :end_time
                ORDER BY event_time DESC
                LIMIT 500
                """
            )

            rows = db.execute(
                sql,
                {
                    "start_time": start,
                    "end_time": end,
                },
            ).mappings().all()

            results = [dict(row) for row in rows]

        elif query.query_type == "endpoint_search":
            sql = text(
                """
                SELECT
                    id,
                    endpoint_id,
                    event_type,
                    process_name,
                    process_path,
                    command_line,
                    username,
                    parent_process,
                    hash_sha256,
                    severity,
                    event_time
                FROM endpoint_events
                WHERE event_time BETWEEN :start_time AND :end_time
                ORDER BY event_time DESC
                LIMIT 500
                """
            )

            rows = db.execute(
                sql,
                {
                    "start_time": start,
                    "end_time": end,
                },
            ).mappings().all()

            results = [dict(row) for row in rows]

        run.result_count = len(results)
        run.status = "completed"
        run.results = {
            "query_uid": query.query_uid,
            "window": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "parameters": parameters or {},
            "records": results,
        }

    except Exception as exc:
        run.status = "failed"
        run.results = {
            "error": str(exc),
        }

    db.commit()
    db.refresh(run)

    return run


def get_run(db: Session, run_id: int):
    run = db.get(HuntingRun, run_id)

    if not run:
        raise HuntingError("Hunting run not found")

    return run


def list_runs(
    db: Session,
    query_id: int | None = None,
    limit: int = 50,
):
    stmt = select(HuntingRun).order_by(
        HuntingRun.created_at.desc()
    ).limit(min(limit, 200))

    if query_id:
        stmt = stmt.where(HuntingRun.query_id == query_id)

    return list(db.scalars(stmt).all())
