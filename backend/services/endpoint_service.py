from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.endpoint import Endpoint, EndpointEvent


def create_endpoint(
    db: Session,
    *,
    endpoint_uid: str,
    asset_id: int,
    hostname: str,
    operating_system: str | None = None,
    agent_version: str | None = None,
    isolation_status: str = "connected",
    protection_status: str = "protected",
):
    existing = db.scalar(
        select(Endpoint).where(
            Endpoint.endpoint_uid == endpoint_uid
        )
    )

    if existing:
        return existing

    now = datetime.utcnow()

    endpoint = Endpoint(
        endpoint_uid=endpoint_uid,
        asset_id=asset_id,
        hostname=hostname,
        operating_system=operating_system,
        agent_version=agent_version,
        isolation_status=isolation_status,
        protection_status=protection_status,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )

    db.add(endpoint)
    db.flush()

    return endpoint


def get_endpoint(
    db: Session,
    endpoint_id: int,
):
    return db.get(Endpoint, endpoint_id)


def list_endpoints(db: Session):
    return list(
        db.scalars(
            select(Endpoint).order_by(
                Endpoint.last_seen_at.desc()
            )
        ).all()
    )


def record_endpoint_event(
    db: Session,
    *,
    endpoint_id: int,
    event_type: str,
    event_time: datetime,
    process_name: str | None = None,
    process_path: str | None = None,
    command_line: str | None = None,
    username: str | None = None,
    parent_process: str | None = None,
    hash_sha256: str | None = None,
    severity: str = "informational",
    metadata: dict | None = None,
):
    endpoint = db.get(Endpoint, endpoint_id)

    if not endpoint:
        raise ValueError("Endpoint not found")

    event = EndpointEvent(
        endpoint_id=endpoint_id,
        event_type=event_type,
        process_name=process_name,
        process_path=process_path,
        command_line=command_line,
        username=username,
        parent_process=parent_process,
        hash_sha256=hash_sha256,
        severity=severity,
        event_time=event_time,
        event_metadata=metadata,
    )

    endpoint.last_seen_at = datetime.utcnow()

    db.add(event)
    db.flush()

    return event


def list_endpoint_events(
    db: Session,
    endpoint_id: int,
):
    return list(
        db.scalars(
            select(EndpointEvent)
            .where(
                EndpointEvent.endpoint_id == endpoint_id
            )
            .order_by(
                EndpointEvent.event_time.desc()
            )
        ).all()
    )


def isolate_endpoint(
    db: Session,
    *,
    endpoint_id: int,
    reason: str,
):
    endpoint = db.get(Endpoint, endpoint_id)

    if not endpoint:
        raise ValueError("Endpoint not found")

    # Controlled PHOENIX containment state.
    # No external network-control command is executed.
    endpoint.isolation_status = "isolated"
    endpoint.updated_at = datetime.utcnow()

    return endpoint


def release_endpoint(
    db: Session,
    *,
    endpoint_id: int,
):
    endpoint = db.get(Endpoint, endpoint_id)

    if not endpoint:
        raise ValueError("Endpoint not found")

    endpoint.isolation_status = "connected"
    endpoint.updated_at = datetime.utcnow()

    return endpoint
