from datetime import datetime

from sqlalchemy.orm import Session

from backend.models.audit_log import AuditLog


def write_audit_log(
    db: Session,
    *,
    action: str,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    description: str | None = None,
    source_ip: str | None = None,
    metadata: dict | None = None,
) -> AuditLog:
    """
    Create a centralized PHOENIX audit record.

    Security-sensitive actions should use this service so
    authentication, response actions, and administrative
    operations have a consistent audit trail.
    """

    audit = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        source_ip=source_ip,
        event_metadata=metadata,
        created_at=datetime.utcnow(),
    )

    db.add(audit)
    db.flush()

    return audit
