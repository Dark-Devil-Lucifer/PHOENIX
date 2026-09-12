from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_type: Mapped[str | None] = mapped_column(
        String(100),
    )

    resource_id: Mapped[str | None] = mapped_column(
        String(100),
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
    )

    event_metadata: Mapped[dict | None] = mapped_column(
        "metadata",
        JSON,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
