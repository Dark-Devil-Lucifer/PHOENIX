from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, JSON, String, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ResponseExecution(Base):
    __tablename__ = "response_executions"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )

    playbook_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("response_playbooks.id"),
        nullable=False,
    )

    incident_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
    )

    execution_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    status: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        server_default=text("'pending'"),
    )

    requested_by: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    approved_by: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    result: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP"),
    )
