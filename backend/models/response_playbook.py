from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, JSON, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ResponsePlaybook(Base):
    __tablename__ = "response_playbooks"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )

    playbook_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    trigger_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    requires_approval: Mapped[bool] = mapped_column(
        Boolean,
        nullable=True,
        server_default=text("1"),
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=True,
        server_default=text("1"),
    )

    definition: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP"),
    )
