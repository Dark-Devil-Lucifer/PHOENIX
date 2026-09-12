from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    endpoint_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(255)
    )

    agent_version: Mapped[str | None] = mapped_column(
        String(100)
    )

    isolation_status: Mapped[str] = mapped_column(
        String(30),
        default="connected",
    )

    protection_status: Mapped[str] = mapped_column(
        String(30),
        default="protected",
    )

    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class EndpointEvent(Base):
    __tablename__ = "endpoint_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    process_name: Mapped[str | None] = mapped_column(
        String(255)
    )

    process_path: Mapped[str | None] = mapped_column(
        String(1024)
    )

    command_line: Mapped[str | None] = mapped_column(
        Text
    )

    username: Mapped[str | None] = mapped_column(
        String(255)
    )

    parent_process: Mapped[str | None] = mapped_column(
        String(255)
    )

    hash_sha256: Mapped[str | None] = mapped_column(
        String(64)
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="informational",
    )

    event_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",
        JSON,
    )
