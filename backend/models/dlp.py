from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class SensitiveResource(Base):
    __tablename__ = "sensitive_resources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    resource_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    location: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    classification: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="confidential",
    )

    owner: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class DLPEvent(Base):
    __tablename__ = "dlp_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    resource_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("sensitive_resources.id"),
        nullable=True,
    )

    event_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    destination: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    data_classification: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    bytes_transferred: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    policy_result: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="allowed",
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
    )

    event_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    event_metadata: Mapped[dict | None] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )
