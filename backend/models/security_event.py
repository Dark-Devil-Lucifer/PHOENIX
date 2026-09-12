from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    event_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    source_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("event_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    asset_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    event_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    category: Mapped[str | None] = mapped_column(
        String(100)
    )

    action: Mapped[str | None] = mapped_column(
        String(100)
    )

    severity: Mapped[str | None] = mapped_column(
        String(20),
        default="informational",
        index=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45)
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        index=True,
    )

    process_name: Mapped[str | None] = mapped_column(
        String(255)
    )

    message: Mapped[str | None] = mapped_column(
        Text
    )

    raw_event: Mapped[dict | None] = mapped_column(
        JSON
    )

    normalized_data: Mapped[dict | None] = mapped_column(
        JSON
    )

    ingestion_time: Mapped[datetime | None] = mapped_column(
        DateTime
    )
