from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    indicator_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    indicator_value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    normalized_value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    source_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "threat_intelligence_sources.id",
            ondelete="SET NULL",
        ),
    )

    threat_type: Mapped[str | None] = mapped_column(
        String(100),
    )

    malware_family: Mapped[str | None] = mapped_column(
        String(255),
    )

    confidence: Mapped[int | None] = mapped_column(
        Integer,
        default=50,
    )

    severity: Mapped[str | None] = mapped_column(
        String(20),
        default="medium",
    )

    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    status: Mapped[str | None] = mapped_column(
        String(30),
        default="active",
    )

    indicator_metadata: Mapped[dict | None] = mapped_column(
        "metadata",
        JSON,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )
