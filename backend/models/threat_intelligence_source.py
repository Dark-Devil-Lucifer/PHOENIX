from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ThreatIntelligenceSource(Base):
    __tablename__ = "threat_intelligence_sources"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    source_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    reliability: Mapped[str | None] = mapped_column(
        String(20),
        default="unknown",
    )

    confidence: Mapped[int | None] = mapped_column(
        Integer,
        default=50,
    )

    feed_url: Mapped[str | None] = mapped_column(
        String(500),
    )

    enabled: Mapped[bool | None] = mapped_column(
        Boolean,
        default=True,
    )

    last_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )
