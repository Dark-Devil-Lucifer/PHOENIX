from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class IndicatorMatch(Base):
    __tablename__ = "indicator_matches"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    indicator_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            "threat_indicators.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    event_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "security_events.id",
            ondelete="CASCADE",
        ),
    )

    alert_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey(
            "alerts.id",
            ondelete="CASCADE",
        ),
    )

    matched_value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    match_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    confidence: Mapped[int | None] = mapped_column(
        Integer,
        default=50,
    )

    matched_at: Mapped[datetime | None] = mapped_column(
        DateTime,
    )

    match_metadata: Mapped[dict | None] = mapped_column(
        "metadata",
        JSON,
    )
