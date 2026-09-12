from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    alert_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    detection_rule_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("detection_rules.id", ondelete="SET NULL"),
    )

    asset_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("assets.id", ondelete="SET NULL"),
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(Text)

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        default=50,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="new",
    )

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
