from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    incident_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
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

    status: Mapped[str | None] = mapped_column(
        String(30),
        default="open",
    )

    priority: Mapped[int | None] = mapped_column(
        Integer,
        default=50,
    )

    assigned_to: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    detected_at: Mapped[datetime | None] = mapped_column(DateTime)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)

    created_at: Mapped[datetime | None] = mapped_column(DateTime)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime)
