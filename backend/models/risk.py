from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class RiskRegister(Base):
    __tablename__ = "risk_register"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    risk_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    likelihood: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    impact: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
    )

    owner: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    treatment: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="open",
    )

    due_date: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    metadata_json: Mapped[dict | None] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
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
