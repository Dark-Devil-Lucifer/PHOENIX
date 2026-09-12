from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    control_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    framework: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    control_id: Mapped[str] = mapped_column(
        String(100),
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

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="not_assessed",
    )

    owner: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    evidence: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    assessment_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    assessed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
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
