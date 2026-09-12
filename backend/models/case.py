from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class SecurityCase(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    case_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(Text)

    status: Mapped[str] = mapped_column(
        String(30),
        default="open",
    )

    priority: Mapped[int] = mapped_column(
        Integer,
        default=50,
    )

    assigned_to: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )

    evidence_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    reference_type: Mapped[str | None] = mapped_column(
        String(100)
    )

    reference_id: Mapped[str | None] = mapped_column(
        String(100)
    )

    description: Mapped[str | None] = mapped_column(Text)

    added_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )
