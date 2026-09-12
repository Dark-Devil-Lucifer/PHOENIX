from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ForensicArtifact(Base):
    __tablename__ = "forensic_artifacts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    artifact_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )

    artifact_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    source: Mapped[str | None] = mapped_column(
        String(255)
    )

    hash_sha256: Mapped[str | None] = mapped_column(
        String(64)
    )

    collected_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    collected_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    evidence: Mapped[dict[str, Any] | None] = mapped_column(
        JSON
    )
