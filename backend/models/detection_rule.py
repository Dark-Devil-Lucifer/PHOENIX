from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    rule_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    rule_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    confidence: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        default=50,
    )

    # Database stores this as LONGTEXT with JSON validation.
    query: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    recommended_response: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=True,
        default=True,
    )

    mitre_tactic: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # Database stores this as LONGTEXT with JSON validation.
    rule_definition: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
