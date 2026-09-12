from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class ZeroTrustPolicy(Base):
    __tablename__ = "zero_trust_policies"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    policy_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(Text)

    source_segment: Mapped[str | None] = mapped_column(
        String(100)
    )

    destination_segment: Mapped[str | None] = mapped_column(
        String(100)
    )

    action: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    required_role: Mapped[str | None] = mapped_column(
        String(100)
    )

    required_device_state: Mapped[str | None] = mapped_column(
        String(100)
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class ZeroTrustDecision(Base):
    __tablename__ = "zero_trust_decisions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    decision_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    policy_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "zero_trust_policies.id",
            ondelete="SET NULL",
        )
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        )
    )

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "assets.id",
            ondelete="SET NULL",
        )
    )

    source_segment: Mapped[str | None] = mapped_column(
        String(100)
    )

    destination_segment: Mapped[str | None] = mapped_column(
        String(100)
    )

    decision: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    reason: Mapped[str | None] = mapped_column(Text)

    evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )
