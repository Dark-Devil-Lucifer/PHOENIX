from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    account_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    account_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    account_identifier: Mapped[str | None] = mapped_column(
        String(255)
    )

    environment: Mapped[str] = mapped_column(
        String(50),
        default="production",
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="active",
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class CloudAsset(Base):
    __tablename__ = "cloud_assets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    cloud_asset_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    cloud_account_id: Mapped[int] = mapped_column(
        ForeignKey(
            "cloud_accounts.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_name: Mapped[str | None] = mapped_column(
        String(255)
    )

    region: Mapped[str | None] = mapped_column(
        String(100)
    )

    criticality: Mapped[str] = mapped_column(
        String(20),
        default="medium",
    )

    configuration: Mapped[dict[str, Any] | None] = mapped_column(
        JSON
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="active",
    )

    created_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )


class CloudSecurityFinding(Base):
    __tablename__ = "cloud_security_findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    finding_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    cloud_asset_id: Mapped[int] = mapped_column(
        ForeignKey(
            "cloud_assets.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    control_id: Mapped[str | None] = mapped_column(
        String(100)
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="open",
    )

    remediation: Mapped[str | None] = mapped_column(
        Text
    )

    detected_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime
    )
