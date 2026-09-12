from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class BackupJob(Base):
    __tablename__ = "backup_jobs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    job_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    target_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    target_reference: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    schedule: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    backup_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="incremental",
    )

    retention_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=30,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="configured",
    )

    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    last_success_at: Mapped[datetime | None] = mapped_column(
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


class RecoveryTest(Base):
    __tablename__ = "recovery_tests"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    test_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    backup_job_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("backup_jobs.id"),
        nullable=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    recovery_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    target_reference: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="planned",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    rto_minutes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    rpo_minutes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    findings: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )
