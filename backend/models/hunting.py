from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class HuntingQuery(Base):
    __tablename__ = "hunting_queries"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    query_uid: Mapped[str] = mapped_column(
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

    query_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="sql",
    )

    query_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
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


class HuntingRun(Base):
    __tablename__ = "hunting_runs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    query_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hunting_queries.id"),
        nullable=False,
    )

    executed_by: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )

    start_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    end_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    result_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
    )

    results: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )
