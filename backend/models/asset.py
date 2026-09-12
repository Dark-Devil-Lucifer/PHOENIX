from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    asset_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    asset_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    ip_address: Mapped[str | None] = mapped_column(String(45))
    operating_system: Mapped[str | None] = mapped_column(String(255))

    environment: Mapped[str] = mapped_column(
        String(50),
        default="production",
    )

    criticality: Mapped[str] = mapped_column(
        String(20),
        default="medium",
    )

    owner: Mapped[str | None] = mapped_column(String(255))
    location: Mapped[str | None] = mapped_column(String(255))

    status: Mapped[str] = mapped_column(
        String(30),
        default="active",
    )

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
