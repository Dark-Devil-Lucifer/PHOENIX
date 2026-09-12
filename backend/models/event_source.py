from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class EventSource(Base):
    __tablename__ = "event_sources"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )

    source_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))

    status: Mapped[str] = mapped_column(
        String(30),
        default="active",
    )

    last_event_at: Mapped[datetime | None] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
