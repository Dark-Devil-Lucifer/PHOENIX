import json
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    actor_type: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    actor_id: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
    )

    occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    # Database column is named `metadata`.
    # Python attribute cannot be named `metadata` because
    # SQLAlchemy reserves that name on Declarative models.
    event_metadata: Mapped[str | None] = mapped_column(
        "metadata",
        Text,
        nullable=True,
    )

    def set_metadata(self, value):
        if value is None:
            self.event_metadata = None
        elif isinstance(value, str):
            self.event_metadata = value
        else:
            self.event_metadata = json.dumps(value, default=str)

    def get_metadata(self):
        if not self.event_metadata:
            return None

        try:
            return json.loads(self.event_metadata)
        except (TypeError, ValueError):
            return self.event_metadata
