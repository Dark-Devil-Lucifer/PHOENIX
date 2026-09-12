from sqlalchemy import BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class AlertEvent(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    event_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("security_events.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
        index=True,
    )
