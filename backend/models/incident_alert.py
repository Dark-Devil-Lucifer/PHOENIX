from sqlalchemy import BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    alert_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
        index=True,
    )
