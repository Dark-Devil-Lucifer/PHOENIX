from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.core.database import Base
from backend.models.associations import user_roles


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
    )

    users = relationship(
        "User",
        secondary=user_roles,
        back_populates="roles",
    )
