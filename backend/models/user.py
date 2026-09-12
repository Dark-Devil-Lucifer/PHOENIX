from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.core.database import Base
from backend.models.associations import user_roles


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    email: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    roles = relationship(
        "Role",
        secondary=user_roles,
        back_populates="users",
    )
