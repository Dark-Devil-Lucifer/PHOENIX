from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.database import get_db
from backend.models.user import User


bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=["HS256"],
        )

        user_id = payload.get("sub")

        if not user_id:
            raise ValueError("Missing subject")

        user = db.scalar(
            select(User).where(
                User.id == int(user_id)
            )
        )

    except (JWTError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive or does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(*allowed_roles: str):
    def dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:

        user_roles = {
            role.name
            for role in current_user.roles
        }

        if not user_roles.intersection(
            set(allowed_roles)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges",
            )

        return current_user

    return dependency
