from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from backend.core.config import settings


password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:
    try:
        return password_hasher.verify(
            password_hash,
            plain_password,
        )
    except VerifyMismatchError:
        return False


def create_access_token(
    user_id: int,
    username: str,
    roles: list[str],
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "username": username,
        "roles": roles,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm="HS256",
    )


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=["HS256"],
        )
    except JWTError as exc:
        raise ValueError(
            "Invalid or expired access token"
        ) from exc
