from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.auth import get_current_user
from backend.core.database import get_db
from backend.core.security import create_access_token, verify_password
from backend.models.user import User
from backend.schemas.auth import LoginRequest, LoginResponse, UserResponse
from backend.services.audit_service import write_audit_log


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"],
)


@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    http_request: Request,
    db: Session = Depends(get_db),
):
    source_ip = (
        http_request.client.host
        if http_request.client
        else None
    )

    user = db.scalar(
        select(User).where(
            User.username == request.username
        )
    )

    # Do not reveal whether the username exists.
    if not user or not user.is_active:
        write_audit_log(
            db,
            action="login_failed",
            resource_type="user",
            resource_id=request.username,
            description="Authentication failed",
            source_ip=source_ip,
            metadata={
                "reason": "invalid_credentials_or_inactive_user",
            },
        )
        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    if not verify_password(
        request.password,
        user.password_hash,
    ):
        write_audit_log(
            db,
            action="login_failed",
            resource_type="user",
            resource_id=str(user.id),
            description="Authentication failed",
            source_ip=source_ip,
            metadata={
                "username": user.username,
                "reason": "invalid_password",
            },
        )
        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    roles = [
        role.name
        for role in user.roles
    ]

    user.last_login_at = datetime.utcnow()

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        roles=roles,
    )

    write_audit_log(
        db,
        action="login_success",
        user_id=user.id,
        resource_type="user",
        resource_id=str(user.id),
        description="User authenticated successfully",
        source_ip=source_ip,
        metadata={
            "username": user.username,
            "roles": roles,
        },
    )

    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": roles,
            "is_active": user.is_active,
        },
    }


@router.get("/me", response_model=UserResponse)
def current_user(
    user: User = Depends(get_current_user),
):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": [
            role.name
            for role in user.roles
        ],
        "is_active": user.is_active,
    }
