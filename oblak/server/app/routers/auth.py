"""Authentication endpoints: register and login (CLI -> server, threats T1/T2/T8)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..config import settings
from ..database import get_db
from ..deps import get_client_ip, get_request_id
from ..models import User
from ..rate_limit import login_limiter
from ..schemas import LoginRequest, RegisterRequest, TokenResponse
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    body: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """Create a new user. Password is stored only as an Argon2 hash (ZR-A2)."""
    rid = get_request_id(request)
    ip = get_client_ip(request)

    user = User(username=body.username, password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Do not reveal whether the username exists beyond what is necessary.
        audit.record(
            db, action="register", outcome="FAILURE", actor=body.username,
            resource="user", request_id=rid, client_ip=ip,
            detail={"reason": "username_taken"},
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username unavailable")

    audit.record(
        db, action="register", outcome="SUCCESS", actor=body.username,
        resource="user", request_id=rid, client_ip=ip,
    )
    return {"message": "registered", "username": body.username}


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate and issue a short-lived JWT (ZR-A3); rate-limited (ZR-A5)."""
    rid = get_request_id(request)
    ip = get_client_ip(request)
    # Rate-limit key combines IP and username to slow brute force / stuffing.
    rl_key = f"{ip}:{body.username}"

    if login_limiter.is_blocked(rl_key):
        audit.record(
            db, action="login", outcome="FAILURE", actor=body.username,
            resource="session", request_id=rid, client_ip=ip,
            detail={"reason": "rate_limited"},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts, try again later",
        )

    user = db.query(User).filter(User.username == body.username).first()
    # Same generic error whether the user is missing or the password is wrong
    # (avoids user enumeration). verify_password is still called to reduce timing
    # signal would require a dummy hash; kept simple here.
    if user is None or not verify_password(body.password, user.password_hash):
        login_limiter.register_failure(rl_key)
        audit.record(
            db, action="login", outcome="FAILURE", actor=body.username,
            resource="session", request_id=rid, client_ip=ip,
            detail={"reason": "bad_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    login_limiter.reset(rl_key)
    token = create_access_token(user.username, is_admin=user.is_admin)
    audit.record(
        db, action="login", outcome="SUCCESS", actor=user.username,
        resource="session", request_id=rid, client_ip=ip,
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )
