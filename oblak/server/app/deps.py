"""Shared FastAPI dependencies: authentication and request context."""

from __future__ import annotations

import uuid

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .security import decode_access_token


def get_request_id(request: Request) -> str:
    """Stable per-request id used to correlate audit entries (ZR-L2)."""
    rid = request.headers.get("X-Request-ID")
    return rid if rid else str(uuid.uuid4())


def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


def get_current_user(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the authenticated user from a Bearer token (fail-closed).

    Any problem — missing header, wrong scheme, bad/expired/forged token, unknown
    user — results in HTTP 401. This directly enforces ZR-A1 and defends T2/T9.
    """
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise credentials_error

    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError:
        # Covers expired, bad signature, missing claims, alg confusion, etc.
        raise credentials_error

    username = payload.get("sub")
    if not username:
        raise credentials_error

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_error
    return user
