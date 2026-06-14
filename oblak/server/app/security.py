"""Password hashing and JWT issuing/verification.

Design decisions map directly to security requirements:
- Argon2id for password hashing (ZR-A2): modern, salted, memory-hard.
- JWT signed with HMAC-SHA256 (ZR-A3/ZR-A4): a *keyed* MAC, not a bare hash, and
  verification rejects missing/invalid signatures (avoids the signature-bypass bug
  seen in the code-review lab).
"""

from __future__ import annotations

import datetime as dt

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from .config import settings

# Argon2 with library defaults (sane, memory-hard parameters).
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Return an Argon2id hash (includes a random salt) for the given password."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification; returns False on any mismatch/parse error."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if the stored hash should be upgraded to current parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def create_access_token(subject: str, *, is_admin: bool = False) -> str:
    """Issue a short-lived JWT access token for `subject` (the username)."""
    now = dt.datetime.now(dt.timezone.utc)
    expire = now + dt.timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": subject,
        "adm": is_admin,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and verify a JWT.

    Raises `jwt.InvalidTokenError` (or subclass) on any problem, including a
    missing/invalid signature or an expired token. Callers must treat any
    exception as authentication failure (fail-closed).
    """
    # `algorithms` is pinned so an attacker cannot downgrade to "none" (alg confusion).
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "sub"]},
    )
