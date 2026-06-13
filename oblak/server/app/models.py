"""ORM models — the shared data model other team members build on.

Member 1 owns `User`, `Function` and `AuditEvent`. Members 2 and 3 extend the
`Function` lifecycle (verification result, artifact location, invoke URL) without
breaking this contract.
"""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _utcnow() -> dt.datetime:
    """Timezone-aware UTC timestamp (req. ZR-L2: accurate event time)."""
    return dt.datetime.now(dt.timezone.utc)


class FunctionStatus(str, enum.Enum):
    """Lifecycle of an uploaded function."""

    UPLOADED = "UPLOADED"      # Member 1: code received and stored
    VERIFYING = "VERIFYING"    # Member 2: under analysis
    REJECTED = "REJECTED"      # Member 2: failed verification
    PREPARING = "PREPARING"    # Member 2: pulling dependencies
    READY = "READY"            # Member 2: invoke URL created
    FAILED = "FAILED"          # generic failure


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    # Argon2 hash only — never the plaintext password (req. ZR-A2).
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    functions: Mapped[list["Function"]] = relationship(back_populates="owner")


class Function(Base):
    __tablename__ = "functions"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_owner_function_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    # SHA-256 of the uploaded package (integrity + non-repudiation, req. ZR-L2/T5).
    code_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[FunctionStatus] = mapped_column(
        Enum(FunctionStatus), default=FunctionStatus.UPLOADED, nullable=False
    )
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    owner: Mapped["User"] = relationship(back_populates="functions")


class AuditEvent(Base):
    """Tamper-evident-ish audit trail in the DB (mirrors the append-only log file).

    Holds NO sensitive data (req. ZR-L3): no passwords, tokens or code contents.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), default="-", nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), default="-", nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)  # SUCCESS / FAILURE
    request_id: Mapped[str] = mapped_column(String(36), default="-", nullable=False)
    client_ip: Mapped[str] = mapped_column(String(64), default="-", nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
