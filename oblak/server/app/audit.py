"""Audit logging mechanism (requirements ZR-L1..L4).

Implements the auditing security pattern from the design-patterns lab:
- every actor-relevant event is recorded (non-repudiation),
- entries carry an accurate UTC timestamp,
- entries contain NO sensitive data (no passwords, tokens or code contents),
- written to an append-only file with restrictive permissions AND mirrored to the
  DB so events are easy to query/extract.

Log rotation / shipping to a central system (ELK) is an open item (OS-2); the file
format here is line-delimited JSON which ingests cleanly into such pipelines.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

from sqlalchemy.orm import Session

from .config import settings
from .models import AuditEvent

_SENSITIVE_KEYS = {"password", "token", "secret", "authorization", "code"}

_audit_logger: Optional[logging.Logger] = None


def _build_logger() -> logging.Logger:
    """Create a dedicated rotating-file logger for audit events."""
    logger = logging.getLogger("oblak.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_path = settings.audit_log_path
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=10)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    # Best-effort: restrict log file permissions (req. ZR-L4). No-op on Windows.
    try:
        os.chmod(log_path, 0o640)
    except OSError:
        pass

    return logger


def _get_logger() -> logging.Logger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = _build_logger()
    return _audit_logger


def _scrub(detail: dict) -> dict:
    """Drop any keys that could carry sensitive data (defense-in-depth, ZR-L3)."""
    return {k: v for k, v in detail.items() if k.lower() not in _SENSITIVE_KEYS}


def record(
    db: Session,
    *,
    action: str,
    outcome: str,
    actor: str = "-",
    resource: str = "-",
    request_id: str = "-",
    client_ip: str = "-",
    detail: Optional[dict] = None,
) -> None:
    """Record one audit event to both the append-only file and the DB.

    `outcome` should be "SUCCESS" or "FAILURE". `detail` is scrubbed of sensitive
    keys before being persisted.
    """
    ts = dt.datetime.now(dt.timezone.utc)
    safe_detail = _scrub(detail or {})

    entry = {
        "ts": ts.isoformat(),
        "actor": actor,
        "action": action,
        "resource": resource,
        "outcome": outcome,
        "request_id": request_id,
        "client_ip": client_ip,
        "detail": safe_detail,
    }

    # 1) Append-only structured log line (JSON) — survives DB loss.
    _get_logger().info(json.dumps(entry, ensure_ascii=False, sort_keys=True))

    # 2) Mirror into the DB for easy querying/extraction.
    event = AuditEvent(
        ts=ts,
        actor=actor,
        action=action,
        resource=resource,
        outcome=outcome,
        request_id=request_id,
        client_ip=client_ip,
        detail=json.dumps(safe_detail, ensure_ascii=False),
    )
    db.add(event)
    db.commit()
