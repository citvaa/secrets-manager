"""Local CLI configuration and credential storage.

The access token is a bearer credential, so it is written to a file with
owner-only permissions (0600), satisfying requirement ZR-K3 and the code-review
lesson about protecting secrets at rest. On Windows, chmod is a no-op but the file
still lives under the user profile directory.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path.home() / ".oblak"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"


@dataclass
class CliConfig:
    server_url: str = "http://127.0.0.1:8000"
    username: str | None = None
    access_token: str | None = None
    expires_in: int | None = None
    _extra: dict = field(default_factory=dict)


def _ensure_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700
    except OSError:
        pass


def load() -> CliConfig:
    if not CREDENTIALS_FILE.exists():
        return CliConfig()
    try:
        data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return CliConfig()
    return CliConfig(
        server_url=data.get("server_url", "http://127.0.0.1:8000"),
        username=data.get("username"),
        access_token=data.get("access_token"),
        expires_in=data.get("expires_in"),
    )


def save(cfg: CliConfig) -> None:
    _ensure_dir()
    payload = {
        "server_url": cfg.server_url,
        "username": cfg.username,
        "access_token": cfg.access_token,
        "expires_in": cfg.expires_in,
    }
    # Write with restrictive permissions from the start.
    fd = os.open(CREDENTIALS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    try:
        os.chmod(CREDENTIALS_FILE, 0o600)
    except OSError:
        pass


def clear_token() -> None:
    cfg = load()
    cfg.username = None
    cfg.access_token = None
    cfg.expires_in = None
    save(cfg)
