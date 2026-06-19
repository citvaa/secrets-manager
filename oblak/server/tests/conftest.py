"""Pytest fixtures. Configures an isolated temp DB/storage before importing the app.

Environment variables must be set BEFORE `app.config` is imported, because settings
are read at import time.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Make the top-level orchestrator/ package importable when running from server/.
_PROJECT_ROOT = str(Path(__file__).parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# --- Configure an isolated environment for the whole test session ---
_TMP = tempfile.mkdtemp(prefix="oblak_test_")
os.environ["OBLAK_JWT_SECRET"] = "test-secret-do-not-use-in-prod-0123456789"
os.environ["OBLAK_DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP, 'test.db')}"
os.environ["OBLAK_STORAGE_DIR"] = os.path.join(_TMP, "storage")
os.environ["OBLAK_AUDIT_LOG_PATH"] = os.path.join(_TMP, "logs", "audit.log")
os.environ["OBLAK_LOGIN_MAX_ATTEMPTS"] = "5"
os.environ["OBLAK_LOGIN_WINDOW_SECONDS"] = "300"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _db():
    init_db()
    yield


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)
