"""Benign integration tests — verify that normal functions execute correctly."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from orchestrator import Orchestrator

_SERVER_DIR = str(Path(__file__).parent.parent.parent / "server")
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

BENIGNI_DIR = Path(__file__).parent


def _make_artifact(src_dir: Path) -> str:
    """Copy a function directory into a minimal artifact layout."""
    tmp = tempfile.mkdtemp(prefix="oblak-test-")
    code_dst = os.path.join(tmp, "code")
    shutil.copytree(str(src_dir), code_dst)
    return tmp


@pytest.fixture(scope="session")
def orchestrator():
    return Orchestrator()


def teardown_artifact(artifact_path: str):
    shutil.rmtree(artifact_path, ignore_errors=True)


class TestHelloFunction:
    def test_returns_greeting(self, orchestrator):
        art = _make_artifact(BENIGNI_DIR / "hello")
        try:
            result = orchestrator.execute(art, event={"name": "Oblak"})
            assert result.return_code == 0
            assert result.execution_mode == "microvm"
            payload = json.loads(result.return_value)
            assert payload["message"] == "Zdravo, Oblak!"
        finally:
            teardown_artifact(art)

    def test_default_event(self, orchestrator):
        art = _make_artifact(BENIGNI_DIR / "hello")
        try:
            result = orchestrator.execute(art, event={})
            assert result.return_code == 0
            payload = json.loads(result.return_value)
            assert "message" in payload
        finally:
            teardown_artifact(art)


class TestMathOps:
    def test_sum_and_product(self, orchestrator):
        art = _make_artifact(BENIGNI_DIR / "math_ops")
        try:
            result = orchestrator.execute(art, event={"a": 3, "b": 4})
            assert result.return_code == 0
            payload = json.loads(result.return_value)
            assert payload["sum"] == 7
            assert payload["product"] == 12
        finally:
            teardown_artifact(art)


class TestWithDeps:
    def test_pip_dependency_available_in_vm(self, orchestrator):
        """Package installed from requirements.txt must be importable inside the MicroVM."""
        from app.preparation import prepare_artifact

        src_dir = str(BENIGNI_DIR / "with_deps")
        tmp = tempfile.mkdtemp(prefix="oblak-test-deps-")
        try:
            prepare_artifact(src_dir, tmp)
            result = orchestrator.execute(tmp, event={"n": 42000})
            assert result.return_code == 0, f"stderr: {result.stderr}"
            payload = json.loads(result.return_value)
            assert payload["formatted"] == "42,000"
        finally:
            teardown_artifact(tmp)
