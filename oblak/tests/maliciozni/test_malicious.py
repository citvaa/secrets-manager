"""Malicious payload tests — verify sandbox containment.

These tests bypass the verification pipeline intentionally: the pipeline would
statically reject these payloads, but these tests target the runtime sandbox layer
as a second line of defence.

Firecracker MicroVM provides:
  - CPU time limits (1 vCPU + wall-clock timeout + SIGKILL)
  - Memory limits (mem_size_mib=128, enforced by hypervisor)
  - Process count limits (jailer cgroup v2)
  - No network interface (OBLAK_VM_NETWORK_ENABLED=false)
  - No host filesystem mounted (read-only code drive only)
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from orchestrator import Orchestrator

MALICIOZNI_DIR = Path(__file__).parent


def _make_artifact(payload_dir: Path) -> str:
    tmp = tempfile.mkdtemp(prefix="oblak-maltest-")
    shutil.copytree(str(payload_dir), os.path.join(tmp, "code"))
    return tmp


def teardown_artifact(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="session")
def orchestrator():
    return Orchestrator()


class TestForkBomb:
    def test_contained_by_process_limits(self, orchestrator):
        """VM process limits (jailer cgroup v2 + 1 vCPU) prevent unbounded forking."""
        art = _make_artifact(MALICIOZNI_DIR / "fork_bomb")
        try:
            result = orchestrator.execute(art)
            assert result.return_code != 0, (
                f"Fork bomb should have failed; got rc={result.return_code}, "
                f"stderr={result.stderr!r}"
            )
        finally:
            teardown_artifact(art)


class TestNetworkExfiltration:
    def test_connection_blocked_in_microvm(self, orchestrator):
        """MicroVM has no NIC; socket.connect must fail."""
        art = _make_artifact(MALICIOZNI_DIR / "network_exfil")
        try:
            result = orchestrator.execute(art)
            assert result.return_code != 0, "Network exfil should fail with no NIC"
        finally:
            teardown_artifact(art)


class TestPathTraversal:
    def test_host_fs_inaccessible_in_microvm(self, orchestrator):
        """MicroVM has no host filesystem mounted; reads of host paths must fail."""
        art = _make_artifact(MALICIOZNI_DIR / "path_traversal")
        try:
            result = orchestrator.execute(art)
            if result.return_code == 0 and result.return_value:
                payload = json.loads(result.return_value)
                for path, content in payload.items():
                    assert "blocked" in str(content), (
                        f"Host file {path} was readable inside MicroVM: {content!r}"
                    )
        finally:
            teardown_artifact(art)


class TestResourceExhaustion:
    def test_killed_before_host_oom(self, orchestrator):
        """Hypervisor mem_size_mib=128 caps memory; VM must exit non-zero."""
        art = _make_artifact(MALICIOZNI_DIR / "resource_exhaustion")
        try:
            result = orchestrator.execute(art)
            assert result.return_code != 0, (
                f"Memory bomb should have failed; got rc={result.return_code}, "
                f"stderr={result.stderr!r}"
            )
        finally:
            teardown_artifact(art)


class TestCpuExhaustion:
    def test_killed_by_timeout(self, orchestrator):
        """Wall-clock timeout SIGKILL must terminate an infinite CPU loop."""
        art = _make_artifact(MALICIOZNI_DIR / "cpu_exhaustion")
        try:
            result = orchestrator.execute(art)
            assert result.return_code != 0, (
                f"CPU hog should have been killed; got rc={result.return_code}"
            )
        finally:
            teardown_artifact(art)
