"""Artifact preparation — Member 2.

Responsibilities:
- create an isolated virtual environment inside the artifact directory,
- install dependencies from requirements.txt,
- validate that requirements.txt does not reference suspicious packages
  (supply-chain threat, ZR-SC1).

Security design decisions
--------------------------
- --no-cache-dir prevents cross-function cache poisoning.
- --index-url https://pypi.org/simple is always passed explicitly,
  blocking accidental use of a poisoned mirror.
- Local paths (./), VCS URLs (git+) and index overrides are rejected.
- Total installation is time-limited to prevent DoS via hung installs.

Open items
----------
OS-SC-1: Hash pinning (--require-hashes) — worth enforcing in production;
         here we log a warning when hashes are absent and continue.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_PREP_TIMEOUT = int(os.getenv("OBLAK_PREP_TIMEOUT_SECONDS", "120"))

# Patterns that are not allowed in requirements.txt lines.
_BLOCKED_REQ_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*-e\s+", re.IGNORECASE),          # editable installs
    re.compile(r"git\+", re.IGNORECASE),               # VCS URLs
    re.compile(r"hg\+|svn\+|bzr\+", re.IGNORECASE),
    re.compile(r"file://", re.IGNORECASE),             # local path references
    re.compile(r"^\s*\./", re.IGNORECASE),
    re.compile(r"^\s*\.\./", re.IGNORECASE),
    re.compile(r"--index-url", re.IGNORECASE),         # index overrides
    re.compile(r"--extra-index-url", re.IGNORECASE),
    re.compile(r"--find-links", re.IGNORECASE),
]


class PreparationError(Exception):
    """Raised when artifact preparation fails. Safe to log."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_requirements(req_path: str) -> list[str]:
    """Parse and validate requirements.txt; return a list of safe lines.

    Raises PreparationError on any forbidden specifier.
    """
    lines: list[str] = []
    with open(req_path, encoding="utf-8") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            for pattern in _BLOCKED_REQ_PATTERNS:
                if pattern.search(line):
                    raise PreparationError(
                        f"requirements.txt line {lineno}: forbidden specifier "
                        f"({line[:80]!r}) — only plain PyPI packages are allowed."
                    )
            if "==" not in line and not line.startswith("--"):
                logger.warning(
                    "requirements.txt line %d has no pinned version: %r "
                    "(OS-SC-1: add ==version for reproducibility)",
                    lineno, line,
                )
            lines.append(line)
    return lines


def _run(cmd: list[str], timeout: int = _PREP_TIMEOUT, **kwargs) -> None:
    """Run a subprocess; raise PreparationError on failure or timeout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, **kwargs
        )
    except subprocess.TimeoutExpired:
        raise PreparationError(f"command timed out after {timeout}s: {cmd}")
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "")[:500]
        raise PreparationError(f"command failed ({result.returncode}): {msg}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def prepare_artifact(src_dir: str, artifact_dir: str) -> str:
    """Create a ready-to-execute artifact from the extracted source.

    Steps:
    1. Copy source files into artifact_dir/code.
    2. If requirements.txt is present, validate and install deps into
       artifact_dir/venv.

    Returns the path to the artifact directory.
    Raises PreparationError on any problem.
    """
    src_path = Path(src_dir)
    art_path = Path(artifact_dir)

    # 1 — copy source into artifact/code (clean slate on re-deploy)
    code_dir = art_path / "code"
    if code_dir.exists():
        shutil.rmtree(code_dir)
    shutil.copytree(src_path, code_dir)
    logger.info("Copied source to %s", code_dir)

    # 2 — handle requirements.txt
    req_file = code_dir / "requirements.txt"
    if not req_file.exists():
        logger.info("No requirements.txt — skipping dependency installation.")
        return artifact_dir

    valid_lines = _validate_requirements(str(req_file))
    if not valid_lines:
        logger.info("requirements.txt is empty — no packages to install.")
        return artifact_dir

    venv_dir = art_path / "venv"
    if venv_dir.exists():
        shutil.rmtree(venv_dir)

    # Create venv using the same Python that runs the server.
    logger.info("Creating venv at %s ...", venv_dir)
    _run([sys.executable, "-m", "venv", str(venv_dir)])

    # Determine pip path inside the venv.
    if os.name == "nt":
        pip_path = venv_dir / "Scripts" / "pip.exe"
    else:
        pip_path = venv_dir / "bin" / "pip"

    # Upgrade pip inside the venv first.
    logger.info("Upgrading pip ...")
    _run([str(pip_path), "install", "--quiet", "--upgrade", "pip"])

    # Install user dependencies.
    logger.info("Installing %d package(s) ...", len(valid_lines))
    _run([
        str(pip_path), "install",
        "--quiet",
        "--no-cache-dir",
        "--index-url", "https://pypi.org/simple",
        *valid_lines,
    ])

    logger.info("Artifact prepared at %s", artifact_dir)
    return artifact_dir