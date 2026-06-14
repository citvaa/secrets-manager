"""Code Verifier — Member 2.

Pipeline (in order):
  1. ClamAV antivirus scan of the raw ZIP (ZR-V4).
  2. Bandit static analysis of every .py file in the extracted source (ZR-V5).
  3. Dangerous-pattern scan: explicit block-list of calls that should never
     appear in user code (eval, exec, os.system, subprocess, socket ...) (ZR-V5).
  4. LLM analysis via the Anthropic API: behavioural summary + suspicion rating
     (ZR-V6). Requires OBLAK_ANTHROPIC_API_KEY in the environment.

Each stage records an audit event. The first failing stage raises
VerificationFailed with a human-readable reason (never containing raw code).

ClamAV installation (Ubuntu/Debian):
    sudo apt-get install clamav clamav-daemon
    sudo systemctl start clamav-daemon

Default socket: /var/run/clamav/clamd.ctl
Override with OBLAK_CLAMD_SOCKET environment variable.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from . import audit

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ANTHROPIC_API_KEY = os.getenv("OBLAK_ANTHROPIC_API_KEY", "")
_CLAMD_SOCKET = os.getenv("OBLAK_CLAMD_SOCKET", "/var/run/clamav/clamd.ctl")

# Calls that are unconditionally forbidden in user-submitted code.
_FORBIDDEN_CALLS: set[str] = {
    "eval", "exec", "compile",
    "os.system", "os.popen", "os.execve", "os.execvp",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "__import__",
    "open",
    "socket.socket",
}

# Modules whose mere import is suspicious in serverless user code.
_FORBIDDEN_IMPORTS: set[str] = {
    "subprocess", "socket", "pty", "ctypes", "cffi",
    "importlib", "pickle", "shelve", "marshal",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    passed: bool
    reason: str
    llm_summary: str = ""
    llm_suspicion: str = "UNKNOWN"
    bandit_issues: list[dict] = field(default_factory=list)


class VerificationFailed(Exception):
    """Raised when code does not pass verification. Message is safe to log."""


# ---------------------------------------------------------------------------
# Stage 1 — ClamAV
# ---------------------------------------------------------------------------

def _scan_clamav(zip_path: str) -> None:
    """Run clamdscan on zip_path. Raises VerificationFailed on a hit.

    Falls back gracefully if the daemon socket is absent (open item OS-AV-1).
    """
    if not os.path.exists(_CLAMD_SOCKET):
        logger.warning(
            "ClamAV daemon socket not found at %s — skipping AV scan (OS-AV-1).",
            _CLAMD_SOCKET,
        )
        return

    try:
        result = subprocess.run(
            ["clamdscan", "--no-summary", "--fdpass", zip_path],
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        logger.warning("clamdscan binary not found — skipping AV scan (OS-AV-1).")
        return
    except subprocess.TimeoutExpired:
        raise VerificationFailed("AV scan timed out")

    # clamdscan exit codes: 0 = clean, 1 = virus found, 2 = error
    if result.returncode == 1:
        raise VerificationFailed("antivirus: malware detected in package")
    if result.returncode == 2:
        logger.warning("clamdscan returned an error: %s", result.stderr.strip())


# ---------------------------------------------------------------------------
# Stage 2 — Bandit static analysis
# ---------------------------------------------------------------------------

def _run_bandit(src_dir: str) -> list[dict]:
    """Run Bandit on src_dir and return a list of issue dicts.

    Raises VerificationFailed if Bandit finds HIGH-severity issues.
    """
    try:
        result = subprocess.run(
            ["bandit", "-r", src_dir, "-f", "json", "--severity-level", "low", "-q"],
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        logger.warning("bandit not found — skipping static analysis.")
        return []
    except subprocess.TimeoutExpired:
        raise VerificationFailed("static analysis timed out")

    issues: list[dict] = []
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            issues = data.get("results", [])
        except json.JSONDecodeError:
            logger.warning("bandit produced non-JSON output; ignoring.")

    high_issues = [i for i in issues if i.get("issue_severity", "").upper() == "HIGH"]
    if high_issues:
        count = len(high_issues)
        raise VerificationFailed(
            f"static analysis: {count} HIGH-severity issue(s) found "
            f"(e.g. {high_issues[0].get('issue_text', '')[:80]})"
        )

    return issues


# ---------------------------------------------------------------------------
# Stage 3 — Dangerous-pattern AST scan
# ---------------------------------------------------------------------------

def _check_forbidden_patterns(src_dir: str) -> None:
    """Walk every .py file and reject any that use forbidden calls/imports.

    Uses the AST so comments and strings do not trigger false positives.
    Raises VerificationFailed on the first match.
    """
    for py_file in Path(src_dir).rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as exc:
            raise VerificationFailed(
                f"syntax error in {py_file.name}: {exc}"
            ) from exc

        for node in ast.walk(tree):
            # import X / import X as Y
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in _FORBIDDEN_IMPORTS:
                        raise VerificationFailed(
                            f"forbidden import '{alias.name}' in {py_file.name}"
                        )

            # from X import Y
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                if mod in _FORBIDDEN_IMPORTS:
                    raise VerificationFailed(
                        f"forbidden import from '{node.module}' in {py_file.name}"
                    )

            # Direct calls: eval(...), exec(...), os.system(...) itd.
            elif isinstance(node, ast.Call):
                func = node.func
                name: Optional[str] = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    parts: list[str] = [func.attr]
                    val = func.value
                    while isinstance(val, ast.Attribute):
                        parts.insert(0, val.attr)
                        val = val.value
                    if isinstance(val, ast.Name):
                        parts.insert(0, val.id)
                    name = ".".join(parts)

                if name in _FORBIDDEN_CALLS:
                    raise VerificationFailed(
                        f"forbidden call '{name}' in {py_file.name}"
                    )


# ---------------------------------------------------------------------------
# Stage 4 — LLM analysis (Anthropic Claude)
# ---------------------------------------------------------------------------

_LLM_SYSTEM = (
    "You are a security-focused code reviewer for a serverless platform. "
    "You will receive Python source files uploaded by untrusted users. "
    "Your task:\n"
    "1. Summarise what the code does in 2-3 sentences (SUMMARY).\n"
    "2. Rate the suspicion level as LOW, MEDIUM, or HIGH (SUSPICION).\n"
    "3. If MEDIUM or HIGH, list the specific concerns (CONCERNS).\n\n"
    "Reply ONLY with a JSON object with keys: summary, suspicion, concerns "
    "(list of strings). No markdown, no extra text."
)


def _collect_source_text(src_dir: str, max_chars: int = 12_000) -> str:
    """Concatenate .py file contents up to max_chars for LLM review."""
    parts: list[str] = []
    total = 0
    for py_file in sorted(Path(src_dir).rglob("*.py")):
        header = f"### {py_file.name} ###\n"
        content = py_file.read_text(encoding="utf-8", errors="replace")
        snippet = content[: max_chars - total]
        parts.append(header + snippet)
        total += len(header) + len(snippet)
        if total >= max_chars:
            parts.append("\n[truncated for review]")
            break
    return "\n\n".join(parts)


def _llm_analyse(src_dir: str) -> tuple[str, str]:
    """Call Anthropic Claude to analyse the source.

    Returns (summary, suspicion_level). On any error returns a safe
    fallback so the pipeline is not blocked by LLM availability.
    """
    if not _ANTHROPIC_API_KEY:
        logger.warning("OBLAK_ANTHROPIC_API_KEY not set — skipping LLM analysis.")
        return "LLM analysis skipped (no API key).", "UNKNOWN"

    source_text = _collect_source_text(src_dir)
    if not source_text.strip():
        return "No Python source files found.", "UNKNOWN"

    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 512,
        "system": _LLM_SYSTEM,
        "messages": [{"role": "user", "content": source_text}],
    }

    try:
        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": _ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        text = response.json()["content"][0]["text"]
        data = json.loads(text)
        summary = data.get("summary", "")
        suspicion = data.get("suspicion", "UNKNOWN").upper()
        concerns = data.get("concerns", [])
        if concerns:
            summary += " Concerns: " + "; ".join(concerns)
        return summary, suspicion
    except Exception as exc:
        logger.warning("LLM analysis failed: %s", exc)
        return f"LLM analysis unavailable: {type(exc).__name__}", "UNKNOWN"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def verify(
    zip_path: str,
    src_dir: str,
    db: Session,
    actor: str,
    function_name: str,
    request_id: str = "-",
    client_ip: str = "-",
) -> VerificationResult:
    """Run the full verification pipeline on an uploaded function.

    zip_path      — path to the stored package.zip (for AV scan).
    src_dir       — path to the already-extracted source tree.
    db            — SQLAlchemy session for audit logging.
    actor         — username of the function owner.
    function_name — used in audit log resource field.

    Returns a VerificationResult. Never raises; failures are encoded in
    the result so the caller can set the appropriate FunctionStatus.
    """
    resource = f"function:{function_name}"

    # Stage 1 — ClamAV
    try:
        _scan_clamav(zip_path)
        audit.record(db, action="verify_av", outcome="SUCCESS",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip)
    except VerificationFailed as exc:
        audit.record(db, action="verify_av", outcome="FAILURE",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip,
                     detail={"reason": str(exc)})
        return VerificationResult(passed=False, reason=str(exc))

    # Stage 2 — Bandit
    try:
        bandit_issues = _run_bandit(src_dir)
        audit.record(db, action="verify_bandit", outcome="SUCCESS",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip,
                     detail={"issue_count": len(bandit_issues)})
    except VerificationFailed as exc:
        audit.record(db, action="verify_bandit", outcome="FAILURE",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip,
                     detail={"reason": str(exc)})
        return VerificationResult(passed=False, reason=str(exc))

    # Stage 3 — Forbidden patterns
    try:
        _check_forbidden_patterns(src_dir)
        audit.record(db, action="verify_patterns", outcome="SUCCESS",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip)
    except VerificationFailed as exc:
        audit.record(db, action="verify_patterns", outcome="FAILURE",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip,
                     detail={"reason": str(exc)})
        return VerificationResult(passed=False, reason=str(exc))

    # Stage 4 — LLM
    llm_summary, llm_suspicion = _llm_analyse(src_dir)
    audit.record(db, action="verify_llm", outcome="SUCCESS",
                 actor=actor, resource=resource,
                 request_id=request_id, client_ip=client_ip,
                 detail={"suspicion": llm_suspicion})

    if llm_suspicion == "HIGH":
        reason = f"LLM rated code as HIGH suspicion: {llm_summary[:200]}"
        audit.record(db, action="verify_llm_reject", outcome="FAILURE",
                     actor=actor, resource=resource,
                     request_id=request_id, client_ip=client_ip,
                     detail={"reason": reason})
        return VerificationResult(
            passed=False, reason=reason,
            llm_summary=llm_summary, llm_suspicion=llm_suspicion,
        )

    return VerificationResult(
        passed=True,
        reason="all checks passed",
        llm_summary=llm_summary,
        llm_suspicion=llm_suspicion,
        bandit_issues=bandit_issues,
    )