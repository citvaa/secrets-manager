"""Tests for the code upload endpoint, including malicious-input cases."""

from __future__ import annotations

import io
import uuid
import zipfile


def _auth_headers(client) -> dict:
    username = f"up_{uuid.uuid4().hex[:8]}"
    password = "CorrectHorseBatteryStaple"
    client.post("/auth/register", json={"username": username, "password": password})
    token = client.post("/auth/login", json={"username": username, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_upload_benign_package(client):
    headers = _auth_headers(client)
    pkg = _zip({"main.py": "def handler(event):\n    return {'ok': True}\n",
                "requirements.txt": "requests==2.32.3\n"})
    r = client.post(
        "/functions",
        headers=headers,
        data={"name": "hello"},
        files={"package": ("package.zip", pkg, "application/zip")},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "UPLOADED"
    assert len(body["code_sha256"]) == 64

    # It should now appear in the owner's list.
    listing = client.get("/functions", headers=headers).json()
    assert any(f["name"] == "hello" for f in listing)


def test_upload_rejects_zip_slip(client):
    """A zip member escaping the target dir must be rejected (threat T4)."""
    headers = _auth_headers(client)
    pkg = _zip({"../../evil.py": "print('pwned')"})
    r = client.post(
        "/functions",
        headers=headers,
        data={"name": "evilfn"},
        files={"package": ("package.zip", pkg, "application/zip")},
    )
    assert r.status_code == 400
    assert "traversal" in r.json()["detail"].lower() or "unsafe" in r.json()["detail"].lower()


def test_upload_rejects_non_zip(client):
    headers = _auth_headers(client)
    r = client.post(
        "/functions",
        headers=headers,
        data={"name": "notzip"},
        files={"package": ("package.zip", b"this is not a zip", "application/zip")},
    )
    assert r.status_code == 400


def test_upload_rejects_bad_name(client):
    headers = _auth_headers(client)
    pkg = _zip({"main.py": "x = 1"})
    r = client.post(
        "/functions",
        headers=headers,
        data={"name": "../etc/passwd"},
        files={"package": ("package.zip", pkg, "application/zip")},
    )
    assert r.status_code == 400


def test_upload_requires_auth(client):
    pkg = _zip({"main.py": "x = 1"})
    r = client.post(
        "/functions",
        data={"name": "noauth"},
        files={"package": ("package.zip", pkg, "application/zip")},
    )
    assert r.status_code == 401
