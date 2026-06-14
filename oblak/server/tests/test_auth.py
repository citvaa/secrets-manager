"""Tests for registration, login, JWT auth and rate limiting."""

from __future__ import annotations

import uuid


def _unique(prefix: str = "user") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def test_register_and_login_success(client):
    username = _unique()
    password = "CorrectHorseBatteryStaple"

    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201

    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] > 0


def test_duplicate_registration_rejected(client):
    username = _unique()
    password = "CorrectHorseBatteryStaple"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 201
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 409


def test_weak_password_rejected(client):
    r = client.post("/auth/register", json={"username": _unique(), "password": "short"})
    assert r.status_code == 422  # pydantic validation (min length 10)


def test_login_wrong_password(client):
    username = _unique()
    client.post("/auth/register", json={"username": username, "password": "CorrectHorseBatteryStaple"})
    r = client.post("/auth/login", json={"username": username, "password": "wrong-password"})
    assert r.status_code == 401


def test_protected_endpoint_requires_token(client):
    r = client.get("/functions")
    assert r.status_code == 401


def test_invalid_token_rejected(client):
    # Tampered/garbage token must be rejected (fail-closed; threat T2).
    r = client.get("/functions", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_login_rate_limit(client):
    username = _unique()
    client.post("/auth/register", json={"username": username, "password": "CorrectHorseBatteryStaple"})
    # 5 failures allowed, the 6th should be rate-limited (429).
    last = None
    for _ in range(6):
        last = client.post("/auth/login", json={"username": username, "password": "bad"})
    assert last.status_code == 429
