"""Thin HTTP client wrapping the Oblak server API."""

from __future__ import annotations

import httpx


class ApiError(Exception):
    """Raised when the server returns an error response."""


class OblakClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _handle(self, resp: httpx.Response) -> dict:
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:  # noqa: BLE001 - best-effort error extraction
                detail = resp.text
            raise ApiError(f"HTTP {resp.status_code}: {detail}")
        return resp.json() if resp.content else {}

    def register(self, username: str, password: str) -> dict:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._base}/auth/register",
                json={"username": username, "password": password},
            )
        return self._handle(resp)

    def login(self, username: str, password: str) -> dict:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._base}/auth/login",
                json={"username": username, "password": password},
            )
        return self._handle(resp)

    def upload(self, name: str, package_bytes: bytes) -> dict:
        files = {"package": ("package.zip", package_bytes, "application/zip")}
        data = {"name": name}
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._base}/functions",
                headers=self._headers(),
                data=data,
                files=files,
            )
        return self._handle(resp)

    def list_functions(self) -> list:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.get(f"{self._base}/functions", headers=self._headers())
        return self._handle(resp)
