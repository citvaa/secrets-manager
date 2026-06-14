"""Pydantic request/response schemas — input validation lives here (req. ZR-V1).

Strict field constraints keep malformed or hostile input out of the core logic.
"""

from __future__ import annotations

import datetime as dt
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Usernames and function names: conservative allow-list to avoid path/format abuse.
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=10, max_length=256)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError("username may contain only letters, digits, '.', '_', '-'")
        return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class FunctionInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    status: str
    code_sha256: str
    created_at: dt.datetime
    # Member 2 additions (nullable until the pipeline reaches READY)
    invoke_token: str | None = None
    verification_detail: str | None = None


class UploadResponse(BaseModel):
    name: str
    status: str
    code_sha256: str
    message: str


class VerifyResponse(BaseModel):
    name: str
    status: str
    message: str
    invoke_url: str | None = None
    llm_suspicion: str | None = None


class FunctionDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    status: str
    code_sha256: str
    created_at: dt.datetime
    invoke_token: str | None = None
    verification_detail: str | None = None