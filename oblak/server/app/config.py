"""Application configuration.

All secrets and environment-specific values are loaded from environment variables
or a local `.env` file. Nothing sensitive is hard-coded here (requirement ZR-K2).
"""

from __future__ import annotations

import secrets
import warnings

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings, sourced from the environment / `.env`."""

    model_config = SettingsConfigDict(
        env_prefix="OBLAK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Authentication / JWT (ZR-A3, ZR-A4) ---
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"  # HMAC-SHA256: keyed MAC, not a bare hash (ZR-A4)
    access_token_expire_minutes: int = 30

    # --- Storage / database ---
    database_url: str = "sqlite:///./oblak.db"
    storage_dir: str = "./_storage"

    # --- Audit logging (ZR-L4) ---
    audit_log_path: str = "./logs/audit.log"

    # --- Upload limits (ZR-V2) ---
    max_upload_bytes: int = 5 * 1024 * 1024  # 5 MiB

    # --- Login rate limiting (ZR-A5) ---
    login_max_attempts: int = 5
    login_window_seconds: int = 300

    # --- Execution / Firecracker ---
    firecracker_bin: str = "/usr/local/bin/firecracker"
    jailer_bin: str = "/usr/local/bin/jailer"
    kernel_path: str = "/var/lib/oblak/vmlinux"
    rootfs_path: str = "/var/lib/oblak/rootfs.ext4"
    vm_vcpus: int = 1
    vm_mem_mib: int = 128
    vm_timeout_seconds: int = 30
    vm_network_enabled: bool = False
    jailer_uid: int = 65533
    jailer_gid: int = 65533

    def ensure_secret(self) -> None:
        """Fail-safe for the JWT secret.

        In production the secret MUST be provided via the environment. If it is
        missing we generate an ephemeral one so the app still boots in dev, but we
        warn loudly because tokens will not survive a restart and this is unsafe
        for real deployments.
        """
        if not self.jwt_secret:
            self.jwt_secret = secrets.token_urlsafe(48)
            warnings.warn(
                "OBLAK_JWT_SECRET is not set — generated an ephemeral secret. "
                "Set a stable secret via environment for any real deployment.",
                RuntimeWarning,
                stacklevel=2,
            )


settings = Settings()
settings.ensure_secret()
