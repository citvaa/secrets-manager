"""Code storage — Member 1 provides a minimal, safe local store for the upload
path; Member 2 replaces the body with the real Code Storage component (integrity,
per-user isolation, access control) behind this same interface.

The functions here already enforce the upload-side safety requirements that belong
to Member 1: size limit (ZR-V2) and zip-slip / path-traversal protection (ZR-V2/V3).
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile

from .config import settings


class UploadRejected(Exception):
    """Raised when an upload violates a safety rule. Maps to HTTP 400."""


def _safe_member_path(base_dir: str, member_name: str) -> str:
    """Resolve an archive member against base_dir, rejecting traversal/zip-slip.

    Mirrors the lesson from the code-review lab: never trust a path coming from a
    user-controlled archive. Absolute paths and any `..` escape are rejected.
    """
    # Normalize and forbid absolute paths or drive letters.
    if member_name.startswith(("/", "\\")) or os.path.splitdrive(member_name)[0]:
        raise UploadRejected(f"unsafe path in archive: {member_name!r}")

    target = os.path.normpath(os.path.join(base_dir, member_name))
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(target)
    # The resolved target must stay inside base_dir.
    if target_abs != base_abs and not target_abs.startswith(base_abs + os.sep):
        raise UploadRejected(f"path traversal blocked: {member_name!r}")
    return target_abs


def validate_and_store(owner: str, name: str, raw: bytes) -> tuple[str, str]:
    """Validate an uploaded ZIP package and store it under the owner's space.

    Returns `(storage_path, sha256_hex)`. Raises `UploadRejected` on any violation.
    """
    # 1) Size limit (ZR-V2 / DoS guard T8).
    if len(raw) > settings.max_upload_bytes:
        raise UploadRejected(
            f"package too large: {len(raw)} bytes (max {settings.max_upload_bytes})"
        )
    if not raw:
        raise UploadRejected("empty package")

    # 2) Must be a valid ZIP.
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise UploadRejected("package is not a valid zip archive") from exc

    # 3) Validate every member path BEFORE writing anything (zip-slip guard, ZR-V2).
    target_dir = os.path.join(settings.storage_dir, owner, name)
    names = zf.namelist()
    if not names:
        raise UploadRejected("archive contains no files")
    for member in names:
        if member.endswith("/"):
            continue  # directory entry
        _safe_member_path(target_dir, member)

    # 4) Content hash for integrity + non-repudiation (ZR-L2, threat T5/T10).
    sha256 = hashlib.sha256(raw).hexdigest()

    # 5) Persist the raw package. Member 2 may instead unpack into an isolated store.
    os.makedirs(target_dir, exist_ok=True)
    package_path = os.path.join(target_dir, "package.zip")
    # Write atomically-ish: write then flush.
    with open(package_path, "wb") as fh:
        fh.write(raw)
    try:
        os.chmod(package_path, 0o640)
    except OSError:
        pass

    return package_path, sha256
