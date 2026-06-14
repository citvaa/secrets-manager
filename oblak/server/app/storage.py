"""Code storage — Member 2 extends Member 1's minimal store with:

- integrity verification on read (SHA-256 re-check, ZR-V3/T5),
- strict per-user/per-function directory isolation (ZR-Z1),
- helper to extract the package into an unpacked source tree for verification
  and preparation.

The public interface (validate_and_store, UploadRejected) is unchanged so
Member 1's upload router keeps working without modification.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import zipfile

from .config import settings


class UploadRejected(Exception):
    """Raised when an upload violates a safety rule. Maps to HTTP 400."""


class StorageIntegrityError(Exception):
    """Raised when a stored package fails its integrity check on read."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_member_path(base_dir: str, member_name: str) -> str:
    """Resolve an archive member against base_dir, rejecting traversal/zip-slip."""
    if member_name.startswith(("/", "\\")) or os.path.splitdrive(member_name)[0]:
        raise UploadRejected(f"unsafe path in archive: {member_name!r}")

    target = os.path.normpath(os.path.join(base_dir, member_name))
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(target)
    if target_abs != base_abs and not target_abs.startswith(base_abs + os.sep):
        raise UploadRejected(f"path traversal blocked: {member_name!r}")
    return target_abs


def _package_dir(owner: str, name: str) -> str:
    """Return the canonical storage directory for this owner/function pair."""
    return os.path.join(settings.storage_dir, owner, name)


# ---------------------------------------------------------------------------
# Public API — used by Member 1's upload router (interface unchanged)
# ---------------------------------------------------------------------------

def validate_and_store(owner: str, name: str, raw: bytes) -> tuple[str, str]:
    """Validate an uploaded ZIP package and store it under the owner's space.

    Returns (storage_path, sha256_hex). Raises UploadRejected on any violation.

    Member 2 additions:
    - stores SHA-256 sidecar file beside the package for later integrity checks,
    - tightens directory permissions to 0o750 (world-excluded, ZR-Z1).
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

    # 3) Validate every member path BEFORE writing anything (zip-slip, ZR-V2).
    target_dir = _package_dir(owner, name)
    names = zf.namelist()
    if not names:
        raise UploadRejected("archive contains no files")
    for member in names:
        if member.endswith("/"):
            continue
        _safe_member_path(target_dir, member)

    # 4) Content hash for integrity + non-repudiation (ZR-L2, threat T5/T10).
    sha256 = hashlib.sha256(raw).hexdigest()

    # 5) Persist: create isolated directory, write package, store hash sidecar.
    os.makedirs(target_dir, exist_ok=True)
    try:
        os.chmod(target_dir, 0o750)  # world-excluded (ZR-Z1)
    except OSError:
        pass

    package_path = os.path.join(target_dir, "package.zip")
    with open(package_path, "wb") as fh:
        fh.write(raw)
    try:
        os.chmod(package_path, 0o640)
    except OSError:
        pass

    # Write SHA-256 sidecar so integrity can be re-checked later.
    sidecar = package_path + ".sha256"
    with open(sidecar, "w") as fh:
        fh.write(sha256)
    try:
        os.chmod(sidecar, 0o640)
    except OSError:
        pass

    return package_path, sha256


# ---------------------------------------------------------------------------
# Member 2 additions — used by the verifier and preparation pipeline
# ---------------------------------------------------------------------------

def verify_integrity(storage_path: str, expected_sha256: str) -> None:
    """Re-hash the stored package and compare against the recorded digest.

    Raises StorageIntegrityError if the file is missing or hash doesn't match.
    Guards against tampering between upload and execution (threat T5).
    """
    if not os.path.isfile(storage_path):
        raise StorageIntegrityError(f"package not found: {storage_path!r}")

    with open(storage_path, "rb") as fh:
        actual = hashlib.sha256(fh.read()).hexdigest()

    if actual != expected_sha256:
        raise StorageIntegrityError(
            f"integrity check failed for {storage_path!r}: "
            f"expected {expected_sha256}, got {actual}"
        )


def extract_source(storage_path: str, owner: str, name: str) -> str:
    """Extract the ZIP package into an isolated source directory.

    Returns the path to the extracted source tree. Previous extraction
    is removed first (re-deploy scenario). Re-applies zip-slip guard.
    """
    target_dir = _package_dir(owner, name)
    src_dir = os.path.join(target_dir, "src")

    if os.path.exists(src_dir):
        shutil.rmtree(src_dir)
    os.makedirs(src_dir, exist_ok=True)

    with zipfile.ZipFile(storage_path) as zf:
        for member in zf.infolist():
            if member.filename.endswith("/"):
                continue
            dest = _safe_member_path(src_dir, member.filename)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(member) as src, open(dest, "wb") as dst:
                dst.write(src.read())

    return src_dir


def artifact_dir(owner: str, name: str) -> str:
    """Return (and create) the directory where the prepared artifact lives."""
    path = os.path.join(_package_dir(owner, name), "artifact")
    os.makedirs(path, exist_ok=True)
    return path