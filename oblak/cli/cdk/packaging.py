"""Package a local function directory into a ZIP for upload.

Only regular files under the given directory are included. Symlinks are skipped to
avoid packaging paths that point outside the project (defense-in-depth, mirrors the
zip-slip concern on the server side).
"""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

# Directories/files we never want to ship to the cloud.
_EXCLUDE_DIRS = {".git", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache"}


def build_package(source_dir: str) -> bytes:
    """Return the bytes of a ZIP archive containing the function source."""
    src = Path(source_dir).resolve()
    if not src.is_dir():
        raise ValueError(f"not a directory: {source_dir}")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(src):
            # Prune excluded directories in-place.
            dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.is_symlink():
                    continue
                arcname = fpath.relative_to(src).as_posix()
                zf.write(fpath, arcname)

    return buffer.getvalue()
