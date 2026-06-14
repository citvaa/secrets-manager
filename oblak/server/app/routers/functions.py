"""Function endpoints: upload code package and list own functions.

This is the entry point of the pipeline. Member 1 receives, validates and stores
the package and records it as UPLOADED. Member 2 picks it up for verification,
dependency preparation and invoke-URL creation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from .. import audit, storage
from ..database import get_db
from ..deps import get_client_ip, get_current_user, get_request_id
from ..models import Function, FunctionStatus, User
from ..schemas import FunctionInfo, UploadResponse
from ..storage import UploadRejected

router = APIRouter(prefix="/functions", tags=["functions"])

# Conservative allow-list for function names (defense against path/format abuse).
import re  # noqa: E402  (local import to keep router header tidy)

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@router.post("", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_function(
    request: Request,
    name: str = Form(...),
    package: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UploadResponse:
    """Accept a ZIP package (Python code + optional requirements.txt) for `name`."""
    rid = get_request_id(request)
    ip = get_client_ip(request)

    if not _NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid function name")

    raw = await package.read()

    try:
        storage_path, sha256 = storage.validate_and_store(user.username, name, raw)
    except UploadRejected as exc:
        audit.record(
            db, action="upload", outcome="FAILURE", actor=user.username,
            resource=f"function:{name}", request_id=rid, client_ip=ip,
            detail={"reason": str(exc)},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Upsert: re-uploading the same function name updates the record.
    fn = (
        db.query(Function)
        .filter(Function.owner_id == user.id, Function.name == name)
        .first()
    )
    if fn is None:
        fn = Function(owner_id=user.id, name=name)
        db.add(fn)
    fn.code_sha256 = sha256
    fn.storage_path = storage_path
    fn.status = FunctionStatus.UPLOADED
    db.commit()

    audit.record(
        db, action="upload", outcome="SUCCESS", actor=user.username,
        resource=f"function:{name}", request_id=rid, client_ip=ip,
        detail={"sha256": sha256, "bytes": len(raw)},
    )
    return UploadResponse(
        name=name,
        status=fn.status.value,
        code_sha256=sha256,
        message="uploaded; queued for verification",
    )


@router.get("", response_model=list[FunctionInfo])
def list_functions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Function]:
    """List functions owned by the caller (ownership enforced — ZR-Z1 / T9)."""
    return db.query(Function).filter(Function.owner_id == user.id).all()
