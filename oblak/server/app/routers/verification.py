"""Verification and invoke-URL endpoints — Member 2.

POST /functions/{name}/verify
    Triggers the full pipeline: integrity check → AV → static analysis →
    LLM analysis → dependency preparation → invoke URL generation.

GET /functions/{name}
    Returns full function info including invoke_token (if READY).

GET /invoke/{token}
    Placeholder endpoint for Member 3. Returns 503 until the Firecracker
    orchestrator is wired in.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit, code_verifier, preparation, storage
from ..database import get_db
from ..deps import get_client_ip, get_current_user, get_request_id
from ..models import Function, FunctionStatus, User
from ..schemas import FunctionDetail, VerifyResponse
from ..storage import StorageIntegrityError

router = APIRouter(tags=["verification"])


# ---------------------------------------------------------------------------
# POST /functions/{name}/verify
# ---------------------------------------------------------------------------

@router.post(
    "/functions/{name}/verify",
    response_model=VerifyResponse,
    summary="Run the verification and preparation pipeline for a function.",
)
def verify_function(
    name: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> VerifyResponse:
    rid = get_request_id(request)
    ip = get_client_ip(request)
    resource = f"function:{name}"

    # 1 — look up the function (ownership enforced, ZR-Z1).
    fn: Function | None = (
        db.query(Function)
        .filter(Function.owner_id == user.id, Function.name == name)
        .first()
    )
    if fn is None:
        raise HTTPException(status_code=404, detail="Function not found")

    if fn.status not in (
        FunctionStatus.UPLOADED,
        FunctionStatus.REJECTED,
        FunctionStatus.FAILED,
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Function is in status {fn.status.value}; "
                "only UPLOADED/REJECTED/FAILED can be re-verified."
            ),
        )

    # 2 — integrity check (ZR-V3 / T5).
    fn.status = FunctionStatus.VERIFYING
    db.commit()

    try:
        storage.verify_integrity(fn.storage_path, fn.code_sha256)
    except StorageIntegrityError as exc:
        fn.status = FunctionStatus.FAILED
        fn.verification_detail = str(exc)
        db.commit()
        audit.record(
            db, action="integrity_check", outcome="FAILURE",
            actor=user.username, resource=resource,
            request_id=rid, client_ip=ip,
            detail={"reason": str(exc)},
        )
        raise HTTPException(status_code=500, detail="Package integrity check failed")

    audit.record(
        db, action="integrity_check", outcome="SUCCESS",
        actor=user.username, resource=resource,
        request_id=rid, client_ip=ip,
    )

    # 3 — extract source for analysis.
    src_dir = storage.extract_source(fn.storage_path, user.username, name)

    # 4 — run full verification pipeline.
    result = code_verifier.verify(
        zip_path=fn.storage_path,
        src_dir=src_dir,
        db=db,
        actor=user.username,
        function_name=name,
        request_id=rid,
        client_ip=ip,
    )

    if not result.passed:
        fn.status = FunctionStatus.REJECTED
        fn.verification_detail = result.reason
        db.commit()
        audit.record(
            db, action="verify", outcome="FAILURE",
            actor=user.username, resource=resource,
            request_id=rid, client_ip=ip,
            detail={"reason": result.reason},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Verification failed: {result.reason}",
        )

    fn.verification_detail = (
        f"[{result.llm_suspicion}] {result.llm_summary}"
        if result.llm_summary
        else "passed"
    )

    # 5 — prepare artifact (install deps into isolated venv).
    fn.status = FunctionStatus.PREPARING
    db.commit()

    art_dir = storage.artifact_dir(user.username, name)
    try:
        preparation.prepare_artifact(src_dir, art_dir)
    except preparation.PreparationError as exc:
        fn.status = FunctionStatus.FAILED
        db.commit()
        audit.record(
            db, action="prepare", outcome="FAILURE",
            actor=user.username, resource=resource,
            request_id=rid, client_ip=ip,
            detail={"reason": str(exc)},
        )
        raise HTTPException(status_code=500, detail=f"Preparation failed: {exc}")

    fn.artifact_path = art_dir
    audit.record(
        db, action="prepare", outcome="SUCCESS",
        actor=user.username, resource=resource,
        request_id=rid, client_ip=ip,
    )

    # 6 — generate unique invoke token (ZR-U1).
    # Re-use existing token if already set (idempotent re-verify).
    if not fn.invoke_token:
        fn.invoke_token = secrets.token_urlsafe(32)

    fn.status = FunctionStatus.READY
    db.commit()

    audit.record(
        db, action="ready", outcome="SUCCESS",
        actor=user.username, resource=resource,
        request_id=rid, client_ip=ip,
    )

    invoke_url = f"/invoke/{fn.invoke_token}"
    return VerifyResponse(
        name=name,
        status=fn.status.value,
        message="verification passed; function is ready",
        invoke_url=invoke_url,
        llm_suspicion=result.llm_suspicion,
    )


# ---------------------------------------------------------------------------
# GET /functions/{name}
# ---------------------------------------------------------------------------

@router.get(
    "/functions/{name}",
    response_model=FunctionDetail,
    summary="Get full details for one of your functions, including the invoke URL.",
)
def get_function(
    name: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Function:
    fn: Function | None = (
        db.query(Function)
        .filter(Function.owner_id == user.id, Function.name == name)
        .first()
    )
    if fn is None:
        raise HTTPException(status_code=404, detail="Function not found")
    return fn


# ---------------------------------------------------------------------------
# GET /invoke/{token} — placeholder for Member 3
# ---------------------------------------------------------------------------

@router.get(
    "/invoke/{token}",
    summary="Invoke a deployed function (Member 3 wires in Firecracker here).",
)
def invoke_function(token: str, db: Session = Depends(get_db)) -> dict:
    fn: Function | None = (
        db.query(Function).filter(Function.invoke_token == token).first()
    )
    if fn is None:
        raise HTTPException(status_code=404, detail="Unknown invoke token")
    if fn.status != FunctionStatus.READY:
        raise HTTPException(
            status_code=503,
            detail=f"Function is not ready (status={fn.status.value})",
        )
    # Member 3 replaces this body with the Firecracker orchestrator call.
    raise HTTPException(
        status_code=503,
        detail="Execution engine not yet connected (Member 3 open item).",
    )