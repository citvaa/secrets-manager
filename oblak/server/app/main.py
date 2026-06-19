"""FastAPI application entry point for the Oblak server.

Member 1 wires up auth + upload + audit. Members 2 and 3 add their routers
(verification status, invoke URL, execution) to this same app.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from .config import settings
from .database import init_db
from .routers import auth, functions, verification


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from orchestrator import Orchestrator
    from orchestrator.config import OrchestratorConfig
    cfg = OrchestratorConfig(
        firecracker_bin=settings.firecracker_bin,
        jailer_bin=settings.jailer_bin,
        kernel_path=settings.kernel_path,
        rootfs_path=settings.rootfs_path,
        vm_vcpus=settings.vm_vcpus,
        vm_mem_mib=settings.vm_mem_mib,
        vm_timeout_seconds=settings.vm_timeout_seconds,
        vm_network_enabled=settings.vm_network_enabled,
        jailer_uid=settings.jailer_uid,
        jailer_gid=settings.jailer_gid,
    )
    app.state.orchestrator = Orchestrator(cfg)
    yield


from fastapi.openapi.utils import get_openapi

app = FastAPI(title="Oblak", version="0.1.0", lifespan=lifespan)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title="Oblak",
        version="0.1.0",
        routes=app.routes,
    )
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
        }
    }
    for path in schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add a few conservative security headers to every response."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # HSTS is meaningful only over HTTPS; safe to advertise regardless.
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
    )
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Never leak internal details / stack traces to clients (threat T6)."""
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(functions.router)
app.include_router(verification.router)
