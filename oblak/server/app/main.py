"""FastAPI application entry point for the Oblak server.

Member 1 wires up auth + upload + audit. Members 2 and 3 add their routers
(verification status, invoke URL, execution) to this same app.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .database import init_db
from .routers import auth, functions


@asynccontextmanager
async def lifespan(app: FastAPI):
    # For the project it's fine to create tables on startup; production would use
    # migrations / seed.sql (see server/seed.sql).
    init_db()
    yield


app = FastAPI(title="Oblak", version="0.1.0", lifespan=lifespan)


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
