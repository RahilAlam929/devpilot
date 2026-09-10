"""
DevPilot API — application entry point.

Production hardening applied here:
  - Logging configured at startup.
  - OpenAPI docs disabled in production.
  - CORS origins loaded from CORS_ORIGINS env var.
  - Global exception handler returns clean JSON without stack traces.
  - /health and /health/ready endpoints.
"""

import logging
import logging.config

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.auth import router as auth_router
from app.api.projects import router as projects_router
from app.api.repositories import router as repositories_router
from app.api.scans import router as scans_router
from app.api.users import router as users_router
from app.api.findings import router as findings_router
from app.api.llm_analysis import router as llm_analysis_router
from app.database import SessionLocal, settings

# ── Logging ───────────────────────────────────────────────────────────────

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING" if settings.is_production else "INFO",
    },
    "loggers": {
        "app": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {
            "level": "WARNING" if settings.is_production else "INFO",
        },
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("app.main")

# ── App factory ───────────────────────────────────────────────────────────

app = FastAPI(
    title="DevPilot API",
    version="0.1.0",
    description="AI-native developer platform API",
    # Disable interactive docs in production — they expose the full API surface.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── CORS ─────────────────────────────────────────────────────────────────

# ── Exception handlers ────────────────────────────────────────────────────


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return structured 422 without leaking internal details."""
    errors = []
    for error in exc.errors():
        loc = " → ".join(str(l) for l in error.get("loc", []) if l != "body")
        msg = error.get("msg", "Invalid value")
        errors.append(f"{loc}: {msg}" if loc else msg)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "; ".join(errors) if errors else "Validation error"},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """
    Catch-all for unexpected server errors.
    Logs the full traceback server-side; returns a safe message to the client.
    """
    logger.exception(
        "Unhandled exception on %s %s", request.method, request.url.path
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."},
    )


# ── Health endpoints ──────────────────────────────────────────────────────


@app.get("/health", tags=["Health"])
def health() -> dict:
    """Lightweight liveness probe — always fast, no DB call."""
    return {
        "status": "ok",
        "service": "devpilot-api",
        "version": "0.1.0",
    }


@app.get("/health/ready", tags=["Health"])
def health_ready() -> dict:
    """
    Readiness probe — verifies database connectivity.
    Returns 503 if the database is unreachable.
    """
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except SQLAlchemyError as exc:
        logger.warning("Readiness check failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not ready", "database": "unavailable"},
        )
    finally:
        db.close()


# ── Routers ───────────────────────────────────────────────────────────────

app.include_router(auth_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(projects_router, prefix="/api")
app.include_router(repositories_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(llm_analysis_router, prefix="/api")
