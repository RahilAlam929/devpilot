import logging
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # ── Core ─────────────────────────────────────────────────────────────────
    DATABASE_URL: str

    # ── Auth ─────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    AUTH_COOKIE_NAME: str = "devpilot_token"

    # ── Deployment ───────────────────────────────────────────────────────────
    # Set to "production" in production environments.
    # Controls: cookie Secure flag, OpenAPI docs availability.
    ENVIRONMENT: str = "development"

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed origins.
    # Example: "https://app.devpilot.io,https://www.devpilot.io"
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # ── GitHub cloning ───────────────────────────────────────────────────────
    GIT_CLONE_TIMEOUT_SECONDS: int = 120

    # ── LLM analysis (Phase 7B) ───────────────────────────────────────────
    # All LLM settings default to safe/disabled values.
    # Enable by setting LLM_ENABLED=true and providing the other values.

    # Master switch. When false (the default), no LLM calls are made and
    # the scanner continues deterministically.
    LLM_ENABLED: bool = False

    # Provider identifier. Supported: "openai", "anthropic".
    # Empty string means "no provider configured".
    LLM_PROVIDER: str = ""

    # Specific model, e.g. "gpt-4o-mini" or "claude-3-haiku-20240307".
    LLM_MODEL: str = ""

    # API key — NEVER log or expose this value.
    # Stored as Optional[str] so an empty .env value stays None (not "").
    LLM_API_KEY: Optional[str] = None

    # Request timeout in seconds.
    LLM_TIMEOUT_SECONDS: int = 30

    # Maximum characters of finding context to send to the LLM.
    # Larger contexts cost more tokens; smaller ones may miss evidence.
    LLM_MAX_CONTEXT_CHARS: int = 12_000

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass
