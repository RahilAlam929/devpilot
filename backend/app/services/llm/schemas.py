"""
Pydantic schemas for LLM analysis results — Phase 7B.

These schemas validate the structured JSON returned by any LLM provider.
All fields are strict so malformed LLM output is caught early and never
silently passed to the database.

Do NOT store raw chain-of-thought here. reasoning_summary is a short
auditable summary only — never the hidden reasoning trace.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ── Analysis version ───────────────────────────────────────────────────────
# Bump this when prompts or schema change to allow result comparison across
# analysis generations.
ANALYSIS_VERSION = "7b.1"


class LLMVerdict(str, Enum):
    """The LLM's determination of whether the finding is real."""

    TRUE_POSITIVE = "true_positive"
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class LLMAnalysisResult(BaseModel):
    """
    Structured result returned by the LLM after analyzing a finding.

    The LLM must return JSON matching this schema. Validation is strict
    so malformed responses fail fast rather than being silently accepted.

    SECURITY NOTE:
      - Do NOT add a raw chain-of-thought or reasoning trace field.
      - reasoning_summary is a short, user-facing auditable summary only.
      - No field here should contain raw API keys, secrets, or PII.
    """

    # ── Core verdict ───────────────────────────────────────────────────────
    verdict: LLMVerdict = Field(
        description="Whether this finding is a real issue or a false positive."
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the verdict, 0.0 to 1.0.",
    )

    exploitability: float = Field(
        ge=0.0,
        le=1.0,
        description="Estimated exploitability of the vulnerability, 0.0 to 1.0.",
    )

    # ── Intelligence fields ────────────────────────────────────────────────
    impact: str = Field(
        max_length=500,
        description="Short structured description of the potential impact.",
    )

    root_cause: str = Field(
        max_length=500,
        description="Short explanation of why this finding exists.",
    )

    explanation: str = Field(
        max_length=2000,
        description="Concise technical explanation of the finding.",
    )

    remediation: str = Field(
        max_length=2000,
        description="Actionable remediation guidance.",
    )

    # ── Audit trail ───────────────────────────────────────────────────────
    reasoning_summary: str = Field(
        max_length=1000,
        description=(
            "Short auditable summary of the reasoning — not a hidden chain-of-thought. "
            "Describes what evidence was used to reach the verdict."
        ),
    )

    # ── Provider metadata (set by the service layer, not the LLM) ─────────
    provider: str = Field(default="", description="LLM provider name.")
    model: str = Field(default="", description="Specific model used.")
    analysis_version: str = Field(
        default=ANALYSIS_VERSION, description="Schema and prompt version."
    )
    analyzed_at: Optional[datetime] = Field(
        default=None, description="UTC timestamp of analysis."
    )

    @field_validator("confidence", "exploitability", mode="before")
    @classmethod
    def clamp_float(cls, v: object) -> float:
        """Accept strings and clamp to [0.0, 1.0]."""
        try:
            f = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(1.0, f))

    class Config:
        use_enum_values = True


class LLMUnavailableResult(BaseModel):
    """
    Returned when LLM analysis is not available for any reason.

    This is a controlled, non-error response that lets callers distinguish
    'no analysis' from 'analysis failed' from 'analysis exists'.
    Never raised as an exception — returned as a value.
    """

    available: bool = False
    reason: str = Field(description="Human-readable reason for unavailability.")

    # Metadata fields — set to None/empty when unavailable
    provider: str = ""
    model: str = ""
    analysis_version: str = ANALYSIS_VERSION
