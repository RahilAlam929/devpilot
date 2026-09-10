"""
LLM Analyzer service — Phase 7B.

Orchestrates finding intelligence: context building, redaction,
provider call, schema validation, caching, and persistence.

RESPONSIBILITIES:
  1. Load the finding (ownership already verified by the caller/router).
  2. Build minimal context from the finding.
  3. Redact sensitive information from the context.
  4. Compute deterministic request hash.
  5. Check for cached analysis (same hash + analysis_version).
  6. Call the LLM provider.
  7. Validate the structured response with Pydantic.
  8. Persist the analysis.
  9. Return the normalized result.

GUARANTEES:
  - LLM errors NEVER crash the scanner or break existing functionality.
  - API keys are never logged, returned, or stored.
  - The LLM does NOT modify the existing deterministic Finding severity.
  - Chain-of-thought is never stored or returned.
  - All repository content is treated as untrusted data.

SECURITY:
  - Ownership is verified upstream (in the API router) before calling this service.
  - This service trusts that the Finding passed to it is already access-controlled.
  - No arbitrary file access or shell execution occurs here.
"""

import logging
from datetime import datetime
from typing import Optional, Union

from sqlalchemy.orm import Session

from app.services.llm.client import (
    LLMUnavailableError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMProviderError,
    get_llm_provider,
)
from app.services.llm.context import build_finding_context
from app.services.llm.prompts import SYSTEM_PROMPT, build_user_message
from app.services.llm.schemas import (
    ANALYSIS_VERSION,
    LLMAnalysisResult,
    LLMUnavailableResult,
)

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """
    Stateless service that runs LLM analysis on a single Finding.

    Usage:
        analyzer = LLMAnalyzer(db)
        result = analyzer.analyze(finding)
    """

    def __init__(self, db: Session) -> None:
        self._db = db

    def analyze(
        self,
        finding,  # app.models.models.Finding — type hint kept loose to avoid circular import
        force: bool = False,
    ) -> Union[LLMAnalysisResult, LLMUnavailableResult]:
        """
        Perform LLM analysis on a finding.

        Returns LLMAnalysisResult on success.
        Returns LLMUnavailableResult on any failure or unavailability —
        NEVER raises an exception that would crash the scanner.

        Args:
            finding: A verified, access-controlled Finding ORM instance.
            force:   If True, skip cache and always call the provider.

        Returns:
            LLMAnalysisResult or LLMUnavailableResult.
        """
        # ── Step 1: Get provider (may raise LLMUnavailableError) ───────────
        try:
            provider = get_llm_provider()
        except LLMUnavailableError as exc:
            logger.info("LLM unavailable for finding %s: %s", finding.id, exc)
            return LLMUnavailableResult(reason=str(exc))

        from app.database import settings  # late import to avoid circular dep

        # ── Step 2: Build context ──────────────────────────────────────────
        max_chars = settings.LLM_MAX_CONTEXT_CHARS
        context = build_finding_context(
            finding=finding,
            provider=provider.provider_name,
            model=provider.model_name,
            max_chars=max_chars,
        )

        # ── Step 3: Check cache ────────────────────────────────────────────
        if not force:
            cached = self._get_cached_analysis(
                finding_id=finding.id,
                request_hash=context.request_hash,
            )
            if cached is not None:
                logger.info(
                    "Returning cached LLM analysis for finding %s (hash=%s)",
                    finding.id,
                    context.request_hash[:16],
                )
                return self._orm_to_result(cached)

        # ── Step 4: Build prompt and call provider ─────────────────────────
        user_message = build_user_message(context.text)

        logger.info(
            "Calling LLM provider=%s model=%s for finding %s",
            provider.provider_name,
            provider.model_name,
            finding.id,
        )
        # SECURITY: Never log user_message (contains repository data)
        # SECURITY: Never log the API key (handled in client.py)

        try:
            result = provider.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_message=user_message,
                timeout=settings.LLM_TIMEOUT_SECONDS,
            )
        except LLMTimeoutError as exc:
            logger.warning(
                "LLM timeout for finding %s: %s", finding.id, exc
            )
            return LLMUnavailableResult(
                reason=f"LLM request timed out after {settings.LLM_TIMEOUT_SECONDS}s."
            )
        except LLMRateLimitError as exc:
            logger.warning(
                "LLM rate limit for finding %s: %s", finding.id, exc
            )
            return LLMUnavailableResult(reason="LLM rate limit exceeded. Try again later.")
        except LLMProviderError as exc:
            logger.warning(
                "LLM provider error for finding %s: %s", finding.id, exc
            )
            return LLMUnavailableResult(reason=f"LLM provider error: {exc}")
        except Exception as exc:
            # Catch-all: LLM errors must NEVER propagate to the scanner
            logger.exception(
                "Unexpected LLM error for finding %s: %s", finding.id, type(exc).__name__
            )
            return LLMUnavailableResult(reason="Unexpected LLM error.")

        # ── Step 5: Stamp provider metadata ───────────────────────────────
        result.provider = provider.provider_name
        result.model = provider.model_name
        result.analysis_version = ANALYSIS_VERSION
        result.analyzed_at = datetime.utcnow()

        # ── Step 6: Persist ────────────────────────────────────────────────
        try:
            self._persist_analysis(
                finding_id=finding.id,
                result=result,
                request_hash=context.request_hash,
            )
        except Exception as exc:
            # DB failures are logged but not swallowed silently in isolation —
            # we still return the result to the caller (in-memory success).
            logger.exception(
                "Failed to persist LLM analysis for finding %s: %s",
                finding.id,
                type(exc).__name__,
            )
            # Return the result anyway — the caller can display it even if persistence failed.

        return result

    def get_latest_analysis(
        self, finding_id: str
    ) -> Optional[Union[LLMAnalysisResult, LLMUnavailableResult]]:
        """
        Return the most recent persisted analysis for a finding, or None if none exists.
        """
        from app.models.models import FindingLLMAnalysis

        record = (
            self._db.query(FindingLLMAnalysis)
            .filter(FindingLLMAnalysis.finding_id == finding_id)
            .order_by(FindingLLMAnalysis.created_at.desc())
            .first()
        )
        if record is None:
            return None
        return self._orm_to_result(record)

    # ── Private helpers ────────────────────────────────────────────────────

    def _get_cached_analysis(self, finding_id: str, request_hash: str):
        """Return a FindingLLMAnalysis ORM record if an identical analysis exists."""
        from app.models.models import FindingLLMAnalysis

        return (
            self._db.query(FindingLLMAnalysis)
            .filter(
                FindingLLMAnalysis.finding_id == finding_id,
                FindingLLMAnalysis.request_hash == request_hash,
                FindingLLMAnalysis.analysis_version == ANALYSIS_VERSION,
            )
            .order_by(FindingLLMAnalysis.created_at.desc())
            .first()
        )

    def _persist_analysis(
        self,
        finding_id: str,
        result: LLMAnalysisResult,
        request_hash: str,
    ) -> None:
        """Persist a new FindingLLMAnalysis row."""
        from app.models.models import FindingLLMAnalysis

        record = FindingLLMAnalysis(
            finding_id=finding_id,
            provider=result.provider,
            model=result.model,
            analysis_version=result.analysis_version,
            verdict=result.verdict if isinstance(result.verdict, str) else result.verdict.value,
            confidence=result.confidence,
            exploitability=result.exploitability,
            impact=result.impact,
            root_cause=result.root_cause,
            explanation=result.explanation,
            remediation=result.remediation,
            reasoning_summary=result.reasoning_summary,
            request_hash=request_hash,
            created_at=result.analyzed_at or datetime.utcnow(),
        )
        self._db.add(record)
        self._db.commit()
        self._db.refresh(record)

    @staticmethod
    def _orm_to_result(record) -> LLMAnalysisResult:
        """Convert a FindingLLMAnalysis ORM record to an LLMAnalysisResult."""
        return LLMAnalysisResult(
            verdict=record.verdict,
            confidence=record.confidence,
            exploitability=record.exploitability,
            impact=record.impact,
            root_cause=record.root_cause,
            explanation=record.explanation,
            remediation=record.remediation,
            reasoning_summary=record.reasoning_summary,
            provider=record.provider,
            model=record.model,
            analysis_version=record.analysis_version,
            analyzed_at=record.created_at,
        )
