"""
LLM Analysis API router — Phase 7B.

Endpoints:

  POST /api/scans/{scan_id}/findings/{finding_id}/analyze
    Trigger LLM analysis for a specific finding.
    Returns cached result if request_hash + analysis_version already exists.
    Returns 503 with controlled error if LLM is unavailable/disabled.

  GET  /api/scans/{scan_id}/findings/{finding_id}/analysis
    Retrieve the latest stored LLM analysis for a finding.
    Returns 404 if no analysis has been run yet.

SECURITY:
  - Both endpoints require authentication (get_current_user).
  - Ownership is enforced through the full chain:
      User → Project → Repository → Scan → Finding
  - The finding must belong to the specified scan_id (not just any scan).
  - Cross-user access is rejected at every layer.
  - API keys are NEVER returned, logged, or included in any response.
  - Raw prompts are NEVER returned in any response.
  - Chain-of-thought is NEVER stored or returned.
  - The existing Finding severity is NEVER modified by this endpoint.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.scans import get_db, get_owned_scan
from app.models import Finding, Project, Repository, Scan, User
from app.services.llm.analyzer import LLMAnalyzer
from app.services.llm.schemas import ANALYSIS_VERSION, LLMAnalysisResult, LLMUnavailableResult

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/scans",
    tags=["LLM Analysis"],
)


# ── Response schemas ───────────────────────────────────────────────────────


class LLMAnalysisResponse(BaseModel):
    """
    Structured LLM analysis result returned to the client.

    SECURITY: Never includes raw prompts, API keys, or chain-of-thought.
    The reasoning_summary is a short, user-visible audit trail only.
    """

    available: bool = True

    # Verdict and scores
    verdict: str
    confidence: float
    exploitability: float

    # Intelligence
    impact: str
    root_cause: str
    explanation: str
    remediation: str
    reasoning_summary: str

    # Research / metadata
    provider: str
    model: str
    analysis_version: str
    analyzed_at: Optional[datetime] = None

    # Linking
    finding_id: str

    class Config:
        from_attributes = True


class LLMUnavailableResponse(BaseModel):
    """Returned when LLM analysis is not available for any reason."""

    available: bool = False
    reason: str
    finding_id: str


# ── Ownership helper ───────────────────────────────────────────────────────


def get_owned_finding_in_scan(
    scan_id: str,
    finding_id: str,
    current_user: User,
    db: Session,
) -> Finding:
    """
    Return the Finding if:
      1. It belongs to the given scan_id.
      2. That scan belongs to a repository owned by current_user.

    Raises 404 if any link in the chain is broken or ownership fails.
    This prevents:
      - Cross-user access
      - Accessing a finding from a different scan
      - Accessing non-existent findings
    """
    finding = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Repository, Scan.repository_id == Repository.id)
        .join(Project, Repository.project_id == Project.id)
        .filter(
            Finding.id == finding_id,
            Finding.scan_id == scan_id,   # Must belong to THIS scan
            Project.user_id == current_user.id,
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found in the specified scan.",
        )

    return finding


# ── POST: Trigger analysis ─────────────────────────────────────────────────


@router.post(
    "/{scan_id}/findings/{finding_id}/analyze",
    response_model=LLMAnalysisResponse,
    responses={
        200: {"description": "Analysis result (may be cached)"},
        404: {"description": "Finding or scan not found"},
        503: {"description": "LLM unavailable", "model": LLMUnavailableResponse},
    },
)
def analyze_finding(
    scan_id: str,
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Trigger LLM analysis for a finding.

    Returns cached analysis if the same request_hash + analysis_version exists.
    Returns 503 (LLM unavailable) if the LLM is disabled, misconfigured,
    timed out, or otherwise unavailable. This is never a hard error.

    SECURITY:
    - Authenticates via JWT cookie.
    - Verifies the finding belongs to scan_id AND to the current user.
    - Never modifies the existing finding severity.
    - Never returns the prompt, API key, or chain-of-thought.
    """
    # Verify ownership: finding must belong to this scan and this user
    finding = get_owned_finding_in_scan(scan_id, finding_id, current_user, db)

    analyzer = LLMAnalyzer(db)
    result = analyzer.analyze(finding)

    if isinstance(result, LLMUnavailableResult):
        logger.info(
            "LLM analysis unavailable for finding %s (scan %s): %s",
            finding_id,
            scan_id,
            result.reason,
        )
        raise HTTPException(
            status_code=503,
            detail={
                "available": False,
                "reason": result.reason,
                "finding_id": finding_id,
            },
        )

    return LLMAnalysisResponse(
        available=True,
        verdict=result.verdict if isinstance(result.verdict, str) else result.verdict.value,
        confidence=result.confidence,
        exploitability=result.exploitability,
        impact=result.impact,
        root_cause=result.root_cause,
        explanation=result.explanation,
        remediation=result.remediation,
        reasoning_summary=result.reasoning_summary,
        provider=result.provider,
        model=result.model,
        analysis_version=result.analysis_version,
        analyzed_at=result.analyzed_at,
        finding_id=finding_id,
    )


# ── GET: Retrieve latest analysis ──────────────────────────────────────────


@router.get(
    "/{scan_id}/findings/{finding_id}/analysis",
    response_model=LLMAnalysisResponse,
    responses={
        200: {"description": "Latest stored LLM analysis"},
        404: {"description": "Finding, scan, or analysis not found"},
    },
)
def get_finding_analysis(
    scan_id: str,
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieve the latest stored LLM analysis for a finding.

    Returns 404 if:
    - The finding does not exist.
    - The finding does not belong to the specified scan.
    - The finding does not belong to the current user.
    - No LLM analysis has been run for this finding yet.

    SECURITY:
    - Authenticates via JWT cookie.
    - Enforces full ownership chain.
    - Never returns the prompt, API key, or chain-of-thought.
    """
    # Verify ownership: finding must belong to this scan and this user
    finding = get_owned_finding_in_scan(scan_id, finding_id, current_user, db)

    analyzer = LLMAnalyzer(db)
    result = analyzer.get_latest_analysis(finding.id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="No LLM analysis found for this finding. Call POST .../analyze first.",
        )

    if isinstance(result, LLMUnavailableResult):
        # This shouldn't happen via get_latest_analysis (it returns None or a real result)
        # but handle it defensively.
        raise HTTPException(
            status_code=404,
            detail="No valid LLM analysis stored for this finding.",
        )

    return LLMAnalysisResponse(
        available=True,
        verdict=result.verdict if isinstance(result.verdict, str) else result.verdict.value,
        confidence=result.confidence,
        exploitability=result.exploitability,
        impact=result.impact,
        root_cause=result.root_cause,
        explanation=result.explanation,
        remediation=result.remediation,
        reasoning_summary=result.reasoning_summary,
        provider=result.provider,
        model=result.model,
        analysis_version=result.analysis_version,
        analyzed_at=result.analyzed_at,
        finding_id=finding_id,
    )
