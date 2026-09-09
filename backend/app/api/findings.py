"""
Findings API router — Phase 6.

GET  /api/findings/{finding_id}/remediation  — remediation details for a finding
POST /api/findings/{finding_id}/verify-fix   — statically verify a patch

All endpoints enforce ownership: the finding must belong to the current user's scan.
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.scans import get_db, PatchResponse, RemediationResponse, VerifyFixResponse
from app.database import SessionLocal
from app.models import Finding, Project, Repository, Scan, User

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/findings",
    tags=["Findings"],
)


# ---------------------------------------------------------------------------
# Ownership helpers
# ---------------------------------------------------------------------------

def get_owned_finding(
    finding_id: str,
    current_user: User,
    db: Session,
) -> Finding:
    """Verify the finding belongs to the current user via the ownership chain."""
    finding = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Repository, Scan.repository_id == Repository.id)
        .join(Project, Repository.project_id == Project.id)
        .filter(
            Finding.id == finding_id,
            Project.user_id == current_user.id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


# ---------------------------------------------------------------------------
# Remediation endpoint
# ---------------------------------------------------------------------------

@router.get("/{finding_id}/remediation", response_model=RemediationResponse)
def get_finding_remediation(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return full remediation details for a specific finding.

    Includes why_risky, impact, remediation steps, fix example, and patch if available.
    """
    finding = get_owned_finding(finding_id, current_user, db)

    patch = None
    if finding.patch_text:
        try:
            patch_dict = json.loads(finding.patch_text)
            patch = PatchResponse(**patch_dict)
        except Exception:
            pass

    return RemediationResponse(
        finding_id=finding.id,
        why_risky=finding.why_risky,
        impact=finding.impact,
        remediation=finding.remediation,
        fix_example=finding.fix_example,
        patch_available=finding.patch_available,
        patch=patch,
    )


# ---------------------------------------------------------------------------
# Verify-fix endpoint
# ---------------------------------------------------------------------------

class VerifyFixRequest(BaseModel):
    """Request body for static fix verification."""
    pass  # Currently uses finding's own patch; no additional params needed


@router.post("/{finding_id}/verify-fix", response_model=VerifyFixResponse)
def verify_fix(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Statically verify a finding's patch.

    Uses in-memory text replacement and re-analysis (where supported).
    NEVER executes repository code, install scripts, or shell commands.

    Returns:
      VERIFIED           — patch removes the finding
      PARTIALLY_VERIFIED — patch reduces but doesn't eliminate findings
      FAILED             — patch doesn't help or couldn't be applied
      NOT_VERIFIED       — no re-analysis function available for this file type
    """
    finding = get_owned_finding(finding_id, current_user, db)

    if not finding.patch_available or not finding.patch_text:
        return VerifyFixResponse(
            finding_id=finding_id,
            status="NOT_VERIFIED",
            message="No patch available for this finding.",
            original_findings=0,
            patched_findings=0,
        )

    # Parse patch
    try:
        patch_dict = json.loads(finding.patch_text)
        patch_original = patch_dict.get("original", "")
        patch_replacement = patch_dict.get("replacement", "")
    except Exception as exc:
        logger.warning("Failed to parse patch for finding %s: %s", finding_id, exc)
        return VerifyFixResponse(
            finding_id=finding_id,
            status="FAILED",
            message="Failed to parse patch data.",
            original_findings=0,
            patched_findings=0,
        )

    from app.services.scan_engine.scanner.risk_engine import (
        verify_patch_statically, VerificationStatus,
    )

    # We don't have access to the original file (it was cloned temporarily).
    # For Phase 6, we verify via content reconstruction from evidence + code_snippet.
    # This is a static text verification only.
    file_content = finding.code_snippet or finding.evidence or ""

    if not file_content or not patch_original:
        return VerifyFixResponse(
            finding_id=finding_id,
            status="NOT_VERIFIED",
            message="Insufficient file content for static verification.",
            original_findings=0,
            patched_findings=0,
        )

    # Determine re-analysis function based on file extension
    re_analyze_fn = None
    file_path = finding.file_path or ""
    lang = finding.language or ""

    if lang == "python" or file_path.endswith(".py"):
        from app.services.scan_engine.scanner.python_analyzer import analyze_python
        def re_analyze_fn(content, fp):
            return analyze_python(content, fp)
    elif lang in ("javascript", "typescript") or file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
        from app.services.scan_engine.scanner.js_analyzer import analyze_js
        def re_analyze_fn(content, fp):
            return analyze_js(content, fp)

    result = verify_patch_statically(
        original_content=file_content,
        patch_original=patch_original,
        patch_replacement=patch_replacement,
        re_analyze_fn=re_analyze_fn,
        file_path=file_path,
    )

    return VerifyFixResponse(
        finding_id=finding_id,
        status=result["status"],
        message=result["message"],
        original_findings=result["original_findings"],
        patched_findings=result["patched_findings"],
    )
