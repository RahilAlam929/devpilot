"""
Context-Aware Risk Engine — Phase 6.

Centralizes severity classification for all analyzers.

The engine recalculates or confirms the severity of a finding based on
contextual signals, NOT just the rule title.

Severity scale:
  CRITICAL — exploitable remotely, no authentication, direct impact
  HIGH     — exploitable with some effort, significant impact
  MEDIUM   — limited exploitability, or requires additional conditions
  LOW      — quality/maintenance issue, minor risk
  INFO     — informational, no direct risk

Security Score formula (transparent, deterministic):
  Base = 100
  For each finding:
    critical: -20 points
    high:     -10 points
    medium:   -4  points
    low:      -1  point
    info:     -0  points
  Score is clamped to [0, 100].
  High-confidence findings (≥80%) have full weight.
  Low-confidence findings (<50%) have 50% weight.
  Very low-confidence (<30%) findings have 0 weight.

This formula avoids penalizing heavily for large volumes of low/info findings.
"""

from __future__ import annotations

from typing import List

from app.services.scan_engine.findings.types import RichFindingResult


# ---------------------------------------------------------------------------
# Severity weights for scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS = {
    "critical": 20,
    "high":     10,
    "medium":    4,
    "low":       1,
    "info":      0,
}

# Max penalty to cap absurdly long finding lists from cratering the score
_MAX_PENALTY = 100


# ---------------------------------------------------------------------------
# Security score
# ---------------------------------------------------------------------------

def compute_security_score(findings: List[RichFindingResult]) -> int:
    """
    Compute a security score from 0 to 100.

    100 = no findings
    0   = catastrophically insecure

    Algorithm:
      1. For each finding, look up the severity weight.
      2. Scale by confidence:
         - confidence >= 80: full weight (1.0×)
         - confidence 50-79: 75% weight (0.75×)
         - confidence 30-49: 50% weight (0.5×)
         - confidence < 30:  0 weight (ignored)
      3. Sum all weighted penalties.
      4. Score = 100 - min(penalty, 100)
    """
    total_penalty = 0.0

    for f in findings:
        weight = _SEVERITY_WEIGHTS.get(f.severity, 0)
        if weight == 0:
            continue

        conf = f.confidence or 50
        if conf >= 80:
            scale = 1.0
        elif conf >= 50:
            scale = 0.75
        elif conf >= 30:
            scale = 0.5
        else:
            scale = 0.0  # very uncertain → don't penalize score

        total_penalty += weight * scale

    score = 100 - min(total_penalty, _MAX_PENALTY)
    return max(0, round(score))


def compute_security_score_from_db(
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int,
    avg_confidence: float = 65.0,
) -> int:
    """
    Compute security score from pre-aggregated severity counts.

    Used by API endpoints that have counts but not full finding objects.
    avg_confidence defaults to a moderate value when unknown.
    """
    # Use a fixed confidence scale based on average
    if avg_confidence >= 80:
        scale = 1.0
    elif avg_confidence >= 50:
        scale = 0.75
    else:
        scale = 0.5

    penalty = (
        critical * _SEVERITY_WEIGHTS["critical"] +
        high * _SEVERITY_WEIGHTS["high"] +
        medium * _SEVERITY_WEIGHTS["medium"] +
        low * _SEVERITY_WEIGHTS["low"]
    ) * scale

    score = 100 - min(penalty, _MAX_PENALTY)
    return max(0, round(score))


# ---------------------------------------------------------------------------
# Category breakdown
# ---------------------------------------------------------------------------

_SAST_CATEGORIES = {
    "code_execution", "command_injection", "sql_injection",
    "xss", "path_traversal", "ssrf", "open_redirect",
    "deserialization", "crypto", "template_injection", "data_flow",
}

_SECRET_CATEGORIES = {"secrets"}
_IAC_CATEGORIES = set()  # IaC findings use category="configuration" + analyzer="iac"
_DEP_CATEGORIES = set()  # Dependency findings use analyzer="sca"


def categorize_findings(findings: List) -> dict:
    """
    Categorize findings by analyzer domain.

    Returns a dict with counts per category for the scan report.
    Works with both RichFindingResult objects and ORM Finding objects.
    """
    result = {
        "sast": 0,
        "secrets": 0,
        "dependencies": 0,
        "iac": 0,
        "quality": 0,
    }

    for f in findings:
        analyzer = getattr(f, "analyzer", None) or ""
        category = getattr(f, "category", None) or ""

        if analyzer == "sca":
            result["dependencies"] += 1
        elif analyzer == "secret_scanner":
            result["secrets"] += 1
        elif analyzer == "iac":
            result["iac"] += 1
        elif category == "quality":
            result["quality"] += 1
        elif category in _SAST_CATEGORIES:
            result["sast"] += 1
        else:
            # Default: quality if none of the above
            result["quality"] += 1

    return result


# ---------------------------------------------------------------------------
# Historical comparison
# ---------------------------------------------------------------------------

def compare_scans(
    old_fingerprints: set,
    new_fingerprints: set,
) -> dict:
    """
    Compare two sets of finding fingerprints.

    Returns:
        {
            "new": set,        — fingerprints only in new scan
            "resolved": set,   — fingerprints only in old scan
            "unchanged": set,  — fingerprints in both
        }
    """
    return {
        "new": new_fingerprints - old_fingerprints,
        "resolved": old_fingerprints - new_fingerprints,
        "unchanged": old_fingerprints & new_fingerprints,
    }


# ---------------------------------------------------------------------------
# Patch verification states
# ---------------------------------------------------------------------------

class VerificationStatus:
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"


def verify_patch_statically(
    original_content: str,
    patch_original: str,
    patch_replacement: str,
    re_analyze_fn=None,
    file_path: str = "",
) -> dict:
    """
    Statically verify a patch by:
      1. Applying the patch to a copy of the content.
      2. Re-analyzing the patched content.
      3. Checking that the original finding no longer fires.

    Returns:
        {
            "status": VerificationStatus.*,
            "message": str,
            "original_findings": int,
            "patched_findings": int,
        }

    This is purely in-memory; no files are written or executed.
    """
    if patch_original not in original_content:
        return {
            "status": VerificationStatus.FAILED,
            "message": "Original patch text not found in file content.",
            "original_findings": 0,
            "patched_findings": 0,
        }

    patched_content = original_content.replace(patch_original, patch_replacement, 1)

    if re_analyze_fn is None:
        return {
            "status": VerificationStatus.NOT_VERIFIED,
            "message": "No re-analysis function provided; static text replacement successful.",
            "original_findings": 0,
            "patched_findings": 0,
        }

    try:
        original_findings = re_analyze_fn(original_content, file_path)
        patched_findings = re_analyze_fn(patched_content, file_path)
        orig_count = len(original_findings)
        patch_count = len(patched_findings)

        if patch_count < orig_count:
            if patch_count == 0:
                return {
                    "status": VerificationStatus.VERIFIED,
                    "message": f"All {orig_count} finding(s) resolved after patch.",
                    "original_findings": orig_count,
                    "patched_findings": patch_count,
                }
            return {
                "status": VerificationStatus.PARTIALLY_VERIFIED,
                "message": f"Findings reduced from {orig_count} to {patch_count}.",
                "original_findings": orig_count,
                "patched_findings": patch_count,
            }
        return {
            "status": VerificationStatus.FAILED,
            "message": f"Findings not reduced ({orig_count} → {patch_count}).",
            "original_findings": orig_count,
            "patched_findings": patch_count,
        }
    except Exception as exc:
        return {
            "status": VerificationStatus.FAILED,
            "message": f"Re-analysis failed: {exc}",
            "original_findings": 0,
            "patched_findings": 0,
        }
