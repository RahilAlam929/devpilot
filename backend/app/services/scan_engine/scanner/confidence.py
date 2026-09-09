"""
Confidence Scorer.

Adjusts the raw base_confidence from a rule up or down based on
contextual signals collected during analysis.

Confidence scale: 0-100
  80-100  HIGH   — strong evidence, AST-confirmed, clear source→sink flow
  50-79   MEDIUM — reasonable evidence, partial flow, or regex-only
  0-49    LOW    — weak evidence, ambiguous, no flow data

The scorer does NOT set finding.confidence directly; callers apply it
after constructing the finding so the logic is testable in isolation.
"""

from __future__ import annotations

from app.services.scan_engine.findings.types import ConfidenceLevel, RichFindingResult


# ---------------------------------------------------------------------------
# Signal weights
# ---------------------------------------------------------------------------

# Positive signals (add to confidence)
_BOOST_USER_CONTROLLED_SOURCE  = +20  # source is clearly user-controlled
_BOOST_DIRECT_FLOW             = +15  # source reaches sink with no branching
_BOOST_NO_SANITIZER            = +10  # no sanitizer detected in the flow
_BOOST_AST_CONFIRMED           = +10  # AST analysis confirmed the pattern
_BOOST_FRAMEWORK_CONTEXT       = +5   # framework confirms source (e.g. FastAPI Request)
_BOOST_SINK_KNOWN              = +5   # sink API is well-known and dangerous

# Negative signals (subtract from confidence)
_PENALTY_SANITIZER_PRESENT     = -25  # a sanitizer was found in the flow
_PENALTY_CONSTANT_SOURCE       = -30  # source appears to be a constant/literal
_PENALTY_REGEX_ONLY            = -15  # only regex evidence, no AST
_PENALTY_INCOMPLETE_FLOW       = -10  # flow is partial / not fully traced
_PENALTY_GENERATED_FILE        = -20  # file is generated (lower analysis reliability)
_PENALTY_AMBIGUOUS_SYNTAX      = -10  # syntax was ambiguous or partially parsed


def score_confidence(
    base: int,
    *,
    has_user_controlled_source: bool = False,
    has_direct_flow: bool = False,
    has_sanitizer: bool = False,
    is_ast_confirmed: bool = False,
    has_framework_context: bool = False,
    sink_is_known: bool = False,
    source_is_constant: bool = False,
    is_regex_only: bool = True,
    flow_is_incomplete: bool = False,
    is_generated_file: bool = False,
    syntax_is_ambiguous: bool = False,
) -> int:
    """
    Compute a final confidence score (0-100) from a base value and signals.

    Parameters mirror the boolean signals collected by analyzers.
    All keyword args default to the most conservative (lowest-confidence)
    assumption so callers only need to set the signals they have evidence for.
    """
    score = base

    if has_user_controlled_source:
        score += _BOOST_USER_CONTROLLED_SOURCE
    if has_direct_flow:
        score += _BOOST_DIRECT_FLOW
    if not has_sanitizer:
        score += _BOOST_NO_SANITIZER
    if is_ast_confirmed:
        score += _BOOST_AST_CONFIRMED
    if has_framework_context:
        score += _BOOST_FRAMEWORK_CONTEXT
    if sink_is_known:
        score += _BOOST_SINK_KNOWN

    if has_sanitizer:
        score += _PENALTY_SANITIZER_PRESENT
    if source_is_constant:
        score += _PENALTY_CONSTANT_SOURCE
    if is_regex_only:
        score += _PENALTY_REGEX_ONLY
    if flow_is_incomplete:
        score += _PENALTY_INCOMPLETE_FLOW
    if is_generated_file:
        score += _PENALTY_GENERATED_FILE
    if syntax_is_ambiguous:
        score += _PENALTY_AMBIGUOUS_SYNTAX

    return max(0, min(100, score))


def confidence_level(score: int) -> str:
    """Convert numeric score to ConfidenceLevel label."""
    if score >= 80:
        return ConfidenceLevel.HIGH.value
    if score >= 50:
        return ConfidenceLevel.MEDIUM.value
    return ConfidenceLevel.LOW.value


def apply_confidence(
    finding: RichFindingResult,
    **kwargs: bool,
) -> RichFindingResult:
    """
    Compute and assign confidence fields on *finding* in place.

    The rule's base_confidence is looked up from the registry if the
    finding.confidence is still at the default (50). Otherwise the
    existing value is used as base.

    Extra keyword arguments are forwarded to score_confidence().
    """
    from app.services.scan_engine.scanner.rules import get_rule

    # Determine base from rule registry if available
    base = finding.confidence
    if base == 50 and finding.rule_id:
        rule = get_rule(finding.rule_id)
        if rule:
            base = rule.base_confidence

    final = score_confidence(base, **kwargs)
    finding.confidence = final
    finding.confidence_level = confidence_level(final)
    return finding
