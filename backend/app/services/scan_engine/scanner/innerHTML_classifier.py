"""
innerHTML Source-to-Sink Classifier.

Provides backward-trace analysis for innerHTML / outerHTML /
insertAdjacentHTML assignments to reduce false positives when the assigned
value is provably a static constant or trusted internal markup.

Strategy
--------
1. Extract the Right-Hand Side (RHS) expression from the assignment line.
2. Walk *backward* through the surrounding lines (up to TRACE_WINDOW) to
   find where the variable or expression originates.
3. Classify the origin into one of six source classes.
4. Return a ClassificationResult with the source class, adjusted severity,
   confidence delta, and human-readable evidence strings.

Source classes
--------------
USER_INPUT       — form input, event.target.value, userInput, inputValue …
URL_DATA         — location.search/hash/href, URLSearchParams, req.query …
API_RESPONSE     — fetch/XHR response bodies, axios responses …
EXTERNAL_DATA    — WebSocket messages, postMessage, localStorage/sessionStorage
STATIC_CONSTANT  — string literals, template literals with no ${} interpolation,
                   const/let assigned to a pure string
TRUSTED_INTERNAL — SVG markup, icon templates, UI skeletons built from
                   known-safe constants (no external input)
UNKNOWN          — origin could not be determined within the trace window

Severity / confidence mapping
------------------------------
USER_INPUT       → high,   confidence +20
URL_DATA         → high,   confidence +15
API_RESPONSE     → medium, confidence +5
EXTERNAL_DATA    → medium, confidence +5
STATIC_CONSTANT  → info,   confidence −30
TRUSTED_INTERNAL → info,   confidence −35
UNKNOWN          → medium, confidence  −5  (manual review required)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRACE_WINDOW = 15   # lines to scan backward from the sink
MAX_VAR_HOPS = 4    # max number of variable-alias hops to follow

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SourceClass(str, Enum):
    USER_INPUT       = "user_input"
    URL_DATA         = "url_data"
    API_RESPONSE     = "api_response"
    EXTERNAL_DATA    = "external_data"
    STATIC_CONSTANT  = "static_constant"
    TRUSTED_INTERNAL = "trusted_internal"
    UNKNOWN          = "unknown"


# ---------------------------------------------------------------------------
# Pattern banks
# ---------------------------------------------------------------------------

# User-controlled input sources
_USER_INPUT_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bevent\.target\.value\b"),
    re.compile(r"\binputValue\b"),
    re.compile(r"\buserInput\b"),
    re.compile(r"\buserData\b"),
    re.compile(r"\bFormData\b"),
    re.compile(r"\btextarea\b.*\.value\b"),
    re.compile(r"\.value\b"),           # generic .value (input/textarea/select)
    re.compile(r"\bgetElementById\b.*\.value\b"),
    re.compile(r"\bquerySelector\b.*\.value\b"),
]

# URL / navigation data sources
_URL_DATA_PATTERNS: List[re.Pattern] = [
    re.compile(r"\blocation\.(?:search|hash|href|pathname)\b"),
    re.compile(r"\bURLSearchParams\b"),
    re.compile(r"\bsearchParams\.get\b"),
    re.compile(r"\bnew\s+URL\s*\("),
    re.compile(r"\bwindow\.location\b"),
    re.compile(r"\bhistory\.(?:state|pushState|replaceState)\b"),
    re.compile(r"\bparams\["),
    re.compile(r"\bparams\."),
    re.compile(r"\breq\.(?:query|params)\b"),
    re.compile(r"\brequest\.(?:query|params)\b"),
    re.compile(r"\bwindow\.name\b"),
    re.compile(r"\bdocument\.referrer\b"),
    re.compile(r"\bdocument\.cookie\b"),
]

# HTTP / API response sources
_API_RESPONSE_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\baxios\b"),
    re.compile(r"\.(?:json|text|formData)\s*\(\s*\)"),
    re.compile(r"\bXMLHttpRequest\b"),
    re.compile(r"\bxhr\.response(?:Text)?\b"),
    re.compile(r"\bresponse\.(?:data|body|text|json)\b"),
    re.compile(r"\bres\.(?:data|body|text|json)\b"),
    re.compile(r"\bdata\s*=\s*await\b"),
    re.compile(r"\bawait\s+fetch\b"),
    re.compile(r"\bawait\s+axios\b"),
    re.compile(r"\breq\.body\b"),
    re.compile(r"\brequest\.body\b"),
    re.compile(r"\brequest\.(?:json|formData|text)\b"),
]

# External/untrusted channel sources
_EXTERNAL_DATA_PATTERNS: List[re.Pattern] = [
    re.compile(r"\blocalStorage\.getItem\b"),
    re.compile(r"\bsessionStorage\.getItem\b"),
    re.compile(r"\bpostMessage\b"),
    re.compile(r"\bevent\.data\b"),
    re.compile(r"\bWebSocket\b"),
    re.compile(r"\bmessageEvent\.data\b"),
    re.compile(r"\bcookies?\["),
    re.compile(r"\bgetCookie\s*\("),
]

# Trusted internal / SVG / icon patterns (not user-facing data)
_TRUSTED_INTERNAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bsvg\s*=\s*`<svg\b"),           # SVG template literal
    re.compile(r"=\s*`\s*<svg\b"),                  # backtick SVG
    re.compile(r"=\s*\"<svg\b"),                    # double-quoted SVG
    re.compile(r"=\s*'<svg\b"),                     # single-quoted SVG
    re.compile(r"\bconst\s+\w+\s*=\s*`[^$`]+`"),   # template literal without ${}
    re.compile(r"\bconst\s+ICON\w*\s*="),           # const ICON... pattern
    re.compile(r"\bconst\s+SVG\w*\s*="),            # const SVG... pattern
    re.compile(r"\bconst\s+\w*[Ii]con\w*\s*="),    # const ...icon... pattern
    re.compile(r"\bconst\s+\w*[Tt]emplate\w*\s*="),# const ...template... pattern
    re.compile(r"\bconst\s+\w*[Mm]arkup\w*\s*="),  # const ...markup... pattern
    re.compile(r"\bconst\s+\w*[Hh]tml\w*\s*=\s*`[^$`]+`"),  # const ...html = `...` no interp
]

# Sanitizer patterns — presence near sink indicates mitigation attempt
_SANITIZER_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bDOMPurify\.(?:sanitize|isValidHTMLId)\b"),
    re.compile(r"\bsanitize(?:Html|HTML)?\s*\("),
    re.compile(r"\bescape(?:Html|HTML)?\s*\("),
    re.compile(r"\bencodeURIComponent\s*\("),
    re.compile(r"\bxss\b.*\("),               # xss() library
    re.compile(r"\bvalidate\s*\("),
]

# Pure string-literal RHS patterns (no variable interpolation)
_PURE_STRING_RE = re.compile(
    r"""^\s*(?:
        \"[^\"]*\"          |   # double-quoted, no variable
        '[^']*'             |   # single-quoted, no variable
        `[^`$]*`            |   # template literal, no ${...}
        \"\"\s*\+\s*\"[^\"]*\"  # simple string concat of literals
    )\s*(?:\.trim\(\))?\s*$""",
    re.VERBOSE,
)

# Template literal that DOES contain interpolation
_INTERPOLATED_TEMPLATE_RE = re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`")

# Variable assignment pattern: (const|let|var) <name> = <rhs>
_VAR_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|\s*$)"
)

# Simple reassignment: <name> = <rhs>  (without let/const/var)
_REASSIGN_RE = re.compile(
    r"^(?!\s*(?:const|let|var|function|class|if|else|return|//|/\*|\*|export|import))"
    r"\s*(\w+)\s*=\s*(.+?)(?:;|\s*$)"
)

# Method-call transform patterns (trim, slice, replace, etc.) — these don't
# change the taint class of the underlying value
_TRANSFORM_CALL_RE = re.compile(
    r"^(\w+)\s*\.\s*(?:trim|slice|substring|replace|replaceAll|split|join|"
    r"toUpperCase|toLowerCase|padStart|padEnd)\s*\("
)

# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------


@dataclass
class ClassificationResult:
    """Result of classifying the source for an innerHTML-style sink."""

    source_class: SourceClass
    """The determined origin class of the value reaching the sink."""

    severity: str
    """Suggested severity: 'critical' | 'high' | 'medium' | 'low' | 'info'."""

    confidence_delta: int
    """Adjustment to apply to the base confidence score (−35 … +20)."""

    evidence: str
    """Single-line evidence string for why this classification was chosen."""

    data_flow_hint: List[str] = field(default_factory=list)
    """Ordered list of assignment steps traced backward (for reporting)."""

    sanitizer_detected: bool = False
    """True if a sanitizer was found near the sink or in the traced chain."""

    is_false_positive_candidate: bool = False
    """True when the source is provably static/internal — likely not XSS."""

    manual_review: bool = False
    """True when the origin is unknown and human review is recommended."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_innerHTML_source(
    lines: List[str],
    sink_line_idx: int,   # 0-based
    rhs_expr: str,        # the expression on the RHS of the assignment
) -> ClassificationResult:
    """
    Classify the source of an innerHTML/outerHTML/insertAdjacentHTML assignment.

    Parameters
    ----------
    lines:
        All lines of the file (0-indexed).
    sink_line_idx:
        0-based index of the assignment line.
    rhs_expr:
        The RHS expression extracted from the assignment (e.g. ``html.trim()``).

    Returns
    -------
    ClassificationResult
        Full classification with severity suggestion, confidence delta, and
        evidence strings.
    """
    rhs = rhs_expr.strip()
    if not rhs:
        return _unknown_result("Empty RHS expression")

    # ── 1. Direct RHS classification (no variable lookup needed) ──────────
    direct = _classify_expression(rhs)
    if direct is not None:
        result = _build_result(direct, rhs, sanitizer=False)
        result.data_flow_hint = [f"rhs: {rhs[:60]}"]
        # Check for sanitizer on the same line or nearby
        result.sanitizer_detected = _has_sanitizer_nearby(lines, sink_line_idx)
        if result.sanitizer_detected:
            result.severity = _downgrade_severity(result.severity)
            result.confidence_delta -= 10
            result.evidence += " (sanitizer detected nearby)"
        return result

    # ── 2. If RHS is a variable, trace it backward ────────────────────────
    root_var = _extract_root_variable(rhs)
    if root_var:
        traced, flow = _trace_variable(lines, sink_line_idx, root_var)
        if traced is not None:
            result = _build_result(traced, root_var, sanitizer=False)
            result.data_flow_hint = flow + [f"sink: {lines[sink_line_idx].strip()[:60]}"]
            result.sanitizer_detected = _has_sanitizer_nearby(lines, sink_line_idx)
            if result.sanitizer_detected:
                result.severity = _downgrade_severity(result.severity)
                result.confidence_delta -= 10
                result.evidence += " (sanitizer detected nearby)"
            return result

    # ── 3. Fallback: scan context window for any known patterns ───────────
    fallback = _scan_context_window(lines, sink_line_idx)
    if fallback is not None:
        result = _build_result(fallback, "context window scan", sanitizer=False)
        result.sanitizer_detected = _has_sanitizer_nearby(lines, sink_line_idx)
        return result

    # ── 4. Truly unknown ──────────────────────────────────────────────────
    result = _unknown_result(
        f"Could not trace origin of '{rhs[:40]}' within {TRACE_WINDOW} lines"
    )
    result.sanitizer_detected = _has_sanitizer_nearby(lines, sink_line_idx)
    return result


def extract_innerHTML_rhs(line: str) -> str:
    """
    Extract the RHS expression from an innerHTML/outerHTML/insertAdjacentHTML
    assignment line.

    Examples
    --------
    ``el.innerHTML = userInput;``         → ``userInput``
    ``template.innerHTML = html.trim();`` → ``html.trim()``
    ``el.insertAdjacentHTML('beforeend', content)`` → ``content``
    ``el.outerHTML = '<b>static</b>';``   → ``'<b>static</b>'``
    """
    # insertAdjacentHTML('position', value) — extract second argument
    m = re.search(
        r"\.insertAdjacentHTML\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(.+?)\s*\)\s*;?\s*$",
        line,
    )
    if m:
        return m.group(1).strip()

    # innerHTML = / outerHTML =
    m = re.search(r"\.(?:innerHTML|outerHTML)\s*=\s*(.+?)(?:;)?\s*$", line)
    if m:
        return m.group(1).strip()

    return ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _classify_expression(expr: str) -> Optional[SourceClass]:
    """
    Classify a single expression string into a SourceClass.

    Returns None if the expression is just a variable name (needs tracing).
    """
    # Pure string literal (no variable interpolation) → STATIC_CONSTANT
    if _PURE_STRING_RE.match(expr):
        return SourceClass.STATIC_CONSTANT

    # Empty string or just whitespace
    if not expr or expr in ('""', "''", "``"):
        return SourceClass.STATIC_CONSTANT

    # Template literal with no interpolation → TRUSTED_INTERNAL or STATIC
    if re.match(r"`[^`$]*`", expr):
        return SourceClass.STATIC_CONSTANT

    # Template literal WITH interpolation — check what's being interpolated
    if _INTERPOLATED_TEMPLATE_RE.match(expr):
        # The interpolated expression might itself be user-controlled —
        # return None so the caller traces the variable
        return None

    # Match known source pattern banks against the full expression
    for pat in _USER_INPUT_PATTERNS:
        if pat.search(expr):
            return SourceClass.USER_INPUT
    for pat in _URL_DATA_PATTERNS:
        if pat.search(expr):
            return SourceClass.URL_DATA
    for pat in _API_RESPONSE_PATTERNS:
        if pat.search(expr):
            return SourceClass.API_RESPONSE
    for pat in _EXTERNAL_DATA_PATTERNS:
        if pat.search(expr):
            return SourceClass.EXTERNAL_DATA
    for pat in _TRUSTED_INTERNAL_PATTERNS:
        if pat.search(expr):
            return SourceClass.TRUSTED_INTERNAL

    return None  # simple variable name or unrecognised expression


def _extract_root_variable(expr: str) -> Optional[str]:
    """
    Extract the root variable name from an expression.

    ``html.trim()``   → ``html``
    ``svg``           → ``svg``
    ``content + ''``  → None  (complex expression, not a simple variable)
    ``3``             → None  (numeric literal)
    """
    # Strip method calls and property accesses
    m = re.match(r"^([A-Za-z_$][\w$]*)\b", expr.strip())
    if m:
        return m.group(1)
    return None


def _trace_variable(
    lines: List[str],
    start_idx: int,
    var_name: str,
    hops: int = 0,
) -> Tuple[Optional[SourceClass], List[str]]:
    """
    Walk backward from *start_idx* to find the definition of *var_name*.

    Returns (SourceClass or None, list-of-flow-steps).
    """
    if hops >= MAX_VAR_HOPS:
        return None, []

    search_start = max(0, start_idx - TRACE_WINDOW)
    flow: List[str] = []

    # Scan backward
    for idx in range(start_idx - 1, search_start - 1, -1):
        line = lines[idx]
        line_stripped = line.strip()

        # Skip comment lines
        if line_stripped.startswith("//") or line_stripped.startswith("*"):
            continue

        # Try to match an assignment of the variable we're looking for
        rhs_for_var = _find_assignment_rhs(line_stripped, var_name)
        if rhs_for_var is None:
            continue

        flow.append(f"line {idx + 1}: {var_name} = {rhs_for_var[:50]}")

        # Classify the RHS of this assignment
        cls = _classify_expression(rhs_for_var)
        if cls is not None:
            return cls, flow

        # The RHS is itself a variable — recurse
        next_var = _extract_root_variable(rhs_for_var)
        if next_var and next_var != var_name:
            deeper_cls, deeper_flow = _trace_variable(lines, idx, next_var, hops + 1)
            if deeper_cls is not None:
                return deeper_cls, flow + deeper_flow

        # RHS is complex / unresolvable at this hop
        return None, flow

    return None, flow


def _find_assignment_rhs(line: str, var_name: str) -> Optional[str]:
    """
    If *line* assigns to *var_name*, return the RHS string; else None.
    Handles:
      const/let/var name = rhs
      name = rhs
      name: Type = rhs   (TypeScript)
    """
    # const/let/var name = rhs
    m = re.match(
        r"(?:const|let|var)\s+" + re.escape(var_name) + r"\s*(?::\s*\w[\w<>\[\]|, .]*)?\s*=\s*(.+)",
        line,
    )
    if m:
        rhs = m.group(1).rstrip(";").strip()
        return rhs if rhs else None

    # Simple reassignment: name = rhs  (not preceded by const/let/var/if/return)
    m = re.match(
        r"^" + re.escape(var_name) + r"\s*(?::\s*\w[\w<>\[\]|, .]*)?\s*=\s*(.+)",
        line,
    )
    if m:
        rhs = m.group(1).rstrip(";").strip()
        # Filter out comparison operators (== ===)
        if rhs.startswith("="):
            return None
        return rhs if rhs else None

    return None


def _scan_context_window(
    lines: List[str],
    sink_idx: int,
) -> Optional[SourceClass]:
    """
    As a last resort, scan ±TRACE_WINDOW lines for any recognizable source
    pattern.  Returns the highest-priority source class found, or None.
    """
    start = max(0, sink_idx - TRACE_WINDOW)
    end = min(len(lines), sink_idx + 3)
    window = lines[start:end]

    # Priority order: user input > url > api > external > static
    for pat in _USER_INPUT_PATTERNS:
        if any(pat.search(ln) for ln in window):
            return SourceClass.USER_INPUT
    for pat in _URL_DATA_PATTERNS:
        if any(pat.search(ln) for ln in window):
            return SourceClass.URL_DATA
    for pat in _API_RESPONSE_PATTERNS:
        if any(pat.search(ln) for ln in window):
            return SourceClass.API_RESPONSE
    for pat in _EXTERNAL_DATA_PATTERNS:
        if any(pat.search(ln) for ln in window):
            return SourceClass.EXTERNAL_DATA

    return None


def _has_sanitizer_nearby(lines: List[str], sink_idx: int, radius: int = 8) -> bool:
    """Return True if any sanitizer pattern appears within *radius* lines of the sink."""
    start = max(0, sink_idx - radius)
    end = min(len(lines), sink_idx + radius + 1)
    for ln in lines[start:end]:
        for pat in _SANITIZER_PATTERNS:
            if pat.search(ln):
                return True
    return False


def _build_result(
    source_class: SourceClass,
    evidence_snippet: str,
    sanitizer: bool,
) -> ClassificationResult:
    """Construct a ClassificationResult from a source class."""
    severity, delta, fp_candidate, manual, evidence = _class_to_attrs(source_class)
    return ClassificationResult(
        source_class=source_class,
        severity=severity,
        confidence_delta=delta,
        evidence=f"{source_class.value}: {evidence} (via '{evidence_snippet[:40]}')",
        sanitizer_detected=sanitizer,
        is_false_positive_candidate=fp_candidate,
        manual_review=manual,
    )


def _unknown_result(reason: str) -> ClassificationResult:
    return ClassificationResult(
        source_class=SourceClass.UNKNOWN,
        severity="medium",
        confidence_delta=-5,
        evidence=f"unknown source — {reason}",
        manual_review=True,
    )


def _class_to_attrs(
    cls: SourceClass,
) -> Tuple[str, int, bool, bool, str]:
    """
    Return (severity, confidence_delta, is_false_positive_candidate,
            manual_review, evidence_label) for a source class.
    """
    return {
        SourceClass.USER_INPUT: (
            "high", +20, False, False,
            "user-controlled input reaches innerHTML sink",
        ),
        SourceClass.URL_DATA: (
            "high", +15, False, False,
            "URL/query/hash data reaches innerHTML sink",
        ),
        SourceClass.API_RESPONSE: (
            "medium", +5, False, False,
            "HTTP/API response data reaches innerHTML sink",
        ),
        SourceClass.EXTERNAL_DATA: (
            "medium", +5, False, False,
            "external/untrusted channel data reaches innerHTML sink",
        ),
        SourceClass.STATIC_CONSTANT: (
            "info", -30, True, False,
            "static string constant assigned to innerHTML — not user-controlled",
        ),
        SourceClass.TRUSTED_INTERNAL: (
            "info", -35, True, False,
            "trusted internal markup (SVG/icon/template) assigned to innerHTML",
        ),
        SourceClass.UNKNOWN: (
            "medium", -5, False, True,
            "source origin could not be determined — manual review required",
        ),
    }[cls]


def _downgrade_severity(severity: str) -> str:
    """Lower a severity by one step when a sanitizer is present."""
    order = ["critical", "high", "medium", "low", "info"]
    try:
        idx = order.index(severity)
        return order[min(idx + 1, len(order) - 1)]
    except ValueError:
        return severity
