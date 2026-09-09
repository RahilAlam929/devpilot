"""
JavaScript / TypeScript / JSX / TSX Structural Analyzer — Phase 5.

No external AST parser required. Uses targeted regex patterns combined with
context-window analysis to detect security issues with low false-positive rates.

Strategy:
  - Line-by-line regex for sink detection
  - Context window (±N lines) to look for source patterns near sinks
  - Next.js / React context awareness
  - Confidence reduced for regex-only findings

Detected patterns:
  - eval() / Function() — code execution
  - dangerouslySetInnerHTML — XSS
  - innerHTML= / outerHTML= — XSS
  - document.write() — XSS
  - child_process.exec/execSync — command injection
  - SQL string interpolation (template literals)
  - console.log/debug — quality
  - debugger — quality
  - Hardcoded secrets — credentials

Context awareness:
  - Checks ±8 lines around dangerous sinks for user-source patterns
  - Recognizes Next.js route handler patterns (req.query, searchParams, params)
  - Recognizes sanitizer patterns (DOMPurify, sanitize, escape)

Never executes JavaScript.
"""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple

from app.services.scan_engine.findings.types import (
    DataFlowStep,
    FindingCategory,
    RichFindingResult,
    SinkInfo,
    SourceInfo,
)
from app.services.scan_engine.scanner.confidence import apply_confidence
from app.services.scan_engine.scanner.deduplication import generate_fingerprint
from app.services.scan_engine.scanner.remediation import enrich_remediation
from app.services.scan_engine.scanner.suppression import SuppressionMap, is_suppressed

# ---------------------------------------------------------------------------
# Context window for source detection near sinks
# ---------------------------------------------------------------------------

SOURCE_WINDOW = 8   # lines to look backward from sink for source patterns

# ---------------------------------------------------------------------------
# Source patterns — user-controlled data in JS/TS
# ---------------------------------------------------------------------------

_JS_SOURCES = [
    re.compile(r"\breq\.(?:query|body|params|headers|cookies)\b"),
    re.compile(r"\bsearchParams\.get\b"),
    re.compile(r"\bURLSearchParams\b"),
    re.compile(r"\blocation\.(?:search|hash|href)\b"),
    re.compile(r"\bdocument\.(?:cookie|referrer)\b"),
    re.compile(r"\bwindow\.name\b"),
    re.compile(r"\bparams\["),
    re.compile(r"\bparams\."),
    re.compile(r"\b(?:getServerSideProps|getStaticProps)\b"),  # Next.js
    re.compile(r"\brequest\.(?:json|body|formData|text)\b"),    # Next.js App Router
    re.compile(r"\bFormData\b"),
    re.compile(r"\bevent\.target\.value\b"),
    re.compile(r"\binputValue\b"),
    re.compile(r"\buserInput\b"),
    re.compile(r"\buserData\b"),
]

# Sanitizer patterns — reduce confidence when present
_JS_SANITIZERS = [
    re.compile(r"\bDOMPurify\.sanitize\b"),
    re.compile(r"\bsanitize(?:Html|HTML)?\s*\("),
    re.compile(r"\bescape(?:Html|HTML)?\s*\("),
    re.compile(r"\bencodeURIComponent\b"),
    re.compile(r"\bencodeURI\b"),
    re.compile(r"\bTextContent\b"),
    re.compile(r"\.textContent\s*="),
]

# Secret variable names
_JS_SECRET_RE = re.compile(
    r"(?:const|let|var)\s+(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|PASSWORD|PRIVATE_KEY"
    r"|AUTH_TOKEN|CLIENT_SECRET|ENCRYPTION_KEY)\s*=\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Sink definitions: (rule_id, pattern, title, category, severity, cwe)
# ---------------------------------------------------------------------------

_SINKS: List[Tuple[str, re.Pattern, str, str, str, str]] = [
    (
        "JS001",
        re.compile(r"\beval\s*\("),
        "Use of eval()",
        FindingCategory.CODE_EXECUTION.value,
        "high",
        "CWE-95",
    ),
    (
        "JS002",
        re.compile(r"\bnew\s+Function\s*\("),
        "Use of Function() constructor",
        FindingCategory.CODE_EXECUTION.value,
        "high",
        "CWE-95",
    ),
    (
        "JS004",
        re.compile(r"\bdangerouslySetInnerHTML\b"),
        "dangerouslySetInnerHTML usage",
        FindingCategory.XSS.value,
        "high",
        "CWE-79",
    ),
    (
        "JS005",
        re.compile(r"\.innerHTML\s*="),
        "Direct innerHTML assignment",
        FindingCategory.XSS.value,
        "medium",
        "CWE-79",
    ),
    (
        "JS005",
        re.compile(r"\.outerHTML\s*="),
        "Direct outerHTML assignment",
        FindingCategory.XSS.value,
        "medium",
        "CWE-79",
    ),
    (
        "JS006",
        re.compile(r"\bdocument\s*\.\s*write\s*\("),
        "Use of document.write()",
        FindingCategory.XSS.value,
        "medium",
        "CWE-79",
    ),
    (
        "JS003",
        re.compile(r"\bexec\s*\("),           # child_process context checked separately
        "Potential child_process.exec() call",
        FindingCategory.COMMAND_INJECTION.value,
        "high",
        "CWE-78",
    ),
    (
        "JS003",
        re.compile(r"\bexecSync\s*\("),
        "child_process.execSync() call",
        FindingCategory.COMMAND_INJECTION.value,
        "high",
        "CWE-78",
    ),
]

# Quality sinks (lower severity, no source needed)
_QUALITY_SINKS: List[Tuple[str, re.Pattern, str, str, str]] = [
    (
        "QA003",
        re.compile(r"\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\("),
        "console statement in production code",
        "low",
        FindingCategory.QUALITY.value,
    ),
    (
        "QA003",
        re.compile(r"\bdebugger\b"),
        "debugger statement",
        "low",
        FindingCategory.QUALITY.value,
    ),
]

# ---------------------------------------------------------------------------
# Console sensitivity analysis
# ---------------------------------------------------------------------------

# Sensitive variable/property names that suggest data disclosure risk
_SENSITIVE_ARG_PATTERN = re.compile(
    r"\b(?:"
    # Authentication/secrets
    r"token|secret|password|passwd|pwd|apikey|api_key|apiKey|accesskey|access_key"
    r"|privatekey|private_key|privateKey|authToken|auth_token|credentials?|credential"
    r"|sessionId|session_id|sessionToken|session_token"
    # User identity (complete objects risk leaking PII)
    r"|user(?!Name|name|Id|id|Label|label|Error|error|Input|input|Data|data|Info|info|Msg|msg|Message|message)"
    r"|userObj|currentUser|loggedInUser|authUser"
    # Environment
    r"|process\.env\."
    # Complete response/request objects that may contain headers/secrets
    r"|response\.headers|req\.headers|request\.headers"
    r")\b",
    re.IGNORECASE,
)

# Benign patterns: error objects, static strings, IDs, counts, booleans
_BENIGN_ARG_PATTERN = re.compile(
    r"""^(?:"""
    r""""[^"]*"|'[^']*'|`[^`]*`"""  # string literals
    r"""|(?:true|false|null|undefined|\d+)"""  # primitives
    r"""|(?:err|error|e|ex|exception)\b"""  # error objects  
    r"""|(?:\w+Id|\w+Count|\w+Length|\w+Size|\w+Index)\b"""  # IDs/counts
    r"""|(?:isLoading|isOpen|isActive|enabled|disabled)\b"""  # booleans
    r")\s*$",
    re.IGNORECASE | re.VERBOSE,
)


def _strip_string_literals(text: str) -> str:
    """
    Remove the content of string literals from *text*, leaving quote markers.
    This prevents matching sensitive keywords that appear inside string values
    like console.log("User logged in") or console.log("No password needed").
    """
    # Replace single-quoted string content with empty placeholder
    text = re.sub(r"'[^']*'", "''", text)
    # Replace double-quoted string content with empty placeholder
    text = re.sub(r'"[^"]*"', '""', text)
    # Replace template literal content with empty placeholder
    text = re.sub(r"`[^`]*`", "``", text)
    return text


def _extract_console_args(line: str) -> str:
    """
    Extract the argument text from a console.xxx(...) call.
    Returns the raw argument string (may be truncated by line end).
    """
    m = re.search(r"\bconsole\s*\.\s*\w+\s*\((.+)", line)
    if not m:
        return ""
    args = m.group(1)
    # Strip trailing ) and whitespace if present on this line
    if args.endswith(");") or args.endswith(")"):
        args = args.rstrip(";)").rstrip()
    return args.strip()


def _classify_console_sensitivity(line: str, args: str) -> tuple[bool, str]:
    """
    Classify whether a console call looks like it may log sensitive data.

    Returns (is_sensitive, reason_label).

    Only matches sensitive keywords that appear as identifiers (variable
    names, property accesses), not inside string literals.
    """
    if not args:
        return False, ""

    # Remove string literal contents so we don't match 'token' inside
    # "no token required" or "User logged in".
    args_stripped = _strip_string_literals(args)

    # If args_stripped is only string literal placeholders, it's definitely
    # a static log message — benign.
    placeholder_only = re.fullmatch(r"""['"` ,+]+""", args_stripped)
    if placeholder_only:
        return False, ""

    # Check for sensitive keywords in the non-literal argument expression
    m = _SENSITIVE_ARG_PATTERN.search(args_stripped)
    if m:
        matched = m.group(0)
        return True, matched

    # Check for process.env access
    if re.search(r"process\.env\.", args_stripped):
        return True, "process.env"

    return False, ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _window(lines: List[str], center: int, radius: int) -> List[str]:
    """Return lines within *radius* of *center* (0-indexed)."""
    start = max(0, center - radius)
    end = min(len(lines), center + radius + 1)
    return lines[start:end]


def _has_source_near(lines: List[str], sink_idx: int) -> Tuple[bool, str]:
    """
    Check whether any source pattern appears in the window before *sink_idx*.
    Returns (found, source_label).
    """
    window = _window(lines, sink_idx, SOURCE_WINDOW)
    for line in window:
        for pat in _JS_SOURCES:
            m = pat.search(line)
            if m:
                return True, m.group(0)
    return False, ""


def _has_sanitizer_near(lines: List[str], sink_idx: int) -> bool:
    """Check whether a sanitizer appears near the sink."""
    window = _window(lines, sink_idx, SOURCE_WINDOW)
    for line in window:
        for pat in _JS_SANITIZERS:
            if pat.search(line):
                return True
    return False


def _is_child_process_exec(lines: List[str], sink_idx: int) -> bool:
    """
    Confirm that an exec() call is from child_process.
    Look for require('child_process') or child_process.exec() pattern.
    """
    snippet = lines[sink_idx]
    # Direct: child_process.exec( / exec(
    if "child_process" in snippet or "childProcess" in snippet:
        return True
    # Check if exec is imported from child_process in surrounding lines
    surrounding = _window(lines, sink_idx, 30)
    for ln in surrounding:
        if re.search(r"require\s*\(\s*['\"]child_process['\"]\s*\)", ln):
            return True
        if re.search(r"from\s+['\"]child_process['\"]\s+import", ln):
            return True
        if "exec" in ln and "child_process" in ln:
            return True
    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_js(
    content: str,
    file_path: str,
    language: str = "javascript",
    sup_map: Optional[SuppressionMap] = None,
) -> List[RichFindingResult]:
    """
    Run JavaScript/TypeScript security analysis on *content*.

    Returns a list of RichFindingResult objects.
    Never raises — all exceptions caught internally.
    """
    findings: List[RichFindingResult] = []

    try:
        lines = content.splitlines()
        _check_security_sinks(lines, file_path, language, findings, sup_map)
        _check_quality(lines, file_path, language, findings, sup_map)
        _check_secrets(lines, file_path, language, findings, sup_map)
    except Exception:
        pass  # Never crash the scan

    for f in findings:
        enrich_remediation(f)
        if not f.fingerprint:
            f.fingerprint = generate_fingerprint(f)

    return findings


# ---------------------------------------------------------------------------
# Security sink checker
# ---------------------------------------------------------------------------

def _check_security_sinks(
    lines: List[str],
    file_path: str,
    language: str,
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1  # 1-indexed
        snippet = line.strip()

        for rule_id, pattern, title, category, severity, cwe in _SINKS:
            if not pattern.search(line):
                continue

            # exec() only counts if it's child_process
            if title.startswith("Potential child_process.exec") or "execSync" in title:
                if not _is_child_process_exec(lines, lineno_0):
                    continue

            if sup_map and is_suppressed(sup_map, lineno, rule_id):
                continue

            # Context: look for user source and sanitizers nearby
            has_source, source_label = _has_source_near(lines, lineno_0)
            has_sanitizer = _has_sanitizer_near(lines, lineno_0)

            # Adjust severity based on context
            effective_severity = severity
            if has_source and not has_sanitizer:
                # escalate if source found
                if severity == "medium":
                    effective_severity = "high"
            elif has_sanitizer:
                # downgrade if sanitized
                if severity == "high":
                    effective_severity = "medium"
                elif severity == "medium":
                    effective_severity = "low"

            # Build lightweight data flow if source found
            data_flow: List[DataFlowStep] = []
            source: Optional[SourceInfo] = None
            if has_source and source_label:
                source = SourceInfo(label=source_label, line=max(1, lineno - SOURCE_WINDOW))
                data_flow = [
                    DataFlowStep(label=source_label, line=source.line, step_type="source"),
                    DataFlowStep(label=snippet[:80], line=lineno, step_type="sink"),
                ]

            finding = RichFindingResult(
                severity=effective_severity,
                title=title + (" with user-controlled input" if has_source and not has_sanitizer else ""),
                description=(
                    f"{title} detected. "
                    + ("User-controlled data found nearby." if has_source and not has_sanitizer else
                       "Sanitizer detected nearby." if has_sanitizer else
                       "Verify the value is not user-controlled.")
                ),
                file_path=file_path,
                line_number=lineno,
                rule_id=rule_id,
                category=category,
                code_snippet=snippet,
                language=language,
                analyzer="ast" if has_source else "regex",
                cwe=cwe,
                evidence=snippet,
                source=source,
                sink=SinkInfo(label=snippet[:80], line=lineno, api=title, is_sanitized=has_sanitizer),
                data_flow=data_flow,
            )
            apply_confidence(
                finding,
                has_user_controlled_source=has_source,
                has_direct_flow=has_source,
                has_sanitizer=has_sanitizer,
                is_ast_confirmed=False,
                is_regex_only=not has_source,
                flow_is_incomplete=has_source,  # context window is not definitive
            )
            findings.append(finding)
            break  # one finding per line per rule group


# ---------------------------------------------------------------------------
# Quality checker
# ---------------------------------------------------------------------------

def _check_quality(
    lines: List[str],
    file_path: str,
    language: str,
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    """
    Detect console statements and debugger calls.

    Console calls are classified by argument sensitivity:
    - Low severity (quality): console.log("hello"), console.error(err)
    - Medium severity / potential info disclosure (secrets category):
      console.log(token), console.log(user), console.log(process.env.SECRET)

    This avoids treating every console statement as a security issue while
    still surfacing meaningful potential data-exposure patterns.
    """
    _console_re = re.compile(r"\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\(")
    _debugger_re = re.compile(r"\bdebugger\b")

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        snippet = line.strip()

        # Skip comment-only lines to reduce false positives on e.g. `// console.log`
        stripped = snippet.lstrip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        # ── debugger statement ──────────────────────────────────────────
        if _debugger_re.search(line):
            if sup_map and is_suppressed(sup_map, lineno, "QA003"):
                continue
            finding = RichFindingResult(
                severity="low",
                title="debugger statement",
                description="debugger statement found in production code — remove before deploying.",
                file_path=file_path,
                line_number=lineno,
                rule_id="QA003",
                category=FindingCategory.QUALITY.value,
                code_snippet=snippet,
                language=language,
                analyzer="regex",
                evidence=snippet,
                remediation="Remove the debugger statement. It pauses execution in DevTools and has no effect in production, but indicates code was not cleaned up.",
            )
            apply_confidence(finding, is_regex_only=True)
            findings.append(finding)
            continue

        # ── console statement ──────────────────────────────────────────
        if not _console_re.search(line):
            continue

        # Extract argument text for sensitivity analysis
        args = _extract_console_args(line)
        is_sensitive, sensitive_match = _classify_console_sensitivity(line, args)

        if is_sensitive:
            # Potentially logging sensitive data — report as secrets/info-disclosure
            if sup_map and is_suppressed(sup_map, lineno, "SEC002"):
                continue
            method_m = re.search(r"console\s*\.\s*(\w+)", line)
            method = method_m.group(1) if method_m else "log"
            finding = RichFindingResult(
                severity="medium",
                title=f"console.{method}() may log sensitive data",
                description=(
                    f"console.{method}() is called with an argument that appears to reference "
                    f"sensitive data ({sensitive_match!r}). Debug logs in production code can "
                    f"expose tokens, passwords, or user PII in browser DevTools or server logs."
                ),
                file_path=file_path,
                line_number=lineno,
                rule_id="SEC002",
                category=FindingCategory.SECRETS.value,
                code_snippet=snippet,
                language=language,
                analyzer="regex",
                cwe="CWE-532",
                evidence=snippet,
                why_risky=(
                    "Logging sensitive values such as authentication tokens, passwords, API keys, "
                    "or full user objects exposes them in browser DevTools (accessible to XSS "
                    "attacks and browser extensions), server logs (may be stored insecurely), and "
                    "monitoring systems."
                ),
                impact=(
                    "Credential or PII exposure in browser DevTools, log files, and monitoring "
                    "pipelines. Depending on what is logged: authentication bypass, account "
                    "takeover, or privacy violation."
                ),
                remediation=(
                    "Remove the console statement or replace it with structured logging that "
                    "masks sensitive values.\n\n"
                    "Examples:\n"
                    "  // Log that auth succeeded without logging the token:\n"
                    "  console.log('User authenticated successfully');\n\n"
                    "  // Log a non-sensitive identifier instead:\n"
                    "  console.log('User ID:', userId);\n\n"
                    "  // For production: use a structured logger with log levels:\n"
                    "  logger.info({ event: 'auth.success', userId });"
                ),
            )
            apply_confidence(
                finding,
                is_regex_only=True,
                source_is_constant=False,
            )
            findings.append(finding)
        else:
            # Generic quality finding — non-sensitive console statement
            if sup_map and is_suppressed(sup_map, lineno, "QA003"):
                continue
            method_m = re.search(r"console\s*\.\s*(\w+)", line)
            method = method_m.group(1) if method_m else "log"
            finding = RichFindingResult(
                severity="low",
                title="console statement in production code",
                description=(
                    f"console.{method}() was left in production code. "
                    "Debug logs clutter output and may leak non-obvious information."
                ),
                file_path=file_path,
                line_number=lineno,
                rule_id="QA003",
                category=FindingCategory.QUALITY.value,
                code_snippet=snippet,
                language=language,
                analyzer="regex",
                evidence=snippet,
                remediation=(
                    "Remove the console statement before deploying to production. "
                    "If logging is needed, replace with a structured logging library "
                    "(pino, winston) that supports log levels and can be disabled in production.\n\n"
                    "// Remove:\n"
                    f"// console.{method}(...);\n\n"
                    "// Or replace with structured logger:\n"
                    "// import { logger } from './lib/logger';\n"
                    "// logger.debug(...);"
                ),
            )
            apply_confidence(finding, is_regex_only=True)
            findings.append(finding)


# ---------------------------------------------------------------------------
# Secret checker
# ---------------------------------------------------------------------------

def _check_secrets(
    lines: List[str],
    file_path: str,
    language: str,
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1
        if not _JS_SECRET_RE.search(line):
            continue
        if sup_map and is_suppressed(sup_map, lineno, "SEC001"):
            continue

        snippet = line.strip()
        finding = RichFindingResult(
            severity="high",
            title="Possible hardcoded secret or credential",
            description=(
                "A credential-related variable is assigned a string literal. "
                "Hardcoded secrets are exposed in version control."
            ),
            file_path=file_path,
            line_number=lineno,
            rule_id="SEC001",
            category=FindingCategory.SECRETS.value,
            code_snippet=snippet,
            language=language,
            analyzer="regex",
            cwe="CWE-798",
            evidence=snippet,
        )
        apply_confidence(finding, is_regex_only=True, source_is_constant=True)
        findings.append(finding)
