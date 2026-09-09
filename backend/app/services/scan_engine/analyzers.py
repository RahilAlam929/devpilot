"""
Static analysis orchestrator — Phase 5.

analyze_repository() remains the primary public entry point.
It now returns List[RichFindingResult] instead of List[FindingResult],
but RichFindingResult has the same core fields (severity/title/description/
file_path/line_number) so engine.py and tests that don't use the new
fields still work without changes.

Pipeline per file:
  1. discover_files() — one walk, share across all analyzers.
  2. For Python files: python_analyzer.analyze_python() (AST + dataflow).
  3. For JS/TS files: js_analyzer.analyze_js() (structural + context).
  4. Regex rules for all remaining supported languages / all languages.
  5. Import graph analysis (cross-file, Python only).
  6. Deduplication and merging across all findings.

Legacy FindingResult is kept for the import_graph module and backward-
compatible callers. The legacy analyze_file() function still works for
tests that call it directly.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, NamedTuple, Optional, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Legacy types (kept for backward compat with existing tests)
# ---------------------------------------------------------------------------


@dataclass
class FindingResult:
    """Legacy finding result — still used by import_graph.py and older tests."""

    severity: str
    title: str
    description: str
    file_path: str
    line_number: int


class Rule(NamedTuple):
    extensions: Set[str]
    pattern: re.Pattern
    severity: str
    title: str
    description: str
    guard: Optional[Callable[[str], bool]] = None


# ---------------------------------------------------------------------------
# Filesystem constants (kept for import_graph.py compatibility)
# ---------------------------------------------------------------------------

IGNORED_DIRS: set[str] = {
    ".git", ".svn", ".hg", ".venv", "venv", "node_modules",
    "__pycache__", ".next", ".nuxt", "dist", "build", "out",
    ".tox", ".mypy_cache", ".pytest_cache", "htmlcov", "coverage",
    ".cache", "target", ".gradle", ".idea",
}

ALLOWED_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
    ".rs", ".php", ".rb", ".cpp", ".c", ".h", ".hpp",
}

# ---------------------------------------------------------------------------
# Helper sets
# ---------------------------------------------------------------------------

_PY    = {".py"}
_JS_TS = {".js", ".jsx", ".ts", ".tsx"}
_JAVA  = {".java"}
_GO    = {".go"}
_ALL: set[str] = set()  # empty → matches all

# ---------------------------------------------------------------------------
# Regex rule table (kept for languages not covered by AST analyzers)
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    # Universal markers
    Rule(
        extensions=_ALL,
        pattern=re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b", re.IGNORECASE),
        severity="info",
        title="Unfinished-work marker",
        description="A TODO/FIXME/HACK/XXX comment was found. Resolve before shipping.",
    ),
    # Hardcoded secrets (all languages) — kept as regex fallback
    Rule(
        extensions=_ALL,
        pattern=re.compile(
            r"(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|PASSWORD|PRIVATE_KEY|AUTH_TOKEN"
            r"|CLIENT_SECRET|ENCRYPTION_KEY|DB_PASSWORD|DATABASE_PASSWORD)"
            r"\s*=\s*['\"][^'\"]{4,}['\"]",
            re.IGNORECASE,
        ),
        severity="high",
        title="Possible hardcoded secret",
        description=(
            "A variable with a credential-related name is assigned a string literal. "
            "Load secrets from environment variables or a secrets manager."
        ),
    ),
    # Python broad except
    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bexcept\s+Exception\s*:"),
        severity="medium",
        title="Broad exception handling (Python)",
        description="`except Exception:` catches almost everything. Catch specific exception types.",
    ),
    Rule(
        extensions=_PY,
        pattern=re.compile(r"^\s*except\s*:"),
        severity="medium",
        title="Bare except clause (Python)",
        description="`except:` catches BaseException including KeyboardInterrupt. Use specific types.",
    ),
    # Python debug
    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bprint\s*\("),
        severity="low",
        title="Debug print statement (Python)",
        description="Use logging.debug() instead of print() in production code.",
    ),
    Rule(
        extensions=_PY,
        pattern=re.compile(r"^\s*assert\s+"),
        severity="low",
        title="Assert statement in production code (Python)",
        description="assert is disabled with -O flag and must not be used for security checks.",
    ),
    # Logging secrets
    Rule(
        extensions=_PY,
        pattern=re.compile(
            r"(?:log(?:ging)?|logger)\s*\.\s*(?:debug|info|warning|error|critical|exception)"
            r"\s*\(.*(?:password|secret|token|api.?key|private.?key)",
            re.IGNORECASE,
        ),
        severity="high",
        title="Possible secret logged (Python)",
        description="A logging call may record a sensitive value. Mask secrets before logging.",
    ),
    # JS/TS debug
    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\("),
        severity="low",
        title="console statement left in code (JavaScript/TypeScript)",
        description="Remove console statements from production code.",
    ),
    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\bdebugger\b"),
        severity="low",
        title="debugger statement (JavaScript/TypeScript)",
        description="Remove debugger statements before deploying to production.",
    ),
    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"""['\"]https?://(?:localhost|127\.0\.0\.1)(?::\d+)?""", re.IGNORECASE),
        severity="medium",
        title="Hardcoded localhost URL (JavaScript/TypeScript)",
        description="Use environment variables instead of hardcoded localhost URLs.",
    ),
    # Java
    Rule(
        extensions=_JAVA,
        pattern=re.compile(r"catch\s*\(\s*Exception\s+\w+\s*\)"),
        severity="medium",
        title="Broad exception catch (Java)",
        description="Catch specific exception types instead of base Exception.",
    ),
    Rule(
        extensions=_JAVA,
        pattern=re.compile(r"\.printStackTrace\s*\(\s*\)"),
        severity="medium",
        title="printStackTrace() call (Java)",
        description="Use a logging framework instead of printStackTrace().",
    ),
    Rule(
        extensions=_JAVA,
        pattern=re.compile(
            r"\"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC)\s[^\"]*\"\s*\+",
            re.IGNORECASE,
        ),
        severity="high",
        title="Potential SQL injection via string concatenation (Java)",
        description="Use PreparedStatements with bind parameters instead of string concatenation.",
    ),
    Rule(
        extensions=_JAVA,
        pattern=re.compile(r"\bSystem\s*\.\s*out\s*\.\s*println\s*\("),
        severity="low",
        title="System.out.println() in production code (Java)",
        description="Replace with a logging framework (SLF4J, Log4j2).",
    ),
    # Go
    Rule(
        extensions=_GO,
        pattern=re.compile(r",\s*_\s*:?="),
        severity="medium",
        title="Error return ignored with _ (Go)",
        description="Handle or log errors instead of discarding them with _.",
    ),
    Rule(
        extensions=_GO,
        pattern=re.compile(r"\bfmt\s*\.\s*Println\s*\("),
        severity="low",
        title="fmt.Println in production code (Go)",
        description="Use a structured logging package (log, zap, zerolog).",
    ),
    Rule(
        extensions=_GO,
        pattern=re.compile(
            r"(?:password|secret|apiKey|api_key|token)\s*:?=\s*\"[^\"]{4,}\"",
            re.IGNORECASE,
        ),
        severity="high",
        title="Possible hardcoded credential (Go)",
        description="Load secrets from environment variables or a secrets manager.",
    ),
]


# ---------------------------------------------------------------------------
# Legacy helper used by import_graph.py
# ---------------------------------------------------------------------------


def should_scan(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in ALLOWED_EXTENSIONS
        and not any(part in IGNORED_DIRS for part in path.parts)
    )


# ---------------------------------------------------------------------------
# Legacy analyze_file (still used by existing tests)
# ---------------------------------------------------------------------------


def analyze_file(root: Path, path: Path) -> list[FindingResult]:
    """
    Legacy per-file analysis. Returns FindingResult objects.
    Used by existing test suite and as fallback for unsupported languages.

    Phase 5: routes Python and JS/TS through new analyzers while also
    preserving legacy regex/AST results for backward compat.
    """
    findings: list[FindingResult] = []

    try:
        raw = path.read_bytes()
    except OSError:
        return findings

    # Binary / null-byte detection
    if b"\x00" in raw[:8192]:
        return findings

    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception:
        return findings

    # Resolve root to handle macOS /private symlinks
    try:
        root_r = root.resolve()
        path_r = path.resolve()
        relative_path = str(path_r.relative_to(root_r))
    except ValueError:
        relative_path = str(path.relative_to(root))

    suffix = path.suffix.lower()

    # Route Python and JS/TS through new analyzers (Phase 5) for security findings
    if suffix in (".py", ".js", ".jsx", ".ts", ".tsx"):
        try:
            root_resolved = root.resolve()
            path_resolved = path.resolve()
            rich = _analyze_file_rich(root_resolved, path_resolved, content)
            seen = set()
            for r in rich:
                key = (r.title, r.line_number)
                if key not in seen:
                    seen.add(key)
                    findings.append(FindingResult(
                        severity=r.severity,
                        title=r.title,
                        description=r.description,
                        file_path=relative_path,
                        line_number=r.line_number,
                    ))
        except Exception:
            pass

    # Always run regex rules (covers print, TODO, secrets fallback, etc.)
    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            if rule.extensions and suffix not in rule.extensions:
                continue
            if rule.guard and not rule.guard(line):
                continue
            if not rule.pattern.search(line):
                continue
            findings.append(FindingResult(
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                file_path=relative_path,
                line_number=line_number,
            ))

    # Legacy AST rules (Python only) — unused imports, annotations, mutable defaults
    if suffix == ".py":
        try:
            from app.services.scan_engine.ast_analyzer import analyze_ast
            for ast_finding in analyze_ast(content, filename=str(path)):
                findings.append(FindingResult(
                    severity=ast_finding.severity,
                    title=ast_finding.title,
                    description=ast_finding.description,
                    file_path=relative_path,
                    line_number=ast_finding.line_number,
                ))
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Phase 5 RichFindingResult conversion helper
# ---------------------------------------------------------------------------


def _finding_result_to_rich(fr: FindingResult) -> "RichFindingResult":
    from app.services.scan_engine.findings.types import RichFindingResult
    return RichFindingResult(
        severity=fr.severity,
        title=fr.title,
        description=fr.description,
        file_path=fr.file_path,
        line_number=fr.line_number,
        analyzer="regex",
    )


# ---------------------------------------------------------------------------
# Phase 5 rich per-file analysis
# ---------------------------------------------------------------------------


def _analyze_file_rich(
    root: Path,
    path: Path,
    content: str,
) -> list:  # List[RichFindingResult]
    """Run Phase 5 analyzers on a single file."""
    from app.services.scan_engine.findings.types import RichFindingResult, FindingCategory
    from app.services.scan_engine.scanner.suppression import build_suppression_map
    from app.services.scan_engine.scanner.python_analyzer import analyze_python
    from app.services.scan_engine.scanner.js_analyzer import analyze_js

    suffix = path.suffix.lower()
    relative_path = str(path.relative_to(root))
    findings: list[RichFindingResult] = []

    # Build suppression map for this file
    sup_map = build_suppression_map(content)

    # Python: full AST + dataflow analysis
    if suffix == ".py":
        try:
            py_findings = analyze_python(content, relative_path, sup_map=sup_map)
            findings.extend(py_findings)
        except Exception as exc:
            logger.warning("Python analyzer error on %s: %s", relative_path, exc)

    # JS/TS: structural + context analysis
    elif suffix in (".js", ".jsx"):
        try:
            js_findings = analyze_js(content, relative_path, language="javascript", sup_map=sup_map)
            findings.extend(js_findings)
        except Exception as exc:
            logger.warning("JS analyzer error on %s: %s", relative_path, exc)

    elif suffix in (".ts", ".tsx"):
        try:
            ts_findings = analyze_js(content, relative_path, language="typescript", sup_map=sup_map)
            findings.extend(ts_findings)
        except Exception as exc:
            logger.warning("TS analyzer error on %s: %s", relative_path, exc)

    # All other supported languages: regex rules only
    else:
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if rule.extensions and suffix not in rule.extensions:
                    continue
                if rule.guard and not rule.guard(line):
                    continue
                if rule.pattern.search(line):
                    findings.append(RichFindingResult(
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        file_path=relative_path,
                        line_number=line_number,
                        analyzer="regex",
                        language=suffix.lstrip("."),
                        code_snippet=line.strip(),
                        evidence=line.strip(),
                    ))

    # For Python/JS/TS, also run regex rules to catch patterns the AST
    # analyzers don't cover (TODO markers, broad except, print(), etc.)
    if suffix in (".py", ".js", ".jsx", ".ts", ".tsx"):
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if rule.extensions and suffix not in rule.extensions:
                    continue
                if rule.guard and not rule.guard(line):
                    continue
                if not rule.pattern.search(line):
                    continue
                # Skip rules handled by the AST analyzers to avoid double-reporting
                # Only skip secrets since those are handled by python_analyzer/js_analyzer.
                # Quality rules (print, console, debugger, TODO) are ONLY in regex.
                skip_titles = {
                    "Possible hardcoded secret",
                }
                if rule.title in skip_titles:
                    continue
                findings.append(RichFindingResult(
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    file_path=relative_path,
                    line_number=line_number,
                    analyzer="regex",
                    language=suffix.lstrip("."),
                    code_snippet=line.strip(),
                    evidence=line.strip(),
                ))

    return findings


# ---------------------------------------------------------------------------
# Main public entry point — analyze_repository
# ---------------------------------------------------------------------------


def analyze_repository(root: Path) -> list:
    """
    Analyze an entire repository rooted at *root*.

    Returns List[RichFindingResult]. The objects also satisfy the legacy
    FindingResult interface (severity/title/description/file_path/line_number).

    Pipeline:
      1. discover_files() — one filesystem walk.
      2. Per-file: Python AST/dataflow, JS structural, or regex rules.
      3. Import graph analysis (Python cross-file).
      4. Deduplication.
    """
    from app.services.scan_engine.scanner.discovery import discover_files, ScanConfig
    from app.services.scan_engine.scanner.deduplication import deduplicate, generate_fingerprint
    from app.services.scan_engine.findings.types import RichFindingResult

    # Resolve root ONCE to handle macOS /private symlinks consistently
    root_resolved = root.resolve()

    config = ScanConfig()
    discovery = discover_files(root_resolved, config)

    all_findings: list[RichFindingResult] = []

    # Per-file analysis
    for df in discovery.files:
        if not df.is_scannable:
            continue
        if df.content is None:
            continue
        try:
            file_findings = _analyze_file_rich(root_resolved, df.absolute_path, df.content)
            all_findings.extend(file_findings)
        except Exception as exc:
            logger.warning("Error analyzing %s: %s", df.relative_path, exc)

    # Cross-file import graph analysis (Python)
    if any(df.language == "python" for df in discovery.files if df.is_scannable):
        try:
            from app.services.scan_engine.import_graph import analyze_imports
            import_findings = analyze_imports(root_resolved)
            # Convert legacy FindingResult → RichFindingResult
            for fr in import_findings:
                all_findings.append(_finding_result_to_rich(fr))
        except Exception as exc:
            logger.warning("Import graph analysis error: %s", exc)

    # Assign fingerprints to any that don't have them
    for f in all_findings:
        if not f.fingerprint:
            f.fingerprint = generate_fingerprint(f)

    # Deduplicate
    all_findings = deduplicate(all_findings)

    return all_findings
