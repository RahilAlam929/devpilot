"""
Static analysis engine: regex-based rules per language.

Rules are grouped by language and severity.  Each rule is a compiled regex
that operates line-by-line.  New rules can be added to the RULES table
without touching the scanning loop.

Rule severity scale:
  high   — security issue likely causing data exposure or code execution
  medium — quality / correctness issue that may cause subtle bugs
  low    — style / maintainability hint
  info   — informational; unfinished-work markers, etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple, Set


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class FindingResult:
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int


class Rule(NamedTuple):
    """A single lint rule."""

    # file extensions this rule applies to, e.g. {".py"}.
    # Empty set means "all supported extensions".
    extensions: Set[str]
    pattern: re.Pattern[str]
    severity: str
    title: str
    description: str
    # Optional guard: called with the line; rule fires only when guard is True.
    guard: Callable[[str], bool] | None = None


# ---------------------------------------------------------------------------
# Filesystem constants
# ---------------------------------------------------------------------------

IGNORED_DIRS: set[str] = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    "htmlcov",
    "coverage",
}

ALLOWED_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
}

# ---------------------------------------------------------------------------
# Helper sets used by multiple rules
# ---------------------------------------------------------------------------

_PY = {".py"}
_JS_TS = {".js", ".jsx", ".ts", ".tsx"}
_JAVA = {".java"}
_GO = {".go"}
_ALL = set()  # empty → matches all allowed extensions

# ---------------------------------------------------------------------------
# Rule table
#
# Rules are evaluated in order.  Each rule fires at most once per line —
# the loop appends one FindingResult per matching rule.
# ---------------------------------------------------------------------------

RULES: list[Rule] = [

    # ── Unfinished-work markers (all languages) ───────────────────────────

    Rule(
        extensions=_ALL,
        pattern=re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b", re.IGNORECASE),
        severity="info",
        title="Unfinished-work marker",
        description=(
            "A TODO/FIXME/HACK/XXX comment was found. "
            "Resolve or remove it before shipping."
        ),
    ),

    # ── Hardcoded secrets (all languages) ─────────────────────────────────

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
            "A variable name associated with credentials or secrets has been "
            "assigned a string literal. Load secrets from environment variables "
            "or a secrets manager instead."
        ),
    ),

    # ── Python: broad exception handling ─────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bexcept\s+Exception\s*:"),
        severity="medium",
        title="Broad exception handling (Python)",
        description=(
            "`except Exception:` catches almost everything, including "
            "programming errors. Catch the specific exception types you expect."
        ),
    ),

    # ── Python: bare except ───────────────────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"^\s*except\s*:"),
        severity="medium",
        title="Bare except clause (Python)",
        description=(
            "`except:` with no exception type catches BaseException, including "
            "KeyboardInterrupt and SystemExit. Use `except Exception:` at minimum, "
            "or preferably a specific exception type."
        ),
    ),

    # ── Python: debug print statement ────────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bprint\s*\("),
        severity="low",
        title="Debug print statement (Python)",
        description=(
            "A `print()` call was found. Use a proper logging framework "
            "(e.g. `logging.debug()`) for production code."
        ),
    ),

    # ── Python: assert in production code ────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"^\s*assert\s+"),
        severity="low",
        title="Assert statement in production code (Python)",
        description=(
            "`assert` statements are disabled when Python is run with the -O "
            "flag and must not be used for security or validation checks."
        ),
    ),

    # ── Python: logging secrets (common patterns) ─────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(
            r"(?:log(?:ging)?|logger)\s*\.\s*(?:debug|info|warning|error|critical|exception)"
            r"\s*\(.*(?:password|secret|token|api.?key|private.?key)",
            re.IGNORECASE,
        ),
        severity="high",
        title="Possible secret logged (Python)",
        description=(
            "A logging call may be recording a sensitive value such as a "
            "password or API key. Scrub or mask secrets before logging."
        ),
    ),

    # ── Python: use of eval() ────────────────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\beval\s*\("),
        severity="high",
        title="Use of eval() (Python)",
        description=(
            "`eval()` executes arbitrary code and is a common vector for "
            "remote code execution. Use safe alternatives (e.g. `ast.literal_eval` "
            "for data parsing)."
        ),
    ),

    # ── Python: use of exec() ────────────────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bexec\s*\("),
        severity="high",
        title="Use of exec() (Python)",
        description=(
            "`exec()` executes arbitrary code. Avoid it or ensure the input "
            "is strictly controlled and never user-supplied."
        ),
    ),

    # ── Python: subprocess shell=True ────────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bsubprocess\b.*\bshell\s*=\s*True"),
        severity="high",
        title="subprocess called with shell=True (Python)",
        description=(
            "Using `shell=True` with subprocess allows shell injection if "
            "any part of the command is user-controlled. Pass a list of "
            "arguments instead and leave shell=False."
        ),
    ),

    # ── Python: SQL string interpolation (potential injection) ────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(
            r"(?:execute|executemany|raw|cursor)\s*\(\s*['\"].*%.*['\"]",
            re.IGNORECASE,
        ),
        severity="high",
        title="Potential SQL injection via string formatting (Python)",
        description=(
            "String formatting inside a SQL execute call can allow SQL "
            "injection. Use parameterised queries with placeholders (?, %s) "
            "instead of %-formatting the SQL string directly."
        ),
    ),

    # ── Python: f-string SQL ─────────────────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(
            r"(?:execute|executemany|raw)\s*\(\s*f['\"].*\{.*\}.*['\"]",
            re.IGNORECASE,
        ),
        severity="high",
        title="Potential SQL injection via f-string (Python)",
        description=(
            "Building a SQL query with an f-string can introduce SQL injection "
            "vulnerabilities. Use parameterised queries instead."
        ),
    ),

    # ── Python: use of MD5/SHA1 for security (weak crypto) ───────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(
            r"hashlib\s*\.\s*(?:md5|sha1)\s*\(",
            re.IGNORECASE,
        ),
        severity="medium",
        title="Weak cryptographic hash (Python)",
        description=(
            "MD5 and SHA-1 are cryptographically broken and must not be used "
            "for security-sensitive purposes (password hashing, HMAC, "
            "certificate fingerprinting). Use SHA-256 or stronger."
        ),
    ),

    # ── Python: pickle deserialization ───────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\bpickle\s*\.\s*loads?\s*\("),
        severity="high",
        title="Unsafe pickle deserialization (Python)",
        description=(
            "`pickle.load` / `pickle.loads` can execute arbitrary code when "
            "deserialising untrusted data. Never unpickle data from an "
            "untrusted or unauthenticated source."
        ),
    ),

    # ── Python: yaml.load without Loader ─────────────────────────────────

    Rule(
        extensions=_PY,
        pattern=re.compile(r"\byaml\s*\.\s*load\s*\(\s*[^,)]+\s*\)"),
        severity="high",
        title="Unsafe yaml.load() call (Python)",
        description=(
            "`yaml.load()` without an explicit `Loader=` argument uses the "
            "unsafe default loader and can execute arbitrary code. "
            "Use `yaml.safe_load()` or `yaml.load(data, Loader=yaml.SafeLoader)`."
        ),
    ),

    # ── JS/TS: use of eval() ─────────────────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\beval\s*\("),
        severity="high",
        title="Use of eval() (JavaScript/TypeScript)",
        description=(
            "`eval()` executes arbitrary JavaScript from a string. It is a "
            "common code-injection vector. Avoid it entirely."
        ),
    ),

    # ── JS/TS: dangerouslySetInnerHTML ────────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"dangerouslySetInnerHTML"),
        severity="high",
        title="dangerouslySetInnerHTML usage (React)",
        description=(
            "`dangerouslySetInnerHTML` bypasses React's XSS protections. "
            "Ensure the value is sanitised with a library such as DOMPurify "
            "before use."
        ),
    ),

    # ── JS/TS: document.write ─────────────────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\bdocument\s*\.\s*write\s*\("),
        severity="medium",
        title="Use of document.write() (JavaScript/TypeScript)",
        description=(
            "`document.write()` can introduce XSS vulnerabilities and blocks "
            "parsing. Use DOM manipulation APIs instead."
        ),
    ),

    # ── JS/TS: innerHTML assignment ──────────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\.innerHTML\s*="),
        severity="medium",
        title="Direct innerHTML assignment (JavaScript/TypeScript)",
        description=(
            "Assigning to `.innerHTML` without sanitisation can introduce "
            "XSS. Use `textContent` for plain text, or a sanitiser for HTML."
        ),
    ),

    # ── JS/TS: console.log left in code ──────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\("),
        severity="low",
        title="console statement left in code (JavaScript/TypeScript)",
        description=(
            "Console statements should be removed from production code or "
            "replaced with a structured logging library."
        ),
    ),

    # ── JS/TS: debugger statement ─────────────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(r"\bdebugger\b"),
        severity="low",
        title="debugger statement (JavaScript/TypeScript)",
        description=(
            "A `debugger` statement pauses execution in a JavaScript debugger. "
            "Remove it before deploying to production."
        ),
    ),

    # ── JS/TS: hardcoded localhost URLs ──────────────────────────────────

    Rule(
        extensions=_JS_TS,
        pattern=re.compile(
            r"""['\"]https?://(?:localhost|127\.0\.0\.1)(?::\d+)?""",
            re.IGNORECASE,
        ),
        severity="medium",
        title="Hardcoded localhost URL (JavaScript/TypeScript)",
        description=(
            "A hardcoded localhost URL will not work in production. "
            "Use environment variables (e.g. `process.env.NEXT_PUBLIC_API_URL`) instead."
        ),
    ),

    # ── Java: broad catch (Exception) ────────────────────────────────────

    Rule(
        extensions=_JAVA,
        pattern=re.compile(r"catch\s*\(\s*Exception\s+\w+\s*\)"),
        severity="medium",
        title="Broad exception catch (Java)",
        description=(
            "Catching the base `Exception` class hides unexpected errors and "
            "makes debugging harder. Catch only the specific exception types "
            "you intend to handle."
        ),
    ),

    # ── Java: printStackTrace ─────────────────────────────────────────────

    Rule(
        extensions=_JAVA,
        pattern=re.compile(r"\.printStackTrace\s*\(\s*\)"),
        severity="medium",
        title="printStackTrace() call (Java)",
        description=(
            "`printStackTrace()` writes to stderr without structure and "
            "may expose internal stack traces. Use a logging framework "
            "(SLF4J, Log4j, java.util.logging) instead."
        ),
    ),

    # ── Java: SQL string concatenation ───────────────────────────────────

    Rule(
        extensions=_JAVA,
        pattern=re.compile(
            r"\"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC)\s[^\"]*\"\s*\+",
            re.IGNORECASE,
        ),
        severity="high",
        title="Potential SQL injection via string concatenation (Java)",
        description=(
            "Building a SQL query by concatenating strings can introduce SQL "
            "injection. Use PreparedStatements with bind parameters instead."
        ),
    ),

    # ── Java: System.out.println ──────────────────────────────────────────

    Rule(
        extensions=_JAVA,
        pattern=re.compile(r"\bSystem\s*\.\s*out\s*\.\s*println\s*\("),
        severity="low",
        title="System.out.println() in production code (Java)",
        description=(
            "`System.out.println()` should be replaced with a proper logging "
            "framework (SLF4J, Log4j2, etc.) in production code."
        ),
    ),

    # ── Go: blank identifier swallowing error ─────────────────────────────

    Rule(
        extensions=_GO,
        pattern=re.compile(r",\s*_\s*:?="),
        severity="medium",
        title="Error return ignored with _ (Go)",
        description=(
            "Assigning an error return to `_` silently discards errors. "
            "Handle or explicitly log errors to avoid silent failures."
        ),
    ),

    # ── Go: fmt.Println ───────────────────────────────────────────────────

    Rule(
        extensions=_GO,
        pattern=re.compile(r"\bfmt\s*\.\s*Println\s*\("),
        severity="low",
        title="fmt.Println in production code (Go)",
        description=(
            "`fmt.Println` is typically used for debugging. Use a structured "
            "logging package (e.g. `log`, `zap`, `zerolog`) in production."
        ),
    ),

    # ── Go: hardcoded credentials pattern ────────────────────────────────

    Rule(
        extensions=_GO,
        pattern=re.compile(
            r"(?:password|secret|apiKey|api_key|token)\s*:?=\s*\"[^\"]{4,}\"",
            re.IGNORECASE,
        ),
        severity="high",
        title="Possible hardcoded credential (Go)",
        description=(
            "A variable named with a credential keyword has been assigned a "
            "string literal. Load secrets from environment variables or a "
            "secrets manager instead."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Analysis entry points
# ---------------------------------------------------------------------------


def should_scan(path: Path) -> bool:
    """Return True if path is an eligible source file."""
    return (
        path.is_file()
        and path.suffix.lower() in ALLOWED_EXTENSIONS
        and not any(part in IGNORED_DIRS for part in path.parts)
    )


def analyze_file(root: Path, path: Path) -> list[FindingResult]:
    """Apply all matching rules to every line of a single file.

    For Python files, also runs the AST-based analyser after the regex pass.
    """
    findings: list[FindingResult] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    relative_path = str(path.relative_to(root))
    suffix = path.suffix.lower()

    # ── Regex rules (all languages) ───────────────────────────────────────
    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            # Determine if rule applies to this file type.
            if rule.extensions and suffix not in rule.extensions:
                continue

            # Check the optional guard first (cheap skip).
            if rule.guard and not rule.guard(line):
                continue

            if rule.pattern.search(line):
                findings.append(
                    FindingResult(
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        file_path=relative_path,
                        line_number=line_number,
                    )
                )

    # ── AST-based rules (Python only) ─────────────────────────────────────
    if suffix == ".py":
        from app.services.scan_engine.ast_analyzer import analyze_ast  # noqa: PLC0415

        for ast_finding in analyze_ast(content, filename=str(path)):
            findings.append(
                FindingResult(
                    severity=ast_finding.severity,
                    title=ast_finding.title,
                    description=ast_finding.description,
                    file_path=relative_path,
                    line_number=ast_finding.line_number,
                )
            )

    return findings


def analyze_repository(root: Path) -> list[FindingResult]:
    """
    Walk *root* and apply all analysis passes:

    1. Per-file regex rules (all supported languages).
    2. Per-file AST rules (Python only, integrated in analyze_file).
    3. Cross-file import graph analysis (Python only).
    """
    findings: list[FindingResult] = []

    # Collect all scannable files in one pass so we never walk the tree twice.
    scannable: list[Path] = [p for p in root.rglob("*") if should_scan(p)]

    # ── Per-file passes (regex + AST) ─────────────────────────────────────
    for path in scannable:
        findings.extend(analyze_file(root, path))

    # ── Cross-file import analysis (Python packages) ──────────────────────
    # Only run when there is at least one Python file in the collected list.
    if any(p.suffix.lower() == ".py" for p in scannable):
        from app.services.scan_engine.import_graph import analyze_imports  # noqa: PLC0415

        findings.extend(analyze_imports(root))

    return findings
