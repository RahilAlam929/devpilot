"""
Context-Aware Secret Scanner — Phase 6.

Detects likely secrets, API keys, tokens, and hardcoded credentials in
source files. Designed to minimize false positives using:
  1. Regex pattern matching against known secret formats.
  2. Context scoring — assignment context raises confidence.
  3. Entropy estimation — high-entropy strings are more likely real.
  4. False-positive filter — known placeholder/test values are excluded.

CRITICAL SECURITY REQUIREMENTS enforced here:
  - NEVER persist or return the full secret value.
  - Evidence is redacted: first 4 chars + stars + last 2 chars.
  - Fingerprint is derived from rule + file + line ONLY (never the secret).
  - No secret value is stored in any field.
  - Log statements never include the actual secret value.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data type
# ---------------------------------------------------------------------------


@dataclass
class SecretMatch:
    rule_id: str
    secret_type: str
    redacted_value: str      # NEVER the full secret
    line: int
    column: int
    context_line: str        # the full source line (may itself be redacted)
    confidence: int
    file_path: str


# ---------------------------------------------------------------------------
# False-positive exclusion: known placeholder/test values
# ---------------------------------------------------------------------------

_FP_PATTERNS: List[re.Pattern] = [
    re.compile(r"^(your[-_]?|my[-_]?|example[-_]?|test[-_]?|fake[-_]?|dummy[-_]?|placeholder|changeme|insert[-_]?|replace[-_]?)", re.IGNORECASE),
    re.compile(r"^(xxx+|abc+|123+|000+|aaa+|bbb+|\*+|\.+|<.*>|\[.*\]|\{.*\})", re.IGNORECASE),
    re.compile(r"^(todo|fixme|none|null|undefined|false|true|n/a|tbd)$", re.IGNORECASE),
    re.compile(r"^[a-f0-9]{4}$"),  # too short hex, likely fragment
    re.compile(r"^(token|secret|key|password|api.?key|access.?token)$", re.IGNORECASE),  # literal placeholder names
    re.compile(r"test.{0,20}(secret|token|key|password)", re.IGNORECASE),
    re.compile(r"do.not.use", re.IGNORECASE),
]

# Minimum length to consider as a potential secret
_MIN_SECRET_LEN = 8

# High entropy threshold (Shannon entropy > this → more likely real secret)
_HIGH_ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _redact(value: str) -> str:
    """
    Redact a secret value. Shows first 4 and last 2 characters only.
    Minimum display: 4 chars + ***** + 2 chars
    """
    if not value:
        return "***"
    n = len(value)
    if n <= 8:
        return value[:2] + "***"
    prefix = value[:4]
    suffix = value[-2:]
    stars = "*" * min(8, n - 6)
    return f"{prefix}{stars}{suffix}"


def _is_false_positive(value: str) -> bool:
    """Return True if the value looks like a placeholder/test value."""
    if len(value) < _MIN_SECRET_LEN:
        return True
    for pat in _FP_PATTERNS:
        if pat.search(value):
            return True
    return False


# ---------------------------------------------------------------------------
# Secret rule definitions
# Patterns target the VALUE portion only (after assignment/key).
# Each rule: (rule_id, secret_type, pattern_for_value, base_confidence)
# ---------------------------------------------------------------------------

@dataclass
class SecretRule:
    rule_id: str
    secret_type: str
    # Pattern that matches the whole assignment line or value
    full_line_pattern: re.Pattern
    # Named group "val" captures the actual secret value
    value_group: str = "val"
    base_confidence: int = 65
    cwe: str = "CWE-798"


_SECRET_RULES: List[SecretRule] = [
    # GitHub personal access token (ghp_...)
    SecretRule(
        rule_id="SEC101",
        secret_type="GitHub Personal Access Token",
        full_line_pattern=re.compile(r"""(ghp_[A-Za-z0-9]{20,})"""),
        base_confidence=95,
    ),
    # GitHub OAuth token
    SecretRule(
        rule_id="SEC102",
        secret_type="GitHub OAuth Token",
        full_line_pattern=re.compile(r"""(gho_[A-Za-z0-9]{20,})"""),
        base_confidence=95,
    ),
    # GitHub App token
    SecretRule(
        rule_id="SEC103",
        secret_type="GitHub App Token",
        full_line_pattern=re.compile(r"""(ghs_[A-Za-z0-9]{20,})"""),
        base_confidence=95,
    ),
    # AWS access key (20+ chars: 4-char prefix + 16 or more uppercase alphanumeric)
    SecretRule(
        rule_id="SEC104",
        secret_type="AWS Access Key",
        full_line_pattern=re.compile(r"""\b((?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16,})\b"""),
        base_confidence=92,
    ),
    # Stripe live secret key
    SecretRule(
        rule_id="SEC105",
        secret_type="Stripe Live Secret Key",
        full_line_pattern=re.compile(r"""(sk_live_[A-Za-z0-9]{20,})"""),
        base_confidence=97,
    ),
    # Stripe test key (lower severity in scoring — still report)
    SecretRule(
        rule_id="SEC106",
        secret_type="Stripe Test Key",
        full_line_pattern=re.compile(r"""(sk_test_[A-Za-z0-9]{20,})"""),
        base_confidence=80,
    ),
    # RSA/PEM private key header
    SecretRule(
        rule_id="SEC107",
        secret_type="Private Key (PEM)",
        full_line_pattern=re.compile(
            r"""(-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PRIVATE)\s+PRIVATE\s+KEY-----)"""
        ),
        base_confidence=98,
    ),
    # Generic high-entropy assignment to credential-named variables
    SecretRule(
        rule_id="SEC108",
        secret_type="Hardcoded Credential",
        full_line_pattern=re.compile(
            r"""(?:api_?key|secret_?key|access_?token|auth_?token|password|passwd|pwd"""
            r"""|private_?key|client_?secret|encryption_?key|db_?password|database_?password)"""
            r"""\s*(?:=|:|=>)\s*['"]([^'"]{10,})['"]""",
            re.IGNORECASE,
        ),
        base_confidence=70,
    ),
    # Bearer token in string
    SecretRule(
        rule_id="SEC109",
        secret_type="Bearer Token",
        full_line_pattern=re.compile(
            r"""['"](Bearer\s+[A-Za-z0-9\-_\.]{20,})['"]\s*""",
            re.IGNORECASE,
        ),
        base_confidence=75,
    ),
    # Database URL with embedded password
    SecretRule(
        rule_id="SEC110",
        secret_type="Database URL with credentials",
        full_line_pattern=re.compile(
            r"""(?:['"]|=)\s*((?:postgres(?:ql)?|mysql|mongodb|redis|amqp)://[^:]+:[^@\s'"]{4,}@[^'"]+)""",
            re.IGNORECASE,
        ),
        base_confidence=85,
    ),
    # Generic JWT (three base64 segments)
    SecretRule(
        rule_id="SEC111",
        secret_type="JSON Web Token",
        full_line_pattern=re.compile(
            r"""['"](eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{20,})['"]\s*""",
        ),
        base_confidence=88,
    ),
    # SendGrid API key
    SecretRule(
        rule_id="SEC112",
        secret_type="SendGrid API Key",
        full_line_pattern=re.compile(r"""(SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,})"""),
        base_confidence=95,
    ),
    # Slack bot/webhook token
    SecretRule(
        rule_id="SEC113",
        secret_type="Slack Token",
        full_line_pattern=re.compile(r"""(xox[baprs]-[0-9A-Za-z\-]{10,})"""),
        base_confidence=95,
    ),
]


# Supported extensions for secret scanning
_SCANNABLE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs",
    ".php", ".rb", ".sh", ".bash", ".env", ".json", ".yaml", ".yml",
    ".toml", ".xml", ".properties", ".conf", ".config", ".ini",
    ".html", ".htm", ".tf",
}

# Files to always skip
_SKIP_NAMES: Set[str] = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "composer.lock", "go.sum", "Cargo.lock",
}

# Directories to skip
_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".next", "dist", "build", "target", ".tox", "coverage",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_secrets(root: Path) -> list:
    """
    Scan the repository for hardcoded secrets.

    Returns List[RichFindingResult] where evidence is ALWAYS redacted.
    The actual secret value is NEVER stored in any field.

    Safety guarantees:
    - Only reads file content; never executes any code.
    - Redacts evidence before creating any finding.
    - Fingerprint does NOT include the secret value.
    """
    from app.services.scan_engine.findings.types import (
        FindingCategory, RichFindingResult,
    )

    findings: list = []
    _walk_secrets(root, root, findings)
    return findings


def _walk_secrets(root: Path, current: Path, findings: list) -> None:
    """Walk directory tree scanning for secrets."""
    try:
        entries = list(current.iterdir())
    except (PermissionError, OSError):
        return

    for entry in entries:
        try:
            resolved = entry.resolve()
        except OSError:
            continue
        try:
            resolved.relative_to(root)
        except ValueError:
            continue

        if resolved.is_dir():
            if entry.name in _SKIP_DIRS:
                continue
            _walk_secrets(root, resolved, findings)
        elif resolved.is_file():
            if entry.name in _SKIP_NAMES:
                continue
            ext = entry.suffix.lower()
            if ext not in _SCANNABLE_EXTENSIONS:
                continue

            rel = str(resolved.relative_to(root))

            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            if size > 512 * 1024:  # skip files > 512 KB
                continue

            try:
                content = resolved.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Skip binary content
            if "\x00" in content[:4096]:
                continue

            _scan_file_for_secrets(content, rel, findings)


def _scan_file_for_secrets(content: str, file_path: str, findings: list) -> None:
    """Apply all secret rules to a single file's content."""
    from app.services.scan_engine.findings.types import (
        FindingCategory, RichFindingResult,
    )

    lines = content.splitlines()
    seen: Set[Tuple[str, int]] = set()  # (rule_id, line_bucket)

    for lineno, line in enumerate(lines, start=1):
        # Skip obvious comment-only lines that explain secrets
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            # Still scan but lower confidence adjustment happens via context
            pass

        for rule in _SECRET_RULES:
            try:
                match = rule.full_line_pattern.search(line)
            except re.error:
                continue

            if not match:
                continue

            # Extract value: use first capturing group
            groups = [g for g in match.groups() if g is not None]
            if not groups:
                # PEM key rule — no capture group needed
                value = match.group(0)
            else:
                value = groups[0]

            # Strip surrounding quotes
            value = value.strip("'\"").strip()

            # Apply false-positive filter
            if _is_false_positive(value):
                continue

            # Dedup at (rule, line_bucket) level
            line_bucket = (lineno // 5) * 5
            key = (rule.rule_id, line_bucket)
            if key in seen:
                continue
            seen.add(key)

            # Compute confidence
            confidence = rule.base_confidence
            entropy = _shannon_entropy(value)
            if entropy < _HIGH_ENTROPY_THRESHOLD:
                confidence -= 20  # lower entropy → less likely a real secret
            if len(value) < 12:
                confidence -= 10

            # Check if line is in a comment (lower confidence)
            if stripped.startswith(("#", "//", "*", "<!--")):
                confidence -= 15

            # Clamp
            confidence = max(10, min(99, confidence))
            conf_level = "high" if confidence >= 80 else "medium" if confidence >= 50 else "low"

            # REDACT — this is critical security
            redacted = _redact(value)

            # Redact the source line for evidence (replace any occurrence)
            evidence_line = line
            if value and len(value) > 4:
                evidence_line = evidence_line.replace(value, redacted)

            # Severity based on confidence + secret type
            severity = _compute_severity(rule, confidence)

            # Build finding — NO FULL SECRET stored in any field
            finding = RichFindingResult(
                severity=severity,
                title=f"Hardcoded {rule.secret_type} detected",
                description=(
                    f"A {rule.secret_type} appears to be hardcoded in source code. "
                    f"Hardcoded secrets are a critical security risk — they are committed "
                    f"to version control history and cannot be rotated without a new commit."
                ),
                file_path=file_path,
                line_number=lineno,
                rule_id=rule.rule_id,
                category=FindingCategory.SECRETS.value,
                cwe=rule.cwe,
                language=_detect_language(file_path),
                analyzer="secret_scanner",
                confidence=confidence,
                confidence_level=conf_level,
                why_risky=(
                    f"Hardcoded secrets in source code are exposed to anyone with read access "
                    f"to the repository (including git history after deletion). "
                    f"They cannot be rotated easily and may leak through logs, error messages, "
                    f"or debug output."
                ),
                impact=(
                    f"An attacker with repository access can extract and use the credential. "
                    f"Depending on the secret type, this may lead to account takeover, "
                    f"data breach, resource abuse, or unauthorized API access."
                ),
                remediation=(
                    f"1. Immediately rotate/revoke the exposed credential.\n"
                    f"2. Remove the hardcoded value from the code.\n"
                    f"3. Store the secret in an environment variable or secrets manager.\n"
                    f"4. Remove the secret from git history using git-filter-repo or BFG.\n"
                    f"5. Add a pre-commit hook or secret scanning CI step to prevent recurrence."
                ),
                fix_example=(
                    f"# Instead of hardcoding:\n"
                    f"# api_key = \"{redacted}\"\n\n"
                    f"# Use environment variables:\n"
                    f"import os\n"
                    f"api_key = os.environ['API_KEY']"
                ),
                evidence=evidence_line.strip(),  # REDACTED evidence
                # Phase 6 extra fields
            )
            # Attach Phase 6 extra fields — never store full secret
            finding.__dict__["secret_type"] = rule.secret_type
            finding.__dict__["redacted_value"] = redacted

            # Generate fingerprint from rule + file + line (NOT the secret value)
            raw_fp = f"{rule.rule_id}:{file_path}:{line_bucket}"
            finding.fingerprint = hashlib.sha256(raw_fp.encode()).hexdigest()[:16]

            findings.append(finding)


def _compute_severity(rule: SecretRule, confidence: int) -> str:
    """Determine severity from secret type and confidence."""
    # High-certainty patterns → high severity regardless of confidence
    if rule.rule_id in ("SEC101", "SEC102", "SEC103", "SEC104", "SEC105", "SEC107", "SEC112", "SEC113"):
        return "high" if confidence >= 70 else "medium"
    # Test keys are medium
    if rule.rule_id == "SEC106":
        return "medium"
    # High confidence generic secrets → high
    if confidence >= 80:
        return "high"
    return "medium"


def _detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
        ".sh": "shell", ".bash": "shell", ".env": "env",
        ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        ".toml": "toml", ".tf": "terraform",
    }
    ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return ext_map.get(ext, "unknown")
