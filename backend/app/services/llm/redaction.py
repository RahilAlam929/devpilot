"""
Secret / sensitive data redaction — Phase 7B.

Redacts credentials, API keys, tokens, and other sensitive patterns from
text before it is ever sent to an external LLM provider.

IMPORTANT:
  - This module MUST run on ALL repository content before it reaches the LLM.
  - The original unredacted text is NEVER stored in the LLM analysis table.
  - Redaction is best-effort — do not rely on it as a sole security control.
  - Reuses conceptual patterns from the Phase 6 secret scanner; redaction here
    is tailored to the LLM context builder, not the scanner finding store.

SECURITY:
  - Redaction uses regex replacements. Patterns are ordered from most specific
    to least specific to avoid partial matches.
  - Placeholders are deliberately non-functional strings so the LLM cannot
    reconstruct secrets from context clues.
"""

import re
from typing import List, NamedTuple


# ── Placeholder constants ──────────────────────────────────────────────────

PLACEHOLDER_SECRET = "[REDACTED_SECRET]"
PLACEHOLDER_TOKEN = "[REDACTED_TOKEN]"
PLACEHOLDER_PASSWORD = "[REDACTED_PASSWORD]"
PLACEHOLDER_KEY = "[REDACTED_KEY]"
PLACEHOLDER_CREDENTIAL = "[REDACTED_CREDENTIAL]"
PLACEHOLDER_DB_URL = "[REDACTED_DB_URL]"


class RedactionPattern(NamedTuple):
    """A named regex pattern and its replacement placeholder."""

    name: str
    pattern: re.Pattern  # type: ignore[type-arg]
    replacement: str


# ── Compiled redaction patterns ────────────────────────────────────────────
# Ordered from most specific to least specific.
# All patterns are case-insensitive where appropriate.

_RAW_PATTERNS: List[tuple] = [
    # ── Database URLs with credentials ────────────────────────────────────
    # postgresql://user:pass@host/db  mysql://user:pass@host/db  etc.
    (
        "db_url_with_credentials",
        r"(?:postgresql|postgres|mysql|mariadb|mongodb|redis|mssql|sqlite)"
        r"(?:\+\w+)?://[^:@\s]+:[^@\s]+@[^\s\"']+",
        PLACEHOLDER_DB_URL,
    ),

    # ── AWS credentials ────────────────────────────────────────────────────
    # AWS Access Key IDs: AKIA…  ASIA…  AROA…  AIDA…  AIPA…  ANPA…  ANVA…  APKA…
    (
        "aws_access_key_id",
        r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}",
        PLACEHOLDER_KEY,
    ),
    # AWS secret key assignment patterns
    (
        "aws_secret_key_assignment",
        r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?[A-Za-z0-9/+]{40}["\']?',
        f"aws_secret_access_key = {PLACEHOLDER_KEY}",
    ),

    # ── JWT tokens (three base64 segments separated by dots) ──────────────
    (
        "jwt_token",
        r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        PLACEHOLDER_TOKEN,
    ),

    # ── Bearer tokens in Authorization headers ─────────────────────────────
    (
        "bearer_token",
        r"(?i)(?:Bearer|Authorization:\s*Bearer)\s+[A-Za-z0-9\-_.~+/]{20,}",
        f"Bearer {PLACEHOLDER_TOKEN}",
    ),

    # ── GitHub tokens ──────────────────────────────────────────────────────
    (
        "github_pat",
        r"(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{36,}",
        PLACEHOLDER_TOKEN,
    ),
    (
        "github_oauth",
        r"gho_[A-Za-z0-9]{36}",
        PLACEHOLDER_TOKEN,
    ),

    # ── Generic API key assignment patterns ───────────────────────────────
    # Covers: API_KEY = "...", api_key: "...", OPENAI_API_KEY = "sk-...", etc.
    (
        "api_key_assignment",
        r'(?i)(?:api[_\-\.]?key|api[_\-\.]?token|access[_\-\.]?token|secret[_\-\.]?key|'
        r'private[_\-\.]?key|auth[_\-\.]?token|client[_\-\.]?secret)\s*[=:]\s*'
        r'["\']?[A-Za-z0-9\-_./+]{16,}["\']?',
        f"api_key = {PLACEHOLDER_KEY}",
    ),

    # ── OpenAI API keys (sk- prefix) ──────────────────────────────────────
    (
        "openai_key",
        r"sk-[A-Za-z0-9\-_]{20,}",
        PLACEHOLDER_KEY,
    ),

    # ── Anthropic API keys ─────────────────────────────────────────────────
    (
        "anthropic_key",
        r"sk-ant-[A-Za-z0-9\-_]{30,}",
        PLACEHOLDER_KEY,
    ),

    # ── Password assignment patterns ───────────────────────────────────────
    (
        "password_assignment",
        r'(?i)(?:password|passwd|pass|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
        f'password = "{PLACEHOLDER_PASSWORD}"',
    ),

    # ── PEM private keys ───────────────────────────────────────────────────
    (
        "private_key_pem",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        PLACEHOLDER_KEY,
    ),

    # ── Generic high-entropy strings after common secret variable names ────
    # Must come AFTER more specific patterns above.
    (
        "generic_secret_var",
        r'(?i)(?:secret|token|credential|auth)\s*[=:]\s*["\'][A-Za-z0-9\-_./+=]{16,}["\']',
        f'secret = "{PLACEHOLDER_SECRET}"',
    ),

    # ── Stripe keys ───────────────────────────────────────────────────────
    (
        "stripe_key",
        r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}",
        PLACEHOLDER_KEY,
    ),

    # ── Slack tokens ──────────────────────────────────────────────────────
    (
        "slack_token",
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        PLACEHOLDER_TOKEN,
    ),
]

# Compile all patterns once at module load time
REDACTION_PATTERNS: List[RedactionPattern] = [
    RedactionPattern(
        name=name,
        pattern=re.compile(pattern, re.MULTILINE | re.DOTALL),
        replacement=replacement,
    )
    for name, pattern, replacement in _RAW_PATTERNS
]


def redact(text: str) -> str:
    """
    Apply all redaction patterns to ``text`` and return the sanitised string.

    Each pattern is applied in order. The replacement is a static placeholder
    string — never the captured group or a transformation of the secret.

    This function is idempotent: running it multiple times on already-redacted
    text is safe and produces the same output.

    SECURITY: Do NOT use re.sub with backreferences to the match — that would
    risk re-inserting parts of the secret into the replacement.
    """
    result = text
    for rp in REDACTION_PATTERNS:
        result = rp.pattern.sub(rp.replacement, result)
    return result


def redact_list(items: List[str]) -> List[str]:
    """Apply redaction to each item in a list."""
    return [redact(item) for item in items]


def count_redactions(original: str, redacted: str) -> int:
    """
    Count how many placeholder strings appear in the redacted output.
    Useful for logging/auditing how much was redacted (without logging what).
    """
    placeholders = [
        PLACEHOLDER_SECRET,
        PLACEHOLDER_TOKEN,
        PLACEHOLDER_PASSWORD,
        PLACEHOLDER_KEY,
        PLACEHOLDER_CREDENTIAL,
        PLACEHOLDER_DB_URL,
    ]
    return sum(redacted.count(p) for p in placeholders)
