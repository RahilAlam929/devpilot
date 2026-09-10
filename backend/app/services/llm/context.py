"""
Finding context builder — Phase 7B.

Constructs a minimal, deterministic representation of a Finding for use
as the LLM user message. Also computes a deterministic SHA-256 request hash
so identical findings generate the same hash (enabling cache lookup).

DESIGN PRINCIPLES:
  1. Include only what is necessary to understand the finding.
     Do NOT blindly send the entire repository.
  2. Context length is bounded by LLM_MAX_CONTEXT_CHARS.
  3. Context construction is deterministic — same finding = same context hash.
  4. Redaction is applied AFTER context construction and BEFORE hashing,
     so the hash is over the redacted, safe representation.
  5. This module is pure (no DB calls, no I/O) to keep it testable.
"""

import hashlib
import logging
from typing import Optional

from app.services.llm.redaction import redact
from app.services.llm.schemas import ANALYSIS_VERSION

logger = logging.getLogger(__name__)

# Default max characters for the context sent to the LLM.
# This can be overridden via LLM_MAX_CONTEXT_CHARS in settings.
DEFAULT_MAX_CONTEXT_CHARS = 12_000


class FindingContext:
    """
    Immutable finding context for LLM analysis.

    Attributes:
        text:         The redacted context text to send as the user message.
        request_hash: Deterministic SHA-256 hex digest over the context.
    """

    __slots__ = ("text", "request_hash")

    def __init__(self, text: str, request_hash: str) -> None:
        self.text = text
        self.request_hash = request_hash


def build_finding_context(
    finding,  # app.models.models.Finding — avoid circular import
    provider: str,
    model: str,
    max_chars: Optional[int] = None,
) -> FindingContext:
    """
    Build a minimal, redacted, deterministic context from a Finding ORM object.

    Steps:
      1. Extract relevant Finding fields (never the entire repository).
      2. Assemble them into a structured text block.
      3. Truncate to max_chars if necessary.
      4. Apply secret redaction.
      5. Compute deterministic SHA-256 hash over the final redacted text plus
         the analysis version and provider/model (so changing the model forces
         a new hash).

    Args:
        finding:   A SQLAlchemy Finding instance.
        provider:  The LLM provider name (used in hash).
        model:     The LLM model name (used in hash).
        max_chars: Maximum character count for the context text.
                   Defaults to DEFAULT_MAX_CONTEXT_CHARS.

    Returns:
        A FindingContext with the redacted text and its hash.
    """
    if max_chars is None:
        max_chars = DEFAULT_MAX_CONTEXT_CHARS

    lines = []

    # ── Finding identity ───────────────────────────────────────────────────
    lines.append(f"Finding ID: {finding.id}")
    if finding.rule_id:
        lines.append(f"Rule ID: {finding.rule_id}")
    lines.append(f"Title: {finding.title}")
    lines.append(f"Severity: {finding.severity}")
    if finding.category:
        lines.append(f"Category: {finding.category}")
    if finding.cwe:
        lines.append(f"CWE: {finding.cwe}")
    if finding.analyzer:
        lines.append(f"Analyzer: {finding.analyzer}")
    if finding.language:
        lines.append(f"Language: {finding.language}")

    # ── Location ───────────────────────────────────────────────────────────
    if finding.file_path:
        location = finding.file_path
        if finding.line_number:
            location += f":{finding.line_number}"
            if finding.column_number:
                location += f":{finding.column_number}"
        lines.append(f"Location: {location}")

    if finding.end_line and finding.line_number:
        lines.append(f"Line range: {finding.line_number}–{finding.end_line}")

    # ── Confidence ────────────────────────────────────────────────────────
    if finding.confidence is not None:
        lines.append(f"Scanner confidence: {finding.confidence}%")
    if finding.confidence_level:
        lines.append(f"Confidence level: {finding.confidence_level}")

    # ── Description ───────────────────────────────────────────────────────
    if finding.description:
        lines.append(f"\nDescription:\n{finding.description}")

    # ── Code snippet ──────────────────────────────────────────────────────
    if finding.code_snippet:
        snippet = finding.code_snippet
        lines.append(f"\nCode snippet:\n```\n{snippet}\n```")

    # ── Evidence ──────────────────────────────────────────────────────────
    if finding.evidence and finding.evidence != finding.code_snippet:
        lines.append(f"\nEvidence:\n{finding.evidence}")

    # ── Data flow ─────────────────────────────────────────────────────────
    if finding.data_flow_text:
        lines.append(f"\nData flow:\n{finding.data_flow_text}")

    if finding.source_label:
        lines.append(f"Source: {finding.source_label}")
    if finding.sink_label:
        lines.append(f"Sink: {finding.sink_label}")

    # ── Existing scanner guidance (context for the LLM) ───────────────────
    if finding.why_risky:
        lines.append(f"\nScanner notes (why risky): {finding.why_risky}")
    if finding.impact:
        lines.append(f"Scanner notes (impact): {finding.impact}")

    # ── Phase 6 metadata ──────────────────────────────────────────────────
    if finding.dependency_name:
        lines.append(f"\nDependency: {finding.dependency_name}")
        if finding.dependency_version:
            lines.append(f"Dependency version: {finding.dependency_version}")
        if finding.fixed_version:
            lines.append(f"Fixed in version: {finding.fixed_version}")
        if finding.advisory_id:
            lines.append(f"Advisory ID: {finding.advisory_id}")

    # Secret scanner findings — provide redacted type only, NEVER the actual value
    if finding.secret_type:
        lines.append(f"\nSecret type: {finding.secret_type}")
        # Deliberately omit redacted_value — it's already redacted but
        # we don't need it for the LLM to understand the finding type.

    raw_text = "\n".join(lines)

    # ── Truncate to max_chars ──────────────────────────────────────────────
    if len(raw_text) > max_chars:
        raw_text = raw_text[:max_chars] + "\n[... truncated to fit context window ...]"
        logger.debug(
            "Finding context truncated to %d chars for finding %s",
            max_chars,
            finding.id,
        )

    # ── Apply redaction ────────────────────────────────────────────────────
    redacted_text = redact(raw_text)

    # ── Deterministic hash ─────────────────────────────────────────────────
    # Hash components (all deterministic, no timestamps or random data):
    #   - The redacted context text (normalised)
    #   - The analysis version (changes when prompt/schema changes)
    #   - The provider and model (hash changes when model changes)
    canonical = "\n".join(
        [
            redacted_text,
            f"analysis_version={ANALYSIS_VERSION}",
            f"provider={provider}",
            f"model={model}",
        ]
    )
    request_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return FindingContext(text=redacted_text, request_hash=request_hash)
