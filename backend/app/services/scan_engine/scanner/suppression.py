"""
Inline suppression support.

DevPilot supports per-line suppression comments that tell the scanner
to skip a specific rule on a specific line.

Syntax (all languages):

  Python / shell / Ruby / Go:
    some_code()  # devpilot: ignore RULE_ID
    some_code()  # devpilot: ignore RULE_ID reason: my reason here

  JavaScript / TypeScript / Java / C / C++ / PHP:
    someCode();  // devpilot: ignore RULE_ID
    someCode();  // devpilot: ignore JS001 reason: trusted internal source

  HTML / YAML:
    <!-- devpilot: ignore RULE_ID -->
    # devpilot: ignore RULE_ID

Rules:
  - The rule_id must be a known rule from the registry; unknown IDs are logged
    but not silently accepted (the suppression is still applied, but a warning
    is recorded so auditors can detect stale/invalid suppressions).
  - Suppression is line-scoped: only the finding on the suppressed line is
    affected. Findings on adjacent lines are NOT suppressed.
  - Critical findings (severity="critical") CAN be suppressed at the line
    level, but suppression of critical findings is recorded so it is auditable.
  - The scanner never suppresses findings silently. Every suppressed finding
    is tracked in the SuppressedFinding list returned alongside scan results.

Usage:
    from scanner.suppression import build_suppression_map, is_suppressed

    sup_map = build_suppression_map(content, language)
    if is_suppressed(sup_map, line_number, rule_id):
        continue  # skip this finding
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for suppression comment parsing
# ---------------------------------------------------------------------------

# Matches:   # devpilot: ignore RULE_ID
#            // devpilot: ignore RULE_ID
#            <!-- devpilot: ignore RULE_ID -->
_SUPPRESS_RE = re.compile(
    r"(?:#|//|/\*|<!--)\s*devpilot:\s*ignore\s+([A-Z0-9_]+)"
    r"(?:\s+reason:\s*(.+?))?(?:\s*-->|\s*\*/)?$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class SuppressionEntry:
    """A single inline suppression instruction."""
    line: int
    rule_id: str           # rule being suppressed
    reason: Optional[str]  # optional developer-supplied reason
    raw_text: str          # the raw comment text for audit trail
    is_unknown_rule: bool = False  # True if rule_id not in registry


@dataclass
class SuppressedFinding:
    """Records that a finding was suppressed (for audit purposes)."""
    file_path: str
    line: int
    rule_id: str
    reason: Optional[str]
    title: str


# SuppressionMap: line_number → set of suppressed rule_ids
SuppressionMap = Dict[int, Set[str]]


# ---------------------------------------------------------------------------
# Build suppression map from file content
# ---------------------------------------------------------------------------


def build_suppression_map(content: str, language: str = "") -> SuppressionMap:
    """
    Parse all suppression comments in *content* and return a dict mapping
    line_number → {rule_id, ...}.

    A suppression on line N suppresses findings exactly on line N.
    """
    sup_map: SuppressionMap = {}
    entries = _parse_suppressions(content)
    for entry in entries:
        sup_map.setdefault(entry.line, set()).add(entry.rule_id.upper())
    return sup_map


def _parse_suppressions(content: str) -> List[SuppressionEntry]:
    """Extract all suppression entries from file content."""
    from app.services.scan_engine.scanner.rules import get_rule

    entries: List[SuppressionEntry] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        m = _SUPPRESS_RE.search(line)
        if not m:
            continue

        rule_id = m.group(1).upper()
        reason = m.group(2).strip() if m.group(2) else None
        raw_text = m.group(0)

        is_unknown = get_rule(rule_id) is None
        if is_unknown:
            logger.warning(
                "Suppression on line %d references unknown rule '%s'. "
                "Suppression still applied.",
                lineno, rule_id,
            )

        entries.append(SuppressionEntry(
            line=lineno,
            rule_id=rule_id,
            reason=reason,
            raw_text=raw_text,
            is_unknown_rule=is_unknown,
        ))

    return entries


# ---------------------------------------------------------------------------
# Check suppression
# ---------------------------------------------------------------------------


def is_suppressed(sup_map: SuppressionMap, line: int, rule_id: str) -> bool:
    """Return True if the given rule_id is suppressed on the given line."""
    suppressed = sup_map.get(line, set())
    return rule_id.upper() in suppressed


def apply_suppressions(
    findings: List,   # List[RichFindingResult]
    sup_map: SuppressionMap,
    file_path: str,
) -> Tuple[List, List[SuppressedFinding]]:
    """
    Filter *findings* through *sup_map*.

    Returns:
        (active_findings, suppressed_records)

    active_findings  — findings that were NOT suppressed
    suppressed_records — audit trail of suppressed findings
    """
    active = []
    suppressed_records: List[SuppressedFinding] = []

    for finding in findings:
        if finding.rule_id and is_suppressed(sup_map, finding.line_number, finding.rule_id):
            reason = sup_map.get(finding.line_number, {})
            suppressed_records.append(SuppressedFinding(
                file_path=file_path,
                line=finding.line_number,
                rule_id=finding.rule_id,
                reason=None,  # reason stored in SuppressionEntry; not recovered here
                title=finding.title,
            ))
            if finding.severity == "critical":
                logger.warning(
                    "CRITICAL finding suppressed: rule=%s file=%s line=%d title='%s'",
                    finding.rule_id, file_path, finding.line_number, finding.title,
                )
        else:
            active.append(finding)

    return active, suppressed_records
