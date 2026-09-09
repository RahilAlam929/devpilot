"""
Finding Deduplication and Correlation Engine.

Multiple analyzers (regex, AST, dataflow, import_graph) can independently
detect the same issue. This module:

  1. Generates stable fingerprints for each finding so duplicates are
     identifiable across scan runs.
  2. Merges duplicate findings, preferring the richest evidence.
  3. Preserves the highest-confidence finding when merging.

Fingerprint design:
  For SECURITY findings:
    rule_id + file_path + line_number(±5 window) + sink_api

  For QUALITY findings (category == "quality"):
    category + file_path + line_number(±5 window)
    This merges any two quality findings at the same location regardless
    of which rule/title first detected them (regex vs js_analyzer both
    fire on console statements).

Using a line window (±5) handles minor indentation changes between scans.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Tuple

from app.services.scan_engine.findings.types import RichFindingResult

# Quality category constant — avoid import cycle with FindingCategory enum
_QUALITY_CATEGORY = "quality"

# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

_LINE_WINDOW = 5  # lines within this distance are considered the same location


def generate_fingerprint(finding: RichFindingResult) -> str:
    """
    Generate a stable, content-independent fingerprint for a finding.

    For quality findings: uses category + normalized file path + bucketed
    line number. This ensures that two analyzers detecting the same console
    statement on the same line will produce the same fingerprint regardless
    of which rule ID or title they used.

    For security findings: uses rule_id + normalized file path + bucketed
    line number + sink api.  The rule_id discriminates genuine security
    findings from one another even when they appear on the same line.
    """
    path = finding.file_path.replace("\\", "/")
    line_bucket = (finding.line_number // _LINE_WINDOW) * _LINE_WINDOW
    category = finding.category or ""

    if category == _QUALITY_CATEGORY:
        # Quality findings: merge by location + category only, BUT only for
        # rules that are genuinely quality rules (QA prefix).
        # Security rules (PY*, JS*, SEC*, CRY*) that happen to carry
        # category="quality" still need rule-level discrimination so that
        # two different security rules on the same line stay separate.
        rule_id = finding.rule_id or ""
        is_quality_rule = (
            rule_id.startswith("QA")
            or (not rule_id and category == _QUALITY_CATEGORY)
        )
        if is_quality_rule:
            # Two QA rules detecting "console.log on line 176" produce one finding.
            raw = f"quality:{path}:{line_bucket}"
        else:
            # Security rule with quality category — keep rule-level granularity
            sink_api = finding.sink.api if finding.sink else ""
            raw = f"{rule_id}:{path}:{line_bucket}:{sink_api}"
    else:
        # Security findings: rule_id distinguishes genuinely different issues
        # that may share a line (e.g. XSS + SQL injection on the same sink).
        rule = finding.rule_id or finding.title.lower().replace(" ", "_")
        sink_api = finding.sink.api if finding.sink else ""
        raw = f"{rule}:{path}:{line_bucket}:{sink_api}"

    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Merge priority
# ---------------------------------------------------------------------------

# Analyzer priority: higher = better evidence, wins in merge
_ANALYZER_PRIORITY: Dict[str, int] = {
    "dataflow":     4,
    "ast":          3,
    "import_graph": 2,
    "regex":        1,
}

_SEVERITY_ORDER: Dict[str, int] = {
    "critical": 5,
    "high":     4,
    "medium":   3,
    "low":      2,
    "info":     1,
}


def _analyzer_rank(f: RichFindingResult) -> int:
    return _ANALYZER_PRIORITY.get(f.analyzer, 0)


def _merge_pair(keep: RichFindingResult, discard: RichFindingResult) -> RichFindingResult:
    """
    Merge *discard* into *keep*, enriching *keep* with any missing fields.

    The richer/higher-priority finding wins on all set fields.
    For quality findings the context-aware analyzer's title and description
    are preferred over the generic regex title.
    """
    # Prefer higher severity
    if _SEVERITY_ORDER.get(discard.severity, 0) > _SEVERITY_ORDER.get(keep.severity, 0):
        keep.severity = discard.severity

    # Prefer higher confidence
    if discard.confidence > keep.confidence:
        keep.confidence = discard.confidence
        keep.confidence_level = discard.confidence_level

    # For quality findings: if the discard title is more specific (longer or
    # uses a known "better" keyword), prefer it for the user-visible title.
    if keep.category == _QUALITY_CATEGORY:
        keep_generic = keep.title in (
            "console statement left in code (JavaScript/TypeScript)",
            "debugger statement (JavaScript/TypeScript)",
            "Debug print statement (Python)",
        )
        discard_specific = discard.title not in (
            "console statement left in code (JavaScript/TypeScript)",
            "debugger statement (JavaScript/TypeScript)",
            "Debug print statement (Python)",
        )
        if keep_generic and discard_specific:
            keep.title = discard.title
            keep.description = discard.description

    # Fill in source/sink/dataflow from discard if keep is missing them
    if not keep.source and discard.source:
        keep.source = discard.source
    if not keep.sink and discard.sink:
        keep.sink = discard.sink
    if not keep.data_flow and discard.data_flow:
        keep.data_flow = discard.data_flow

    # Fill in explanation fields
    if not keep.why_risky and discard.why_risky:
        keep.why_risky = discard.why_risky
    if not keep.impact and discard.impact:
        keep.impact = discard.impact
    if not keep.remediation and discard.remediation:
        keep.remediation = discard.remediation
    if not keep.fix_example and discard.fix_example:
        keep.fix_example = discard.fix_example
    if not keep.patch_available and discard.patch_available:
        keep.patch_available = discard.patch_available
        keep.patch = discard.patch

    # Merge evidence
    if not keep.evidence and discard.evidence:
        keep.evidence = discard.evidence
    if not keep.code_snippet and discard.code_snippet:
        keep.code_snippet = discard.code_snippet

    # Merge transforms list
    for t in discard.transforms:
        if t not in keep.transforms:
            keep.transforms.append(t)

    return keep


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def deduplicate(findings: List[RichFindingResult]) -> List[RichFindingResult]:
    """
    Deduplicate a list of findings and return a merged, unique list.

    Algorithm:
      1. Generate fingerprints for all findings.
      2. Group findings by fingerprint.
      3. Within each group, keep the highest-priority analyzer's finding
         and merge in fields from lower-priority duplicates.
      4. Return one finding per unique fingerprint.
    """
    # Ensure all fingerprints are set
    for f in findings:
        if not f.fingerprint:
            f.fingerprint = generate_fingerprint(f)

    # Group by fingerprint
    groups: Dict[str, List[RichFindingResult]] = {}
    for f in findings:
        groups.setdefault(f.fingerprint, []).append(f)

    result: List[RichFindingResult] = []

    for fp, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Sort: highest analyzer priority first, then highest confidence
        group.sort(key=lambda f: (_analyzer_rank(f), f.confidence), reverse=True)

        winner = group[0]
        for duplicate in group[1:]:
            winner = _merge_pair(winner, duplicate)

        result.append(winner)

    # Stable output order: by file, then line
    result.sort(key=lambda f: (f.file_path, f.line_number))
    return result
