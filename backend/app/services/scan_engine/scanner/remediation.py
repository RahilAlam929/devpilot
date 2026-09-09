"""
Remediation Engine.

Takes a RichFindingResult that already has rule_id/severity/category set,
and enriches it with:
  - why_risky
  - impact
  - remediation
  - fix_example
  - references
  - patch (if deterministic)

Remediation content is sourced from the rule registry. The engine should not
be called until after the finding's rule_id is assigned.
"""

from __future__ import annotations

from app.services.scan_engine.findings.types import PatchInfo, RichFindingResult
from app.services.scan_engine.scanner.rules import get_rule


def enrich_remediation(finding: RichFindingResult) -> RichFindingResult:
    """
    Populate remediation fields on *finding* from the rule registry.

    Mutates the finding in place and returns it.
    Does nothing if rule_id is empty or not found in the registry.
    """
    if not finding.rule_id:
        return finding

    rule = get_rule(finding.rule_id)
    if not rule:
        return finding

    # Only overwrite if the field is not already set by the analyzer
    if not finding.why_risky:
        finding.why_risky = rule.why_risky
    if not finding.impact:
        finding.impact = rule.impact
    if not finding.remediation:
        finding.remediation = rule.remediation
    if not finding.fix_example:
        finding.fix_example = rule.fix_example
    if not finding.references:
        finding.references = list(rule.references)
    if not finding.cwe:
        finding.cwe = rule.cwe

    # Try to generate a safe deterministic patch
    if not finding.patch_available:
        patch = _try_generate_patch(finding)
        if patch:
            finding.patch = patch
            finding.patch_available = True

    return finding


def _try_generate_patch(finding: RichFindingResult) -> PatchInfo | None:
    """
    Attempt to generate a safe, deterministic patch for a finding.

    Returns None if:
    - The fix is ambiguous or application-specific.
    - The replacement could change semantics.
    - The evidence is insufficient to construct an exact patch.
    - The rule does not have a deterministic one-line fix.
    """
    # Only attempt patches for rules we explicitly know how to patch
    rule_id = finding.rule_id
    snippet = finding.code_snippet or ""
    line = finding.line_number

    if not snippet or not line:
        return None

    # yaml.load() → yaml.safe_load() — deterministic, single-line
    if rule_id == "PY008":
        return _patch_yaml_load(finding, snippet, line)

    # Weak hash — can suggest sha256 but only if usage is simple
    # Not generating patches for most rules — too risky to be wrong

    return None


def _patch_yaml_load(
    finding: RichFindingResult,
    snippet: str,
    line: int,
) -> PatchInfo | None:
    """
    yaml.load(data) → yaml.safe_load(data)

    Only when it's a single-argument call (no existing Loader= argument).
    """
    import re

    # Match: yaml.load(<expr>) — no second argument
    m = re.match(r"^(\s*)(.*)yaml\.load\(([^,)]+)\)(.*)", snippet)
    if not m:
        return None

    indent = m.group(1)
    prefix = m.group(2)
    arg = m.group(3).strip()
    suffix = m.group(4)

    replacement = f"{indent}{prefix}yaml.safe_load({arg}){suffix}"

    return PatchInfo(
        file_path=finding.file_path,
        start_line=line,
        end_line=line,
        original=snippet,
        replacement=replacement,
        reason="Replace yaml.load() with yaml.safe_load() to prevent arbitrary code execution during YAML deserialization.",
    )
