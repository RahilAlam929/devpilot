"""
Core finding types for DevPilot Phase 5 intelligent scanner.

RichFindingResult is the primary output type from all analyzers.
It carries full context: source, sink, data-flow, CWE, confidence,
remediation, and optional deterministic patch.

Backward compatibility: the legacy FindingResult dataclass is still
imported by other modules. RichFindingResult is a strict superset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    HIGH = "high"      # 80-100 %
    MEDIUM = "medium"  # 50-79 %
    LOW = "low"        # 0-49 %


class FindingCategory(str, Enum):
    CODE_EXECUTION     = "code_execution"
    COMMAND_INJECTION  = "command_injection"
    XSS                = "xss"
    SQL_INJECTION      = "sql_injection"
    PATH_TRAVERSAL     = "path_traversal"
    SSRF               = "ssrf"
    OPEN_REDIRECT      = "open_redirect"
    DESERIALIZATION    = "deserialization"
    SECRETS            = "secrets"
    CRYPTO             = "crypto"
    TEMPLATE_INJECTION = "template_injection"
    CONFIGURATION      = "configuration"
    QUALITY            = "quality"
    DATA_FLOW          = "data_flow"


# ---------------------------------------------------------------------------
# Data-flow step
# ---------------------------------------------------------------------------


@dataclass
class DataFlowStep:
    """One step in a taint/data-flow trace."""

    label: str           # Human-readable description, e.g. "request.query_params['cmd']"
    line: int            # Source line in file
    step_type: str       # "source" | "assignment" | "sanitizer" | "sink" | "call"
    variable: Optional[str] = None   # Variable name involved, if any


# ---------------------------------------------------------------------------
# Source / Sink descriptors
# ---------------------------------------------------------------------------


@dataclass
class SourceInfo:
    """Description of where tainted data originates."""

    label: str              # e.g. "request.query_params['id']"
    line: int               # Line number
    is_user_controlled: bool = True
    framework: Optional[str] = None  # "fastapi" | "flask" | "express" | "nextjs" | None


@dataclass
class SinkInfo:
    """Description of the dangerous operation receiving tainted data."""

    label: str              # e.g. "subprocess.run(..., shell=True)"
    line: int               # Line number
    api: str                # e.g. "subprocess.run"
    is_sanitized: bool = False


# ---------------------------------------------------------------------------
# Safe patch descriptor
# ---------------------------------------------------------------------------


@dataclass
class PatchInfo:
    """
    A deterministic, safe code patch.

    Only generated when the exact fix is unambiguous and the replacement
    cannot break application semantics.
    """

    file_path: str
    start_line: int
    end_line: int
    original: str       # exact original text (one or more lines)
    replacement: str    # replacement text
    reason: str         # why this patch is safe


# ---------------------------------------------------------------------------
# Rich finding
# ---------------------------------------------------------------------------


@dataclass
class RichFindingResult:
    """
    A fully-decorated static-analysis finding.

    All fields beyond the core (severity/title/description/file_path/line_number)
    are optional so that simple regex-based rules that don't yet carry rich
    metadata can still produce valid findings.
    """

    # ── Core (always present) ──────────────────────────────────────────────
    severity: str          # "critical"|"high"|"medium"|"low"|"info"
    title: str
    description: str
    file_path: str
    line_number: int

    # ── Identity ───────────────────────────────────────────────────────────
    rule_id: str = ""
    category: str = FindingCategory.QUALITY.value

    # ── Location detail ────────────────────────────────────────────────────
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    code_snippet: Optional[str] = None   # the actual source line(s)

    # ── Risk context ───────────────────────────────────────────────────────
    cwe: Optional[str] = None           # e.g. "CWE-78"
    language: Optional[str] = None      # "python" | "javascript" | "typescript" …
    analyzer: str = "regex"             # "regex" | "ast" | "dataflow" | "import_graph"

    # ── Confidence ─────────────────────────────────────────────────────────
    confidence: int = 50                # 0-100
    confidence_level: str = ConfidenceLevel.MEDIUM.value  # "high"|"medium"|"low"

    # ── Source → Sink ──────────────────────────────────────────────────────
    source: Optional[SourceInfo] = None
    sink: Optional[SinkInfo] = None
    transforms: List[str] = field(default_factory=list)   # sanitizer labels
    data_flow: List[DataFlowStep] = field(default_factory=list)

    # ── Developer explanation ──────────────────────────────────────────────
    why_risky: Optional[str] = None     # narrative WHY
    impact: Optional[str] = None        # narrative IMPACT
    remediation: Optional[str] = None   # step-by-step HOW TO FIX
    fix_example: Optional[str] = None   # safe code snippet
    references: List[str] = field(default_factory=list)

    # ── Patch ──────────────────────────────────────────────────────────────
    patch_available: bool = False
    patch: Optional[PatchInfo] = None

    # ── Deduplication ──────────────────────────────────────────────────────
    fingerprint: str = ""               # stable hash for deduplication

    # ── Evidence ──────────────────────────────────────────────────────────
    evidence: Optional[str] = None      # matched text or AST node description

    def data_flow_text(self) -> str:
        """Render the data-flow chain as a human-readable string."""
        if not self.data_flow:
            return ""
        lines = []
        for i, step in enumerate(self.data_flow):
            arrow = "    ↓\n" if i < len(self.data_flow) - 1 else ""
            lines.append(f"{step.label}{arrow}")
        return "".join(lines)
