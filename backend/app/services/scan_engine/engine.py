"""
ScanEngine — Phase 5 / Phase 8 (GitHub source navigation).

Orchestrates a single scan run:
  1. Validate the repository path.
  2. Set scan status to "running".
  3. Capture git commit SHA + branch from the cloned path (Phase 8).
  4. Call analyze_repository() which returns List[RichFindingResult].
  5. Persist all rich fields to the Finding model.
  6. Mark scan "completed" or "failed".

Backward compatible: the core lifecycle is unchanged.
New (Phase 8): captures commit_sha and branch from the cloned repo so that
  "Open on GitHub" links can point to the exact revision that was scanned.
"""

import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.models import Finding, Repository, Scan
from app.services.scan_engine.analyzers import analyze_repository

logger = logging.getLogger(__name__)


class ScanEngine:
    """Run safe static analysis for a repository."""

    def __init__(self, db: Session, scan: Scan, repository: Repository):
        self.db = db
        self.scan = scan
        self.repository = repository

    def run(self, repository_path: str) -> list[Finding]:
        root = Path(repository_path)

        if not root.exists():
            raise FileNotFoundError(
                f"Repository path does not exist: {root}"
            )

        if not root.is_dir():
            raise NotADirectoryError(
                f"Repository path is not a directory: {root}"
            )

        self.scan.status = "running"
        self.scan.started_at = datetime.utcnow()

        # ── Phase 8: capture git ref for "Open on GitHub" links ───────────
        commit_sha, branch = _capture_git_ref(root)
        if commit_sha:
            self.scan.commit_sha = commit_sha
        if branch:
            self.scan.branch = branch

        self.db.commit()

        try:
            results = analyze_repository(root)
            findings = []

            for result in results:
                finding = self._persist_finding(result)
                self.db.add(finding)
                findings.append(finding)

            self.scan.status = "completed"
            self.scan.completed_at = datetime.utcnow()
            self.db.commit()

            for finding in findings:
                self.db.refresh(finding)

            self.db.refresh(self.scan)
            return findings

        except Exception:
            self.scan.status = "failed"
            self.scan.completed_at = datetime.utcnow()
            self.db.commit()
            raise

    def _persist_finding(self, result) -> Finding:
        """Map a RichFindingResult to a Finding ORM object."""
        # Core fields (always present)
        finding = Finding(
            scan_id=self.scan.id,
            severity=result.severity,
            title=result.title,
            description=result.description,
            file_path=result.file_path,
            line_number=result.line_number,
        )

        # Phase 5 rich fields (only if the result has them)
        finding.rule_id = _get(result, "rule_id") or None
        finding.category = _get(result, "category") or None
        finding.column_number = _get(result, "column") or None
        finding.end_line = _get(result, "end_line") or None
        finding.code_snippet = _get(result, "code_snippet") or None
        finding.cwe = _get(result, "cwe") or None
        finding.language = _get(result, "language") or None
        finding.analyzer = _get(result, "analyzer") or None
        finding.confidence = _get(result, "confidence") or None
        finding.confidence_level = _get(result, "confidence_level") or None
        finding.why_risky = _get(result, "why_risky") or None
        finding.impact = _get(result, "impact") or None
        finding.remediation = _get(result, "remediation") or None
        finding.fix_example = _get(result, "fix_example") or None
        finding.evidence = _get(result, "evidence") or None
        finding.fingerprint = _get(result, "fingerprint") or None

        # patch_available: default False if not set
        patch_available = _get(result, "patch_available")
        finding.patch_available = bool(patch_available) if patch_available is not None else False

        # Phase 6: SCA / Dependency fields
        finding.dependency_name = _get_dict(result, "dependency_name") or None
        finding.dependency_version = _get_dict(result, "dependency_version") or None
        finding.fixed_version = _get_dict(result, "fixed_version") or None
        finding.advisory_id = _get_dict(result, "advisory_id") or None

        # Phase 6: Secret scanner — NEVER store full secret
        finding.secret_type = _get_dict(result, "secret_type") or None
        finding.redacted_value = _get_dict(result, "redacted_value") or None

        # Patch text: serialize PatchInfo to JSON string
        patch = _get(result, "patch")
        if patch is not None:
            try:
                finding.patch_text = json.dumps({
                    "file_path": patch.file_path,
                    "start_line": patch.start_line,
                    "end_line": patch.end_line,
                    "original": patch.original,
                    "replacement": patch.replacement,
                    "reason": patch.reason,
                })
            except Exception:
                finding.patch_text = None

        # Source label
        source = _get(result, "source")
        if source is not None:
            finding.source_label = getattr(source, "label", None)

        # Sink label
        sink = _get(result, "sink")
        if sink is not None:
            finding.sink_label = getattr(sink, "label", None)

        # Data flow — serialize to human-readable text
        data_flow = _get(result, "data_flow")
        if data_flow:
            try:
                steps = []
                for i, step in enumerate(data_flow):
                    label = getattr(step, "label", "?")
                    line = getattr(step, "line", 0)
                    arrow = "\n    ↓\n" if i < len(data_flow) - 1 else ""
                    steps.append(f"{label} (line {line}){arrow}")
                finding.data_flow_text = "".join(steps)
            except Exception:
                finding.data_flow_text = None

        return finding


def _get(obj, attr: str, default=None):
    """Safely get an attribute from an object."""
    return getattr(obj, attr, default)


def _get_dict(obj, key: str, default=None):
    """Get a value from an object's __dict__ or attributes (for Phase 6 dynamic fields)."""
    # Try __dict__ first (dynamic attributes set by Phase 6 analyzers)
    obj_dict = getattr(obj, "__dict__", {})
    val = obj_dict.get(key, None)
    if val is not None:
        return val
    return getattr(obj, key, default)


def _capture_git_ref(repo_path: Path) -> "tuple[Optional[str], Optional[str]]":
    """
    Capture the git commit SHA and branch name from a cloned repository.

    Uses ``git rev-parse HEAD`` and ``git rev-parse --abbrev-ref HEAD``
    executed inside *repo_path*.  Both calls are safe:
      - Never shell=True.
      - No user input is passed as arguments.
      - Failure is silently swallowed; the scan continues normally.

    Returns
    -------
    (commit_sha, branch) — either or both may be None if git is not
    available, the path is not a git repository, or the call fails.
    """
    import os

    commit_sha: str | None = None
    branch: str | None = None

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            cwd=str(repo_path),
            timeout=10,
            shell=False,
            env={**os.environ},
        )
        if result.returncode == 0:
            sha = result.stdout.decode(errors="replace").strip()
            # Validate: must be 40 or 64 hex chars (SHA-1 or SHA-256)
            if sha and all(c in "0123456789abcdefABCDEF" for c in sha) and len(sha) in (40, 64):
                commit_sha = sha
    except Exception:
        pass  # git not available or not a git repo — that's fine

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            cwd=str(repo_path),
            timeout=10,
            shell=False,
            env={**os.environ},
        )
        if result.returncode == 0:
            ref = result.stdout.decode(errors="replace").strip()
            # "HEAD" means detached HEAD — not a useful branch name
            if ref and ref != "HEAD":
                branch = ref
    except Exception:
        pass

    return commit_sha, branch
