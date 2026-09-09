import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database import SessionLocal, settings
from app.models import Finding, Project, Repository, Scan, User
from app.services.github import (
    GitCloneError,
    GitCloneTimeoutError,
    clone_repository,
    validate_github_url,
)
from app.services.scan_engine.engine import ScanEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class ScanCreate(BaseModel):
    """Client only sends the repository_id. The backend clones the repo."""
    repository_id: str


class ScanResponse(BaseModel):
    id: str
    repository_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PatchResponse(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    original: str
    replacement: str
    reason: str


class DataFlowStepResponse(BaseModel):
    label: str
    line: int
    step_type: str
    variable: Optional[str] = None


class FindingResponse(BaseModel):
    """
    Phase 5 finding response.
    All new fields are Optional so existing clients using only the original
    5 fields continue to work without any changes.
    """
    # ── Original fields (always present) ─────────────────────────────────
    id: str
    scan_id: str
    severity: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None

    # ── Phase 5 fields (nullable) ─────────────────────────────────────────
    rule_id: Optional[str] = None
    category: Optional[str] = None
    column_number: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe: Optional[str] = None
    language: Optional[str] = None
    analyzer: Optional[str] = None
    confidence: Optional[int] = None
    confidence_level: Optional[str] = None
    why_risky: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    fix_example: Optional[str] = None
    source_label: Optional[str] = None
    sink_label: Optional[str] = None
    data_flow_text: Optional[str] = None
    evidence: Optional[str] = None
    patch_available: Optional[bool] = None
    patch: Optional[PatchResponse] = None
    fingerprint: Optional[str] = None

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_with_patch(cls, finding: Finding) -> "FindingResponse":
        """Build response, deserializing patch_text JSON if present."""
        data = {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "rule_id": finding.rule_id,
            "category": finding.category,
            "column_number": finding.column_number,
            "end_line": finding.end_line,
            "code_snippet": finding.code_snippet,
            "cwe": finding.cwe,
            "language": finding.language,
            "analyzer": finding.analyzer,
            "confidence": finding.confidence,
            "confidence_level": finding.confidence_level,
            "why_risky": finding.why_risky,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "fix_example": finding.fix_example,
            "source_label": finding.source_label,
            "sink_label": finding.sink_label,
            "data_flow_text": finding.data_flow_text,
            "evidence": finding.evidence,
            "patch_available": finding.patch_available,
            "fingerprint": finding.fingerprint,
            "patch": None,
        }
        # Deserialize patch JSON if present
        if finding.patch_text:
            try:
                patch_dict = json.loads(finding.patch_text)
                data["patch"] = PatchResponse(**patch_dict)
            except Exception:
                pass
        return cls(**data)


class ScanSummary(BaseModel):
    scan_id: str
    status: str
    total_findings: int
    # Original severity counts
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    # Phase 5 additions
    critical: int = 0
    security_findings: int = 0
    quality_findings: int = 0
    high_confidence_findings: int = 0
    fixable_findings: int = 0


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def get_owned_repository(
    repository_id: str,
    current_user: User,
    db: Session,
) -> Repository:
    repository = (
        db.query(Repository)
        .join(Project, Repository.project_id == Project.id)
        .filter(
            Repository.id == repository_id,
            Project.user_id == current_user.id,
        )
        .first()
    )

    if not repository:
        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )

    return repository


def get_owned_scan(
    scan_id: str,
    current_user: User,
    db: Session,
) -> Scan:
    scan = (
        db.query(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .join(Project, Repository.project_id == Project.id)
        .filter(
            Scan.id == scan_id,
            Project.user_id == current_user.id,
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan


# ---------------------------------------------------------------------------
# Background task: clone → scan → cleanup
# ---------------------------------------------------------------------------


def run_scan_background(
    scan_id: str,
    repository_id: str,
    repository_url: str,
    clone_timeout: int,
) -> None:
    """
    Execute a full scan outside the HTTP request lifecycle.

    A fresh database session is created because the original request session
    must not be reused inside BackgroundTasks.
    """
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        repository = db.query(Repository).filter(Repository.id == repository_id).first()

        if not scan or not repository:
            logger.error(
                "run_scan_background: scan %s or repository %s not found",
                scan_id, repository_id,
            )
            return

        try:
            with clone_repository(repository_url, timeout=clone_timeout) as repo_path:
                engine = ScanEngine(db=db, scan=scan, repository=repository)
                engine.run(str(repo_path))

        except GitCloneTimeoutError as exc:
            logger.warning("Clone timed out for scan %s: %s", scan_id, exc.user_message)
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.commit()

        except GitCloneError as exc:
            logger.warning("Clone failed for scan %s: %s", scan_id, exc.user_message)
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.commit()

        except Exception:
            logger.exception("Unexpected error in scan %s", scan_id)
            try:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                db.commit()
            except Exception:
                db.rollback()

    except Exception:
        logger.exception("Fatal error setting up scan %s", scan_id)
        try:
            db.rollback()
        except Exception:
            pass

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=ScanResponse, status_code=201)
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Trigger a new scan. Returns immediately while analysis runs in background."""
    repository = get_owned_repository(scan_data.repository_id, current_user, db)

    try:
        validated_url = validate_github_url(repository.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    scan = Scan(repository_id=repository.id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        run_scan_background,
        scan.id,
        repository.id,
        validated_url,
        settings.GIT_CLONE_TIMEOUT_SECONDS,
    )

    return scan


@router.get("", response_model=List[ScanResponse])
def list_scans(
    repository_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    repository = get_owned_repository(repository_id, current_user, db)
    return (
        db.query(Scan)
        .filter(Scan.repository_id == repository.id)
        .order_by(Scan.id.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_owned_scan(scan_id, current_user, db)


@router.get("/{scan_id}/summary")
def get_scan_summary(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanSummary:
    scan = get_owned_scan(scan_id, current_user, db)

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    # Security categories (non-quality)
    SECURITY_CATS = {
        "code_execution", "command_injection", "xss", "sql_injection",
        "path_traversal", "ssrf", "open_redirect", "deserialization",
        "secrets", "crypto", "template_injection", "configuration", "data_flow",
    }

    severity_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    security_count = 0
    quality_count = 0
    high_conf_count = 0
    fixable_count = 0

    for f in findings:
        sev = f.severity if f.severity in severity_counts else "info"
        severity_counts[sev] += 1

        cat = f.category or ""
        if cat in SECURITY_CATS:
            security_count += 1
        else:
            quality_count += 1

        if f.confidence is not None and f.confidence >= 80:
            high_conf_count += 1

        if f.patch_available:
            fixable_count += 1

    return ScanSummary(
        scan_id=scan.id,
        status=scan.status,
        total_findings=len(findings),
        critical=severity_counts["critical"],
        high=severity_counts["high"],
        medium=severity_counts["medium"],
        low=severity_counts["low"],
        info=severity_counts["info"],
        security_findings=security_count,
        quality_findings=quality_count,
        high_confidence_findings=high_conf_count,
        fixable_findings=fixable_count,
    )


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
def list_findings(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return findings for a scan.

    Optional query params:
      severity  — filter by severity (critical|high|medium|low|info)
      category  — filter by category (e.g. command_injection)
    """
    scan = get_owned_scan(scan_id, current_user, db)

    query = db.query(Finding).filter(Finding.scan_id == scan.id)

    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)

    db_findings = query.order_by(Finding.id.desc()).all()

    return [FindingResponse.from_orm_with_patch(f) for f in db_findings]
