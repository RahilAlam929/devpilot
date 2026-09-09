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
    # Phase 6 fields
    dependency_name: Optional[str] = None
    dependency_version: Optional[str] = None
    fixed_version: Optional[str] = None
    advisory_id: Optional[str] = None
    secret_type: Optional[str] = None
    redacted_value: Optional[str] = None

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
            # Phase 6 fields
            "dependency_name": getattr(finding, "dependency_name", None),
            "dependency_version": getattr(finding, "dependency_version", None),
            "fixed_version": getattr(finding, "fixed_version", None),
            "advisory_id": getattr(finding, "advisory_id", None),
            "secret_type": getattr(finding, "secret_type", None),
            "redacted_value": getattr(finding, "redacted_value", None),
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
    # Phase 6 additions
    security_score: int = 100
    sast_findings: int = 0
    secret_findings: int = 0
    dependency_findings: int = 0
    iac_findings: int = 0
    files_scanned: int = 0


class SecurityScoreResponse(BaseModel):
    scan_id: str
    score: int
    grade: str
    breakdown: Dict[str, Any]


class CategorySummaryResponse(BaseModel):
    scan_id: str
    categories: Dict[str, Any]


class DependencyFindingResponse(BaseModel):
    id: str
    package_name: str
    version: Optional[str]
    advisory_id: Optional[str]
    severity: str
    title: str
    fixed_version: Optional[str]
    file_path: Optional[str]
    cwe: Optional[str]


class SecretFindingResponse(BaseModel):
    id: str
    secret_type: Optional[str]
    redacted_value: Optional[str]
    severity: str
    file_path: Optional[str]
    line_number: Optional[int]
    confidence: Optional[int]
    evidence: Optional[str]


class IacFindingResponse(BaseModel):
    id: str
    rule_id: Optional[str]
    title: str
    severity: str
    file_path: Optional[str]
    line_number: Optional[int]
    evidence: Optional[str]
    remediation: Optional[str]


class RiskSummaryResponse(BaseModel):
    scan_id: str
    security_score: int
    grade: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    top_risks: List[Dict[str, Any]]
    categories: Dict[str, int]


class RemediationResponse(BaseModel):
    finding_id: str
    why_risky: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    fix_example: Optional[str]
    patch_available: Optional[bool]
    patch: Optional[PatchResponse]


class VerifyFixRequest(BaseModel):
    finding_id: str


class VerifyFixResponse(BaseModel):
    finding_id: str
    status: str
    message: str
    original_findings: int
    patched_findings: int


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
    dep_count = 0
    secret_count = 0
    iac_count = 0
    sast_count = 0

    for f in findings:
        sev = f.severity if f.severity in severity_counts else "info"
        severity_counts[sev] += 1

        cat = f.category or ""
        analyzer = f.analyzer or ""
        if cat in SECURITY_CATS:
            security_count += 1
        else:
            quality_count += 1

        if f.confidence is not None and f.confidence >= 80:
            high_conf_count += 1

        if f.patch_available:
            fixable_count += 1

        # Phase 6 category breakdown
        if analyzer == "sca":
            dep_count += 1
        elif analyzer == "secret_scanner":
            secret_count += 1
        elif analyzer == "iac":
            iac_count += 1
        elif cat in SECURITY_CATS:
            sast_count += 1

    # Phase 6: compute security score
    from app.services.scan_engine.scanner.risk_engine import compute_security_score_from_db
    total_conf = sum((f.confidence or 50) for f in findings)
    avg_conf = (total_conf / len(findings)) if findings else 65.0
    score = compute_security_score_from_db(
        critical=severity_counts["critical"],
        high=severity_counts["high"],
        medium=severity_counts["medium"],
        low=severity_counts["low"],
        info=severity_counts["info"],
        avg_confidence=avg_conf,
    )

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
        security_score=score,
        sast_findings=sast_count,
        secret_findings=secret_count,
        dependency_findings=dep_count,
        iac_findings=iac_count,
    )


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
def list_findings(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    analyzer: Optional[str] = None,
    confidence_min: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return findings for a scan.

    Optional query params:
      severity       — filter by severity (critical|high|medium|low|info)
      category       — filter by category (e.g. command_injection)
      analyzer       — filter by analyzer (sca|secret_scanner|iac|ast|dataflow|regex)
      confidence_min — minimum confidence threshold (0-100)
    """
    scan = get_owned_scan(scan_id, current_user, db)

    query = db.query(Finding).filter(Finding.scan_id == scan.id)

    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)
    if analyzer:
        query = query.filter(Finding.analyzer == analyzer)
    if confidence_min is not None:
        query = query.filter(
            (Finding.confidence >= confidence_min) | (Finding.confidence == None)
        )

    db_findings = query.order_by(Finding.id.desc()).all()

    return [FindingResponse.from_orm_with_patch(f) for f in db_findings]


# ---------------------------------------------------------------------------
# Phase 6 endpoints
# ---------------------------------------------------------------------------


@router.get("/{scan_id}/security-score")
def get_security_score(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityScoreResponse:
    """Return the security score and grade for a completed scan."""
    scan = get_owned_scan(scan_id, current_user, db)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    from app.services.scan_engine.scanner.risk_engine import (
        compute_security_score_from_db, categorize_findings,
    )

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_conf = 0
    for f in findings:
        sev = f.severity if f.severity in counts else "info"
        counts[sev] += 1
        total_conf += f.confidence or 50

    avg_conf = (total_conf / len(findings)) if findings else 65.0
    score = compute_security_score_from_db(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        avg_confidence=avg_conf,
    )

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    categories = categorize_findings(findings)

    return SecurityScoreResponse(
        scan_id=scan_id,
        score=score,
        grade=grade,
        breakdown={
            "severity_counts": counts,
            "categories": categories,
            "total_findings": len(findings),
            "avg_confidence": round(avg_conf, 1),
        },
    )


@router.get("/{scan_id}/categories")
def get_scan_categories(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CategorySummaryResponse:
    """Return finding counts broken down by analyzer category."""
    scan = get_owned_scan(scan_id, current_user, db)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    from app.services.scan_engine.scanner.risk_engine import categorize_findings
    categories = categorize_findings(findings)

    # Also group by category string for detail
    by_category: Dict[str, int] = {}
    for f in findings:
        cat = f.category or "unknown"
        by_category[cat] = by_category.get(cat, 0) + 1

    return CategorySummaryResponse(
        scan_id=scan_id,
        categories={
            "summary": categories,
            "by_category": by_category,
        },
    )


@router.get("/{scan_id}/dependencies", response_model=List[DependencyFindingResponse])
def get_dependency_findings(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return SCA dependency vulnerability findings for a scan."""
    scan = get_owned_scan(scan_id, current_user, db)
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id,
            Finding.analyzer == "sca",
        )
        .all()
    )
    result = []
    for f in findings:
        result.append(DependencyFindingResponse(
            id=f.id,
            package_name=getattr(f, "dependency_name", None) or f.title,
            version=getattr(f, "dependency_version", None),
            advisory_id=getattr(f, "advisory_id", None),
            severity=f.severity,
            title=f.title,
            fixed_version=getattr(f, "fixed_version", None),
            file_path=f.file_path,
            cwe=f.cwe,
        ))
    return result


@router.get("/{scan_id}/secrets", response_model=List[SecretFindingResponse])
def get_secret_findings(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return secret scanner findings for a scan.

    IMPORTANT: Evidence and redacted_value are redacted. Full secrets are never returned.
    """
    scan = get_owned_scan(scan_id, current_user, db)
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id,
            Finding.analyzer == "secret_scanner",
        )
        .all()
    )
    result = []
    for f in findings:
        result.append(SecretFindingResponse(
            id=f.id,
            secret_type=getattr(f, "secret_type", None),
            redacted_value=getattr(f, "redacted_value", None),
            severity=f.severity,
            file_path=f.file_path,
            line_number=f.line_number,
            confidence=f.confidence,
            evidence=f.evidence,  # already redacted at scan time
        ))
    return result


@router.get("/{scan_id}/iac", response_model=List[IacFindingResponse])
def get_iac_findings(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return IaC security findings for a scan."""
    scan = get_owned_scan(scan_id, current_user, db)
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id,
            Finding.analyzer == "iac",
        )
        .all()
    )
    return [
        IacFindingResponse(
            id=f.id,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            file_path=f.file_path,
            line_number=f.line_number,
            evidence=f.evidence,
            remediation=f.remediation,
        )
        for f in findings
    ]


@router.get("/{scan_id}/risk-summary")
def get_risk_summary(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RiskSummaryResponse:
    """Return a comprehensive risk summary for a scan."""
    scan = get_owned_scan(scan_id, current_user, db)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    from app.services.scan_engine.scanner.risk_engine import (
        compute_security_score_from_db, categorize_findings,
    )

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_conf = 0
    for f in findings:
        sev = f.severity if f.severity in counts else "info"
        counts[sev] += 1
        total_conf += f.confidence or 50

    avg_conf = (total_conf / len(findings)) if findings else 65.0
    score = compute_security_score_from_db(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        avg_confidence=avg_conf,
    )

    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    # Top risks: critical+high findings, sorted by confidence
    top_risk_findings = sorted(
        [f for f in findings if f.severity in ("critical", "high")],
        key=lambda f: (f.confidence or 0),
        reverse=True,
    )[:5]

    top_risks = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category or "unknown",
            "file_path": f.file_path,
            "line_number": f.line_number,
            "confidence": f.confidence,
        }
        for f in top_risk_findings
    ]

    categories = categorize_findings(findings)

    return RiskSummaryResponse(
        scan_id=scan_id,
        security_score=score,
        grade=grade,
        total=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        top_risks=top_risks,
        categories=categories,
    )
