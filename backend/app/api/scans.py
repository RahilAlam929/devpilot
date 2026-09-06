from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Finding, Repository, Scan
from app.services.scan_engine.engine import ScanEngine


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


class ScanCreate(BaseModel):
    repository_id: str
    repository_path: str


class ScanResponse(BaseModel):
    id: str
    repository_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    severity: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None

    class Config:
        from_attributes = True


def run_scan_background(
    scan_id: str,
    repository_id: str,
    repository_path: str,
):
    """
    Execute a scan outside the HTTP request lifecycle.

    A fresh database session is created because the original
    request session must not be reused inside BackgroundTasks.
    """
    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        repository = (
            db.query(Repository)
            .filter(Repository.id == repository_id)
            .first()
        )

        if not scan or not repository:
            return

        engine = ScanEngine(
            db=db,
            scan=scan,
            repository=repository,
        )

        engine.run(repository_path)

    except Exception:
        # ScanEngine already marks the scan as failed.
        # Roll back any transaction that may still be open.
        db.rollback()

    finally:
        db.close()


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
)
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    repository = (
        db.query(Repository)
        .filter(Repository.id == scan_data.repository_id)
        .first()
    )

    if not repository:
        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )

    scan = Scan(
        repository_id=scan_data.repository_id,
        status="pending",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        run_scan_background,
        scan.id,
        repository.id,
        scan_data.repository_path,
    )

    return scan


@router.get(
    "",
    response_model=List[ScanResponse],
)
def list_scans(
    repository_id: str,
    db: Session = Depends(get_db),
):
    return (
        db.query(Scan)
        .filter(Scan.repository_id == repository_id)
        .order_by(Scan.id.desc())
        .all()
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan


@router.get(
    "/{scan_id}/summary",
)
def get_scan_summary(
    scan_id: str,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "total_findings": len(findings),
        **counts,
    }


@router.get(
    "/{scan_id}/findings",
    response_model=List[FindingResponse],
)
def list_findings(
    scan_id: str,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.desc())
        .all()
    )
