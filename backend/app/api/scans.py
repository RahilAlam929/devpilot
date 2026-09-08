import logging
from datetime import datetime
from typing import List, Optional

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

    Workflow:
      1. Validate the repository URL.
      2. Clone the repository into an isolated temporary directory.
      3. Run the ScanEngine against the cloned tree.
      4. Temporary directory is always cleaned up (handled by clone_repository
         context manager regardless of success or failure).

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
                scan_id,
                repository_id,
            )
            return

        # Clone into a temporary directory; cleanup is guaranteed on exit.
        try:
            with clone_repository(repository_url, timeout=clone_timeout) as repo_path:
                engine = ScanEngine(db=db, scan=scan, repository=repository)
                engine.run(str(repo_path))

        except GitCloneTimeoutError as exc:
            logger.warning(
                "Clone timed out for scan %s (repo %s): %s",
                scan_id, repository_id, exc.user_message,
            )
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.commit()

        except GitCloneError as exc:
            logger.warning(
                "Clone failed for scan %s (repo %s): %s",
                scan_id, repository_id, exc.user_message,
            )
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.commit()

        except Exception:
            logger.exception(
                "Unexpected error in scan %s (repo %s)", scan_id, repository_id
            )
            try:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                db.commit()
            except Exception:
                db.rollback()

    except Exception:
        logger.exception(
            "Fatal error setting up scan %s", scan_id
        )
        try:
            db.rollback()
        except Exception:
            pass

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
)
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Trigger a new scan for a repository.

    The client only sends ``repository_id``. The backend retrieves the stored
    repository URL, validates it, creates a ``pending`` scan record, and
    enqueues the clone + analysis as a background task.
    """
    repository = get_owned_repository(scan_data.repository_id, current_user, db)

    # Validate the stored URL here so we can reject it immediately with a
    # clear 422 rather than silently failing in the background.
    try:
        validated_url = validate_github_url(repository.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )

    scan = Scan(
        repository_id=repository.id,
        status="pending",
    )
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


@router.get(
    "",
    response_model=List[ScanResponse],
)
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


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_owned_scan(scan_id, current_user, db)


@router.get(
    "/{scan_id}/summary",
)
def get_scan_summary(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = get_owned_scan(scan_id, current_user, db)

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .all()
    )

    counts: dict = {"high": 0, "medium": 0, "low": 0, "info": 0}
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = get_owned_scan(scan_id, current_user, db)

    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.id.desc())
        .all()
    )
