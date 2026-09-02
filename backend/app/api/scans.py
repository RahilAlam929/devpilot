from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Repository, Scan


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


class ScanResponse(BaseModel):
    id: str
    repository_id: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
)
def create_scan(
    scan_data: ScanCreate,
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
