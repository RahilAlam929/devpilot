from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Project, Repository


router = APIRouter(
    prefix="/repositories",
    tags=["Repositories"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RepositoryCreate(BaseModel):
    name: str
    url: str
    project_id: str


class RepositoryResponse(BaseModel):
    id: str
    name: str
    url: str
    project_id: str

    class Config:
        from_attributes = True


@router.post(
    "",
    response_model=RepositoryResponse,
    status_code=201,
)
def create_repository(
    repository_data: RepositoryCreate,
    db: Session = Depends(get_db),
):
    project = (
        db.query(Project)
        .filter(Project.id == repository_data.project_id)
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    repository = Repository(
        name=repository_data.name,
        url=repository_data.url,
        project_id=repository_data.project_id,
    )

    db.add(repository)
    db.commit()
    db.refresh(repository)

    return repository


@router.get(
    "",
    response_model=List[RepositoryResponse],
)
def list_repositories(
    project_id: str,
    db: Session = Depends(get_db),
):
    return (
        db.query(Repository)
        .filter(Repository.project_id == project_id)
        .order_by(Repository.created_at.desc())
        .all()
    )


@router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
)
def get_repository(
    repository_id: str,
    db: Session = Depends(get_db),
):
    repository = (
        db.query(Repository)
        .filter(Repository.id == repository_id)
        .first()
    )

    if not repository:
        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )

    return repository
