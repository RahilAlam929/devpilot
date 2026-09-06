from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database import SessionLocal
from app.models import Project, Repository, User


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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == repository_data.project_id,
            Project.user_id == current_user.id,
        )
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
        project_id=project.id,
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.user_id == current_user.id,
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return (
        db.query(Repository)
        .filter(Repository.project_id == project.id)
        .order_by(Repository.created_at.desc())
        .all()
    )


@router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
)
def get_repository(
    repository_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
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
