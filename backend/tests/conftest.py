"""
Shared pytest fixtures for DevPilot backend API tests.

Uses an in-memory SQLite database so tests never touch the real database,
require no network access, and run without a running PostgreSQL instance.

SQLAlchemy's StaticPool is used so that every connection (including the
TestClient's sessions) uses the same underlying in-memory connection.
"""

import os
import pytest

# ── Set dummy env vars BEFORE importing any app code ──────────────────────
# pydantic-settings reads these at import time; if they are missing the
# import fails.  We set them here so tests are self-contained.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production")

from fastapi.testclient import TestClient           # noqa: E402
from sqlalchemy import create_engine, event         # noqa: E402
from sqlalchemy.orm import sessionmaker             # noqa: E402
from sqlalchemy.pool import StaticPool              # noqa: E402

from app.database import Base                       # noqa: E402
from app.models.models import (                     # noqa: E402
    Finding, Project, Repository, Scan, User,
)
from main import app                                # noqa: E402
from app.api.auth import get_current_user           # noqa: E402
from app.api.scans import get_db as scans_get_db    # noqa: E402
from app.api.repositories import get_db as repos_get_db  # noqa: E402
from app.auth import hash_password                  # noqa: E402


# ── In-memory SQLite engine (shared connection via StaticPool) ─────────────
#
# StaticPool reuses the same underlying DBAPI connection for all requests,
# so all sessions — including those created inside the TestClient — see the
# same in-memory database and the tables created by the reset_db fixture.

test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    bind=test_engine,
    autoflush=False,
    autocommit=False,
)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def reset_db():
    """Create all tables before each test; drop them after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture()
def db():
    """Yield a raw SQLAlchemy session tied to the in-memory database."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


# ── Test user fixtures ────────────────────────────────────────────────────

@pytest.fixture()
def test_user(db):
    """Create and return a persisted test user."""
    user = User(
        email="test@example.com",
        name="Test User",
        password_hash=hash_password("password123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def other_user(db):
    """A second user for authorization-boundary tests."""
    user = User(
        email="other@example.com",
        name="Other User",
        password_hash=hash_password("password123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── Authenticated test clients ────────────────────────────────────────────

@pytest.fixture()
def client(test_user):
    """
    TestClient with:
     - DB overridden to in-memory SQLite
     - get_current_user overridden to return test_user (no JWT needed)
    """
    from app.api.findings import get_db as findings_get_db
    app.dependency_overrides[scans_get_db] = override_get_db
    app.dependency_overrides[repos_get_db] = override_get_db
    app.dependency_overrides[findings_get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: test_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture()
def other_client(other_user):
    """TestClient authenticated as other_user."""
    from app.api.findings import get_db as findings_get_db
    app.dependency_overrides[scans_get_db] = override_get_db
    app.dependency_overrides[repos_get_db] = override_get_db
    app.dependency_overrides[findings_get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: other_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# ── Data fixtures ─────────────────────────────────────────────────────────

@pytest.fixture()
def project(db, test_user):
    """A project owned by test_user."""
    p = Project(name="Test Project", user_id=test_user.id)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@pytest.fixture()
def other_project(db, other_user):
    """A project owned by other_user."""
    p = Project(name="Other Project", user_id=other_user.id)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@pytest.fixture()
def repository(db, project):
    """A repository under test_user's project, with a valid GitHub URL."""
    r = Repository(
        name="Test Repo",
        url="https://github.com/owner/repo.git",
        project_id=project.id,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@pytest.fixture()
def other_repository(db, other_project):
    """A repository owned by other_user."""
    r = Repository(
        name="Other Repo",
        url="https://github.com/other/repo.git",
        project_id=other_project.id,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@pytest.fixture()
def scan(db, repository):
    """A pending scan for test_user's repository."""
    s = Scan(repository_id=repository.id, status="pending")
    db.add(s)
    db.commit()
    db.refresh(s)
    return s
