from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    password_hash: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    projects: Mapped[list["Project"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    owner: Mapped["User"] = relationship(
        back_populates="projects",
    )

    repositories: Mapped[list["Repository"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    project: Mapped["Project"] = relationship(
        back_populates="repositories",
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
    )

    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
    )

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
    )

    repository: Mapped["Repository"] = relationship(
        back_populates="scans",
    )

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class Finding(Base):
    """
    Persisted finding from a scan.

    Phase 5 adds rich metadata columns. All new columns are nullable
    so existing data and the test suite remain compatible.
    Old columns (severity, title, description, file_path, line_number)
    are unchanged.
    """

    __tablename__ = "findings"

    # ── Core (original columns — never removed) ───────────────────────────
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    file_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    line_number: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    # ── Phase 5 additions (all nullable for backward compat) ──────────────

    rule_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    category: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    # Location detail
    column_number: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    end_line: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    code_snippet: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Risk metadata
    cwe: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )

    language: Mapped[Optional[str]] = mapped_column(
        String(30),
        nullable=True,
    )

    analyzer: Mapped[Optional[str]] = mapped_column(
        String(30),
        nullable=True,
    )

    # Confidence
    confidence: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    confidence_level: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
    )

    # Developer explanation (stored as Text blobs)
    why_risky: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    impact: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    fix_example: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Source → Sink (stored as JSON text)
    source_label: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    sink_label: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    data_flow_text: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    evidence: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Patch
    patch_available: Mapped[Optional[bool]] = mapped_column(
        nullable=True,
        default=False,
    )

    patch_text: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Deduplication
    fingerprint: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )

    # ── Phase 6 additions (all nullable for backward compat) ──────────────

    # SCA / Dependency findings
    dependency_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    dependency_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    fixed_version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    advisory_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # Secret scanner findings
    secret_type: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # REDACTED value only — never the full secret
    redacted_value: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Relationship ──────────────────────────────────────────────────────
    scan: Mapped["Scan"] = relationship(
        back_populates="findings",
    )

    # ── Phase 7B: LLM analyses ────────────────────────────────────────────
    llm_analyses: Mapped[list["FindingLLMAnalysis"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class FindingLLMAnalysis(Base):
    """
    Persisted LLM analysis result for a specific finding — Phase 7B.

    Each row records one LLM analysis call. The (finding_id, request_hash,
    analysis_version) combination provides a natural uniqueness key so that
    identical analysis requests are not re-stored.

    SECURITY NOTES:
      - Do NOT store the raw LLM prompt here.
      - Do NOT store the API key here.
      - Do NOT store hidden chain-of-thought here.
      - reasoning_summary is a short, user-visible audit trail only.
      - The request_hash is computed over REDACTED context, never raw secrets.
    """

    __tablename__ = "finding_llm_analyses"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Provider metadata ──────────────────────────────────────────────────
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    model: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    analysis_version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    # ── Verdict ───────────────────────────────────────────────────────────
    # Stored as string enum: true_positive | likely_true_positive |
    #                        false_positive | uncertain
    verdict: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    confidence: Mapped[float] = mapped_column(
        nullable=False,
        default=0.0,
    )

    exploitability: Mapped[float] = mapped_column(
        nullable=False,
        default=0.0,
    )

    # ── Intelligence fields ────────────────────────────────────────────────
    impact: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    root_cause: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    explanation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    remediation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Short auditable summary of reasoning — NOT raw chain-of-thought
    reasoning_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ── Deduplication / research metadata ─────────────────────────────────
    # SHA-256 hex digest over the redacted context + analysis version + model
    request_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    # ── Relationship ──────────────────────────────────────────────────────
    finding: Mapped["Finding"] = relationship(
        back_populates="llm_analyses",
    )
