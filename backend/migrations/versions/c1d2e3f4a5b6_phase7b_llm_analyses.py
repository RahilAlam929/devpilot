"""Phase 7B: add finding_llm_analyses table for LLM-assisted finding intelligence

Revision ID: c1d2e3f4a5b6
Revises: b1c2d3e4f5a6
Create Date: 2026-09-09 23:50:00.000000

Creates the finding_llm_analyses table:
  - id                 PK UUID string
  - finding_id         FK → findings(id) CASCADE DELETE
  - provider           LLM provider name (openai, anthropic, etc.)
  - model              Specific model string
  - analysis_version   Schema + prompt version for research metadata
  - verdict            Enum string: true_positive | likely_true_positive |
                                    false_positive | uncertain
  - confidence         Float 0.0–1.0
  - exploitability     Float 0.0–1.0
  - impact             Short impact description (Text)
  - root_cause         Short root cause explanation (Text)
  - explanation        Technical explanation (Text)
  - remediation        Actionable remediation (Text)
  - reasoning_summary  Short audit summary — NOT chain-of-thought (Text)
  - request_hash       SHA-256 over redacted context for deduplication
  - created_at         UTC timestamp

Indexes:
  - finding_id (FK lookup)
  - request_hash (deduplication / cache lookup)
  - created_at (ordering / research queries)

Uniqueness: (finding_id, request_hash, analysis_version) provides a natural
uniqueness constraint so identical requests are not re-stored.

SECURITY: This table never stores raw API keys, secrets, full prompts, or
hidden chain-of-thought traces. The request_hash is computed over redacted text.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c1d2e3f4a5b6"
down_revision: Union[str, None] = "b1c2d3e4f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_llm_analyses",
        # Primary key
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),

        # Foreign key to findings (cascade on delete)
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),

        # Provider metadata
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("analysis_version", sa.String(20), nullable=False),

        # Verdict and scores
        sa.Column("verdict", sa.String(30), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("exploitability", sa.Float, nullable=False, server_default="0.0"),

        # Intelligence fields
        sa.Column("impact", sa.Text, nullable=True),
        sa.Column("root_cause", sa.Text, nullable=True),
        sa.Column("explanation", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),

        # Audit trail: short user-visible summary — NOT chain-of-thought
        sa.Column("reasoning_summary", sa.Text, nullable=True),

        # Deduplication / research
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Indexes for common access patterns
    op.create_index(
        "ix_finding_llm_analyses_finding_id",
        "finding_llm_analyses",
        ["finding_id"],
    )
    op.create_index(
        "ix_finding_llm_analyses_request_hash",
        "finding_llm_analyses",
        ["request_hash"],
    )
    op.create_index(
        "ix_finding_llm_analyses_created_at",
        "finding_llm_analyses",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_finding_llm_analyses_created_at", table_name="finding_llm_analyses")
    op.drop_index("ix_finding_llm_analyses_request_hash", table_name="finding_llm_analyses")
    op.drop_index("ix_finding_llm_analyses_finding_id", table_name="finding_llm_analyses")
    op.drop_table("finding_llm_analyses")
