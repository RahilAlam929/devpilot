"""Phase 5: add rich finding metadata columns

Revision ID: a1b2c3d4e5f6
Revises: 02914dbc1623
Create Date: 2026-09-09 02:15:00.000000

Adds all Phase 5 finding metadata columns to the findings table.
All new columns are nullable so existing data remains valid.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "02914dbc1623"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Identity / rule
    op.add_column("findings", sa.Column("rule_id", sa.String(50), nullable=True))
    op.add_column("findings", sa.Column("category", sa.String(50), nullable=True))

    # Location detail
    op.add_column("findings", sa.Column("column_number", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("end_line", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("code_snippet", sa.Text(), nullable=True))

    # Risk metadata
    op.add_column("findings", sa.Column("cwe", sa.String(20), nullable=True))
    op.add_column("findings", sa.Column("language", sa.String(30), nullable=True))
    op.add_column("findings", sa.Column("analyzer", sa.String(30), nullable=True))

    # Confidence
    op.add_column("findings", sa.Column("confidence", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("confidence_level", sa.String(10), nullable=True))

    # Developer explanation
    op.add_column("findings", sa.Column("why_risky", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("impact", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("fix_example", sa.Text(), nullable=True))

    # Source → Sink (serialized as text)
    op.add_column("findings", sa.Column("source_label", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("sink_label", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("data_flow_text", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("evidence", sa.Text(), nullable=True))

    # Patch
    op.add_column("findings", sa.Column("patch_available", sa.Boolean(), nullable=True, server_default="false"))
    op.add_column("findings", sa.Column("patch_text", sa.Text(), nullable=True))

    # Deduplication fingerprint
    op.add_column("findings", sa.Column("fingerprint", sa.String(32), nullable=True))
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_column("findings", "fingerprint")
    op.drop_column("findings", "patch_text")
    op.drop_column("findings", "patch_available")
    op.drop_column("findings", "evidence")
    op.drop_column("findings", "data_flow_text")
    op.drop_column("findings", "sink_label")
    op.drop_column("findings", "source_label")
    op.drop_column("findings", "fix_example")
    op.drop_column("findings", "remediation")
    op.drop_column("findings", "impact")
    op.drop_column("findings", "why_risky")
    op.drop_column("findings", "confidence_level")
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "analyzer")
    op.drop_column("findings", "language")
    op.drop_column("findings", "cwe")
    op.drop_column("findings", "code_snippet")
    op.drop_column("findings", "end_line")
    op.drop_column("findings", "column_number")
    op.drop_column("findings", "category")
    op.drop_column("findings", "rule_id")
