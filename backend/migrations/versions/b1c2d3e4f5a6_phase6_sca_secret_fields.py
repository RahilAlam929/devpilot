"""Phase 6: add SCA dependency, secret, and advisory fields to findings

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f6
Create Date: 2026-09-09 12:00:00.000000

Adds Phase 6 finding metadata columns:
  - dependency_name   (SCA)
  - dependency_version (SCA)
  - fixed_version     (SCA)
  - advisory_id       (SCA / CVE)
  - secret_type       (Secret scanner)
  - redacted_value    (Secret scanner — NEVER the full secret)

All new columns are nullable so existing data and the test suite remain compatible.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b1c2d3e4f5a6"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SCA / Dependency fields
    op.add_column("findings", sa.Column("dependency_name", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("dependency_version", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("fixed_version", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("advisory_id", sa.String(100), nullable=True))

    # Secret scanner fields — redacted only
    op.add_column("findings", sa.Column("secret_type", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("redacted_value", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "redacted_value")
    op.drop_column("findings", "secret_type")
    op.drop_column("findings", "advisory_id")
    op.drop_column("findings", "fixed_version")
    op.drop_column("findings", "dependency_version")
    op.drop_column("findings", "dependency_name")
