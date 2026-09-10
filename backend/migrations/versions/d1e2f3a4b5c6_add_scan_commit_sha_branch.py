"""Add commit_sha and branch columns to scans for GitHub source navigation

Revision ID: d1e2f3a4b5c6
Revises: c1d2e3f4a5b6
Create Date: 2026-09-10 08:00:00.000000

Adds two nullable columns to the scans table:
  - commit_sha  VARCHAR(64)  — full git commit SHA captured after shallow clone
  - branch      VARCHAR(255) — branch name checked out during the clone

Both columns are nullable so existing scan rows are unaffected.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d1e2f3a4b5c6"
down_revision: Union[str, None] = "c1d2e3f4a5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("commit_sha", sa.String(64), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("branch", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "branch")
    op.drop_column("scans", "commit_sha")
