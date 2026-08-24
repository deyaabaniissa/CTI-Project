"""Initial CTI persistence schema.

Revision ID: 20260728_01
Revises:
Create Date: 2026-07-28
"""

from alembic import op

from cti.db.models import Base


revision = "20260728_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # This revision deliberately uses the initial ORM metadata snapshot. Future
    # changes must be represented by new Alembic revisions, never by altering
    # this initial migration.
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=False)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=False)
