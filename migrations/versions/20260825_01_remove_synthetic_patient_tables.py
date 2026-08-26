"""Remove the retired synthetic-patient data path.

Revision ID: 20260825_01
Revises: 20260728_01
Create Date: 2026-08-25
"""

from alembic import op
import sqlalchemy as sa


revision = "20260825_01"
down_revision = "20260728_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("event_patient_links", if_exists=True)
    op.drop_table("synthetic_patient_context", if_exists=True)


def downgrade() -> None:
    op.create_table(
        "synthetic_patient_context",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("data_source_id", sa.Uuid(), sa.ForeignKey("data_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("patient_token", sa.String(length=64), nullable=False),
        sa.Column("administrative_gender", sa.String(length=32)),
        sa.Column("condition_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("encounter_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("patient_token", name="uq_synthetic_patient_token"),
    )
    op.create_table(
        "event_patient_links",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("hospital_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "patient_context_id",
            sa.Uuid(),
            sa.ForeignKey("synthetic_patient_context.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(length=64), nullable=False, server_default="synthetic_context"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("event_id", "patient_context_id", name="uq_event_patient_link"),
    )

