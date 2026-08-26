"""Add the held-out model evaluation sample table.

Revision ID: 20260826_01
Revises: 20260825_01
Create Date: 2026-08-26
"""

from alembic import op
import sqlalchemy as sa


revision = "20260826_01"
down_revision = "20260825_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("model_evaluation_samples"):
        return
    op.create_table(
        "model_evaluation_samples",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("model_version_id", sa.Uuid(), sa.ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sample_key", sa.String(length=64), nullable=False),
        sa.Column("dataset_name", sa.String(length=160), nullable=False),
        sa.Column("dataset_split", sa.String(length=128), nullable=False),
        sa.Column("source_file", sa.String(length=512), nullable=False),
        sa.Column("source_row_number", sa.Integer(), nullable=False),
        sa.Column("attack_subclass", sa.String(length=160), nullable=False),
        sa.Column("true_family", sa.String(length=64), nullable=False),
        sa.Column("predicted_family", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("correct", sa.Boolean(), nullable=False),
        sa.Column("feature_snapshot", sa.JSON(), nullable=False),
        sa.Column("class_probabilities", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("sample_key", name="uq_model_evaluation_samples_sample_key"),
    )
    op.create_index(
        "ix_model_evaluation_samples_true_family",
        "model_evaluation_samples",
        ["true_family"],
    )
    op.create_index(
        "ix_model_evaluation_samples_correct",
        "model_evaluation_samples",
        ["correct"],
    )


def downgrade() -> None:
    op.drop_table("model_evaluation_samples")
