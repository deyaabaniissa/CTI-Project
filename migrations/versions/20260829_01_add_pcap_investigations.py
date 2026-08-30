"""Add a dedicated PCAP investigation table.

Revision ID: 20260829_01
Revises: 20260826_01
Create Date: 2026-08-29
"""

from alembic import op
import sqlalchemy as sa


revision = "20260829_01"
down_revision = "20260826_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("pcap_investigations"):
        return
    op.create_table(
        "pcap_investigations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("investigation_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("file_name", sa.String(length=512), nullable=False),
        sa.Column("file_sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("packets_read", sa.Integer(), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("indicator_count", sa.Integer(), nullable=False),
        sa.Column("public_indicator_count", sa.Integer(), nullable=False),
        sa.Column("model_status", sa.String(length=64), nullable=False),
        sa.Column("predicted_family", sa.String(length=64)),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("report_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pcap_investigations_created_at", "pcap_investigations", ["created_at"])
    op.create_index("ix_pcap_investigations_sha256", "pcap_investigations", ["file_sha256"])


def downgrade() -> None:
    op.drop_table("pcap_investigations")
