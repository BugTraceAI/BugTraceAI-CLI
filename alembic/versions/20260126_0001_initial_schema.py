"""Initial database schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-26

This migration creates the initial database schema for BugTraceAI.
It includes tables for targets, scans, findings, and scan state.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial database schema."""

    # Target table
    op.create_table(
        "target",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_target_url", "target", ["url"], unique=False)

    # Scan table
    op.create_table(
        "scan",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    # Finding table
    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("details", sa.String(), nullable=True),
        sa.Column("payload_used", sa.String(), nullable=True),
        sa.Column("reflection_context", sa.String(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("visual_validated", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("validator_notes", sa.String(), nullable=True),
        sa.Column("proof_screenshot_path", sa.String(), nullable=True),
        sa.Column("attack_url", sa.String(), nullable=True),
        sa.Column("vuln_parameter", sa.String(), nullable=True),
        sa.Column("reproduction_command", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_status", "finding", ["status"], unique=False)
    op.create_index("idx_finding_scan_status", "finding", ["scan_id", "status"], unique=False)

    # Scan state table (for checkpoints)
    op.create_table(
        "scan_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("state_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table("scan_state")
    op.drop_index("idx_finding_scan_status", table_name="finding")
    op.drop_index("ix_finding_status", table_name="finding")
    op.drop_table("finding")
    op.drop_table("scan")
    op.drop_index("ix_target_url", table_name="target")
    op.drop_table("target")
