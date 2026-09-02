"""DatabaseManager mixin."""

from __future__ import annotations

from typing import Optional, List, Dict, Any, Tuple
import os
import json
import time
from datetime import datetime
from pathlib import Path

from sqlmodel import SQLModel, create_engine, Session, select
from sqlalchemy import Engine, text, event, func
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.exc import IntegrityError, OperationalError
from tenacity import retry, stop_after_attempt, wait_fixed

try:
    import lancedb
    LANCEDB_AVAILABLE = True
except Exception:
    lancedb = None
    LANCEDB_AVAILABLE = False

from bugtrace.schemas.db_models import (
    TargetTable, ScanTable, FindingTable, ScanStateTable,
    ScanStatus, FindingStatus,
)
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.database_helpers import (
    ScanInfo,
    _evidence_to_description,
    _higher_severity,
    _resolve_confidence,
    _resolve_status,
    _rank_severity,
    _convert_evidence_to_description,
)

logger = get_logger("core.database")

class DatabaseMigrationsMixin:
    """Schema create / migrate helpers."""

    def _create_tables(self):
        try:
            # Force import models to register with SQLModel metadata
            from bugtrace.schemas.db_models import TargetTable, ScanTable, FindingTable, ScanStateTable

            # Create all tables
            SQLModel.metadata.create_all(self.engine)

            # Verify tables were created (especially critical for SQLite after file deletion)
            self._verify_tables_exist()

            self._run_migrations()
            logger.info("SQL Tables initialized.")
        except Exception as e:
            logger.error(f"Failed to create SQL tables: {e}", exc_info=True)
            raise
    def _verify_tables_exist(self):
        """Verify critical tables exist, recreate if needed."""
        required_tables = ['target', 'scan', 'finding', 'scan_state']
        with Session(self.engine) as session:
            for table in required_tables:
                try:
                    session.exec(text(f"SELECT 1 FROM {table} LIMIT 1"))
                except Exception:
                    logger.warning(f"Table '{table}' not found, forcing recreation...")
                    session.rollback()
                    # Force recreate - drop metadata cache and recreate
                    SQLModel.metadata.create_all(self.engine)
                    break
    def _run_migrations(self):
        """Run lightweight schema migrations for new columns on existing tables."""
        with self.get_session() as session:
            # Migration: Add 'origin' column to scan table (v2.1)
            self._migrate_origin_column(session)
            # Migration: Add 'report_dir' column to scan table (v5.1)
            self._migrate_report_dir_column(session)
            # Migration: Add 'enrichment_status' column to scan table (v5.2)
            self._migrate_enrichment_status_column(session)
            # Migration: Add scan config columns (v5.3)
            self._migrate_scan_config_columns(session)
            # Migration: Add 'provider' column to scan table (v5.4)
            self._migrate_provider_column(session)
            # Migration: Add scan resumption columns (v5.5)
            self._migrate_scan_resumption_columns(session)
    def _ensure_scan_column(self, session, column_name: str, column_definition: str):
        """Add a scan column if it does not exist yet."""
        try:
            session.exec(text(f"SELECT {column_name} FROM scan LIMIT 1"))
        except Exception:
            session.rollback()
            try:
                session.exec(text(f"ALTER TABLE scan ADD COLUMN {column_name} {column_definition}"))
                session.commit()
                logger.info(f"Migration: Added '{column_name}' column to scan table")
            except Exception as e:
                session.rollback()
                logger.warning(f"Migration '{column_name}' column skipped: {e}")
    def _migrate_origin_column(self, session):
        """Migrate 'origin' column to scan table."""
        try:
            session.exec(text("SELECT origin FROM scan LIMIT 1"))
        except Exception:
            session.rollback()
            self._add_origin_column(session)
    def _add_origin_column(self, session):
        """Add origin column to scan table."""
        try:
            session.exec(text("ALTER TABLE scan ADD COLUMN origin VARCHAR DEFAULT 'unknown'"))
            session.commit()
            logger.info("Migration: Added 'origin' column to scan table")
        except Exception as e:
            session.rollback()
            logger.warning(f"Migration 'origin' column skipped: {e}")
    def _migrate_report_dir_column(self, session):
        """Migrate 'report_dir' column to scan table."""
        try:
            session.exec(text("SELECT report_dir FROM scan LIMIT 1"))
        except Exception:
            session.rollback()
            self._add_report_dir_column(session)
    def _add_report_dir_column(self, session):
        """Add report_dir column to scan table."""
        try:
            session.exec(text("ALTER TABLE scan ADD COLUMN report_dir VARCHAR"))
            session.commit()
            logger.info("Migration: Added 'report_dir' column to scan table")
        except Exception as e:
            session.rollback()
            logger.warning(f"Migration 'report_dir' column skipped: {e}")
    def _migrate_enrichment_status_column(self, session):
        """Migrate 'enrichment_status' column to scan table."""
        try:
            session.exec(text("SELECT enrichment_status FROM scan LIMIT 1"))
        except Exception:
            session.rollback()
            try:
                session.exec(text("ALTER TABLE scan ADD COLUMN enrichment_status VARCHAR DEFAULT NULL"))
                session.commit()
                logger.info("Migration: Added 'enrichment_status' column to scan table")
            except Exception as e:
                session.rollback()
                logger.warning(f"Migration 'enrichment_status' column skipped: {e}")
    def _migrate_scan_config_columns(self, session):
        """Migrate scan_type, max_depth, max_urls columns to scan table."""
        for col, col_type in [("scan_type", "VARCHAR"), ("max_depth", "INTEGER"), ("max_urls", "INTEGER")]:
            try:
                session.exec(text(f"SELECT {col} FROM scan LIMIT 1"))
            except Exception:
                session.rollback()
                try:
                    session.exec(text(f"ALTER TABLE scan ADD COLUMN {col} {col_type} DEFAULT NULL"))
                    session.commit()
                    logger.info(f"Migration: Added '{col}' column to scan table")
                except Exception as e:
                    session.rollback()
                    logger.warning(f"Migration '{col}' column skipped: {e}")
    def _migrate_provider_column(self, session):
        """Migrate 'provider' column to scan table."""
        try:
            session.exec(text("SELECT provider FROM scan LIMIT 1"))
        except Exception:
            session.rollback()
            try:
                session.exec(text("ALTER TABLE scan ADD COLUMN provider VARCHAR DEFAULT NULL"))
                session.commit()
                logger.info("Migration: Added 'provider' column to scan table")
            except Exception as e:
                session.rollback()
                logger.warning(f"Migration 'provider' column skipped: {e}")
    def _migrate_scan_resumption_columns(self, session):
        """Migrate scan resumption columns to existing scan tables."""
        for column_name, column_definition in [
            ("last_phase_completed", "VARCHAR DEFAULT NULL"),
            ("retry_count", "INTEGER DEFAULT 0"),
            ("last_error", "VARCHAR DEFAULT NULL"),
            ("resumed_from_id", "INTEGER DEFAULT NULL"),
        ]:
            self._ensure_scan_column(session, column_name, column_definition)
