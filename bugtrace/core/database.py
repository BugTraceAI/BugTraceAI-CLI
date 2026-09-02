from typing import Optional, List, Dict
import os
from datetime import datetime
from dataclasses import dataclass
from sqlmodel import SQLModel, create_engine, Session, select
from sqlalchemy import Engine, text, event, func
from sqlalchemy.engine import make_url
from sqlalchemy.pool import QueuePool, StaticPool
try:
    import lancedb
    LANCEDB_AVAILABLE = True
except Exception:
    lancedb = None
    LANCEDB_AVAILABLE = False

# LanceDB may perform native initialization that is slow or unavailable on
# minimal/heterogeneous deployments. Keep API startup deterministic and make
# the optional vector store an explicit opt-in. Set BUGTRACE_LANCEDB_ENABLED=1
# only after validating the runtime image and persistence path.
LANCEDB_ENABLED = os.getenv("BUGTRACE_LANCEDB_ENABLED", "0").strip().lower() in {
    "1", "true", "yes", "on"
}

from bugtrace.schemas.db_models import (
    TargetTable, ScanTable, FindingTable, ScanStateTable,
    ScanStatus, FindingStatus
)
from bugtrace.utils.logger import get_logger
logger = get_logger("core.database")
from tenacity import retry, stop_after_attempt, wait_fixed


from bugtrace.core.config import settings
from bugtrace.core.database_helpers import (
    ScanInfo,
    _build_csti_description,
    _build_sqli_description,
    _build_xss_description,
    _convert_evidence_to_description,
    SEVERITY_RANK,
    DEFAULT_CONFIDENCE,
    CONFIDENCE_FLOOR,
    _TERMINAL_VERDICTS,
    _rank_severity,
    _higher_severity,
    _resolve_confidence,
    _resolve_status,
    _evidence_to_description,
)
from bugtrace.core.database_migrations import DatabaseMigrationsMixin
from bugtrace.core.database_findings import DatabaseFindingsMixin

class DatabaseManager(DatabaseMigrationsMixin, DatabaseFindingsMixin):
    _instance: Optional["DatabaseManager"] = None

    # Connection pool configuration
    POOL_SIZE = 10  # Max connections in pool
    MAX_OVERFLOW = 20  # Additional connections when pool is full
    POOL_TIMEOUT = 30  # Seconds to wait for connection
    POOL_RECYCLE = 3600  # Recycle connections after 1 hour
    POOL_PRE_PING = True  # Verify connection before use

    def __init__(self, db_url: str = "sqlite:///bugtrace.db", vector_db_path: str = "./data/lancedb"):
        self.db_url = db_url
        self.vector_db_path = vector_db_path

        # SQL Engine with connection pooling
        self.engine: Engine = self._create_engine()

        # Test Connection with Retry
        self._wait_for_db()

        # LanceDB Connection (optional — graceful degradation if unavailable)
        if LANCEDB_AVAILABLE and LANCEDB_ENABLED:
            os.makedirs(vector_db_path, exist_ok=True)
            self.vector_db = lancedb.connect(self.vector_db_path)
        else:
            self.vector_db = None
            if LANCEDB_AVAILABLE and not LANCEDB_ENABLED:
                logger.info("LanceDB disabled by default; set BUGTRACE_LANCEDB_ENABLED=1 to opt in.")
            else:
                logger.warning("LanceDB unavailable (possible AVX2 requirement). Vector search disabled.")

        # Initialize tables
        self._create_tables()
        self._init_vector_store()
    def _create_engine(self) -> Engine:
        """
        Create SQLAlchemy engine with appropriate connection pooling.

        - SQLite: Uses StaticPool for thread safety (single connection)
        - PostgreSQL/MySQL: Uses QueuePool with configurable size
        """
        is_sqlite = self.db_url.startswith("sqlite")
        is_memory = ":memory:" in self.db_url or self.db_url == "sqlite://"

        if is_sqlite and is_memory:
            # SQLite memory: Use StaticPool for thread-safe single connection
            engine = create_engine(
                self.db_url,
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
                echo=False
            )
        elif is_sqlite:
            # Ensure parent dir exists for file-backed SQLite DB.
            db_path = make_url(self.db_url).database or ""
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            # SQLite file: Use QueuePool
            engine = create_engine(
                self.db_url,
                poolclass=QueuePool,
                pool_size=self.POOL_SIZE,
                max_overflow=self.MAX_OVERFLOW,
                connect_args={"check_same_thread": False, "timeout": 30.0},
                echo=False
            )
            # Enable SQLite optimizations
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()
        else:
            # PostgreSQL/MySQL: Use QueuePool with connection pooling
            engine = create_engine(
                self.db_url,
                poolclass=QueuePool,
                pool_size=self.POOL_SIZE,
                max_overflow=self.MAX_OVERFLOW,
                pool_timeout=self.POOL_TIMEOUT,
                pool_recycle=self.POOL_RECYCLE,
                pool_pre_ping=self.POOL_PRE_PING,
                echo=False
            )

        logger.info(f"Database engine created: {type(engine.pool).__name__}")
        return engine
    def _wait_for_db(self):
        try:
            with Session(self.engine) as session:
                session.exec(text("SELECT 1"))
            logger.info("Database connection established.")
        except Exception as e:
            logger.warning(f"Waiting for database... {e}")
            raise
    @classmethod
    def get_instance(cls) -> "DatabaseManager":
        if cls._instance is None:
            from bugtrace.core.config import settings
            data_dir = settings.DATA_DIR
            data_dir.mkdir(parents=True, exist_ok=True)
            log_dir = settings.LOG_DIR
            log_dir.mkdir(parents=True, exist_ok=True)
            cls._instance = cls(
                db_url=f"sqlite:///{data_dir / 'bugtrace.db'}",
                vector_db_path=str(log_dir / "lancedb"),
            )
        return cls._instance
    @classmethod
    def reset_instance(cls) -> None:
        """Dispose the singleton (tests / hermetic runtime rebind).

        Safe to call when no instance exists. Does not delete database files.
        """
        inst = cls._instance
        cls._instance = None
        if inst is None:
            return
        engine = getattr(inst, "engine", None)
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass
        # Drop vector handle so the next instance re-opens under the new path.
        if hasattr(inst, "vector_db"):
            inst.vector_db = None
    def _init_vector_store(self):
        """Initialize vector store with explicit schema for findings_embeddings."""
        if not self.vector_db:
            return
        try:
            import pyarrow as pa

            collection = "findings_embeddings"
            if collection not in self.vector_db.table_names():
                schema = pa.schema([
                    pa.field("finding_id", pa.string()),
                    pa.field("type", pa.string()),
                    pa.field("url", pa.string()),
                    pa.field("parameter", pa.string()),
                    pa.field("payload", pa.string()),
                    pa.field("severity", pa.string()),
                    pa.field("confidence", pa.float64()),
                    pa.field("vector", pa.list_(pa.float32(), 384)),
                    pa.field("timestamp", pa.string()),
                ])
                self.vector_db.create_table(collection, schema=schema)
                logger.info(f"Created '{collection}' table with explicit schema")

            logger.info("Vector Store initialized.")
        except Exception as e:
            logger.error(f"Failed to init vector store: {e}", exc_info=True)
    def get_session(self) -> Session:
        return Session(self.engine)
    def _try_get_existing_target(self, session, url: str) -> Optional[TargetTable]:
        """Try to get existing target from database."""
        statement = select(TargetTable).where(TargetTable.url == url)
        target = session.exec(statement).first()
        if target:
            session.expunge(target)
        return target
    def _try_create_target(self, session, url: str) -> Optional[TargetTable]:
        """Try to create new target, returns None on IntegrityError."""
        from sqlalchemy.exc import IntegrityError
        try:
            target = TargetTable(url=url)
            session.add(target)
            session.commit()
            session.refresh(target)
            session.expunge(target)
            logger.info(f"Created new target: {url}")
            return target
        except IntegrityError:
            session.rollback()
            logger.debug(f"Race condition: target created by another process")
            return None
    def _handle_race_condition(self, session, url: str, attempt: int, max_retries: int) -> Optional[TargetTable]:
        """Handle race condition by fetching target created by another process."""
        statement = select(TargetTable).where(TargetTable.url == url)
        target = session.exec(statement).first()
        if target:
            session.expunge(target)
            logger.debug(f"Target fetched after race condition: {url}")
            return target

        logger.warning(f"Target disappeared after race condition, retrying ({attempt + 1}/{max_retries})")
        return None
    def get_or_create_target(self, url: str, max_retries: int = 3) -> TargetTable:
        """Get existing target or create new one with race condition handling."""
        for attempt in range(max_retries):
            with self.get_session() as session:
                # Try to get existing target
                target = self._try_get_existing_target(session, url)
                if target:
                    return target

                # Target not found, try to create
                target = self._try_create_target(session, url)
                if target:
                    return target

                # Race condition occurred, try to fetch it
                target = self._handle_race_condition(session, url, attempt, max_retries)
                if target:
                    return target

        raise RuntimeError(f"Failed to get or create target after {max_retries} attempts: {url}")
    def get_active_scan(self, target_url: str) -> Optional[int]:
        """Check if there is an interrupted/active scan for this target."""
        with self.get_session() as session:
            statement = select(TargetTable).where(TargetTable.url == target_url)
            target = session.exec(statement).first()
            if not target: return None
            
            # Find most recent non-completed scan
            scan_query = select(ScanTable).where(
                ScanTable.target_id == target.id,
                ScanTable.status != ScanStatus.COMPLETED
            ).order_by(ScanTable.id.desc())
            
            scan = session.exec(scan_query).first()
            return scan.id if scan else None
    def get_latest_scan_id(self, target_url: str) -> Optional[int]:
        """Get the absolute latest scan ID for a target, regardless of status."""
        with self.get_session() as session:
            statement = select(TargetTable).where(TargetTable.url == target_url)
            target = session.exec(statement).first()
            if not target: return None
            
            scan_query = select(ScanTable).where(
                ScanTable.target_id == target.id
            ).order_by(ScanTable.id.desc())
            
            scan = session.exec(scan_query).first()
            return scan.id if scan else None
    def get_most_recent_scan_id(self) -> Optional[int]:
        """Get the most recent scan ID across all targets."""
        with self.get_session() as session:
            scan_query = select(ScanTable).order_by(ScanTable.id.desc())
            scan = session.exec(scan_query).first()
            return scan.id if scan else None
    def get_scan_info(self, scan_id: int) -> Optional[ScanInfo]:
        """Get scan metadata including target URL."""
        with self.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            if not scan:
                return None

            target = session.get(TargetTable, scan.target_id)
            return ScanInfo(
                scan_id=scan.id,
                target_url=target.url if target else "Unknown",
                timestamp=scan.timestamp,
                status=scan.status,
                progress_percent=scan.progress_percent
            )
    def create_new_scan(
        self,
        target_url: str,
        origin: str = "unknown",
        scan_type: str = None,
        max_depth: int = None,
        max_urls: int = None,
        provider: str = None,
    ) -> int:
        """Create a new scan record with RUNNING status.

        Args:
            target_url: Target URL to scan
            origin: Where the scan was launched from ('cli' or 'web')
            scan_type: Scan type ('full', 'hunter', 'manager', etc.)
            max_depth: Crawl depth configured
            max_urls: Max URLs configured
            provider: LLM provider used ('openrouter', 'zai', etc.)
        """
        target = self.get_or_create_target(target_url)
        target_id = target.id  # Extract ID while target is still valid
        with self.get_session() as session:
            scan = ScanTable(
                target_id=target_id,
                status=ScanStatus.RUNNING,
                progress_percent=0,
                origin=origin,
                scan_type=scan_type,
                max_depth=max_depth,
                max_urls=max_urls,
                provider=provider,
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id
        logger.info(f"Created scan {scan_id} in database (target_id={target_id}, origin={origin}, type={scan_type}, depth={max_depth}, urls={max_urls}, provider={provider})")
        return scan_id
    def update_scan_progress(self, scan_id: int, progress: int, status: Optional[ScanStatus] = None):
        """Update scan progress and optionally status."""
        try:
            progress = max(0, min(100, int(progress)))
        except (TypeError, ValueError):
            progress = 0
        with self.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            if scan:
                scan.progress_percent = progress
                if status:
                    scan.status = status
                session.add(scan)
                session.commit()
    def update_scan_status(self, scan_id: int, status: ScanStatus):
        """Update scan status."""
        with self.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            if scan:
                scan.status = status
                session.add(scan)
                session.commit()
    def update_scan_enrichment_status(self, scan_id: int, enrichment_status: str):
        """Update scan enrichment status."""
        with self.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            if scan:
                scan.enrichment_status = enrichment_status
                session.add(scan)
                session.commit()
    def update_scan_report_dir(self, scan_id: int, report_dir: str):
        """Update scan report directory."""
        with self.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            if scan:
                scan.report_dir = report_dir
                session.add(scan)
                session.commit()
                logger.info(f"Updated scan {scan_id} report_dir to {report_dir}")
    def save_checkpoint(self, scan_id: int, state_data: str):
        """Save orchestrator state to DB."""
        with self.get_session() as session:
            # Check if exists
            chk_query = select(ScanStateTable).where(ScanStateTable.scan_id == scan_id)
            checkpoint = session.exec(chk_query).first()
            
            if checkpoint:
                checkpoint.state_json = state_data
                checkpoint.updated_at = datetime.utcnow()
            else:
                checkpoint = ScanStateTable(scan_id=scan_id, state_json=state_data)
            
            session.add(checkpoint)
            session.commit()
    def get_checkpoint(self, scan_id: int) -> Optional[str]:
        """Load state from DB."""
        with self.get_session() as session:
            chk_query = select(ScanStateTable).where(ScanStateTable.scan_id == scan_id)
            checkpoint = session.exec(chk_query).first()
            
            return checkpoint.state_json if checkpoint else None
    def _get_or_create_scan(self, session, target_url: str, scan_id: Optional[int]) -> ScanTable:
        """Get existing scan or create new one."""
        if scan_id:
            scan = session.get(ScanTable, scan_id)
            if scan:
                return scan
            # Fallback if scan_id not found
            target = self.get_or_create_target(target_url)
            scan = ScanTable(target_id=target.id, status=ScanStatus.RUNNING)
        else:
            target = self.get_or_create_target(target_url)
            scan = ScanTable(target_id=target.id, status=ScanStatus.COMPLETED)

        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan


# Lazy initialization - don't create at import time
def get_db_manager() -> DatabaseManager:
    """Get or create database manager instance."""
    return DatabaseManager.get_instance()
