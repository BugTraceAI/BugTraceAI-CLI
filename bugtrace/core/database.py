from typing import Optional, List, Dict
import os
from datetime import datetime
from sqlmodel import SQLModel, create_engine, Session, select
from sqlalchemy import Engine, text, event
from sqlalchemy.pool import QueuePool, StaticPool
import lancedb
from bugtrace.schemas.db_models import (
    TargetTable, ScanTable, FindingTable, ScanStateTable,
    ScanStatus, FindingStatus
)
from bugtrace.utils.logger import get_logger
logger = get_logger("core.database")
from tenacity import retry, stop_after_attempt, wait_fixed


def _build_csti_description(evidence: Dict, param: str, payload: str) -> List[str]:
    """Build CSTI-specific description parts."""
    engine = evidence.get("engine", "unknown")
    method = evidence.get("method", "injection")
    parts = [
        f"Client-Side Template Injection (CSTI) detected via {method}.",
        f"Parameter: {param}",
        f"Template Engine: {engine}"
    ]
    if payload:
        parts.append(f"Payload: {payload}")
    if "proof" in evidence:
        parts.append(f"Evidence: {evidence['proof']}")
    return parts


def _build_sqli_description(evidence: Dict, param: str) -> List[str]:
    """Build SQLi-specific description parts."""
    parts = [
        f"SQL Injection vulnerability confirmed.",
        f"Parameter: {param}"
    ]
    if evidence.get("db_type"):
        parts.append(f"Database: {evidence['db_type']}")
    if evidence.get("injection_type"):
        parts.append(f"Type: {evidence['injection_type']}")
    return parts


def _build_xss_description(evidence: Dict, param: str, payload: str) -> List[str]:
    """Build XSS-specific description parts."""
    parts = [
        f"Cross-Site Scripting (XSS) vulnerability detected.",
        f"Parameter: {param}"
    ]
    if payload:
        parts.append(f"Payload: {payload}")
    if evidence.get("context"):
        parts.append(f"Context: {evidence['context']}")
    return parts


def _convert_evidence_to_description(evidence: Dict, finding_data: Dict) -> str:
    """Convert evidence dict to readable description."""
    if isinstance(evidence, str):
        return evidence

    if not isinstance(evidence, dict):
        return "Vulnerability detected."

    vuln_type = (finding_data.get("type") or "").upper()
    param = finding_data.get("parameter", "unknown")
    payload = finding_data.get("payload", "")

    if vuln_type in ["CSTI", "SSTI"]:
        parts = _build_csti_description(evidence, param, payload)
    elif vuln_type in ["SQLI", "SQL"]:
        parts = _build_sqli_description(evidence, param)
    elif vuln_type == "XSS":
        parts = _build_xss_description(evidence, param, payload)
    else:
        # Generic fallback
        parts = [f"{k}: {v}" for k, v in evidence.items() if isinstance(v, str) and v]

    return "\n".join(parts) if parts else "Vulnerability detected."


def _evidence_to_description(finding_data: Dict) -> str:
    """Convert finding data to a human-readable description."""
    # Priority: description > note > evidence (converted) > fallback
    desc = finding_data.get("description")
    if desc and isinstance(desc, str) and len(desc) > 10:
        return desc

    note = finding_data.get("note")
    if note and isinstance(note, str) and len(note) > 10:
        return note

    evidence = finding_data.get("evidence")
    if evidence:
        return _convert_evidence_to_description(evidence, finding_data)

    # Fallback
    vuln_type = finding_data.get("type", "Unknown")
    param = finding_data.get("parameter", "")
    return f"{vuln_type} vulnerability detected on parameter: {param}" if param else f"{vuln_type} vulnerability detected."


class DatabaseManager:
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

        # LanceDB Connection
        os.makedirs(vector_db_path, exist_ok=True)
        self.vector_db = lancedb.connect(self.vector_db_path)

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

        if is_sqlite:
            # SQLite: Use StaticPool for thread-safe single connection
            # Also enable foreign keys and WAL mode for better concurrency
            engine = create_engine(
                self.db_url,
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
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

    @retry(stop=stop_after_attempt(5), wait=wait_fixed(2))
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
            cls._instance = cls(
                db_url=f"sqlite:///{settings.BASE_DIR}/bugtrace.db",
                vector_db_path=str(settings.LOG_DIR / "lancedb")
            )
        return cls._instance

    def _create_tables(self):
        try:
            SQLModel.metadata.create_all(self.engine)
            self._run_migrations()
            logger.info("SQL Tables initialized.")
        except Exception as e:
            logger.error(f"Failed to create SQL tables: {e}")

    def _run_migrations(self):
        """Run lightweight schema migrations for new columns on existing tables."""
        with self.get_session() as session:
            # Migration: Add 'origin' column to scan table (v2.1)
            try:
                session.exec(text("SELECT origin FROM scan LIMIT 1"))
            except Exception:
                session.rollback()
                try:
                    session.exec(text("ALTER TABLE scan ADD COLUMN origin VARCHAR DEFAULT 'cli'"))
                    session.commit()
                    logger.info("Migration: Added 'origin' column to scan table")
                except Exception as e:
                    session.rollback()
                    logger.warning(f"Migration 'origin' column skipped: {e}")

    def _init_vector_store(self):
        try:
            if "dom_structures" not in self.vector_db.table_names():
                pass
            logger.info("Vector Store initialized.")
        except Exception as e:
            logger.error(f"Failed to init vector store: {e}")

    def get_session(self) -> Session:
        return Session(self.engine)

    # =========================================================================
    # PERSISTENCE METHODS - Save and load scan results
    # =========================================================================
    
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
    def create_new_scan(self, target_url: str, origin: str = "cli") -> int:
        """Create a new scan record with RUNNING status.

        Args:
            target_url: Target URL to scan
            origin: Where the scan was launched from ('cli' or 'web')
        """
        with self.get_session() as session:
            target = self.get_or_create_target(target_url)
            scan = ScanTable(target_id=target.id, status=ScanStatus.RUNNING, progress_percent=0, origin=origin)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan.id

    def update_scan_progress(self, scan_id: int, progress: int, status: Optional[ScanStatus] = None):
        """Update scan progress and optionally status."""
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

    def update_finding_status(self, finding_id: int, status: FindingStatus, notes: Optional[str] = None, screenshot: Optional[str] = None):
        """Update finding validation status and evidence."""
        with self.get_session() as session:
            finding = session.get(FindingTable, finding_id)
            if finding:
                finding.status = status
                if notes: finding.validator_notes = notes
                if screenshot: finding.proof_screenshot_path = screenshot
                if status == FindingStatus.VALIDATED_CONFIRMED:
                    finding.visual_validated = True
                session.add(finding)
                session.commit()

    def get_pending_findings(self, scan_id: Optional[int] = None) -> List[FindingTable]:
        """Get all findings waiting for validation."""
        with self.get_session() as session:
            statement = select(FindingTable).where(FindingTable.status == FindingStatus.PENDING_VALIDATION)
            if scan_id:
                statement = statement.where(FindingTable.scan_id == scan_id)
            results = session.exec(statement).all()
            # Expunge to prevent DetachedInstanceError
            for r in results:
                session.expunge(r)
            return list(results)

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

    def _normalize_vuln_type(self, vuln_type_str: str):
        """Normalize vulnerability type string to enum."""
        from bugtrace.schemas.models import normalize_vuln_type, VulnType
        try:
            return normalize_vuln_type(vuln_type_str)
        except Exception as e:
            logger.warning(f"Failed to normalize type '{vuln_type_str}': {e}, using MISCONFIG")
            return VulnType.MISCONFIG

    def _update_existing_finding(self, existing_finding: FindingTable, finding_data: Dict):
        """Update existing finding with new data."""
        if finding_data.get("payload"):
            existing_finding.payload_used = finding_data.get("payload")

        if finding_data.get("validated") or finding_data.get("conductor_validated"):
            existing_finding.visual_validated = True
            existing_finding.status = FindingStatus.VALIDATED_CONFIRMED

        new_conf = finding_data.get("confidence", 0.0)
        if new_conf > existing_finding.confidence_score:
            existing_finding.confidence_score = new_conf

        new_details = _evidence_to_description(finding_data)
        if len(new_details) > len(existing_finding.details):
            existing_finding.details = new_details

        new_screenshot = finding_data.get("screenshot_path") or finding_data.get("screenshot")
        if new_screenshot and not existing_finding.proof_screenshot_path:
            existing_finding.proof_screenshot_path = new_screenshot

    def _create_new_finding(self, scan_id: int, vuln_type, finding_data: Dict, target_url: str) -> FindingTable:
        """Create new finding record from data."""
        raw_status = finding_data.get("status")
        if raw_status:
            try:
                finding_status = FindingStatus(raw_status)
            except ValueError:
                finding_status = FindingStatus.PENDING_VALIDATION
        else:
            finding_status = (
                FindingStatus.VALIDATED_CONFIRMED
                if finding_data.get("conductor_validated")
                else FindingStatus.PENDING_VALIDATION
            )

        return FindingTable(
            scan_id=scan_id,
            type=vuln_type,
            severity=finding_data.get("severity", "MEDIUM"),
            details=_evidence_to_description(finding_data),
            payload_used=finding_data.get("payload") or "N/A",
            confidence_score=finding_data.get("confidence", 0.85),
            visual_validated=finding_data.get("validated") or finding_data.get("conductor_validated", False),
            attack_url=finding_data.get("url", target_url),
            vuln_parameter=finding_data.get("parameter", finding_data.get("param", "")),
            reproduction_command=finding_data.get("reproduction") or finding_data.get("reproduction_command"),
            status=finding_status,
            proof_screenshot_path=finding_data.get("screenshot_path") or finding_data.get("screenshot")
        )

    def _find_existing_finding(self, session, scan_id: int, vuln_type, finding_data: Dict, target_url: str):
        """Check if finding already exists for this scan."""
        return session.exec(
            select(FindingTable).where(
                FindingTable.scan_id == scan_id,
                FindingTable.type == vuln_type,
                FindingTable.attack_url == finding_data.get("url", target_url),
                FindingTable.vuln_parameter == finding_data.get("parameter", finding_data.get("param", ""))
            )
        ).first()

    def save_scan_result(self, target_url: str, findings: List[Dict], scan_id: Optional[int] = None) -> int:
        """Save scan results to database."""
        with self.get_session() as session:
            scan = self._get_or_create_scan(session, target_url, scan_id)

            for finding_data in findings:
                vuln_type_str = finding_data.get("type", "Unknown")
                vuln_type = self._normalize_vuln_type(vuln_type_str)

                existing_finding = self._find_existing_finding(
                    session, scan.id, vuln_type, finding_data, target_url
                )

                if existing_finding:
                    logger.info(f"Updating existing finding: {vuln_type} on {finding_data.get('parameter')}")
                    self._update_existing_finding(existing_finding, finding_data)
                    session.add(existing_finding)
                else:
                    finding = self._create_new_finding(scan.id, vuln_type, finding_data, target_url)
                    session.add(finding)

            session.commit()
            logger.info(f"Updated scan {scan.id} with {len(findings)} findings for {target_url}")
            return scan.id

    def get_findings_for_scan(self, scan_id: int) -> List[FindingTable]:
        """Get all findings for a specific scan."""
        with self.get_session() as session:
            statement = select(FindingTable).where(FindingTable.scan_id == scan_id)
            results = session.exec(statement).all()
            for r in results:
                session.expunge(r)
            return list(results)
    
    def get_findings_for_target(self, target_url: str) -> List[Dict]:
        """
        Get all previous findings for a target.
        
        Args:
            target_url: URL to look up
            
        Returns:
            List of finding dictionaries
        """
        with self.get_session() as session:
            statement = select(TargetTable).where(TargetTable.url == target_url)
            target = session.exec(statement).first()
            
            if not target:
                return []
            
            # Get all scans for this target
            scan_statement = select(ScanTable).where(ScanTable.target_id == target.id)
            scans = session.exec(scan_statement).all()
            
            findings = []
            for scan in scans:
                finding_statement = select(FindingTable).where(FindingTable.scan_id == scan.id)
                scan_findings = session.exec(finding_statement).all()
                
                for f in scan_findings:
                    findings.append({
                        "type": f.type,
                        "severity": f.severity,
                        "details": f.details,
                        "payload": f.payload_used,
                        "confidence": f.confidence_score,
                        "validated": f.visual_validated,
                        "url": f.attack_url,
                        "parameter": f.vuln_parameter,
                        "scan_date": scan.timestamp.isoformat()
                    })
            
            logger.info(f"Found {len(findings)} previous findings for {target_url}")
            return findings
    
    def get_scan_count(self, target_url: str) -> int:
        """Get number of previous scans for a target."""
        with self.get_session() as session:
            statement = select(TargetTable).where(TargetTable.url == target_url)
            target = session.exec(statement).first()
            
            if not target:
                return 0
            
            scan_statement = select(ScanTable).where(ScanTable.target_id == target.id)
            scans = session.exec(scan_statement).all()
            return len(scans)

    # =========================================================================
    # VECTOR OPERATIONS - Semantic search and similarity
    # =========================================================================
    
    def add_vector_embedding(self, collection_name: str, data: List[dict]):
        """Add data (must contain 'vector' field) to LanceDB collection."""
        try:
            if collection_name in self.vector_db.table_names():
                tbl = self.vector_db.open_table(collection_name)
                tbl.add(data)
            else:
                self.vector_db.create_table(collection_name, data=data)
        except Exception as e:
            logger.error(f"Vector add failed: {e}")
    
    def search_similar_findings(self, query_text: str, limit: int = 5) -> List[Dict]:
        """
        Search for similar findings using semantic similarity.
        
        Args:
            query_text: Search query (e.g., "SQL injection in id parameter")
            limit: Max results to return
            
        Returns:
            List of similar findings with similarity scores
        """
        try:
            from bugtrace.core.embeddings import get_embedding_manager
            
            collection = "findings_embeddings"
            
            # Check if collection exists
            if collection not in self.vector_db.table_names():
                logger.debug("No findings embeddings table exists yet")
                return []
            
            # Get embedding for query
            emb_manager = get_embedding_manager()
            query_vector = emb_manager.encode_query(query_text)
            
            # Search in LanceDB
            tbl = self.vector_db.open_table(collection)
            results = tbl.search(query_vector).limit(limit).to_list()
            
            # Format results
            similar_findings = []
            for result in results:
                similar_findings.append({
                    "type": result.get("type"),
                    "url": result.get("url"),
                    "parameter": result.get("parameter"),
                    "payload": result.get("payload"),
                    "distance": result.get("_distance", 0.0),  # Lower is more similar
                    "timestamp": result.get("timestamp")
                })
            
            logger.info(f"Found {len(similar_findings)} similar findings for query: {query_text[:50]}")
            return similar_findings
            
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return []
    
    def store_finding_embedding(self, finding: Dict, embedding: Optional[List[float]] = None):
        """
        Store a finding with its vector embedding for future similarity search.
        
        Args:
            finding: Finding dictionary
            embedding: Optional pre-computed embedding. If None, will generate automatically.
        """
        try:
            from bugtrace.core.embeddings import get_embedding_manager
            from typing import Optional
            from datetime import datetime
            
            # Generate embedding if not provided
            if embedding is None:
                emb_manager = get_embedding_manager()
                embedding = emb_manager.encode_finding(finding)
            
            collection = "findings_embeddings"
            data = [{
                "finding_id": finding.get("id", "unknown"),
                "type": finding.get("type", ""),
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "payload": finding.get("payload", "")[:200],  # Truncate
                "vector": embedding,
                "timestamp": datetime.now().isoformat()
            }]
            self.add_vector_embedding(collection, data)
            logger.debug(f"Stored embedding for finding: {finding.get('type')}")
        except Exception as e:
            logger.error(f"Failed to store finding embedding: {e}")
            import traceback
            logger.debug(traceback.format_exc())

    # =========================================================================
    # HEALTH CHECK & METRICS
    # =========================================================================

    def health_check(self) -> Dict:
        """
        Check database health and connectivity.

        Returns:
            Dict with status ('healthy' or 'unhealthy'), latency, and error info
        """
        import time
        result = {
            "status": "unhealthy",
            "sql_db": {"status": "unknown"},
            "vector_db": {"status": "unknown"},
            "latency_ms": 0
        }

        start = time.perf_counter()

        # Check SQL database
        try:
            with self.get_session() as session:
                session.exec(text("SELECT 1"))
            result["sql_db"] = {"status": "healthy"}
        except Exception as e:
            result["sql_db"] = {"status": "unhealthy", "error": str(e)}
            logger.error(f"SQL health check failed: {e}")

        # Check LanceDB
        try:
            _ = self.vector_db.table_names()
            result["vector_db"] = {"status": "healthy"}
        except Exception as e:
            result["vector_db"] = {"status": "unhealthy", "error": str(e)}
            logger.error(f"Vector DB health check failed: {e}")

        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)

        # Overall status
        if result["sql_db"]["status"] == "healthy" and result["vector_db"]["status"] == "healthy":
            result["status"] = "healthy"

        return result

    def get_metrics(self) -> Dict:
        """
        Get database metrics for monitoring.

        Returns:
            Dict with pool stats, table counts, and other metrics
        """
        metrics = {
            "pool": {},
            "tables": {},
            "vector_collections": []
        }

        # Connection pool metrics
        pool = self.engine.pool
        metrics["pool"] = {
            "pool_class": type(pool).__name__,
            "size": getattr(pool, "size", lambda: "N/A")() if callable(getattr(pool, "size", None)) else getattr(pool, "_pool", {}).qsize() if hasattr(pool, "_pool") else "N/A",
            "checked_in": pool.checkedin() if hasattr(pool, "checkedin") else "N/A",
            "checked_out": pool.checkedout() if hasattr(pool, "checkedout") else "N/A",
            "overflow": pool.overflow() if hasattr(pool, "overflow") else "N/A",
        }

        # Table row counts
        try:
            with self.get_session() as session:
                metrics["tables"]["targets"] = session.exec(select(TargetTable)).all().__len__()
                metrics["tables"]["scans"] = session.exec(select(ScanTable)).all().__len__()
                metrics["tables"]["findings"] = session.exec(select(FindingTable)).all().__len__()
        except Exception as e:
            logger.warning(f"Failed to get table metrics: {e}")
            metrics["tables"]["error"] = str(e)

        # Vector DB collections
        try:
            metrics["vector_collections"] = self.vector_db.table_names()
        except Exception as e:
            logger.warning(f"Failed to get vector DB metrics: {e}")
            metrics["vector_collections_error"] = str(e)

        return metrics

    def _validate_backup_prerequisites(self) -> tuple[bool, Optional[str], Optional[str]]:
        """Validate that backup can proceed. Returns (can_proceed, error_msg, db_path)."""
        if not self.db_url.startswith("sqlite"):
            logger.warning("Backup attempted on non-SQLite database")
            return False, "Backup only supported for SQLite databases", None

        db_path = self.db_url.replace("sqlite:///", "")
        if not os.path.exists(db_path):
            return False, f"Database file not found: {db_path}", None

        return True, None, db_path

    def _prepare_backup_path(self, db_path: str, backup_dir: Optional[str]) -> str:
        """Prepare backup directory and generate backup file path."""
        if backup_dir is None:
            backup_dir = os.path.join(os.path.dirname(db_path), "backups")
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"bugtrace_backup_{timestamp}.db"
        return os.path.join(backup_dir, backup_filename)

    def _perform_sqlite_backup(self, db_path: str, backup_path: str) -> int:
        """Perform actual SQLite backup and return size."""
        import sqlite3
        source = sqlite3.connect(db_path)
        dest = sqlite3.connect(backup_path)
        with dest:
            source.backup(dest)
        source.close()
        dest.close()
        return os.path.getsize(backup_path)

    def backup_database(self, backup_dir: Optional[str] = None) -> Dict:
        """Create a backup of the SQLite database."""
        result = {
            "status": "failed",
            "path": None,
            "size_bytes": 0,
            "timestamp": datetime.utcnow().isoformat()
        }

        can_proceed, error_msg, db_path = self._validate_backup_prerequisites()
        if not can_proceed:
            result["error"] = error_msg
            return result

        try:
            backup_path = self._prepare_backup_path(db_path, backup_dir)
            backup_size = self._perform_sqlite_backup(db_path, backup_path)

            result["status"] = "success"
            result["path"] = backup_path
            result["size_bytes"] = backup_size

            logger.info(f"Database backup created: {backup_path} ({backup_size} bytes)")
            self._cleanup_old_backups(os.path.dirname(backup_path), keep=5)

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Database backup failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())

        return result

    def _cleanup_old_backups(self, backup_dir: str, keep: int = 5):
        """Remove old backups, keeping only the most recent ones."""
        from pathlib import Path

        try:
            backup_files = sorted(
                Path(backup_dir).glob("bugtrace_backup_*.db"),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )

            for old_backup in backup_files[keep:]:
                old_backup.unlink()
                logger.debug(f"Removed old backup: {old_backup}")

        except Exception as e:
            logger.warning(f"Failed to cleanup old backups: {e}")


# Lazy initialization - don't create at import time
def get_db_manager() -> DatabaseManager:
    """Get or create database manager instance."""
    return DatabaseManager.get_instance()
