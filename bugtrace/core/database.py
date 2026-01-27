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


def _evidence_to_description(finding_data: Dict) -> str:
    """
    Convert finding data to a human-readable description.
    2026-01-24 FIX: Prevents dict becoming "{'key': 'value'}" in reports.

    Priority: description > note > evidence (converted) > "No description"
    """
    # 1. Use description if it's a proper string
    desc = finding_data.get("description")
    if desc and isinstance(desc, str) and len(desc) > 10:
        return desc

    # 2. Use note if available
    note = finding_data.get("note")
    if note and isinstance(note, str) and len(note) > 10:
        return note

    # 3. Convert evidence dict to readable text
    evidence = finding_data.get("evidence")
    if evidence:
        if isinstance(evidence, str):
            return evidence
        elif isinstance(evidence, dict):
            # Build readable description from dict
            parts = []
            vuln_type = (finding_data.get("type") or "").upper()
            param = finding_data.get("parameter", "unknown")
            payload = finding_data.get("payload", "")

            # Type-specific descriptions
            if vuln_type in ["CSTI", "SSTI"]:
                engine = evidence.get("engine", "unknown")
                method = evidence.get("method", "injection")
                parts.append(f"Client-Side Template Injection (CSTI) detected via {method}.")
                parts.append(f"Parameter: {param}")
                parts.append(f"Template Engine: {engine}")
                if payload:
                    parts.append(f"Payload: {payload}")
                if "proof" in evidence:
                    parts.append(f"Evidence: {evidence['proof']}")
            elif vuln_type in ["SQLI", "SQL"]:
                parts.append(f"SQL Injection vulnerability confirmed.")
                parts.append(f"Parameter: {param}")
                if evidence.get("db_type"):
                    parts.append(f"Database: {evidence['db_type']}")
                if evidence.get("injection_type"):
                    parts.append(f"Type: {evidence['injection_type']}")
            elif vuln_type == "XSS":
                parts.append(f"Cross-Site Scripting (XSS) vulnerability detected.")
                parts.append(f"Parameter: {param}")
                if payload:
                    parts.append(f"Payload: {payload}")
                if evidence.get("context"):
                    parts.append(f"Context: {evidence['context']}")
            else:
                # Generic fallback for other types
                for k, v in evidence.items():
                    if isinstance(v, str) and v:
                        parts.append(f"{k}: {v}")

            return "\n".join(parts) if parts else "Vulnerability detected."

    # 4. Fallback
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
    
    def get_or_create_target(self, url: str, max_retries: int = 3) -> TargetTable:
        """
        Get existing target or create new one with race condition handling.

        Uses a retry loop pattern that is portable across SQLite and PostgreSQL:
        1. First attempts to SELECT the target
        2. If not found, attempts INSERT
        3. On IntegrityError, retries the SELECT (handles race condition)

        Args:
            url: Target URL to get or create
            max_retries: Maximum retry attempts on race condition (default: 3)

        Returns:
            TargetTable instance (either existing or newly created)

        Raises:
            RuntimeError: If unable to get or create target after max retries
        """
        from sqlalchemy.exc import IntegrityError

        for attempt in range(max_retries):
            with self.get_session() as session:
                # Step 1: Try to get existing target
                statement = select(TargetTable).where(TargetTable.url == url)
                target = session.exec(statement).first()

                if target:
                    # Expunge to prevent DetachedInstanceError after session closes
                    session.expunge(target)
                    return target

                # Step 2: Target not found, try to create
                try:
                    target = TargetTable(url=url)
                    session.add(target)
                    session.commit()
                    session.refresh(target)
                    session.expunge(target)
                    logger.info(f"Created new target: {url}")
                    return target
                except IntegrityError:
                    # Race condition: another process created it between our SELECT and INSERT
                    session.rollback()
                    logger.debug(f"Race condition on attempt {attempt + 1}: target created by another process")

                    # Fetch the target that was created by the other process
                    target = session.exec(statement).first()
                    if target:
                        session.expunge(target)
                        logger.debug(f"Target fetched after race condition: {url}")
                        return target

                    # Target still not found (rare: deleted between our attempts)
                    # Continue to next retry iteration
                    logger.warning(f"Target disappeared after race condition, retrying ({attempt + 1}/{max_retries})")

        # Exhausted retries - this should be extremely rare
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
    
    def save_scan_result(self, target_url: str, findings: List[Dict], scan_id: Optional[int] = None) -> int:
        """
        Save scan results to database.
        
        Args:
            target_url: The scanned URL
            findings: List of finding dictionaries
            scan_id: Optional existing scan ID to add findings to
            
        Returns:
            Scan ID
        """
        with self.get_session() as session:
            if scan_id:
                scan = session.get(ScanTable, scan_id)
                if not scan:
                    # Fallback if scan_id not found
                    target = self.get_or_create_target(target_url)
                    scan = ScanTable(target_id=target.id, status=ScanStatus.RUNNING)
                    session.add(scan)
                    session.commit()
                    session.refresh(scan)
            else:
                # Get or create target
                target = self.get_or_create_target(target_url)

                # Create scan record
                scan = ScanTable(
                    target_id=target.id,
                    status=ScanStatus.COMPLETED
                )
                session.add(scan)
                session.commit()
                session.refresh(scan)
            
            # Save findings
            for finding_data in findings:
                # Normalize vulnerability type to match enum
                from bugtrace.schemas.models import normalize_vuln_type
                vuln_type_str = finding_data.get("type", "Unknown")
                try:
                    vuln_type = normalize_vuln_type(vuln_type_str)
                except Exception as e:
                    logger.warning(f"Failed to normalize type '{vuln_type_str}': {e}, using MISCONFIG")
                    from bugtrace.schemas.models import VulnType
                    vuln_type = VulnType.MISCONFIG
                
                # Check if this specific finding (URL+Param+Type) already exists for this scan
                existing_finding = session.exec(
                    select(FindingTable).where(
                        FindingTable.scan_id == scan.id,
                        FindingTable.type == vuln_type,
                        FindingTable.attack_url == finding_data.get("url", target_url),
                        FindingTable.vuln_parameter == finding_data.get("parameter", finding_data.get("param", ""))
                    )
                ).first()

                if existing_finding:
                    # UPDATE existing finding (Upsert)
                    logger.info(f"Updating existing finding: {vuln_type} on {finding_data.get('parameter')}")
                    
                    # Merge payloads/details if needed, but usually newer is better/more specific
                    if finding_data.get("payload"):
                        existing_finding.payload_used = finding_data.get("payload")
                    
                    # If the new one is validated confirm, upgrade status
                    if finding_data.get("validated") or finding_data.get("conductor_validated"):
                        existing_finding.visual_validated = True
                        existing_finding.status = FindingStatus.VALIDATED_CONFIRMED
                    
                    # Update confidence if higher
                    new_conf = finding_data.get("confidence", 0.0)
                    if new_conf > existing_finding.confidence_score:
                        existing_finding.confidence_score = new_conf
                        
                    # Update details/evidence
                    new_details = _evidence_to_description(finding_data)
                    if len(new_details) > len(existing_finding.details):
                        existing_finding.details = new_details

                    # FIX: Update screenshot if provided
                    new_screenshot = finding_data.get("screenshot_path") or finding_data.get("screenshot")
                    if new_screenshot and not existing_finding.proof_screenshot_path:
                        existing_finding.proof_screenshot_path = new_screenshot

                    session.add(existing_finding)
                else:
                    # CREATE new finding
                    # Determine status: use provided status or infer from validation state
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

                    finding = FindingTable(
                        scan_id=scan.id,
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

    def backup_database(self, backup_dir: Optional[str] = None) -> Dict:
        """
        Create a backup of the SQLite database.

        Args:
            backup_dir: Directory to store backup. Defaults to ./backups/

        Returns:
            Dict with backup status, path, and size
        """
        import shutil
        from pathlib import Path

        result = {
            "status": "failed",
            "path": None,
            "size_bytes": 0,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Only works for SQLite
        if not self.db_url.startswith("sqlite"):
            result["error"] = "Backup only supported for SQLite databases"
            logger.warning("Backup attempted on non-SQLite database")
            return result

        try:
            # Extract database file path from URL
            db_path = self.db_url.replace("sqlite:///", "")
            if not os.path.exists(db_path):
                result["error"] = f"Database file not found: {db_path}"
                return result

            # Create backup directory
            if backup_dir is None:
                backup_dir = os.path.join(os.path.dirname(db_path), "backups")
            os.makedirs(backup_dir, exist_ok=True)

            # Generate backup filename with timestamp
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"bugtrace_backup_{timestamp}.db"
            backup_path = os.path.join(backup_dir, backup_filename)

            # Create backup using SQLite's backup API for consistency
            import sqlite3
            source = sqlite3.connect(db_path)
            dest = sqlite3.connect(backup_path)
            with dest:
                source.backup(dest)
            source.close()
            dest.close()

            # Get backup size
            backup_size = os.path.getsize(backup_path)

            result["status"] = "success"
            result["path"] = backup_path
            result["size_bytes"] = backup_size

            logger.info(f"Database backup created: {backup_path} ({backup_size} bytes)")

            # Cleanup old backups (keep last 5)
            self._cleanup_old_backups(backup_dir, keep=5)

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
