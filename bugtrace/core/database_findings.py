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

class DatabaseFindingsMixin:
    """Finding CRUD and enrichment persistence."""

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
    def update_findings_from_enrichment(self, scan_id: int, enriched_findings: List[Dict]):
        """Persist enriched severity and confidence back to DB after CVSS enrichment."""
        with self.get_session() as session:
            db_findings = session.exec(
                select(FindingTable).where(FindingTable.scan_id == scan_id)
            ).all()

            # Two-tier index (stable 4074425): URL-qualified first, legacy (type,param)
            # fallback so same type+param on different URLs do not collide.
            def _match_key(vuln_type, parameter, url=None):
                raw = vuln_type.value if hasattr(vuln_type, "value") else vuln_type
                return (str(raw or "").upper(), (parameter or "").lower(), (url or "").strip())

            lookup_by_url = {}
            lookup_legacy = {}
            for f in db_findings:
                lookup_by_url[_match_key(f.type, f.vuln_parameter, f.attack_url)] = f
                lookup_legacy[_match_key(f.type, f.vuln_parameter)] = f

            updated = 0
            for ef in enriched_findings:
                ef_type = ef.get("type")
                ef_param = ef.get("parameter") or ef.get("param")
                db_f = (
                    lookup_by_url.get(_match_key(ef_type, ef_param, ef.get("url")))
                    or lookup_legacy.get(_match_key(ef_type, ef_param))
                )
                if not db_f:
                    continue

                new_sev = _higher_severity(db_f.severity, ef.get("severity") or db_f.severity)
                new_conf = max(db_f.confidence_score, ef.get("confidence") or 0.0)

                changed = new_sev != db_f.severity or new_conf != db_f.confidence_score
                db_f.severity = new_sev
                db_f.confidence_score = new_conf

                if changed:
                    session.add(db_f)
                    updated += 1

            if updated:
                session.commit()
                logger.info(f"Enrichment persisted: updated {updated} findings in DB for scan {scan_id}")
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

        validated = bool(
            finding_data.get("validated") or finding_data.get("conductor_validated")
        )
        if validated:
            existing_finding.visual_validated = True
        # Honor explicit validator verdicts (incl. downgrades to FALSE_POSITIVE /
        # MANUAL_REVIEW) instead of only ever upgrading to CONFIRMED.
        existing_finding.status = _resolve_status(
            existing_finding.status, finding_data.get("status"), validated
        )

        existing_finding.confidence_score = max(
            existing_finding.confidence_score,
            _resolve_confidence(finding_data.get("confidence"), existing_finding.status),
        )

        new_severity = finding_data.get("severity")
        if new_severity:
            existing_finding.severity = _higher_severity(existing_finding.severity, new_severity)

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
            confidence_score=_resolve_confidence(finding_data.get("confidence"), finding_status),
            visual_validated=finding_data.get("validated") or finding_data.get("conductor_validated", False),
            attack_url=finding_data.get("url", target_url),
            vuln_parameter=finding_data.get("parameter", finding_data.get("param", "")),
            reproduction_command=finding_data.get("reproduction") or finding_data.get("reproduction_command"),
            status=finding_status,
            proof_screenshot_path=finding_data.get("screenshot_path") or finding_data.get("screenshot")
        )
    def _is_global_parameter(self, param: str) -> bool:
        """
        Check if parameter is global (affects all endpoints, not URL-specific).

        Global parameters include cookies, headers, and auth tokens that persist
        across all requests to a domain.
        """
        param_lower = (param or "").lower()
        global_indicators = ["cookie", "header", "authorization", "bearer", "token", "session"]
        return any(indicator in param_lower for indicator in global_indicators)
    def _normalize_parameter_for_lookup(self, param: str) -> str:
        """Normalize parameter for database lookup (handles variations)."""
        param_lower = (param or "").lower().strip()

        # Cookie: extract just the cookie name
        if "cookie" in param_lower:
            clean = param_lower.replace("cookie:", "").replace("cookie", "").strip()
            clean = clean.split()[0] if clean else ""
            return f"cookie:{clean}" if clean else param_lower

        return param_lower
    def _find_existing_finding(self, session, scan_id: int, vuln_type, finding_data: Dict, target_url: str):
        """
        Check if finding already exists for this scan.

        For global parameters (cookies, headers), ignores the URL since the
        vulnerability affects all endpoints equally.
        """
        param = finding_data.get("parameter", finding_data.get("param", ""))
        param_normalized = self._normalize_parameter_for_lookup(param)

        if self._is_global_parameter(param):
            # Global parameter: match by (scan_id, type, param) - ignore URL
            # Use LIKE to handle parameter variations
            results = session.exec(
                select(FindingTable).where(
                    FindingTable.scan_id == scan_id,
                    FindingTable.type == vuln_type
                )
            ).all()

            # Check if any existing finding has a matching normalized parameter
            for existing in results:
                existing_param_norm = self._normalize_parameter_for_lookup(existing.vuln_parameter)
                if existing_param_norm == param_normalized:
                    return existing

            return None
        else:
            # URL-specific parameter: full match required
            return session.exec(
                select(FindingTable).where(
                    FindingTable.scan_id == scan_id,
                    FindingTable.type == vuln_type,
                    FindingTable.attack_url == finding_data.get("url", target_url),
                    FindingTable.vuln_parameter == param
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

            # Store embeddings in LanceDB for cross-scan learning
            self._store_embeddings_if_enabled(findings)

            return scan.id
    def _store_embeddings_if_enabled(self, findings: List[Dict]) -> None:
        """Store finding embeddings in LanceDB if enabled and model is real."""
        try:
            from bugtrace.core.config import settings
            if not getattr(settings, 'LANCEDB_ENABLED', False):
                return

            from bugtrace.core.embeddings import get_embedding_manager
            emb_manager = get_embedding_manager()
            if not emb_manager.is_real_model:
                logger.debug("LanceDB skipped: MockEmbeddingModel active (no real model)")
                return

            stored = 0
            for finding_data in findings:
                self.store_finding_embedding(finding_data)
                stored += 1
            if stored:
                logger.info(f"Stored {stored} finding embeddings in LanceDB")
        except Exception as e:
            logger.warning(f"LanceDB embedding storage failed (non-fatal): {e}")
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
    def add_vector_embedding(self, collection_name: str, data: List[dict]):
        """Add data (must contain 'vector' field) to LanceDB collection."""
        if not self.vector_db:
            return
        try:
            if collection_name in self.vector_db.table_names():
                tbl = self.vector_db.open_table(collection_name)
                tbl.add(data)
            else:
                self.vector_db.create_table(collection_name, data=data)
        except Exception as e:
            logger.error(f"Vector add failed: {e}", exc_info=True)
    def search_similar_findings(self, query_text: str, limit: int = 5) -> List[Dict]:
        """
        Search for similar findings using semantic similarity.

        Args:
            query_text: Search query (e.g., "SQL injection in id parameter")
            limit: Max results to return

        Returns:
            List of similar findings with similarity scores, severity, confidence, and finding_id
        """
        if not self.vector_db:
            return []
        try:
            from bugtrace.core.embeddings import get_embedding_manager

            collection = "findings_embeddings"

            if collection not in self.vector_db.table_names():
                logger.debug("No findings embeddings table exists yet")
                return []

            emb_manager = get_embedding_manager()
            query_vector = emb_manager.encode_query(query_text)

            # L2: Guard against failed query encoding
            if query_vector is None:
                logger.warning("Query encoding failed, cannot search similar findings")
                return []

            tbl = self.vector_db.open_table(collection)
            results = tbl.search(query_vector).limit(limit).to_list()

            similar_findings = []
            for result in results:
                similar_findings.append({
                    "finding_id": result.get("finding_id"),
                    "type": result.get("type"),
                    "url": result.get("url"),
                    "parameter": result.get("parameter"),
                    "payload": result.get("payload"),
                    "severity": result.get("severity", ""),
                    "confidence": result.get("confidence", 0.0),
                    "distance": result.get("_distance", 0.0),
                    "timestamp": result.get("timestamp")
                })

            logger.info(f"Found {len(similar_findings)} similar findings for query: {query_text[:50]}")
            return similar_findings

        except Exception as e:
            logger.error(f"Vector search failed: {e}", exc_info=True)
            return []
    def store_finding_embedding(self, finding: Dict, embedding: Optional[List[float]] = None):
        """
        Store a finding with its vector embedding for future similarity search.

        Includes type normalization (L1), zero-vector guard (L2), and deduplication (L4).

        Args:
            finding: Finding dictionary
            embedding: Optional pre-computed embedding. If None, will generate automatically.
        """
        if not self.vector_db:
            return
        try:
            from bugtrace.core.embeddings import get_embedding_manager
            from datetime import datetime

            # Generate embedding if not provided
            if embedding is None:
                emb_manager = get_embedding_manager()
                embedding = emb_manager.encode_finding(finding)

            # L2: Zero-vector guard — skip storage if encoding failed
            if embedding is None:
                logger.warning(f"Skipping LanceDB storage for finding (embedding failed): {finding.get('type')}")
                return

            # L1: Normalize type to consistent string
            raw_type = finding.get("type", "")
            try:
                from bugtrace.schemas.models import normalize_vuln_type
                normalized_type = normalize_vuln_type(str(raw_type)).value
            except Exception:
                normalized_type = str(raw_type).upper().strip()

            collection = "findings_embeddings"
            finding_url = finding.get("url", "")
            finding_param = finding.get("parameter", "")

            # L4: Dedup — check if (url, parameter, type) already exists
            try:
                if collection in self.vector_db.table_names():
                    tbl = self.vector_db.open_table(collection)
                    safe_url = finding_url.replace("'", "''")
                    safe_param = finding_param.replace("'", "''")
                    safe_type = normalized_type.replace("'", "''")
                    existing = tbl.search().where(
                        f"url = '{safe_url}' AND parameter = '{safe_param}' AND type = '{safe_type}'"
                    ).limit(1).to_list()
                    if existing:
                        logger.debug(f"Dedup: finding already in LanceDB ({normalized_type} on {finding_param})")
                        return
            except Exception as dedup_err:
                logger.debug(f"Dedup check skipped: {dedup_err}")

            data = [{
                "finding_id": finding.get("id", "unknown"),
                "type": normalized_type,
                "url": finding_url,
                "parameter": finding_param,
                "payload": str(finding.get("payload", ""))[:200],
                "severity": finding.get("severity", ""),
                "confidence": float(finding.get("confidence_score", finding.get("confidence", 0.0))),
                "vector": embedding,
                "timestamp": datetime.now().isoformat()
            }]
            self.add_vector_embedding(collection, data)
            logger.debug(f"Stored embedding for finding: {normalized_type}")
        except Exception as e:
            logger.error(f"Failed to store finding embedding: {e}", exc_info=True)
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
            logger.error(f"SQL health check failed: {e}", exc_info=True)

        # Check LanceDB
        if self.vector_db:
            try:
                _ = self.vector_db.table_names()
                result["vector_db"] = {"status": "healthy"}
            except Exception as e:
                result["vector_db"] = {"status": "unhealthy", "error": str(e)}
                logger.error(f"Vector DB health check failed: {e}", exc_info=True)
        else:
            result["vector_db"] = {"status": "disabled"}

        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)

        # Overall status — healthy if SQL works (vector_db is optional)
        if result["sql_db"]["status"] == "healthy" and result["vector_db"]["status"] in ("healthy", "disabled"):
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
                metrics["tables"]["targets"] = session.exec(select(func.count()).select_from(TargetTable)).one()
                metrics["tables"]["scans"] = session.exec(select(func.count()).select_from(ScanTable)).one()
                metrics["tables"]["findings"] = session.exec(select(func.count()).select_from(FindingTable)).one()
        except Exception as e:
            logger.warning(f"Failed to get table metrics: {e}")
            metrics["tables"]["error"] = str(e)

        # Vector DB collections
        if self.vector_db:
            try:
                metrics["vector_collections"] = self.vector_db.table_names()
            except Exception as e:
                logger.warning(f"Failed to get vector DB metrics: {e}")
                metrics["vector_collections_error"] = str(e)
        else:
            metrics["vector_collections"] = "disabled"

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
        try:
            with dest:
                source.backup(dest)
        finally:
            source.close()
            dest.close()
        return os.path.getsize(backup_path)
    def backup_database(self, backup_dir: Optional[str] = None) -> Dict:
        """Create a backup of the SQLite database and LanceDB knowledge store."""
        result = {
            "status": "failed",
            "path": None,
            "size_bytes": 0,
            "lancedb_backup": None,
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

            # L6: Also backup LanceDB directory
            try:
                import shutil
                lancedb_src = self.vector_db_path
                if os.path.isdir(lancedb_src):
                    lancedb_backup_path = backup_path.replace(".db", "_lancedb")
                    shutil.copytree(lancedb_src, lancedb_backup_path, dirs_exist_ok=True)
                    result["lancedb_backup"] = lancedb_backup_path
                    logger.info(f"LanceDB backup created: {lancedb_backup_path}")
            except Exception as lance_err:
                logger.warning(f"LanceDB backup failed (SQLite backup OK): {lance_err}")

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Database backup failed: {e}", exc_info=True)

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
