import json
import os
import threading
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("core.state")

# Module-level lock for thread-safe finding operations
_finding_lock = threading.Lock()


class StateManager:
    """
    Manages application state using JSON persistence.
    Replaces the broken Git-based implementation.
    """
    
    
    def __init__(self, target: str, scan_id: Optional[int] = None):
        self.target = target
        self.scan_id = scan_id
        self.scan_dir: Optional[Path] = None  # V3.2: For file-based findings
        from bugtrace.core.database import get_db_manager
        self.db = get_db_manager()

        # Legacy File Fallback
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        self.state_file = settings.LOG_DIR / f"state_{safe_target}.json"
        self._ensure_log_dir()
        
    def _ensure_log_dir(self):
        if not settings.LOG_DIR.exists():
            settings.LOG_DIR.mkdir(parents=True, exist_ok=True)

    def set_scan_id(self, scan_id: int):
        """Update scan ID after initialization."""
        self.scan_id = scan_id

    def set_scan_dir(self, scan_dir: Path):
        """Set the scan directory for file-based findings (V3.2 architecture)."""
        self.scan_dir = scan_dir
        logger.debug(f"StateManager scan_dir set to: {scan_dir}")

    def save_state(self, state_data: Dict[str, Any]):
        """Saves current state to DB (preferred) or File (fallback)."""
        if self.scan_id:
            try:
                # Serialize JSON
                json_data = json.dumps(state_data)
                self.db.save_checkpoint(self.scan_id, json_data)
                logger.debug(f"State saved to DB for scan {self.scan_id}")
                return
            except Exception as e:
                logger.error(f"Failed to save state to DB: {e}, falling back to file.", exc_info=True)
        
        # Fallback to file
        try:
            wrapper = {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "data": state_data
            }
            with open(self.state_file, 'w') as f:
                json.dump(wrapper, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state to file: {e}", exc_info=True)

    def add_finding(self, **finding_dict):
        """
        DEPRECATED: No longer saves to DB.

        V3.2 Architecture: Files are the source of truth for findings.
        - Findings are written to specialists/wet/*.json by thinking_consolidation_agent
        - API reads findings from files via scan_service.get_findings()
        - DB is only for scan progress tracking, not findings storage

        This method now only logs for backward compatibility with legacy agent calls.
        """
        with _finding_lock:
            try:
                # Validate payload format for logging purposes
                from bugtrace.utils.validation import validate_payload_format
                is_valid, error_msg = validate_payload_format(finding_dict)

                if not is_valid:
                    logger.warning(f"Finding validation failed: {error_msg}")
                    return

                # V3.2: Log only, no DB save. Files are source of truth.
                vuln_type = finding_dict.get("type", "Unknown")
                param = finding_dict.get("parameter", "N/A")
                logger.debug(
                    f"Finding registered (files are source of truth): "
                    f"type={vuln_type}, param={param}"
                )
            except Exception as e:
                logger.error(f"Failed to process finding: {e}", exc_info=True)

    def load_state(self) -> Dict[str, Any]:
        """Loads state from DB (preferred) or File."""
        if self.scan_id:
            try:
                state_json = self.db.get_checkpoint(self.scan_id)
                if state_json:
                    logger.info(f"Loaded active state from DB for scan {self.scan_id}")
                    return json.loads(state_json)
            except Exception as e:
                logger.error(f"Failed to load state from DB: {e}", exc_info=True)
        
        # Fallback to file
        if not self.state_file.exists():
            return {}
            
        try:
            with open(self.state_file, 'r') as f:
                content = json.load(f)
                return content.get("data", {})
        except Exception as e:
            logger.error(f"Failed to load state: {e}", exc_info=True)
            return {}

    def clear(self):
        """Clears state for a fresh run."""
        if self.scan_id:
            try:
                # Optionally clear the checkpoint in DB if we want a TRULY fresh start
                self.db.save_checkpoint(self.scan_id, "")
                logger.debug(f"State cleared for scan {self.scan_id}")
            except Exception as e:
                logger.error(f"Failed to clear state: {e}", exc_info=True)

    def snapshot(self, filename: str, message: str):
        """Legacy compatibility wrapper - logs a snapshot event but doesn't use Git."""
        logger.debug(f"Snapshot requested ({filename}): {message}")
        # In the future, we could copy files to a snapshot dir if needed
        pass

    def get_findings(self) -> list:
        """
        Retrieves all finding objects for the current scan.

        V3.2: Reads from FILES (source of truth) instead of database.
        Files: specialists/wet/*.json, specialists/dry/*.json, specialists/results/*.json

        IMPORTANT: Merges findings from ALL stages to avoid race conditions.
        Real-time reports need to see both validated (results) and in-progress (wet/dry) findings.
        The _source field indicates which stage each finding is from.
        """
        if not self.scan_dir:
            logger.warning("StateManager.get_findings() called without scan_dir set")
            return []

        try:
            from bugtrace.core.payload_format import decode_finding_payloads

            specialists_dir = self.scan_dir / "specialists"
            if not specialists_dir.exists():
                logger.debug(f"No specialists dir in {self.scan_dir}")
                return []

            results = []
            seen_keys = set()  # Deduplication: (url, parameter, type, payload)

            # Merge findings from ALL stages (no break - race condition fix)
            # Order: results first (highest priority status), then dry, then wet
            for subdir in ["results", "dry", "wet"]:
                subdir_path = specialists_dir / subdir
                if not subdir_path.exists():
                    continue

                for json_file in subdir_path.glob("*.json"):
                    try:
                        findings = self._read_findings_file(json_file, subdir)
                        for finding in findings:
                            # Decode base64 payloads if present
                            finding = decode_finding_payloads(finding)

                            # Deduplicate: skip if same finding already seen from higher-priority dir
                            dedup_key = (
                                finding.get("url", ""),
                                finding.get("parameter", ""),
                                finding.get("type", ""),
                                finding.get("payload", "")
                            )
                            if dedup_key in seen_keys:
                                continue
                            seen_keys.add(dedup_key)

                            results.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to read {json_file}: {e}")

            logger.debug(f"StateManager loaded {len(results)} findings from files (merged all stages)")
            return results

        except Exception as e:
            logger.error(f"StateManager failed to retrieve findings: {e}", exc_info=True)
            return []

    def _read_findings_file(self, file_path: Path, source_dir: str) -> list:
        """
        Read findings from a JSON or JSON Lines file.

        Robust parsing:
        - JSON Lines: Recovers valid lines, skips corrupted ones
        - JSON Array: Logs warning if corrupted, doesn't crash
        """
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8").strip()
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            return []

        if not content:
            return []

        # Try JSON Lines first (one object per line)
        if content.startswith("{"):
            lines = content.split("\n")
            valid_count = 0
            corrupt_count = 0

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Handle v3.2 format with nested "finding" key
                    if "finding" in entry:
                        finding = entry["finding"]
                    else:
                        finding = entry

                    # Normalize to standard format
                    normalized = {
                        "type": finding.get("type", "Unknown"),
                        "url": finding.get("url", ""),
                        "parameter": finding.get("parameter", ""),
                        "payload": finding.get("payload", ""),
                        "evidence": finding.get("evidence") or finding.get("description", ""),
                        "severity": finding.get("severity", "HIGH"),
                        "status": finding.get("status", "PENDING_VALIDATION"),
                        "screenshot": finding.get("screenshot"),
                        "_source": source_dir,
                    }
                    findings.append(normalized)
                    valid_count += 1
                except json.JSONDecodeError:
                    corrupt_count += 1
                    continue

            # Log if any lines were corrupted (partial write, crash, etc.)
            if corrupt_count > 0:
                logger.warning(
                    f"File {file_path.name}: recovered {valid_count} findings, "
                    f"skipped {corrupt_count} corrupted lines"
                )

        # Try JSON Array
        elif content.startswith("["):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for finding in data:
                        normalized = {
                            "type": finding.get("type", "Unknown"),
                            "url": finding.get("url", ""),
                            "parameter": finding.get("parameter", ""),
                            "payload": finding.get("payload", ""),
                            "evidence": finding.get("evidence") or finding.get("description", ""),
                            "severity": finding.get("severity", "HIGH"),
                            "status": finding.get("status", "PENDING_VALIDATION"),
                            "screenshot": finding.get("screenshot"),
                            "_source": source_dir,
                        }
                        findings.append(normalized)
            except json.JSONDecodeError as e:
                # JSON arrays are atomic - can't recover partial arrays
                logger.warning(
                    f"File {file_path.name}: JSON array corrupted, cannot recover. "
                    f"Error: {e}. Consider using JSON Lines format for crash resilience."
                )

        return findings

def get_state_manager(target: str) -> StateManager:
    return StateManager(target)
