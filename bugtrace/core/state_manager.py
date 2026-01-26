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
                logger.error(f"Failed to save state to DB: {e}, falling back to file.")
        
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
            logger.error(f"Failed to save state to file: {e}")

    def add_finding(self, **finding_dict):
        """Proxy to save_scan_result to support legacy agent calls while using V3 DB.

        Thread-safe: Uses module-level lock to prevent concurrent write corruption.
        """
        with _finding_lock:
            try:
                # --- V3.5 REACTOR: PRE-FLIGHT VALIDATION ---
                from bugtrace.utils.validation import validate_payload_format
                is_valid, error_msg = validate_payload_format(finding_dict)

                if not is_valid:
                    logger.warning(f"Finding rejected by StateManager: {error_msg}")
                    # We return without saving to DB
                    return

                # Wrap single finding as a list for the DB manager
                self.db.save_scan_result(self.target, [finding_dict], scan_id=self.scan_id)
                logger.debug(f"Finding persisted to DB (PENDING_VALIDATION) via proxy.")
            except Exception as e:
                logger.error(f"Failed to proxy finding to DB: {e}")

    def load_state(self) -> Dict[str, Any]:
        """Loads state from DB (preferred) or File."""
        if self.scan_id:
            try:
                state_json = self.db.get_checkpoint(self.scan_id)
                if state_json:
                    logger.info(f"Loaded active state from DB for scan {self.scan_id}")
                    return json.loads(state_json)
            except Exception as e:
                logger.error(f"Failed to load state from DB: {e}")
        
        # Fallback to file
        if not self.state_file.exists():
            return {}
            
        try:
            with open(self.state_file, 'r') as f:
                content = json.load(f)
                return content.get("data", {})
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return {}

    def clear(self):
        """Clears state for a fresh run."""
        if self.scan_id:
            try:
                # Optionally clear the checkpoint in DB if we want a TRULY fresh start
                self.db.save_checkpoint(self.scan_id, "")
                logger.debug(f"State cleared for scan {self.scan_id}")
            except Exception as e:
                logger.error(f"Failed to clear state: {e}")

    def snapshot(self, filename: str, message: str):
        """Legacy compatibility wrapper - logs a snapshot event but doesn't use Git."""
        logger.debug(f"Snapshot requested ({filename}): {message}")
        # In the future, we could copy files to a snapshot dir if needed
        pass

    def get_findings(self) -> list:
        """Retrieves all finding objects for the current scan from DB."""
        if not self.scan_id:
            return []
        
        try:
            db_findings = self.db.get_findings_for_scan(self.scan_id)
            # Convert SQLAlchemy models to simple dictionaries for agents
            results = []
            for f in db_findings:
                results.append({
                    "type": str(f.type.value if hasattr(f.type, 'value') else f.type), # Handle Enum
                    "url": f.attack_url,
                    "parameter": f.vuln_parameter,
                    "payload": f.payload_used,
                    "evidence": f.details,
                    "severity": f.severity,
                    "status": f.status,
                    "screenshot": f.proof_screenshot_path
                })
            return results
        except Exception as e:
            logger.error(f"StateManager failed to retrieve findings: {e}")
            return []

def get_state_manager(target: str) -> StateManager:
    return StateManager(target)
