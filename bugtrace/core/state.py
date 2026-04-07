import json
import os
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
from bugtrace.utils.logger import get_logger
logger = get_logger("core.state")
from bugtrace.core.config import settings

import threading

_state_lock = threading.Lock()

class StateManager:
    def __init__(self, target_hash: str):
        self.state_file = settings.LOG_DIR / f"state_{target_hash}.json"
        
    def clear(self):
        """Wipes the previous state file."""
        if self.state_file.exists():
            logger.info(f"Clearing previous state: {self.state_file}")
            os.remove(self.state_file)
        else:
            logger.debug("No previous state to clear.")
            
    def load(self) -> Dict[str, Any]:
        """Loads state if exists, else returns empty dict."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load state: {e}", exc_info=True)
        return {}
        
    def save(self, data: Dict[str, Any]):
        """Persists state to disk."""
        # Ensure log dir exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.state_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}", exc_info=True)

    def add_finding(self, url: str, type: str, description: str, severity: str, parameter: str = None, payload: str = None, validated: bool = False, evidence: str = None, screenshot_path: str = None):
        """Adds a finding to the ephemeral state."""
        with _state_lock:
            state = self.load()
            if "findings" not in state:
                state["findings"] = []
            
            state["findings"].append({
                "url": url,
                "type": type,
                "description": description,
                "severity": severity,
                "parameter": parameter,
                "payload": payload,
                "validated": validated,
                "evidence": evidence,
                "screenshot_path": screenshot_path,
                "timestamp": datetime.now().isoformat()
            })
            self.save(state)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Returns all findings from state."""
        return self.load().get("findings", [])

# Factory
def get_state_manager(target: str) -> StateManager:
    # simple hash of target for filename
    import hashlib
    target_hash = hashlib.md5(target.encode()).hexdigest()
    return StateManager(target_hash)
