"""
Adaptive Payload Batching System.

Organizes payloads into context-specific batches for progressive escalation.
"""

from dataclasses import dataclass
from typing import List, Optional, Set
from enum import Enum
from bugtrace.utils.logger import get_logger

logger = get_logger("payload_batches")

class EscalationReason(Enum):
    SUCCESS = "success"
    NO_REFLECTION = "no_reflection"
    WAF_DETECTED = "waf_detected"
    TAG_BLOCKED = "tag_blocked"
    JS_CONTEXT = "js_context"
    CLEAN_REFLECTION = "clean_reflection"


@dataclass
class ProbeResult:
    """Result of probing a parameter."""
    reflected: bool
    surviving_chars: str  # e.g., "<>\"'" or "" if none
    waf_detected: bool
    waf_name: Optional[str]
    context: str  # "attribute", "tag", "script", "unknown"
    status_code: int


class PayloadBatcher:
    """
    Manages adaptive payload batching based on probe results.
    """
    
    BATCH_SIZE = 50
    
    def __init__(self):
        self.batches = {
            "universal": self._load_batch("universal"),
            "waf_bypass": self._load_batch("waf_bypass"),
            "no_tag": self._load_batch("no_tag"),
            "js_context": self._load_batch("js_context"),
            "polyglots": self._load_batch("polyglots"),
        }
    
    def _load_batch(self, batch_name: str) -> List[str]:
        """Load payloads from data/xss_batches/{batch_name}.txt"""
        from pathlib import Path
        batch_file = Path(f"bugtrace/data/xss_batches/{batch_name}.txt")
        if batch_file.exists():
            return [line.strip() for line in batch_file.read_text().splitlines() if line.strip()]
        logger.warning(f"Batch file not found: {batch_file}")
        return []
    
    def get_initial_batch(self) -> List[str]:
        """Get first batch (universal payloads)."""
        return self.batches.get("universal", [])[:self.BATCH_SIZE]
    
    def decide_escalation(self, probe_result: ProbeResult, tried_batches: Set[str]) -> Optional[str]:
        """
        Decide which batch to try next based on probe results.
        
        Returns batch name or None if should stop.
        """
        if not probe_result.reflected:
            return None  # Stop - completely hardened
        
        # Priority 1: WAF Bypass if detected
        if probe_result.waf_detected and "waf_bypass" not in tried_batches:
            return "waf_bypass"
        
        # Priority 2: Context-specific breakouts
        if probe_result.context == "script" and "js_context" not in tried_batches:
            return "js_context"
            
        # Priority 3: Filter evasion
        if ("<" not in probe_result.surviving_chars and ">" not in probe_result.surviving_chars) and "no_tag" not in tried_batches:
            return "no_tag"
        
        # Priority 4: Last resort polyglots (if clean reflection but no success yet)
        if "polyglots" not in tried_batches:
            return "polyglots"
            
        return None
    
    def get_batch(self, batch_name: str) -> List[str]:
        """Get specific batch by name."""
        return self.batches.get(batch_name, [])[:self.BATCH_SIZE]


# Singleton
payload_batcher = PayloadBatcher()
