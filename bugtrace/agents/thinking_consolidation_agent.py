"""
ThinkingConsolidationAgent - Evaluation phase coordinator for v2.3 Pipeline.

Responsibilities:
1. Subscribe to url_analyzed events from Discovery phase
2. Deduplicate findings using vuln_type:parameter:url_path keys
3. Classify findings by vulnerability type
4. Prioritize by exploitation probability
5. Distribute to specialist queues
6. Support batch and streaming processing modes

Author: BugtraceAI Team
Date: 2026-01-29
Version: 1.0.0
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Set
from collections import OrderedDict
from dataclasses import dataclass, field
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.queue import queue_manager, SPECIALIST_QUEUES
from bugtrace.core.config import settings


# Vulnerability type to specialist queue mapping
# Maps finding['type'] values to SPECIALIST_QUEUES names
VULN_TYPE_TO_SPECIALIST: Dict[str, str] = {
    # XSS variants
    "xss": "xss",
    "cross-site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "dom-based xss": "xss",

    # SQL Injection variants
    "sql injection": "sqli",
    "sqli": "sqli",
    "sql": "sqli",
    "blind sql injection": "sqli",
    "boolean-based sqli": "sqli",
    "time-based sqli": "sqli",
    "error-based sqli": "sqli",

    # Template injection
    "ssti": "csti",
    "csti": "csti",
    "server-side template injection": "csti",
    "client-side template injection": "csti",
    "template injection": "csti",

    # File inclusion
    "lfi": "lfi",
    "local file inclusion": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "file read": "lfi",

    # Access control
    "idor": "idor",
    "insecure direct object reference": "idor",
    "broken access control": "idor",
    "authorization bypass": "idor",
    "privilege escalation": "idor",

    # Remote code execution
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "os command injection": "rce",
    "code injection": "rce",
    "deserialization": "rce",

    # Server-side request forgery
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "url injection": "ssrf",

    # XML vulnerabilities
    "xxe": "xxe",
    "xml external entity": "xxe",
    "xml injection": "xxe",

    # JWT vulnerabilities
    "jwt": "jwt",
    "jwt vulnerability": "jwt",
    "jwt bypass": "jwt",
    "jwt manipulation": "jwt",
    "authentication bypass": "jwt",

    # Open redirect
    "open redirect": "openredirect",
    "openredirect": "openredirect",
    "url redirect": "openredirect",
    "redirect": "openredirect",

    # Prototype pollution
    "prototype pollution": "prototype_pollution",
    "prototype_pollution": "prototype_pollution",
    "__proto__ pollution": "prototype_pollution",

    # Header injection (maps to XSS specialist as similar validation)
    "header injection": "xss",
    "crlf injection": "xss",
    "http response splitting": "xss",
}


# Severity to base priority score mapping
SEVERITY_PRIORITY: Dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "information": 10,
}


@dataclass
class FindingRecord:
    """Record of a finding for deduplication and processing."""
    key: str  # vuln_type:parameter:url_path
    finding: Dict[str, Any]
    received_at: float = field(default_factory=time.monotonic)
    scan_context: str = ""
    processed: bool = False


class DeduplicationCache:
    """
    LRU cache for finding deduplication.

    Tracks seen findings using vuln_type:parameter:url_path keys.
    Evicts oldest entries when max_size is reached.
    """

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: OrderedDict[str, FindingRecord] = OrderedDict()
        self._lock = asyncio.Lock()

    def _make_key(self, finding: Dict[str, Any]) -> str:
        """
        Create deduplication key from finding.

        Format: vuln_type:parameter:url_path

        Example: "XSS:id:/api/users"
        """
        vuln_type = finding.get("type", "Unknown").lower()
        parameter = finding.get("parameter", "unknown").lower()
        url = finding.get("url", "")

        # Extract path from URL (remove protocol and domain)
        url_path = url
        if "://" in url:
            parts = url.split("/", 3)
            url_path = "/" + parts[3] if len(parts) > 3 else "/"

        # Normalize: remove query params for dedup purposes
        if "?" in url_path:
            url_path = url_path.split("?")[0]

        return f"{vuln_type}:{parameter}:{url_path}"

    async def check_and_add(self, finding: Dict[str, Any], scan_context: str) -> tuple[bool, str]:
        """
        Check if finding is duplicate and add if not.

        Args:
            finding: Finding dict from url_analyzed event
            scan_context: Scan context for tracking

        Returns:
            (is_duplicate, key): Tuple of duplicate status and the key
        """
        key = self._make_key(finding)

        async with self._lock:
            if key in self._cache:
                # Move to end (most recently seen)
                self._cache.move_to_end(key)
                logger.debug(f"[ThinkingAgent] Duplicate: {key}")
                return (True, key)

            # Add new entry
            record = FindingRecord(
                key=key,
                finding=finding.copy(),
                scan_context=scan_context
            )
            self._cache[key] = record

            # Evict oldest if over limit
            while len(self._cache) > self.max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                logger.debug(f"[ThinkingAgent] Evicted oldest: {oldest_key}")

            return (False, key)

    def clear(self) -> None:
        """Clear the deduplication cache."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current cache size."""
        return len(self._cache)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "fill_ratio": len(self._cache) / self.max_size if self.max_size > 0 else 0
        }


class ThinkingConsolidationAgent(BaseAgent):
    """
    Evaluation phase coordinator for the v2.3 5-phase pipeline.

    Subscribes to url_analyzed events, deduplicates findings,
    classifies by vulnerability type, prioritizes, and distributes
    to specialist queues.
    """

    def __init__(self, scan_context: str = None):
        super().__init__(
            name="ThinkingConsolidationAgent",
            role="Evaluation Coordinator",
            agent_id="thinking_consolidation_agent"
        )

        self.scan_context = scan_context or f"thinking_{id(self)}"

        # Deduplication cache
        self._dedup_cache = DeduplicationCache(
            max_size=settings.THINKING_DEDUP_WINDOW
        )

        # Processing mode
        self._mode = settings.THINKING_MODE  # "streaming" or "batch"

        # Batch processing buffer (used in batch mode)
        self._batch_buffer: List[Dict[str, Any]] = []
        self._batch_lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None

        # Statistics
        self._stats = {
            "total_received": 0,
            "duplicates_filtered": 0,
            "fp_filtered": 0,
            "distributed": 0,
            "by_specialist": {}
        }

        logger.info(f"[{self.name}] Initialized in {self._mode} mode")

    def _setup_event_subscriptions(self):
        """Subscribe to url_analyzed events from Discovery phase."""
        self.event_bus.subscribe(EventType.URL_ANALYZED.value, self._handle_url_analyzed)
        logger.info(f"[{self.name}] Subscribed to {EventType.URL_ANALYZED.value}")

    def _cleanup_event_subscriptions(self):
        """Unsubscribe from events on shutdown."""
        self.event_bus.unsubscribe(EventType.URL_ANALYZED.value, self._handle_url_analyzed)
        logger.info(f"[{self.name}] Unsubscribed from events")

    async def _handle_url_analyzed(self, data: Dict[str, Any]) -> None:
        """
        Handle url_analyzed event from DASTySASTAgent.

        Event payload:
        - url: The analyzed URL
        - scan_context: Context for ordering
        - findings: List of findings with fp_confidence
        - stats: Summary statistics
        """
        url = data.get("url", "unknown")
        scan_context = data.get("scan_context", self.scan_context)
        findings = data.get("findings", [])

        logger.info(f"[{self.name}] Received url_analyzed: {len(findings)} findings for {url[:50]}")

        self._stats["total_received"] += len(findings)

        # Process each finding
        for finding in findings:
            await self._process_finding(finding, scan_context)

    async def _process_finding(self, finding: Dict[str, Any], scan_context: str) -> None:
        """
        Process a single finding through deduplication.

        Steps:
        1. Check fp_confidence threshold
        2. Check deduplication cache
        3. Forward to classification/prioritization (Plan 02)
        """
        # 1. FP confidence filter
        fp_confidence = finding.get("fp_confidence", 0.5)
        if fp_confidence < settings.THINKING_FP_THRESHOLD:
            logger.debug(f"[{self.name}] FP filtered: {finding.get('type')} "
                        f"(fp_confidence: {fp_confidence:.2f} < {settings.THINKING_FP_THRESHOLD})")
            self._stats["fp_filtered"] += 1
            return

        # 2. Deduplication check
        is_duplicate, key = await self._dedup_cache.check_and_add(finding, scan_context)
        if is_duplicate:
            self._stats["duplicates_filtered"] += 1
            return

        # 3. Forward for classification (implemented in Plan 02)
        # For now, just log that we would process it
        logger.debug(f"[{self.name}] New finding: {key} (fp: {fp_confidence:.2f})")

        # Placeholder for Plan 02 - will call classify/prioritize
        # await self._classify_and_prioritize(finding, scan_context)

    async def run_loop(self):
        """Main agent loop - manages batch processing if in batch mode."""
        if self._mode == "batch":
            # Start batch processor
            self._batch_task = asyncio.create_task(self._batch_processor())
            logger.info(f"[{self.name}] Started batch processor")

        # Keep running until stopped
        while self.running:
            await asyncio.sleep(1.0)
            await self.check_pause()

        # Cleanup
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass

    async def _batch_processor(self):
        """
        Background task for batch mode processing.
        Collects findings and processes in batches.
        """
        while self.running:
            try:
                await asyncio.sleep(settings.THINKING_BATCH_TIMEOUT)

                async with self._batch_lock:
                    if self._batch_buffer:
                        batch = self._batch_buffer[:settings.THINKING_BATCH_SIZE]
                        self._batch_buffer = self._batch_buffer[settings.THINKING_BATCH_SIZE:]

                        logger.info(f"[{self.name}] Processing batch of {len(batch)} findings")
                        # Process batch (implemented in Plan 02/03)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[{self.name}] Batch processor error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            **self._stats,
            "dedup_cache": self._dedup_cache.get_stats(),
            "mode": self._mode
        }

    def reset_stats(self) -> None:
        """Reset statistics (for testing)."""
        self._stats = {
            "total_received": 0,
            "duplicates_filtered": 0,
            "fp_filtered": 0,
            "distributed": 0,
            "by_specialist": {}
        }
        self._dedup_cache.clear()


# Module exports
__all__ = ["ThinkingConsolidationAgent", "DeduplicationCache", "FindingRecord"]
