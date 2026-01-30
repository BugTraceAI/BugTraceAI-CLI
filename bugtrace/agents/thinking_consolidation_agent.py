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
from bugtrace.core.dedup_metrics import dedup_metrics, get_dedup_summary


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

    # Header injection / CRLF (has dedicated specialist now)
    "header injection": "header_injection",
    "crlf": "header_injection",
    "crlf injection": "header_injection",
    "http response header injection": "header_injection",
    "response splitting": "header_injection",
    "http header injection": "header_injection",
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


@dataclass
class PrioritizedFinding:
    """Finding with classification and priority for queue distribution."""
    finding: Dict[str, Any]
    specialist: str  # Queue name (e.g., "xss", "sqli")
    priority: float  # 0-100, higher = more urgent
    scan_context: str
    classified_at: float = field(default_factory=time.monotonic)

    @property
    def queue_payload(self) -> Dict[str, Any]:
        """Prepare payload for specialist queue."""
        return {
            "finding": self.finding,
            "priority": self.priority,
            "scan_context": self.scan_context,
            "classified_at": self.classified_at,
        }


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
        # Log deduplication summary on shutdown
        dedup_metrics.log_summary()
        logger.info(f"[{self.name}] Unsubscribed from events")

    async def _handle_url_analyzed(self, data: Dict[str, Any]) -> None:
        """
        Handle url_analyzed event from DASTySASTAgent.

        Processing depends on THINKING_MODE:
        - streaming: Process each finding immediately
        - batch: Buffer findings, process when batch is full or timeout

        Event payload:
        - url: The analyzed URL
        - scan_context: Context for ordering
        - findings: List of findings with fp_confidence
        - stats: Summary statistics
        """
        url = data.get("url", "unknown")
        scan_context = data.get("scan_context", self.scan_context)
        findings = data.get("findings", [])

        logger.info(f"[{self.name}] Processing batch: {len(findings)} findings from {url[:50]}")

        self._stats["total_received"] += len(findings)

        if self._mode == "streaming":
            # Process each finding immediately
            for finding in findings:
                await self._process_finding(finding, scan_context)
        else:
            # Batch mode: buffer findings for batch processing
            async with self._batch_lock:
                for finding in findings:
                    # Add scan_context to finding for batch processing
                    finding_with_context = finding.copy()
                    finding_with_context["_scan_context"] = scan_context
                    self._batch_buffer.append(finding_with_context)

                # Check if batch is full
                if len(self._batch_buffer) >= settings.THINKING_BATCH_SIZE:
                    await self._process_batch()

    def _classify_finding(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Classify finding to determine target specialist queue.

        Args:
            finding: Finding dict with 'type' field

        Returns:
            Specialist queue name (e.g., "xss") or None if unclassifiable
        """
        vuln_type = finding.get("type", "").lower().strip()

        # Direct match
        if vuln_type in VULN_TYPE_TO_SPECIALIST:
            return VULN_TYPE_TO_SPECIALIST[vuln_type]

        # Partial match (for compound types like "Reflected XSS in parameter")
        for pattern, specialist in VULN_TYPE_TO_SPECIALIST.items():
            if pattern in vuln_type:
                return specialist

        # Unknown type
        logger.warning(f"[{self.name}] Unknown vulnerability type: {vuln_type}")
        return None

    def _calculate_priority(self, finding: Dict[str, Any]) -> float:
        """
        Calculate exploitation probability priority score.

        Priority Formula:
        priority = (severity_base * 0.4) + (fp_confidence * 100 * 0.35) + (skeptical_score * 10 * 0.25)

        Components:
        - Severity base (40%): Critical=100, High=75, Medium=50, Low=25
        - FP confidence (35%): 0.0-1.0 scaled to 0-100
        - Skeptical score (25%): 0-10 scaled to 0-100

        Returns:
            Priority score 0-100 (higher = more likely to be exploitable)
        """
        # Get severity base score
        severity = finding.get("severity", "medium").lower()
        severity_base = SEVERITY_PRIORITY.get(severity, 50)

        # Get FP confidence (0.0-1.0)
        fp_confidence = finding.get("fp_confidence", 0.5)

        # Get skeptical score (0-10)
        skeptical_score = finding.get("skeptical_score", 5)

        # Calculate weighted priority
        priority = (
            (severity_base * 0.40) +           # Severity: 40% weight
            (fp_confidence * 100 * 0.35) +     # FP confidence: 35% weight
            (skeptical_score * 10 * 0.25)      # Skeptical score: 25% weight
        )

        # Boost for validated findings
        if finding.get("validated", False):
            priority = min(100, priority * 1.2)

        # Boost for high vote count (multiple approaches agreed)
        votes = finding.get("votes", 1)
        if votes >= 4:
            priority = min(100, priority * 1.1)

        return round(priority, 2)

    async def _classify_and_prioritize(
        self, finding: Dict[str, Any], scan_context: str
    ) -> Optional[PrioritizedFinding]:
        """
        Classify finding and calculate priority for queue distribution.

        Args:
            finding: Finding dict from url_analyzed event
            scan_context: Scan context for tracking

        Returns:
            PrioritizedFinding ready for queue, or None if unclassifiable
        """
        # Classify to get specialist
        specialist = self._classify_finding(finding)
        if not specialist:
            logger.debug(f"[{self.name}] Unclassifiable: {finding.get('type')}")
            return None

        # Calculate priority
        priority = self._calculate_priority(finding)

        # Create prioritized finding
        prioritized = PrioritizedFinding(
            finding=finding,
            specialist=specialist,
            priority=priority,
            scan_context=scan_context
        )

        logger.debug(
            f"[{self.name}] Classified: {finding.get('type')} -> {specialist} "
            f"(priority: {priority:.1f})"
        )

        return prioritized

    async def _distribute_to_queue(self, prioritized: PrioritizedFinding) -> bool:
        """
        Distribute a prioritized finding to the appropriate specialist queue.

        Handles backpressure by retrying with exponential backoff.

        Args:
            prioritized: PrioritizedFinding with specialist and priority

        Returns:
            True if successfully queued, False if queue full after retries
        """
        specialist = prioritized.specialist
        queue = queue_manager.get_queue(specialist)

        # Prepare queue payload
        payload = prioritized.queue_payload

        # Try to enqueue with backpressure handling
        for attempt in range(settings.THINKING_BACKPRESSURE_RETRIES):
            success = await queue.enqueue(payload, prioritized.scan_context)

            if success:
                self._stats["distributed"] += 1
                self._stats["by_specialist"][specialist] = \
                    self._stats["by_specialist"].get(specialist, 0) + 1

                logger.debug(
                    f"[{self.name}] Queued: {prioritized.finding.get('type')} -> "
                    f"{specialist} (priority: {prioritized.priority:.1f})"
                )
                return True

            # Backpressure - wait and retry
            delay = settings.THINKING_BACKPRESSURE_DELAY * (2 ** attempt)
            logger.warning(
                f"[{self.name}] Queue {specialist} full, retry {attempt + 1}/"
                f"{settings.THINKING_BACKPRESSURE_RETRIES} in {delay:.1f}s"
            )
            await asyncio.sleep(delay)

        # Failed after all retries
        self._stats.setdefault("backpressure_drops", 0)
        self._stats["backpressure_drops"] += 1
        logger.error(
            f"[{self.name}] Dropped finding: {prioritized.finding.get('type')} -> "
            f"{specialist} (queue full after {settings.THINKING_BACKPRESSURE_RETRIES} retries)"
        )
        return False

    async def _emit_work_queued_event(self, prioritized: PrioritizedFinding) -> None:
        """
        Emit work_queued_{specialist} event for downstream coordination.

        Event types are from EventType enum:
        - WORK_QUEUED_XSS, WORK_QUEUED_SQLI, etc.

        Args:
            prioritized: The distributed finding
        """
        if not settings.THINKING_EMIT_EVENTS:
            return

        # Map specialist to EventType
        specialist_to_event = {
            "xss": EventType.WORK_QUEUED_XSS,
            "sqli": EventType.WORK_QUEUED_SQLI,
            "csti": EventType.WORK_QUEUED_CSTI,
            "lfi": EventType.WORK_QUEUED_LFI,
            "idor": EventType.WORK_QUEUED_IDOR,
            "rce": EventType.WORK_QUEUED_RCE,
            "ssrf": EventType.WORK_QUEUED_SSRF,
            "xxe": EventType.WORK_QUEUED_XXE,
            "jwt": EventType.WORK_QUEUED_JWT,
            "openredirect": EventType.WORK_QUEUED_OPENREDIRECT,
            "prototype_pollution": EventType.WORK_QUEUED_PROTOTYPE_POLLUTION,
            "header_injection": EventType.WORK_QUEUED_HEADER_INJECTION,
        }

        event_type = specialist_to_event.get(prioritized.specialist)
        if not event_type:
            logger.warning(f"[{self.name}] No event type for specialist: {prioritized.specialist}")
            return

        event_data = {
            "specialist": prioritized.specialist,
            "finding": {
                "type": prioritized.finding.get("type"),
                "parameter": prioritized.finding.get("parameter"),
                "url": prioritized.finding.get("url"),
                "severity": prioritized.finding.get("severity"),
                "fp_confidence": prioritized.finding.get("fp_confidence"),
            },
            "priority": prioritized.priority,
            "scan_context": prioritized.scan_context,
            "timestamp": time.time(),
        }

        try:
            await self.event_bus.emit(event_type, event_data)
            logger.debug(f"[{self.name}] Emitted {event_type.value}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to emit {event_type.value}: {e}")

    async def _process_finding(self, finding: Dict[str, Any], scan_context: str) -> None:
        """
        Process a single finding through the full pipeline.

        Steps:
        1. Record received (for metrics)
        2. Check fp_confidence threshold
        3. Check deduplication cache
        4. Classify and prioritize
        5. Distribute to specialist queue
        6. Emit work_queued event
        """
        # 1. Get specialist type for metrics tracking (before any filtering)
        specialist = self._classify_finding(finding) or "unknown"
        dedup_metrics.record_received(specialist)

        # 2. FP confidence filter
        # SQLi findings bypass this filter - SQLMap is the authoritative judge, not LLM confidence
        # This ensures all potential SQLi reaches the SQLiAgent for proper testing
        fp_confidence = finding.get("fp_confidence", 0.5)
        is_sqli = specialist == "sqli"
        is_probe_validated = finding.get("probe_validated", False)

        if not is_sqli and not is_probe_validated and fp_confidence < settings.THINKING_FP_THRESHOLD:
            logger.debug(f"[{self.name}] FP filtered: {finding.get('type')} "
                        f"(fp_confidence: {fp_confidence:.2f} < {settings.THINKING_FP_THRESHOLD})")
            self._stats["fp_filtered"] += 1
            dedup_metrics.record_fp_filtered()
            return

        if is_sqli and fp_confidence < settings.THINKING_FP_THRESHOLD:
            logger.info(f"[{self.name}] SQLi bypass: {finding.get('type')} forwarded to SQLMap for validation "
                       f"(fp_confidence: {fp_confidence:.2f} < threshold, but SQLMap decides)")

        # 3. Deduplication check
        is_duplicate, key = await self._dedup_cache.check_and_add(finding, scan_context)
        if is_duplicate:
            self._stats["duplicates_filtered"] += 1
            dedup_metrics.record_duplicate(specialist, key)
            return

        # 4. Classify and prioritize
        prioritized = await self._classify_and_prioritize(finding, scan_context)
        if not prioritized:
            self._stats.setdefault("unclassified", 0)
            self._stats["unclassified"] += 1
            return

        # 5. Distribute to specialist queue
        success = await self._distribute_to_queue(prioritized)

        # 6. Emit work_queued event and record metrics (only if successfully queued)
        if success:
            dedup_metrics.record_distributed(prioritized.specialist)
            await self._emit_work_queued_event(prioritized)

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

    async def _process_batch(self) -> None:
        """
        Process a batch of findings.

        Called when:
        - Batch buffer reaches THINKING_BATCH_SIZE
        - Batch timeout expires (in _batch_processor)
        - Explicitly flushed (flush_batch)

        Processes findings in priority order within the batch.
        """
        if not self._batch_buffer:
            return

        # Extract batch (already holding lock from caller or timeout handler)
        batch = self._batch_buffer[:settings.THINKING_BATCH_SIZE]
        self._batch_buffer = self._batch_buffer[settings.THINKING_BATCH_SIZE:]

        logger.info(f"[{self.name}] Processing batch of {len(batch)} findings")

        # Pre-process all findings to get priority scores
        prioritized_batch: List[PrioritizedFinding] = []

        for finding in batch:
            scan_context = finding.pop("_scan_context", self.scan_context)

            # Record received for metrics (before filtering)
            specialist = self._classify_finding(finding) or "unknown"
            dedup_metrics.record_received(specialist)

            # FP filter
            fp_confidence = finding.get("fp_confidence", 0.5)
            if fp_confidence < settings.THINKING_FP_THRESHOLD:
                self._stats["fp_filtered"] += 1
                dedup_metrics.record_fp_filtered()
                continue

            # Dedup check
            is_duplicate, key = await self._dedup_cache.check_and_add(finding, scan_context)
            if is_duplicate:
                self._stats["duplicates_filtered"] += 1
                dedup_metrics.record_duplicate(specialist, key)
                continue

            # Classify and prioritize
            prioritized = await self._classify_and_prioritize(finding, scan_context)
            if prioritized:
                prioritized_batch.append(prioritized)
            else:
                self._stats.setdefault("unclassified", 0)
                self._stats["unclassified"] += 1

        # Sort by priority (highest first) for optimal specialist utilization
        prioritized_batch.sort(key=lambda p: p.priority, reverse=True)

        # Distribute all in batch
        for prioritized in prioritized_batch:
            success = await self._distribute_to_queue(prioritized)
            if success:
                dedup_metrics.record_distributed(prioritized.specialist)
                await self._emit_work_queued_event(prioritized)

        logger.info(f"[{self.name}] Batch complete: {len(prioritized_batch)} distributed")

    async def flush_batch(self) -> int:
        """
        Flush any remaining findings in the batch buffer.

        Returns:
            Number of findings flushed
        """
        async with self._batch_lock:
            initial_count = len(self._batch_buffer)
            while self._batch_buffer:
                await self._process_batch()
            return initial_count

    async def _batch_processor(self):
        """
        Background task for batch mode processing.

        Processes accumulated batches on timeout even if not full.
        This ensures findings don't sit in buffer indefinitely.
        """
        while self.running:
            try:
                await asyncio.sleep(settings.THINKING_BATCH_TIMEOUT)

                async with self._batch_lock:
                    if self._batch_buffer:
                        logger.debug(
                            f"[{self.name}] Batch timeout: processing {len(self._batch_buffer)} buffered"
                        )
                        await self._process_batch()

            except asyncio.CancelledError:
                # Flush remaining on shutdown
                async with self._batch_lock:
                    if self._batch_buffer:
                        logger.info(f"[{self.name}] Shutdown: flushing {len(self._batch_buffer)} buffered")
                        while self._batch_buffer:
                            await self._process_batch()
                break
            except Exception as e:
                logger.error(f"[{self.name}] Batch processor error: {e}")

    def set_mode(self, mode: str) -> None:
        """
        Change processing mode at runtime.

        Args:
            mode: "streaming" or "batch"

        Note: Changing to streaming while batch buffer has items
              will trigger immediate processing.
        """
        if mode not in ("streaming", "batch"):
            raise ValueError(f"Invalid mode: {mode}. Must be 'streaming' or 'batch'")

        old_mode = self._mode
        self._mode = mode
        logger.info(f"[{self.name}] Mode changed: {old_mode} -> {mode}")

        # If switching from batch to streaming, flush buffer
        if old_mode == "batch" and mode == "streaming" and self._batch_buffer:
            asyncio.create_task(self.flush_batch())

    def log_batch_summary(self):
        """Log summary of batch processing."""
        stats = self.get_stats()
        logger.info(
            f"[{self.name}] Batch Summary: "
            f"received={stats['total_received']}, "
            f"deduplicated={stats['duplicates_filtered']}, "
            f"fp_filtered={stats['fp_filtered']}, "
            f"distributed={stats['distributed']}"
        )
        for specialist, count in stats.get('by_specialist', {}).items():
            logger.info(f"[{self.name}]   {specialist}: {count} findings queued")

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            **self._stats,
            "dedup_cache": self._dedup_cache.get_stats(),
            "mode": self._mode,
            "batch_buffer_size": len(self._batch_buffer) if self._mode == "batch" else 0,
            "dedup_metrics": get_dedup_summary(),
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
__all__ = ["ThinkingConsolidationAgent", "DeduplicationCache", "FindingRecord", "PrioritizedFinding"]
