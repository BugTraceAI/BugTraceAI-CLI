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
import json
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

    def _normalize_parameter(self, param: str, vuln_type: str) -> str:
        """
        Normalize parameter names for better deduplication.

        This prevents duplicate findings caused by inconsistent parameter naming
        from the LLM (e.g., "POST Body", "POST Body (Stock Check)", "XML Payload").

        Args:
            param: Raw parameter string from finding
            vuln_type: Vulnerability type (e.g., "xxe", "sqli")

        Returns:
            Normalized parameter name
        """
        param_lower = param.lower()

        # XXE: Normalize all POST body variations
        if vuln_type == "xxe":
            if ("post" in param_lower and "body" in param_lower) or "xml" in param_lower:
                return "post_body"

        # SQLi: Normalize cookie names (keep just the cookie name)
        if "cookie:" in param_lower:
            # Extract cookie name: "Cookie: TrackingId" -> "cookie:trackingid"
            parts = param_lower.split("cookie:")
            if len(parts) > 1:
                cookie_name = parts[1].strip().split()[0]  # Get first word after "cookie:"
                return f"cookie:{cookie_name}"

        # Header injection: Normalize header names
        if "header" in param_lower and ":" in param:
            # "Header: X-Forwarded-For" -> "header:x-forwarded-for"
            parts = param_lower.split(":", 1)
            if len(parts) > 1:
                header_name = parts[1].strip().split()[0]
                return f"header:{header_name}"

        # Default: return lowercase
        return param_lower

    def _make_key(self, finding: Dict[str, Any]) -> str:
        """
        Create deduplication key from finding.

        Format: vuln_type:parameter:url_path

        Example: "XSS:id:/api/users"
        """
        vuln_type = finding.get("type", "Unknown").lower()
        parameter_raw = finding.get("parameter", "unknown")
        url = finding.get("url", "")

        # Normalize parameter for better deduplication
        parameter = self._normalize_parameter(parameter_raw, vuln_type)

        # Extract path from URL (remove protocol and domain)
        url_path = url
        if "://" in url:
            parts = url.split("/", 3)
            url_path = "/" + parts[3] if len(parts) > 3 else "/"

        # Normalize: remove query params for dedup purposes
        if "?" in url_path:
            url_path = url_path.split("?")[0]

        # GLOBAL PARAMETER CHECK
        # If the parameter is global (Cookie, Header), the URL path is irrelevant.
        # Use the host instead to deduplicate across the entire domain.
        if any(p in parameter for p in ["cookie", "header", "user-agent", "referer", "bearer", "authorization"]):
            # Extract host
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                url_path = f"GLOBAL_HOST:{parsed.netloc}"
            except:
                url_path = "GLOBAL_HOST:unknown"

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
        self.scan_id: Optional[int] = None  # To be set by TeamOrchestrator for DB access
        
        # Determine scan directory for persistence
        self.scan_dir = None
        self._queues_dir_cached = None
        self._queues_initialized = False

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

    def _get_queues_dir(self):
        """Helper to find and ensure queues directory, initializes file queues if needed."""
        if self._queues_dir_cached:
            return self._queues_dir_cached

        report_dir = settings.REPORT_DIR
        found_dir = None
        
        # Locate scan directory
        if report_dir.exists():
            for p in report_dir.iterdir():
                if p.is_dir() and self.scan_context in p.name:
                    found_dir = p
                    break
        
        if not found_dir:
            # Fallback
            found_dir = report_dir / f"{settings.APP_NAME}_scan_{self.scan_context}"
            found_dir.mkdir(parents=True, exist_ok=True)
            
        queues_dir = found_dir / "queues"
        queues_dir.mkdir(exist_ok=True)
        
        self._queues_dir_cached = queues_dir
        
        # Initialize SpecialistQueues for file tailing
        if not self._queues_initialized:
            queue_manager.initialize_file_queues(queues_dir)
            self._queues_initialized = True
            
        return queues_dir

    def _setup_event_subscriptions(self):
        """Subscribe to url_analyzed events from Discovery phase.

        NOTE: In v3 sequential pipeline, ThinkingAgent starts AFTER DISCOVERY
        completes, so this subscription is not used. We process from JSON files
        instead of real-time events.
        """
        # Disable event-driven processing (use batch file processing instead)
        logger.info(f"[{self.name}] Event subscriptions disabled (batch mode)")
        # self.event_bus.subscribe(EventType.URL_ANALYZED.value, self._handle_url_analyzed)

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
        - report_files: Paths to JSON/MD reports (v2.1.0)
        """
        url = data.get("url", "unknown")
        scan_context = data.get("scan_context", self.scan_context)
        findings = data.get("findings", [])
        report_files = data.get("report_files", {})  # v2.1.0: JSON/MD report paths

        logger.info(f"[{self.name}] Processing batch: {len(findings)} findings from {url[:50]}")

        self._stats["total_received"] += len(findings)

        if self._mode == "streaming":
            # Process each finding immediately
            for i, finding in enumerate(findings):
                # Attach report files reference (v2.1.0)
                finding["_report_files"] = report_files
                logger.info(f"[{self.name}] Processing finding {i+1}/{len(findings)}: {finding.get('type')}")
                await self._process_finding(finding, scan_context)
                logger.info(f"[{self.name}] Completed finding {i+1}/{len(findings)}")
            logger.info(f"[{self.name}] All findings processed for {url[:50]}")
        else:
            # Batch mode: buffer findings for batch processing
            batch_to_process = None
            async with self._batch_lock:
                for finding in findings:
                    # Add scan_context and report files to finding for batch processing (v2.1.0)
                    finding_with_context = finding.copy()
                    finding_with_context["_scan_context"] = scan_context
                    finding_with_context["_report_files"] = report_files  # v2.1.0: Attach JSON/MD paths
                    self._batch_buffer.append(finding_with_context)

                # Check if batch is full
                if len(self._batch_buffer) >= settings.THINKING_BATCH_SIZE:
                    # Extract batch to process outside of lock
                    batch_to_process = self._batch_buffer[:settings.THINKING_BATCH_SIZE]
                    self._batch_buffer = self._batch_buffer[settings.THINKING_BATCH_SIZE:]

            # Process batch outside of lock to avoid blocking input
            if batch_to_process:
                await self._process_batch_items(batch_to_process)

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

        logger.error(
            f"[{self.name}] Dropped finding: {prioritized.finding.get('type')} -> "
            f"{specialist} (queue full after {settings.THINKING_BACKPRESSURE_RETRIES} retries)"
        )
        return False

    async def _persist_queue_item(self, specialist: str, finding: Dict[str, Any]) -> None:
        """
        Persist finding to a file-based queue for durability and auditing.
        Also appends to the concatenated findings log.

        File structure (v3.1 - XML-like with Base64 encoded JSON for payload integrity):
        - reports/{scan_id}/queues/{specialist}.queue
        - reports/{scan_id}/concatenated_findings.queue
        
        Format:
        <QUEUE_ITEM>
          <TIMESTAMP>1706882445.123</TIMESTAMP>
          <SPECIALIST>xss</SPECIALIST>
          <SCAN_CONTEXT>ginandjuice_12345</SCAN_CONTEXT>
          <FINDING_B64>eyJ0eXBlIjogIlhTUyIsICJwYXlsb2FkIjogIjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4ifQ==</FINDING_B64>
        </QUEUE_ITEM>
        
        Why Base64? Security payloads often contain characters that break JSON Lines:
        - Newlines in payloads
        - Unicode control characters
        - Nested quotes and escape sequences
        Base64 guarantees 100% fidelity.
        """
        import base64
        
        try:
            # Determine scan report directory
            # We construct this dynamically based on scan_context
            # Reuse cached directory logic which ensures file queues are initialized
            queues_dir = self._get_queues_dir()
            found_dir = queues_dir.parent
            
            # Prepare data - encode finding as Base64 JSON
            finding_json = json.dumps(finding, ensure_ascii=False, separators=(',', ':'))
            finding_b64 = base64.b64encode(finding_json.encode('utf-8')).decode('ascii')
            
            # Build XML-like queue entry (one block per item)
            queue_entry = (
                f"<QUEUE_ITEM>\n"
                f"  <TIMESTAMP>{time.time()}</TIMESTAMP>\n"
                f"  <SPECIALIST>{specialist}</SPECIALIST>\n"
                f"  <SCAN_CONTEXT>{self.scan_context}</SCAN_CONTEXT>\n"
                f"  <FINDING_B64>{finding_b64}</FINDING_B64>\n"
                f"</QUEUE_ITEM>\n"
            )

            # 1. Append to specialist queue file
            queue_file = queues_dir / f"{specialist}.queue"
            async with asyncio.Lock(): # Simple lock for file safety
                with open(queue_file, "a", encoding="utf-8") as f:
                    f.write(queue_entry)

            # 2. Append to concatenated findings file
            concat_file = found_dir / "concatenated_findings.queue"
            async with asyncio.Lock():
                 with open(concat_file, "a", encoding="utf-8") as f:
                     f.write(queue_entry)

            # 3. Persist to SQLite Database (if scan_id available)
            if self.scan_id:
                try:
                    from bugtrace.core.database import get_db_manager
                    db = get_db_manager()
                    
                    # Adapt finding data for save_scan_result
                    # save_scan_result expects a list of findings
                    # It handles deduplication internally
                    await asyncio.to_thread(
                        db.save_scan_result, 
                        target_url=finding.get("url", "unknown"),
                        findings=[finding],
                        scan_id=self.scan_id
                    )
                except Exception as db_err:
                    logger.error(f"[{self.name}] Failed to save finding to DB: {db_err}")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to persist queue item: {e}")

    async def _distribute_to_queue(self, prioritized: PrioritizedFinding) -> bool:
        """
        Distribute a prioritized finding to the appropriate specialist queue.

        Handles backpressure by retrying with exponential backoff.

        Args:
            prioritized: PrioritizedFinding with specialist and priority

        Returns:
            True if successfully queued, False if queue full after retries
        """
        # Persist to file first (Durability)
        await self._persist_queue_item(prioritized.specialist, prioritized.finding)

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
        logger.debug(f"[{self.name}] Step 1: Classifying finding type={finding.get('type')}")
        specialist = self._classify_finding(finding) or "unknown"
        dedup_metrics.record_received(specialist)
        logger.debug(f"[{self.name}] Step 1 done: specialist={specialist}")

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
        logger.debug(f"[{self.name}] Step 3: Checking dedup cache")
        is_duplicate, key = await self._dedup_cache.check_and_add(finding, scan_context)
        logger.debug(f"[{self.name}] Step 3 done: duplicate={is_duplicate}")
        if is_duplicate:
            self._stats["duplicates_filtered"] += 1
            dedup_metrics.record_duplicate(specialist, key)
            return

        # 4. Classify and prioritize
        logger.debug(f"[{self.name}] Step 4: Classify and prioritize")
        prioritized = await self._classify_and_prioritize(finding, scan_context)
        if not prioritized:
            self._stats.setdefault("unclassified", 0)
            self._stats["unclassified"] += 1
            logger.debug(f"[{self.name}] Step 4: Unclassified, returning")
            return
        logger.debug(f"[{self.name}] Step 4 done: specialist={prioritized.specialist}, priority={prioritized.priority}")

        # 5. Distribute to specialist queue
        logger.debug(f"[{self.name}] Step 5: Distribute to queue {prioritized.specialist}")
        success = await self._distribute_to_queue(prioritized)
        logger.debug(f"[{self.name}] Step 5 done: success={success}")

        # 6. Emit work_queued event and record metrics (only if successfully queued)
        if success:
            logger.debug(f"[{self.name}] Step 6: Emit work_queued event")
            dedup_metrics.record_distributed(prioritized.specialist)
            await self._emit_work_queued_event(prioritized)
            logger.debug(f"[{self.name}] Step 6 done")

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

    async def _process_batch_items(self, batch: List[Dict[str, Any]]) -> None:
        """
        Process a specific batch of findings.
        
        This runs WITHOUT the _batch_lock to ensure input processing isn't blocked 
        by queue backpressure or slow distribution.
        """
        if not batch:
            return

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
        # Extract all items under lock
        all_items = []
        async with self._batch_lock:
            all_items = self._batch_buffer[:]
            self._batch_buffer = []
            
        initial_count = len(all_items)
        
        # Process in chunks of THINKING_BATCH_SIZE (or all at once? Let's respect batch size)
        # Actually for flush, we can process all, but respecting batch size logic for consistency
        # is better if we want chunks. However, _process_batch_items handles any list size.
        # Let's feed it in chunks to mimic normal operation if needed, or just one go.
        # Given _process_batch_items sorts by priority, larger batches might be better for global priority.
        # But let's stick to chunks to avoid blocking the event loop for too long.
        
        chunk_size = settings.THINKING_BATCH_SIZE
        for i in range(0, len(all_items), chunk_size):
            chunk = all_items[i:i + chunk_size]
            await self._process_batch_items(chunk)
            
        return initial_count

    async def process_batch_from_list(
        self, findings: List[Dict[str, Any]], scan_context: str = None
    ) -> int:
        """
        Process a batch of findings from a Python list (not events).

        This is used for STRATEGY phase batch processing when reading
        from JSON files instead of URL_ANALYZED events.

        Args:
            findings: List of finding dictionaries loaded from JSON
            scan_context: Scan context for tracking

        Returns:
            Number of findings successfully processed and queued
        """
        if not findings:
            logger.info(f"[{self.name}] No findings to process")
            return 0

        scan_ctx = scan_context or self.scan_context
        logger.info(f"[{self.name}] Processing batch of {len(findings)} findings from list")

        # Add scan_context to each finding if missing
        for finding in findings:
            if "_scan_context" not in finding:
                finding["_scan_context"] = scan_ctx

        # Process using existing batch infrastructure
        # This reuses _process_batch_items which handles:
        # - FP filtering
        # - Deduplication
        # - Classification
        # - Prioritization
        # - Queue distribution
        await self._process_batch_items(findings)

        # Return count of distributed items
        distributed = self._stats.get("distributed", 0)
        logger.info(f"[{self.name}] Distributed {distributed} findings to specialist queues")
        return distributed

    async def _batch_processor(self):
        """
        Background task for batch mode processing.

        Processes accumulated batches on timeout even if not full.
        This ensures findings don't sit in buffer indefinitely.
        """
        while self.running:
            try:
                await asyncio.sleep(settings.THINKING_BATCH_TIMEOUT)

                batch_to_process = None
                async with self._batch_lock:
                    if self._batch_buffer:
                        # Extract all buffered items on timeout? 
                        # Or just one batch?
                        # The original code did:
                        # logger.debug(...)
                        # await self._process_batch() -> which takes ONE batch (THINKING_BATCH_SIZE)
                        
                        # So we should extract up to batch size
                        count = min(len(self._batch_buffer), settings.THINKING_BATCH_SIZE)
                        if count > 0:
                            logger.debug(
                                f"[{self.name}] Batch timeout: processing {count} buffered"
                            )
                            batch_to_process = self._batch_buffer[:count]
                            self._batch_buffer = self._batch_buffer[count:]

                if batch_to_process:
                    await self._process_batch_items(batch_to_process)

            except asyncio.CancelledError:
                # Flush remaining on shutdown
                # We can call flush_batch, but that's async and we are in exception handler
                # Better to just log and try to flush if possible, or just let flush_batch handle it if called elsewhere
                logger.info(f"[{self.name}] Batch processor cancelled")
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
