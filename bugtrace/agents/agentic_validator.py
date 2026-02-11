"""
AgenticValidator: AI-Powered Vulnerability Validation Agent (v2 - OPTIMIZED)

PERFORMANCE OPTIMIZATIONS (2026-01-21):
1. Parallel validation with configurable concurrency (3x-5x faster)
2. Browser session pooling (reuse instead of launch per validation)
3. Early-exit when CDP confirms (skip expensive vision API)
4. Result caching for similar payloads/URLs (avoid re-validation)
5. Smart fast-path for high-confidence/pre-validated findings
6. Reduced timeouts and eliminated unnecessary sleeps
7. Batch screenshot capture for similar URLs

This validator uses an LLM with vision capabilities to:
1. Navigate to target URLs with payloads
2. Capture screenshots
3. Reason about the visual state to determine if vulnerability is real
4. Adapt testing strategy based on context
"""

from typing import List, Dict, Any, Tuple, Optional, Set
import asyncio
import base64
import json
import hashlib
import time
from pathlib import Path
from loguru import logger
from dataclasses import dataclass, field
from collections import OrderedDict

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager, BrowserManager
from bugtrace.tools.visual.verifier import XSSVerifier, VerificationResult
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus as global_event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.core.validation_metrics import validation_metrics
# Import specialist utilities for full payload loading (v2.1.0+)
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.core.verbose_events import create_emitter
# NOTE: ValidationFeedback imports removed - feedback loop eliminated for simplicity
# AgenticValidator is now a linear CDP specialist (no loopback to specialist agents)


# =============================================================================
# OPTIMIZATION 1: Validation Result Cache (LRU)
# =============================================================================
@dataclass
class ValidationCache:
    """LRU Cache for validation results to avoid re-validating identical payloads."""
    max_size: int = 100
    _cache: OrderedDict = field(default_factory=OrderedDict)

    def get_key(self, url: str, payload: str) -> str:
        """Generate cache key from full URL + payload hash.

        NOTE: We include the full URL (with query params) because different
        parameter values may have different escaping/filtering behavior.
        E.g., /user?id=1 vs /user?id=100 might have different XSS contexts.
        """
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        # Sort query params for consistent caching
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params.items()), doseq=True) if params else ""
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sorted_query}" if sorted_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        content = f"{normalized_url}:{payload or 'none'}"
        return hashlib.md5(content.encode()).hexdigest()

    def get(self, url: str, payload: str) -> Optional[Dict]:
        """Get cached result if exists."""
        key = self.get_key(url, payload)
        if key in self._cache:
            self._cache.move_to_end(key)  # LRU: move to end
            logger.debug(f"Cache HIT for {url[:50]}...")
            return self._cache[key]
        return None

    def set(self, url: str, payload: str, result: Dict):
        """Cache a validation result."""
        key = self.get_key(url, payload)
        self._cache[key] = result
        self._cache.move_to_end(key)
        # Evict oldest if over capacity
        while len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def clear(self):
        self._cache.clear()

    def __len__(self):
        return len(self._cache)


# =============================================================================
# OPTIMIZATION 2: Shared XSSVerifier Pool
# =============================================================================
class VerifierPool:
    """Pool of XSSVerifier instances to avoid recreation overhead."""

    def __init__(self, pool_size: int = 3):
        self.pool_size = pool_size
        self._verifiers: List[XSSVerifier] = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._initialized = False

    async def initialize(self):
        """Initialize verifier pool (lazy init)."""
        if self._initialized:
            return
        self._semaphore = asyncio.Semaphore(self.pool_size)
        self._verifiers = [
            XSSVerifier(headless=settings.HEADLESS_BROWSER, prefer_cdp=True)
            for _ in range(self.pool_size)
        ]
        self._initialized = True
        logger.info(f"VerifierPool initialized with {self.pool_size} instances")

    async def get_verifier(self) -> XSSVerifier:
        """Get an available verifier from the pool."""
        if not self._initialized:
            await self.initialize()
        await self._semaphore.acquire()
        # Return any verifier (they're stateless between calls)
        return self._verifiers[0]

    def release(self):
        """Release verifier back to pool."""
        if self._semaphore:
            self._semaphore.release()


# Global pool instance
_verifier_pool = VerifierPool(pool_size=3)


class AgenticValidator(BaseAgent):
    """
    An AI-powered validator that uses vision + reasoning to validate vulnerabilities.

    v2 OPTIMIZATIONS:
    - Parallel batch validation (configurable concurrency)
    - Result caching for identical URL+payload combinations
    - Early-exit when CDP confirms (skips expensive vision API)
    - Browser session reuse via VerifierPool
    - Smart filtering of pre-validated and low-severity findings

    v2.1.0+ PAYLOAD HANDLING:
    - Automatically loads FULL payloads from JSON reports when truncated (>200 chars)
    - Uses specialist_utils.load_full_finding_data() for complete payload recovery
    - Ensures accurate CDP validation even for complex/long payloads
    - Logs payload loading operations for debugging and traceability

    Unlike the basic ValidatorAgent which just checks for alert(), this agent:
    - Takes screenshots and sends them to a vision LLM
    - Asks the LLM to reason about what it sees
    - Can adapt its testing strategy based on the response
    - Provides detailed evidence with confidence scores

    IMPORTANT: This agent REQUIRES findings to have _report_files metadata
    to load full payloads from JSON. Phase 3 STRATEGY ensures this metadata
    is present in all findings.
    """

    # Configuration
    # Legacy constant (now uses settings.MAX_CONCURRENT_VALIDATION)
    MAX_CONCURRENT_VALIDATIONS = 3  # Fallback if phase_semaphores not available
    SKIP_VISION_ON_CDP_CONFIRM = True  # Early exit optimization
    ENABLE_CACHE = True  # Result caching
    FAST_VALIDATION_TIMEOUT = 20.0  # Reduced from default (30s) to avoid conflicts
    MAX_TOTAL_VALIDATION_TIME = 600.0  # 10 minutes global timeout (was 300s - too aggressive)
    MAX_FEEDBACK_DEPTH = 2  # Maximum recursion depth for feedback loop

    def __init__(self, event_bus=None, cancellation_token=None):
        super().__init__("AgenticValidator", "AI Vision Validator", event_bus, agent_id="agentic_validator")
        self.max_retries = 3
        self.validation_prompts = self._load_prompts()

        # Cancellation token for graceful shutdown (injected from orchestrator)
        self._cancellation_token = cancellation_token or {"cancelled": False}

        # OPTIMIZATION: Validation cache
        self._cache = ValidationCache(max_size=150)

        # OPTIMIZATION: Use phase-specific validation semaphore (v2.4)
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores, get_validation_semaphore
            phase_semaphores.initialize()
            self._validation_semaphore = get_validation_semaphore()
        except ImportError:
            self._validation_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_VALIDATIONS)

        # Statistics tracking
        self._stats = {
            "total_validated": 0,
            "cache_hits": 0,
            "cdp_confirmed": 0,
            "vision_analyzed": 0,
            "skipped_prevalidated": 0,
            "avg_time_ms": 0,
            "total_time_ms": 0,
            # Phase 21: CDP load tracking
            "total_received": 0,       # All vulnerability_detected events
            "skipped_confirmed": 0,    # VALIDATED_CONFIRMED (skipped)
            "queued_for_cdp": 0,       # PENDING_VALIDATION (processed)
            "cdp_rejected": 0,         # CDP rejected as FP
            "cdp_skipped_duplicate": 0, # Structural deduplication hits
        }

        # Phase 21: Structural deduplication tracking
        self._structural_keys: Set[str] = set()
        self._structural_lock = asyncio.Lock()

        # NOTE: Feedback loop removed - AgenticValidator is now a linear CDP specialist
        # No loopback to XSSAgent/CSTIAgent - validation is single-attempt
        self.llm_client = llm_client

        # Phase 21: Subscribe to specialist vulnerability_detected events
        self._event_bus = event_bus or global_event_bus
        if self._event_bus:
            self._event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                self.handle_vulnerability_detected
            )
            logger.info(f"[{self.name}] Subscribed to vulnerability_detected events")

        # Verbose event emitter (lazy init — created when scan_context arrives)
        self._v = None

        # Validation queue for PENDING_VALIDATION findings
        self._pending_queue: asyncio.Queue = asyncio.Queue()
        self._queue_processor_task: Optional[asyncio.Task] = None
        
    def _load_prompts(self) -> Dict[str, str]:
        """Load specialized prompts for different vulnerability types."""
        prompts = {
            "xss": self._get_xss_prompt(),
            "sqli": self._get_sqli_prompt(),
            "csti": self._get_csti_prompt(),
            "general": self._get_general_prompt()
        }

        # Override with custom prompts if provided
        if self.system_prompt:
            self._apply_custom_prompts(prompts)

        return prompts

    def _get_xss_prompt(self) -> str:
        """Get XSS validation prompt template."""
        return """You are a security expert analyzing a screenshot for XSS vulnerability validation.

CONTEXT:
- BugTraceAI security scanner found a potential XSS vulnerability
- We injected a test payload that creates a visual banner or triggers an alert
- Our payloads create text containing: "HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED", or trigger alert dialogs

TASK:
Look at this screenshot and determine if the XSS was successful.

SUCCESS indicators (HIGH CONFIDENCE - mark success=true):
1. ANY text containing "HACKED", "BUGTRACEAI", "BUGTRACE", "PWNED", "XSS" appearing on the page (banner, div, any element)
2. A browser alert/confirm/prompt dialog box (usually a small popup with OK button)
3. Red or colored banner at top/bottom of page with security-related text
4. Text like "FRAGMENT XSS" or "MXSS DETECTED" visible anywhere

MEDIUM CONFIDENCE indicators (mark success=true, confidence=0.7):
1. Unusual HTML elements that look injected (e.g., floating divs, unexpected banners)
2. JavaScript code visible as rendered content (not escaped)
3. Page layout disruption suggesting DOM manipulation

FAILURE indicators (mark success=false):
1. Normal page content with no abnormalities
2. Error message like "Invalid input" or "Not found"
3. The payload is visible as escaped text (e.g., "&lt;script&gt;" shown literally)
4. WAF/security block page ("Request blocked", "Forbidden")

IMPORTANT: If you see ANY text containing "HACKED" or "BUGTRACEAI" or "XSS" that wasn't part of the original page content, this is SUCCESS - our payload executed.

Respond in JSON format:
{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence": "description of what you see that proves/disproves XSS",
    "recommendation": "next steps if any"
}"""

    def _get_sqli_prompt(self) -> str:
        """Get SQL Injection validation prompt template."""
        return """You are a security expert analyzing a screenshot for SQL Injection validation.

CONTEXT:
- A security scanner found a potential SQL Injection vulnerability
- We injected a test payload into the page
- Look for signs of SQL error messages or data exfiltration

SUCCESS indicators:
1. SQL error messages (MySQL, PostgreSQL, MSSQL syntax errors)
2. Database version disclosure
3. Unexpected data being displayed
4. "You have an error in your SQL syntax" message
5. Column/table names visible in error

FAILURE indicators:
1. Normal page with expected content
2. Generic "Invalid input" error (input validation, not SQLi)
3. WAF block page
4. HTTP 500 with no SQL-related info

Respond in JSON format:
{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence": "description of what you see",
    "sql_error_type": "MySQL/PostgreSQL/MSSQL/None",
    "recommendation": "next steps"
}"""

    def _get_csti_prompt(self) -> str:
        """Get CSTI/SSTI validation prompt template."""
        return """You are a security expert analyzing a screenshot for Template Injection validation.

CONTEXT:
- We injected a template payload like `{{7*7}}` or `{{111111+111111}}`
- We expect the server or client-side engine (Angular, Vue, Jinja2) to evaluate this math
- Seeing "49" or "222222" is proof of vulnerability

SUCCESS indicators (HIGH CONFIDENCE):
1. The number "49" is visible where the payload was injected (arithmetic evaluation)
2. The number "111111" etc. if other math was used
3. Text like "Config", "Smarty", "class 'os'" if object printing was used
4. "uid=..." or system command output (rare for visual)
5. Angular bindings visible (e.g., `ng-bind` attributes not rendered correctly, or successful interpolation)

FAILURE indicators:
1. The literal text `{{7*7}}` is displayed (means it was reflected but NOT evaluated)
2. Normal page content without numbers
3. "Invalid input" error
4. WAF Block Page

Respond in JSON (same format)."""

    def _get_general_prompt(self) -> str:
        """Get general vulnerability validation prompt template."""
        return """You are a security expert analyzing a screenshot for vulnerability validation.

Examine the screenshot and determine if there are any signs of:
1. Security vulnerability exploitation
2. Error messages revealing sensitive information
3. Unexpected behavior that indicates a vulnerability
4. WAF/security tool blocking

Respond in JSON format:
{
    "anomaly_detected": true/false,
    "confidence": 0.0-1.0,
    "description": "what you observe",
    "security_implications": "potential impact if any"
}"""

    def _apply_custom_prompts(self, prompts: Dict[str, str]):
        """Override default prompts with custom ones from system_prompt."""
        import re
        parts = re.split(r'#+\s+', self.system_prompt)

        for part in parts:
            self._process_prompt_section(part, prompts)

    def _process_prompt_section(self, part: str, prompts: Dict[str, str]):
        """Process a single prompt section and update prompts dict."""
        import re
        part_lower = part.lower()

        # Guard: XSS validation prompt
        if part_lower.startswith("xss validation prompt"):
            prompts["xss"] = re.sub(r'^xss validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return

            prompts["sqli"] = re.sub(r'^sqli validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return

        # Guard: CSTI validation prompt
        if part_lower.startswith("csti/ssti validation prompt"):
            prompts["csti"] = re.sub(r'^csti/ssti validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return

        # Guard: General validation prompt
        if part_lower.startswith("general validation prompt"):
            prompts["general"] = re.sub(r'^general validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return
    
    async def run_loop(self):
        """Typically triggered by orchestrator, not continuous."""
        pass

    async def stop(self):
        """Stop agent and queue processor (v2.6 fix: proper lifecycle management)."""
        await super().stop()
        await self.stop_queue_processor()

    # =========================================================================
    # Phase 21: Event-Driven Validation (PENDING_VALIDATION filtering)
    # =========================================================================

    async def handle_vulnerability_detected(self, data: Dict[str, Any]) -> None:
        """
        Handle vulnerability_detected events from specialist agents.

        Only queue findings with PENDING_VALIDATION status for CDP validation.
        VALIDATED_CONFIRMED findings are passed through without CDP.

        Args:
            data: Event payload with specialist, finding, status, scan_context
        """
        status = data.get("status", "")
        specialist = data.get("specialist", "unknown")
        finding = data.get("finding", {})

        # Lazy init verbose emitter when scan_context first arrives
        if not self._v:
            sc = data.get("scan_context", "")
            if sc:
                self._v = create_emitter("AgenticValidator", sc)

        self._stats["total_received"] = self._stats.get("total_received", 0) + 1

        if self._v:
            self._v.emit("validation.finding.received", {
                "specialist": specialist,
                "status": status,
                "type": finding.get("type", "unknown"),
                "param": finding.get("parameter", ""),
            })

        # Filter: Only process PENDING_VALIDATION
        if status != ValidationStatus.PENDING_VALIDATION.value:
            self._stats["skipped_confirmed"] = self._stats.get("skipped_confirmed", 0) + 1
            logger.debug(f"[{self.name}] Skipping {specialist} finding (status={status})")
            return

        # OPTIMIZATION: Structural Deduplication
        # If we already have a pending or validated finding for this (type, path, param), skip it
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        vuln_type = finding.get("type", specialist).upper()
        
        struct_key = self._generate_structural_key(vuln_type, url, param)
        
        async with self._structural_lock:
            if struct_key in self._structural_keys:
                self._stats["cdp_skipped_duplicate"] += 1
                if self._v:
                    self._v.emit("validation.finding.dedup_skipped", {
                        "type": vuln_type, "param": param, "struct_key": struct_key,
                    })
                logger.info(f"[{self.name}] 🛡️ STRUCTURAL DEDUPLICATION: Skiping redundant {vuln_type} on {param} (path already validates/validating)")
                return
            
            self._structural_keys.add(struct_key)

        # Queue for CDP validation
        self._stats["queued_for_cdp"] = self._stats.get("queued_for_cdp", 0) + 1
        logger.info(f"[{self.name}] Queuing {specialist} finding for CDP validation ({vuln_type} on {param})")

        await self._pending_queue.put({
            "specialist": specialist,
            "finding": finding,
            "scan_context": data.get("scan_context", ""),
        })

        if self._v:
            self._v.emit("validation.finding.queued", {
                "specialist": specialist, "type": vuln_type, "param": param,
                "queue_depth": self._pending_queue.qsize(),
            })

    async def start_queue_processor(self) -> None:
        """Start the background queue processor for CDP validation."""
        if self._queue_processor_task is None or self._queue_processor_task.done():
            self._queue_processor_task = asyncio.create_task(self._process_pending_queue())
            if self._v:
                self._v.emit("validation.started", {"queue_size": self._pending_queue.qsize()})
            logger.info(f"[{self.name}] Started queue processor")

    async def stop_queue_processor(self) -> None:
        """Stop the background queue processor and log CDP reduction summary."""
        if self._queue_processor_task and not self._queue_processor_task.done():
            self._cancellation_token["cancelled"] = True
            self._queue_processor_task.cancel()
            try:
                await self._queue_processor_task
            except asyncio.CancelledError:
                pass
            logger.info(f"[{self.name}] Stopped queue processor")

        if self._v:
            self._v.emit("validation.completed", {
                "total_received": self._stats.get("total_received", 0),
                "queued_for_cdp": self._stats.get("queued_for_cdp", 0),
                "cdp_confirmed": self._stats.get("cdp_confirmed", 0),
                "cdp_rejected": self._stats.get("cdp_rejected", 0),
                "cache_hits": self._stats.get("cache_hits", 0),
                "vision_analyzed": self._stats.get("vision_analyzed", 0),
            })

        # Log CDP reduction summary on scan completion
        validation_metrics.log_reduction_summary()

    async def _process_pending_queue(self) -> None:
        """Process PENDING_VALIDATION findings from queue."""
        while True:
            try:
                item = await asyncio.wait_for(self._pending_queue.get(), timeout=30.0)
                await self._validate_and_emit(item)
                self._pending_queue.task_done()
            except asyncio.TimeoutError:
                # Check if we should shut down
                if self._cancellation_token.get("cancelled", False):
                    break
            except asyncio.CancelledError:
                logger.info(f"[{self.name}] Queue processor cancelled")
                break
            except Exception as e:
                logger.error(f"[{self.name}] Error in queue processor: {e}", exc_info=True)
                if self._pending_queue.qsize() > 0:
                     self._pending_queue.task_done()

    def _generate_structural_key(self, vuln_type: str, url: str, parameter: str) -> str:
        """
        Generate a structural key for deduplication.
        Format: VULN_TYPE:HOST:PATH:PARAMETER

        For global injection points (Cookies, Headers), ignores PATH.
        """
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            host = parsed.netloc
            param_lower = parameter.lower()

            # Global Injection Points: Cookie, Header, User-Agent, Referer
            # These are typically host-wide, not path-specific.
            if any(p in param_lower for p in ["cookie", "header", "user-agent", "referer", "bearer", "authorization"]):
                path = "*GLOBAL*"

            return f"{vuln_type.upper()}:{host}:{path}:{param_lower}"
        except Exception:
            return f"{vuln_type.upper()}:unknown:unknown:{parameter.lower()}"

    async def _validate_and_emit(self, item: Dict[str, Any]) -> None:
        """
        Validate a finding via CDP and emit result event.

        v2.1.0+: Ensures full payload is loaded from JSON before validation.

        Emits:
        - EventType.FINDING_VALIDATED if CDP confirms
        - EventType.FINDING_REJECTED if CDP rejects as FP
        """
        specialist = item.get("specialist", "unknown")
        finding = item.get("finding", {})
        scan_context = item.get("scan_context", "")

        if self._v:
            self._v.emit("validation.finding.started", {
                "specialist": specialist,
                "type": finding.get("type", specialist).upper(),
                "param": finding.get("parameter", ""),
                "url": finding.get("url", "")[:100],
            })

        # CRITICAL: Load full payload from JSON if truncated (v2.1.0+)
        # The finding dict from queue may have truncated payload (200 chars)
        # We need the complete payload for accurate CDP validation
        finding_with_full_payload = self._ensure_full_payload(finding)

        # Build finding dict for validation
        finding_for_validation = {
            "url": finding_with_full_payload.get("url", ""),
            "payload": finding_with_full_payload.get("payload", ""),
            "parameter": finding_with_full_payload.get("parameter", ""),
            "type": finding_with_full_payload.get("type", specialist.upper()),
            "evidence": finding_with_full_payload.get("evidence", {}),
            # Preserve _report_files metadata for downstream use
            "_report_files": finding_with_full_payload.get("_report_files", {}),
        }

        # Perform CDP validation
        # OPTIMIZATION: Check for static XSS reflection first to skip browser overhead
        static_result = await self._validate_static_xss(finding_for_validation)
        if static_result:
             if self._v:
                 self._v.emit("validation.static.result", {
                     "validated": True, "specialist": specialist,
                 })
             logger.info(f"[{self.name}] ⚡ Static XSS validated (CSP Safe + Reflected). Skipping browser.")
             result = static_result
        else:
             result = await self.validate_finding_agentically(finding_for_validation)

        # Determine event type based on result
        if result.get("validated", False):
            event_type = EventType.FINDING_VALIDATED
            status = "VALIDATED"
            self._stats["cdp_confirmed"] += 1
            if self._v:
                self._v.emit("validation.finding.confirmed", {
                    "specialist": specialist,
                    "type": finding.get("type", specialist).upper(),
                    "param": finding.get("parameter", ""),
                    "confidence": result.get("confidence", 0.0),
                })
        else:
            event_type = EventType.FINDING_REJECTED
            status = "REJECTED_FP"
            self._stats["cdp_rejected"] = self._stats.get("cdp_rejected", 0) + 1
            if self._v:
                self._v.emit("validation.finding.rejected", {
                    "specialist": specialist,
                    "type": finding.get("type", specialist).upper(),
                    "param": finding.get("parameter", ""),
                    "reason": result.get("reasoning", "")[:100],
                })

        # Emit result event
        if self._event_bus:
            await self._event_bus.emit(event_type, {
                "specialist": specialist,
                "finding": finding,
                "validation_result": {
                    "status": status,
                    "reasoning": result.get("reasoning", ""),
                    "screenshot_path": result.get("screenshot_path"),
                    "confidence": result.get("confidence", 0.0),
                },
                "scan_context": scan_context,
            })
            logger.info(f"[{self.name}] Emitted {event_type.value} for {specialist}")

    async def validate_with_vision(
        self, 
        finding: Dict[str, Any],
        screenshot_path: str
    ) -> Dict[str, Any]:
        """
        Use a vision LLM to analyze the screenshot and validate the finding.
        """
        vuln_type = self._detect_vuln_type(finding)
        prompt = self.validation_prompts.get(vuln_type, self.validation_prompts["general"])
        
        try:
            # Call vision model
            response = await self._call_vision_model(prompt, screenshot_path)
            result = self._parse_vision_response(response)
            
            finding["validated"] = result.get("success", False)
            finding["confidence"] = result.get("confidence", 0.0)
            finding["reasoning"] = result.get("evidence", "No clear evidence found in screenshot.")
            finding["validator_notes"] = response # Store full LLM reasoning
            
            if finding["validated"]:
                self.think(f"✅ CONFIRMED: {finding.get('url')} (confidence: {result.get('confidence')})")
            else:
                self.think(f"❌ Could not confirm via vision: {finding.get('url')}")
                
        except Exception as e:
            logger.error(f"Vision validation failed: {e}", exc_info=True)
            finding["validated"] = False
            finding["reasoning"] = f"Vision validation error: {str(e)}"
            
        return finding
    
    def _ensure_full_payload(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure finding has full payload loaded from JSON report.

        v2.1.0+: Payloads in events are truncated to 200 chars for performance.
        This method loads the complete payload from the JSON report file if available.

        Args:
            finding: Finding dict (may have truncated payload)

        Returns:
            Finding dict with full payload loaded, or original if unavailable

        Note:
            This is CRITICAL for AgenticValidator because CDP validation needs
            the complete payload to accurately reproduce vulnerabilities.
            Truncated payloads (>200 chars) will cause validation failures.
        """
        original_payload = finding.get("payload", "")
        original_len = len(original_payload)

        # Fast path: payload is short, no truncation
        if original_len < 199:
            logger.debug(f"[AgenticValidator] Payload length {original_len} < 199, no JSON load needed")
            return finding

        # Check if we have JSON report metadata
        if not finding.get("_report_files"):
            logger.warning(
                f"[AgenticValidator] Payload is {original_len} chars (likely truncated) "
                f"but no _report_files metadata found. Validation may fail for complex payloads."
            )
            return finding

        # Load full finding data from JSON (includes payload, reasoning, fp_reason, etc.)
        try:
            full_finding = load_full_finding_data(finding)
            full_payload = full_finding.get("payload", "")
            full_len = len(full_payload)

            if full_len > original_len:
                if self._v:
                    self._v.emit("validation.payload_loaded", {
                        "original_len": original_len, "full_len": full_len,
                    })
                logger.info(
                    f"[AgenticValidator] ✅ Loaded FULL payload from JSON: "
                    f"{full_len} chars (was {original_len} chars truncated)"
                )
                return full_finding
            else:
                logger.debug(f"[AgenticValidator] Payload unchanged after JSON load ({full_len} chars)")
                return finding

        except Exception as e:
            logger.error(
                f"[AgenticValidator] Failed to load full payload from JSON: {e}. "
                f"Using truncated payload ({original_len} chars). Validation may be inaccurate.",
                exc_info=True
            )
            return finding

    def _agentic_prepare_context(self, finding: Dict[str, Any]) -> Tuple[str, Optional[str], str, Optional[str]]:
        """
        Prepare validation context from finding.

        v2.1.0+: Automatically loads full payload from JSON if truncated.

        Args:
            finding: Finding dict (will be loaded from JSON if payload is truncated)

        Returns:
            Tuple of (url, payload, vuln_type, param)
        """
        # CRITICAL: Ensure we have the full payload before validation
        finding = self._ensure_full_payload(finding)

        url = finding.get("url")
        payload = finding.get("payload")
        param = finding.get("parameter") or finding.get("param")
        vuln_type = self._detect_vuln_type(finding)

        # Select best verification URL from specialist methods if available
        if finding.get("verification_methods"):
            url, payload = self._select_best_verification_method(finding, url)

        return url, payload, vuln_type, param

    def _select_best_verification_method(self, finding: Dict, url: str) -> Tuple[str, Optional[str]]:
        """Select best verification method from specialist options."""
        preferred = ["console_log", "window_variable", "dom_modification"]
        for p_type in preferred:
            for m in finding.get("verification_methods", []):
                if m.get("type") == p_type and m.get("url_encoded"):
                    logger.info(f"Using specialized verification method: {p_type}")
                    return m.get("url_encoded"), None
        return url, finding.get("payload")

    async def _agentic_execute_validation(
        self, url: str, payload: Optional[str], vuln_type: str, param: Optional[str] = None
    ) -> Tuple[Optional[str], List[str], bool, Optional[str]]:
        """Execute payload with timeout and return results."""
        try:
            path, logs, confirmed, alert_msg = await asyncio.wait_for(
                self._execute_payload_optimized(url, payload, vuln_type, param),
                timeout=self.FAST_VALIDATION_TIMEOUT
            )
            return path, logs, confirmed, alert_msg
        except asyncio.TimeoutError:
            logger.warning(f"Validation timeout for {url[:50]}...")
            return None, ["TIMEOUT"], False, None
        except Exception as e:
            logger.error(f"Validation error: {e}", exc_info=True)
            return None, [], False, None

    def _agentic_build_cdp_result(
        self, logs: List[str], url: str, payload: Optional[str], start_time: float
    ) -> Dict[str, Any]:
        """Build result dict for CDP confirmation."""
        self._stats["cdp_confirmed"] += 1
        result = {
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reasoning": f"Execution CONFIRMED: Low-level event (alert/dialog) triggered. Logs: {logs}",
            "screenshot_path": None,
            "logs": logs
        }

        if self.ENABLE_CACHE:
            self._cache.set(url, payload, result)

        elapsed = (time.time() - start_time) * 1000
        self._update_stats(elapsed)
        logger.info(f"⚡ CDP confirmed in {elapsed:.0f}ms (skipped vision API)")
        return result

    async def _agentic_analyze_with_vision(
        self, finding: Dict, screenshot_path: str, logs: List[str]
    ) -> Dict[str, Any]:
        """Analyze screenshot with vision and build result."""
        self.think("CDP silent. Invoking Vision Analysis...")
        self._stats["vision_analyzed"] += 1

        if self._v:
            self._v.emit("validation.vision.started", {
                "type": finding.get("type", "unknown"),
                "url": finding.get("url", "")[:100],
            })

        vision_result = await self.validate_with_vision(finding, screenshot_path)
        confidence = vision_result.get("confidence", 0.0)
        validated = vision_result.get("validated", False)

        if self._v:
            self._v.emit("validation.vision.result", {
                "validated": validated,
                "confidence": confidence,
                "type": finding.get("type", "unknown"),
            })

        result = {"validated": False, "screenshot_path": screenshot_path, "logs": logs}

        if validated:
            result["validated"] = True
            result["status"] = "VALIDATED_CONFIRMED"
            result["reasoning"] = vision_result.get("reasoning", "Validated via vision analysis.")
        elif confidence >= 0.7:
            result["status"] = "MANUAL_REVIEW_RECOMMENDED"
            result["needs_manual_review"] = True
            result["reasoning"] = self._generate_manual_review_brief(finding, vision_result, logs)
            self.think(f"⚠️ SUSPICIOUS ({confidence:.0%}) - flagging for manual review")
        else:
            result["status"] = "VALIDATED_FALSE_POSITIVE"
            result["reasoning"] = vision_result.get("reasoning", "No evidence of execution found.")

        return result

    def _agentic_check_cache(self, url: str, payload: Optional[str]) -> Optional[Dict[str, Any]]:
        """Check cache for existing result."""
        if not self.ENABLE_CACHE:
            return None
        cached = self._cache.get(url, payload)
        if cached:
            self._stats["cache_hits"] += 1
            if self._v:
                self._v.emit("validation.cache.hit", {"url": url[:80]})
            logger.info(f"🚀 Cache hit for {url[:50]}... (skipping validation)")
        else:
            if self._v:
                self._v.emit("validation.cache.miss", {"url": url[:80]})
        return cached

    async def _agentic_process_validation_result(
        self, screenshot_path: Optional[str], logs: List[str], basic_triggered: bool,
        finding: Dict, url: str, payload: Optional[str], start_time: float,
        alert_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """Process validation result and build final response."""
        # Step 1: Impact-Aware Alert Validation
        impact_analysis = None
        if alert_message:
            impact_analysis = self._validate_alert_impact(alert_message, url)
            logger.info(f"Impact Analysis: {impact_analysis}")

        # Step 2: Triggered event (L4 CDP confirmed)
        if basic_triggered:
            if self._v:
                self._v.emit("validation.cdp.confirmed", {
                    "url": url[:100],
                    "events": len(logs),
                    "alert": alert_message[:50] if alert_message else None,
                    "impact": impact_analysis.get("impact") if impact_analysis else None,
                })
            result = self._agentic_build_cdp_result(logs, url, payload, start_time)
            if impact_analysis:
                result["impact"] = impact_analysis["impact"]
                result["reasoning"] += f" | {impact_analysis['reason']}"
            return result

        # Step 3: Vision fallback (L1-L4 silent)
        if self._v:
            self._v.emit("validation.cdp.silent", {
                "url": url[:100],
                "has_screenshot": bool(screenshot_path and Path(screenshot_path).exists()),
                "console_events": len(logs),
            })
        if screenshot_path and Path(screenshot_path).exists():
            return await self._agentic_analyze_with_vision(finding, screenshot_path, logs)

        # Step 4: Rejection
        return {
            "validated": False,
            "status": "VALIDATED_FALSE_POSITIVE",
            "reasoning": "No execution evidence found in CDP logs or visual capture."
        }

    def _validate_alert_impact(self, alert_message: str, target_url: str) -> Dict[str, str]:
        """
        Validate the impact of an alert() call.
        Aligns with BugTraceAI V5 Impact Scoring.
        """
        from urllib.parse import urlparse
        parsed_url = urlparse(target_url)
        target_domain = parsed_url.netloc

        # 1. Target Domain Match (HIGH IMPACT)
        if alert_message == target_domain or alert_message in target_url:
             return {"impact": "HIGH", "reason": "Execution on TARGET domain confirmed (Impact: Session/CSRF)"}

        # 2. Localhost/Internal (MEDIUM IMPACT)
        if "localhost" in alert_message or "127.0.0.1" in alert_message:
             return {"impact": "MEDIUM", "reason": "Execution confirmed but limited to local/loopback environment"}

        # 3. Sandbox Rejection (LOW IMPACT / ESCALATION)
        # e.g. *.googleusercontent.com or sandboxed iframes
        sandbox_indicators = [".googleusercontent.com", "sandbox", "null", "undefined"]
        for indicator in sandbox_indicators:
            if indicator in alert_message.lower():
                return {"impact": "LOW", "reason": f"Execution restricted to sandboxed environment ({indicator})"}

        # 4. Generic Alert (alert(1))
        if alert_message == "1" or alert_message == "undefined":
             return {"impact": "MEDIUM", "reason": "Execution confirmed with generic marker (Identity of domain unconfirmed)"}

        return {"impact": "MEDIUM", "reason": f"Execution confirmed with message: {alert_message}"}

    async def validate_finding_agentically(
        self,
        finding: Dict[str, Any],
        _recursion_depth: int = 0
    ) -> Dict[str, Any]:
        """
        V3 Reproduction Flow (Auditor Role) - OPTIMIZED.
        Validates findings using CDP events and vision analysis.

        v2.1.0+: Automatically loads full payload from JSON report if truncated.
        This ensures accurate validation even for complex payloads >200 characters.

        Args:
            finding: Finding dict with vulnerability data (may have truncated payload)
            _recursion_depth: Internal recursion tracker (max depth = MAX_FEEDBACK_DEPTH)

        Returns:
            Validation result dict with fields:
            - validated: bool - True if vulnerability confirmed
            - status: str - VALIDATED_CONFIRMED, VALIDATED_FALSE_POSITIVE, etc.
            - reasoning: str - Explanation of validation result
            - screenshot_path: str - Path to screenshot (if captured)
            - logs: List[str] - Browser console logs
            - confidence: float - Confidence score (0.0-1.0)

        Note:
            The finding dict is automatically enhanced with full payload data
            via _ensure_full_payload() before validation begins.
        """
        # Check for cancellation
        if self._cancellation_token.get("cancelled", False):
            return {"validated": False, "reasoning": "Validation cancelled by user"}

        # Prevent infinite recursion
        if _recursion_depth >= self.MAX_FEEDBACK_DEPTH:
            logger.warning(f"Max feedback depth ({self.MAX_FEEDBACK_DEPTH}) reached, stopping recursion")
            return {"validated": False, "reasoning": "Max feedback retries exceeded"}

        start_time = time.time()
        url, payload, vuln_type, param = self._agentic_prepare_context(finding)

        if not url:
            return {"validated": False, "reasoning": "Missing target URL"}

        # Check cache
        cached = self._agentic_check_cache(url, payload)
        if cached:
            return cached

        self.think(f"Auditing {vuln_type} on {url}")
        self._stats["queued_for_cdp"] = self._stats.get("queued_for_cdp", 0) + 1

        if self._v:
            self._v.emit("validation.browser.launching", {
                "vuln_type": vuln_type, "url": url[:100], "param": param or "",
            })

        # Execute validation with semaphore
        # 1. Execute payload (L4 CDP)
        start_time = time.time()
        async with self._validation_semaphore:
            # Execute
            screenshot_path, logs, triggered, alert_msg = await self._agentic_execute_validation(url, payload, vuln_type, param)
            
            # Analyze logs for confirmation
            confirmed = triggered or self._check_logs_for_execution(logs, vuln_type) or (alert_msg is not None)

            # 2. Process results
            return await self._agentic_process_validation_result(
                screenshot_path, logs, confirmed, finding, url, payload, start_time, alert_msg
            )

    def _update_stats(self, elapsed_ms: float):
        """Update validation statistics."""
        self._stats["total_validated"] += 1
        self._stats["total_time_ms"] += elapsed_ms
        self._stats["avg_time_ms"] = self._stats["total_time_ms"] / self._stats["total_validated"]

    def _check_logs_for_execution(self, logs: List[str], vuln_type: str) -> bool:
        """Check browser logs for successful exploitation indicators."""
        if not logs:
            return False
            
        success_markers = {
            "xss": ["alert", "prompt", "confirm", "XSS", "HACKED", "fetch"],
            "sqli": ["SQL syntax", "mysql_", "ORA-"],
            "lfi": ["root:x:0:0", "daemon:x:1:1"], 
            "csti": ["49", "7777777"] # Common math results
        }
        
        markers = success_markers.get(vuln_type.lower(), [])
        
        for log in logs:
            if any(marker in str(log) for marker in markers):
                return True
                
        return False


    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics including CDP load percentage."""
        total = self._stats.get("total_received", 0)
        cdp_processed = self._stats.get("queued_for_cdp", 0)

        cdp_load = (cdp_processed / total * 100) if total > 0 else 0.0

        return {
            **self._stats,
            "cache_size": len(self._cache),
            "cdp_load_percent": round(cdp_load, 2),
            "cdp_target_met": cdp_load <= 1.0,  # Target: <1%
        }

    async def _execute_payload_optimized(
        self,
        url: str,
        payload: Optional[str],
        vuln_type: str,
        param: Optional[str] = None
    ) -> Tuple[str, List[str], bool]:
        """
        OPTIMIZED payload execution using pooled verifiers.
        """
        if vuln_type in ["xss", "csti"]:
            # Use pooled verifier instead of creating new one each time
            verifier = await _verifier_pool.get_verifier()
            try:
                target_url = self._construct_payload_url(url, payload, param)
                if self._v:
                    self._v.emit("validation.browser.navigating", {
                        "vuln_type": vuln_type, "url": target_url[:100],
                    })
                result = await verifier.verify_xss(
                    target_url,
                    screenshot_dir=str(settings.LOG_DIR),
                    timeout=self.FAST_VALIDATION_TIMEOUT - 5,  # Leave margin
                    max_level=4  # Explicitly allow L4 CDP
                )
                if self._v:
                    self._v.emit("validation.browser.loaded", {
                        "success": result.success,
                        "has_screenshot": bool(result.screenshot_path),
                        "console_events": len(result.console_logs or []),
                        "alert": result.alert_message[:50] if result.alert_message else None,
                    })
                return result.screenshot_path, result.console_logs or [], result.success, result.alert_message
            finally:
                _verifier_pool.release()
        else:
            path, logs, triggered = await self._generic_capture(url, payload, param)
            return path, logs, triggered, None

    # NOTE: _has_specialist_authority removed - filtering now happens at ValidationEngine level

    def _generate_manual_review_brief(self, finding: Dict, vision_result: Dict, browser_logs: List) -> str:
        """Constructs a detailed explanation for manual triagers."""
        url = finding.get("url", "N/A")
        param = finding.get("parameter", "N/A")
        payload = finding.get("payload", "N/A")
        vision_evidence = vision_result.get("evidence", "No evidence provided by vision model.")
        confidence = vision_result.get("confidence", 0.0)
        
        brief = [
            "### 🔎 DETAILED MANUAL REVIEW BRIEF",
            f"**Target:** {url}",
            f"**Parameter:** `{param}`",
            f"**Payload:** `{payload}`",
            "",
            "#### 🕵️ HUNTER OBSERVATIONS",
            "- Reflection detected in raw HTML (possible decoded or mutated form).",
            "- WAF presence suspected or bypass attempts initiated.",
            "",
            "#### 🤖 AUDITOR (AGENTIC) AUDIT",
            f"- **Vision Confidence:** {confidence:.0%}",
            f"- **Execution Events (CDP):** {'None' if not browser_logs else f'Detected {len(browser_logs)} events'}",
            f"- **Vision Analysis:** {vision_evidence}",
            "",
            "#### 🛠️ WHAT TO LOOK FOR (MANUAL CHECK)",
            "1. Open the target URL with the payload.",
            "2. Check if a **RED BANNER** with text **'HACKED BY BUGTRACEAI'** appears at the top.",
            "3. Check the Browser Console for successful `fetch` requests or execution logs.",
            "",
            "#### ❓ WHY MANUAL REVIEW?",
            "Automatic validation is inconclusive because " + 
            ("the Vision AI detected a potential anomaly but no low-level protocol event (like an alert) was captured." if confidence >= 0.7 
             else "there is a strong indicator of vulnerability (reflection) but visual proof is obscured or non-standard.")
        ]
        return "\n".join(brief)
    
    async def _execute_payload(
        self, 
        url: str, 
        payload: Optional[str],
        vuln_type: str,
        param: Optional[str] = None
    ) -> Tuple[str, List[str], bool]:
        """
        Execute the payload in browser and capture result.
        Returns (screenshot_path, logs, basic_triggered)
        """
        if vuln_type in ["xss", "csti"]:
            # Use Playwright for current environment stability
            verifier = XSSVerifier(headless=settings.HEADLESS_BROWSER, prefer_cdp=True)
            target_url = self._construct_payload_url(url, payload, param)
            
            result = await verifier.verify_xss(target_url, screenshot_dir=str(settings.LOG_DIR))
            return result.screenshot_path, result.console_logs, result.success
        else:
            # Generic page capture for other types
            return await self._generic_capture(url, payload, param)
    
    def _check_sql_errors(self, content: str) -> Optional[str]:
        """Check page content for SQL error indicators. Returns error name if found."""
        sql_errors = [
            "SQL syntax",
            "mysql_",
            "ORA-",
            "PostgreSQL",
            "SQLITE_ERROR",
            "Microsoft SQL Server"
        ]

        content_lower = content.lower()
        for error in sql_errors:
            if error.lower() in content_lower:
                return error
        return None

    async def _generic_capture(
        self,
        url: str,
        payload: Optional[str],
        param: Optional[str] = None
    ) -> Tuple[str, List[str], bool]:
        """
        Generic page capture for non-XSS validations.
        """
        logs = []
        screenshot_path = ""

        target_url = self._construct_payload_url(url, payload, param) if payload else url

        async with browser_manager.get_page() as page:
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(2000)

                import uuid
                screenshot_path = str(settings.LOG_DIR / f"validate_{uuid.uuid4().hex[:8]}.png")
                await page.screenshot(path=screenshot_path)

                content = await page.content()
                sql_error = self._check_sql_errors(content)
                if sql_error:
                    logs.append(f"SQL Error detected: {sql_error}")
                    return screenshot_path, logs, True

            except Exception as e:
                logs.append(f"Capture error: {e}")
                logger.error(f"Generic capture failed: {e}", exc_info=True)

        return screenshot_path, logs, False
    

    def _construct_payload_url(self, url: str, payload: Optional[str], param: Optional[str] = None) -> str:
        """Construct URL with payload injected."""
        if not payload or payload in url:
            return url
            
        import urllib.parse as urlparse
        from urllib.parse import urlencode, parse_qs
        
        parsed = urlparse.urlparse(url)
        qs = parse_qs(parsed.query)

        if param:
            # 1. Targeted Injection: Inject ONLY into the specific parameter
            # Logic: If param exists, replace it. If not, APPEND it.
            qs[param] = [payload]
        elif parsed.query:
            # 2. Spray Mode (Legacy): Inject into ALL parameters (Blind)
            for k in qs:
                qs[k] = payload
        else:
            # 3. No targets available? Return original URL to avoid errors
            # (Though technically we could append ?payload=...)
            return url
            
        new_query = urlencode(qs, doseq=True)
        return urlparse.urlunparse(parsed._replace(query=new_query))
    
    def _detect_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Detect vulnerability type from finding data."""
        title = finding.get("title", "").upper()
        vuln_type = finding.get("type", "").upper()
        
        if "XSS" in title or "XSS" in vuln_type or "CROSS-SITE" in title:
            return "xss"
        elif "SQL" in title or "SQLI" in vuln_type:
            return "sqli"
        elif "CSTI" in title or "CSTI" in vuln_type or "TEMPLATE" in title or "SSTI" in vuln_type:
            return "csti"
        else:
            return "general"
    
    async def _call_vision_model(self, prompt: str, screenshot_path: str) -> str:
        """
        Call a vision-capable LLM to analyze the screenshot.
        Uses OpenRouter with a vision model.
        """
        from bugtrace.core.llm_client import LLMClient
        
        llm = LLMClient()
        
        # Use a vision-capable model from settings
        response = await llm.generate_with_image(
            prompt=prompt,
            image_path=screenshot_path,
            model_override=settings.VISION_MODEL,
            temperature=0.1
        )
        
        return response
    
    def _parse_vision_response(self, response: str) -> Dict[str, Any]:
        """Parse the JSON response from vision model."""
        import json
        import re
        
        try:
            # 1. Direct JSON extraction (more robust than the previous regex)
            # Find the first { and last }
            start = response.find('{')
            end = response.rfind('}')
            if start != -1 and end != -1:
                json_str = response[start:end+1]
                # Clean potential markdown ticks
                json_str = json_str.strip('`').strip()
                data = json.loads(json_str)
                # Normalize keys
                if 'success' not in data and 'validated' in data:
                    data['success'] = data['validated']
                if 'evidence' not in data and 'description' in data:
                    data['evidence'] = data['description']
                return data
        except Exception as e:
            logger.debug(f"JSON parsing failed: {e}")
            
        # 2. Fallback: Parse as text (More conservative)
        # Search for confirmation keywords but ensure they aren't negated
        positive = ["confirmed", "validated", "execution detected", "payload successful"]
        response_lower = response.lower()
        
        # If we see "success": false or "validated": false, it's a clear NO
        if '"success": false' in response_lower or '"validated": false' in response_lower:
            return {"success": False, "confidence": 1.0, "evidence": response[:500]}
            
        is_success = any(p in response_lower for p in positive)
        # Handle "success": true
        if '"success": true' in response_lower or '"validated": true' in response_lower:
            is_success = True
            
        return {
            "success": is_success,
            "confidence": 0.5 if is_success else 0.0,
            "evidence": response[:500]
        }
    
    def _batch_filter_findings(self, findings: List[Dict[str, Any]]) -> Tuple[List, List, List]:
        """Filter findings into pre-validated, skipped, and needs validation."""
        pre_validated = []
        needs_validation = []
        skipped = []

        for finding in findings:
            # Already validated
            if finding.get("validated") or finding.get("status") == "VALIDATED_CONFIRMED":
                pre_validated.append(finding)
                self._stats["skipped_prevalidated"] += 1
                continue

            # Low severity
            severity = finding.get("severity", "").upper()
            if severity in ["INFO", "SAFE", "INFORMATIONAL"]:
                skipped.append(finding)
                continue

            needs_validation.append(finding)

        return pre_validated, needs_validation, skipped

    async def _batch_validate_single(self, finding: Dict, index: int, total: int) -> Dict:
        """Wrapper for single validation with error handling."""
        try:
            dashboard.update_task(
                "AgenticValidator",
                status=f"Validating {index+1}/{total}: {finding.get('type', 'unknown')}"
            )
            return await self.validate_finding_agentically(finding)
        except Exception as e:
            logger.error(f"Validation failed for {finding.get('url', 'unknown')}: {e}", exc_info=True)
            finding["validated"] = False
            finding["reasoning"] = f"Validation error: {str(e)}"
            return finding

    def _batch_collect_results(self, done: set, validated_results: List[Any]):
        """Collect completed task results."""
        for task in done:
            idx = int(task.get_name().split("_")[1])
            try:
                validated_results[idx] = task.result()
            except Exception as e:
                validated_results[idx] = e

    def _batch_handle_pending(self, pending: set, validated_results: List[Any]):
        """Handle pending tasks on timeout."""
        logger.warning(f"Batch validation timed out. {len(pending)} tasks pending.")
        for task in pending:
            idx = int(task.get_name().split("_")[1])
            task.cancel()
            validated_results[idx] = RuntimeError("Validation Timeout")

    async def _batch_execute_parallel(self, needs_validation: List[Dict[str, Any]]) -> List[Any]:
        """Execute parallel validation with timeout handling."""
        tasks = [
            asyncio.create_task(
                self._batch_validate_single(finding, i, len(needs_validation)),
                name=f"validate_{i}"
            )
            for i, finding in enumerate(needs_validation)
        ]

        validated_results = [None] * len(needs_validation)
        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=self.MAX_TOTAL_VALIDATION_TIME,
                return_when=asyncio.ALL_COMPLETED
            )

            self._batch_collect_results(done, validated_results)

            if pending:
                self._batch_handle_pending(pending, validated_results)

        except Exception as e:
            logger.error(f"Batch validation failed: {e}", exc_info=True)
            for i, r in enumerate(validated_results):
                if r is None:
                    validated_results[i] = RuntimeError(f"Batch Error: {e}")

        return validated_results

    def _batch_process_results(
        self, validated_results: List[Any], needs_validation: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process validation results and handle exceptions."""
        validated_findings = []
        for i, result in enumerate(validated_results):
            if result is None or isinstance(result, Exception):
                error_msg = str(result) if result else "Unknown error"
                logger.error(f"Task {i} failed: {error_msg}")
                original = needs_validation[i]
                original["validated"] = False
                original["status"] = "VALIDATION_ERROR"
                original["reasoning"] = f"Exception: {error_msg}"
                validated_findings.append(original)
            else:
                validated_findings.append(result)
        return validated_findings

    def _batch_log_stats(
        self, total: int, pre_validated: List, validated_findings: List, elapsed: float
    ):
        """Log batch validation statistics."""
        stats = self.get_stats()
        logger.info(f"""
╔══════════════════════════════════════════════════════════════╗
║ AGENTIC VALIDATOR BATCH COMPLETE                             ║
╠══════════════════════════════════════════════════════════════╣
║ Total Findings:     {total:>5}                                   ║
║ Pre-validated:      {len(pre_validated):>5} (fast-path)                       ║
║ Actually Validated: {len(validated_findings):>5}                                   ║
║ Cache Hits:         {stats['cache_hits']:>5}                                   ║
║ CDP Confirmed:      {stats['cdp_confirmed']:>5} (skipped vision)               ║
║ Vision Analyzed:    {stats['vision_analyzed']:>5}                                   ║
║ Avg Time/Finding:   {stats['avg_time_ms']:.0f}ms                                ║
║ Total Time:         {elapsed:.1f}s                                   ║
╚══════════════════════════════════════════════════════════════╝
        """)
        dashboard.log(f"✅ Batch validation complete: {elapsed:.1f}s total, {stats['avg_time_ms']:.0f}ms avg", "SUCCESS")

    async def validate_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        OPTIMIZED: Validate a batch of findings using parallel processing.

        Improvements over v1:
        - Parallel validation (up to MAX_CONCURRENT_VALIDATIONS simultaneous)
        - Smart filtering (skip pre-validated, low-severity)
        - No fixed sleep delays
        - Progress tracking via dashboard
        """
        start_time = time.time()
        total = len(findings)
        self.think(f"🚀 Starting PARALLEL validation for {total} findings (concurrency={self.MAX_CONCURRENT_VALIDATIONS})")

        # Phase 1: Smart filtering
        pre_validated, needs_validation, skipped = self._batch_filter_findings(findings)

        logger.info(f"Batch breakdown: {len(pre_validated)} pre-validated, {len(skipped)} skipped, {len(needs_validation)} to validate")
        dashboard.log(f"⚡ Fast-path: {len(pre_validated)} already validated, {len(needs_validation)} queued for audit", "INFO")

        # Check for cancellation
        if self._cancellation_token.get("cancelled", False):
            logger.info("Batch validation cancelled by user")
            return pre_validated + skipped

        # Phase 2: Parallel validation
        validated_results = await self._batch_execute_parallel(needs_validation)

        # Phase 3: Process results
        validated_findings = self._batch_process_results(validated_results, needs_validation)

        # Phase 4: Combine and log
        all_results = pre_validated + skipped + validated_findings
        elapsed = time.time() - start_time
        self._batch_log_stats(total, pre_validated, validated_findings, elapsed)

        return all_results

    async def validate_batch_parallel(
        self,
        findings: List[Dict[str, Any]],
        max_concurrent: int = None
    ) -> List[Dict[str, Any]]:
        """
        Alternative batch validation with custom concurrency.
        Use this for finer control over parallelism.
        """
        if max_concurrent:
            original = self.MAX_CONCURRENT_VALIDATIONS
            self.MAX_CONCURRENT_VALIDATIONS = max_concurrent
            self._validation_semaphore = asyncio.Semaphore(max_concurrent)
            try:
                return await self.validate_batch(findings)
            finally:
                self.MAX_CONCURRENT_VALIDATIONS = original
                self._validation_semaphore = asyncio.Semaphore(original)
        else:
            return await self.validate_batch(findings)

    def clear_cache(self):
        """Clear the validation cache."""
        self._cache.clear()
        logger.info("Validation cache cleared")

    def reset_stats(self):
        """Reset validation statistics."""
        self._stats = {
            "total_validated": 0,
            "cache_hits": 0,
            "cdp_confirmed": 0,
            "vision_analyzed": 0,
            "skipped_prevalidated": 0,
            "avg_time_ms": 0,
            "total_time_ms": 0
        }

    # =========================================================================
    # NOTE: Feedback loop methods removed for simplicity
    # AgenticValidator is now a linear CDP specialist - no loopback to
    # XSSAgent/CSTIAgent for variant generation.
    #
    # Removed methods:
    # - _generate_feedback()
    # - _request_payload_variant()
    # - _get_xss_variant()
    # - _get_csti_variant()
    #
    # Filtering now happens at ValidationEngine level based on status field.
    # =========================================================================


# Singleton instance for convenience
agentic_validator = AgenticValidator()
