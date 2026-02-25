"""
Validation Agent

Thin orchestrator for AI-powered vulnerability validation.
Delegates pure logic to core.py and I/O to browser.py.

Extracted from agentic_validator.py for modularity.
"""

import asyncio
import time
from typing import Dict, List, Any, Tuple, Optional, Set
from pathlib import Path
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager, BrowserManager
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus as global_event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.core.validation_metrics import validation_metrics
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.core.verbose_events import create_emitter

from bugtrace.agents.validation.core import (
    ValidationCache,
    VerifierPool,
    detect_vuln_type,
    check_logs_for_execution,
    parse_vision_response,
    validate_alert_impact,
    construct_payload_url,
    generate_structural_key,
    generate_manual_review_brief,
    batch_filter_findings,
    select_best_verification_method,
    load_prompts,
)
from bugtrace.agents.validation.browser import (
    execute_payload_optimized,
    generic_capture,
    validate_static_xss,
    call_vision_model,
    _verifier_pool,
)


class AgenticValidator(BaseAgent):
    """
    AI-powered validator using vision + reasoning to validate vulnerabilities.

    This is a thin orchestrator that delegates:
    - Pure validation logic/prompts to validation.core
    - Browser I/O operations to validation.browser
    """

    # Configuration
    MAX_CONCURRENT_VALIDATIONS = 3
    SKIP_VISION_ON_CDP_CONFIRM = True
    ENABLE_CACHE = True
    FAST_VALIDATION_TIMEOUT = 20.0
    MAX_TOTAL_VALIDATION_TIME = 600.0
    MAX_FEEDBACK_DEPTH = 2

    def __init__(self, event_bus=None, cancellation_token=None):
        super().__init__("AgenticValidator", "AI Vision Validator", event_bus, agent_id="agentic_validator")
        self.max_retries = 3
        self.validation_prompts = load_prompts(self.system_prompt)

        self._cancellation_token = cancellation_token or {"cancelled": False}

        # Cache
        self._cache = ValidationCache(max_size=150)

        # Validation semaphore
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores, get_validation_semaphore
            phase_semaphores.initialize()
            self._validation_semaphore = get_validation_semaphore()
        except ImportError:
            self._validation_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_VALIDATIONS)

        # Statistics
        self._stats = {
            "total_validated": 0,
            "cache_hits": 0,
            "cdp_confirmed": 0,
            "vision_analyzed": 0,
            "skipped_prevalidated": 0,
            "avg_time_ms": 0,
            "total_time_ms": 0,
            "total_received": 0,
            "skipped_confirmed": 0,
            "queued_for_cdp": 0,
            "cdp_rejected": 0,
            "cdp_skipped_duplicate": 0,
        }

        # Structural deduplication
        self._structural_keys: Set[str] = set()
        self._structural_lock = asyncio.Lock()

        self.llm_client = llm_client

        # Event subscriptions
        self._event_bus = event_bus or global_event_bus
        if self._event_bus:
            self._event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                self.handle_vulnerability_detected
            )
            logger.info(f"[{self.name}] Subscribed to vulnerability_detected events")

        self._v = None

        # Validation queue
        self._pending_queue: asyncio.Queue = asyncio.Queue()
        self._queue_processor_task: Optional[asyncio.Task] = None

    # =====================================================================
    # EVENT HANDLING
    # =====================================================================

    async def handle_vulnerability_detected(self, data: Dict[str, Any]) -> None:
        """Handle vulnerability_detected events from specialist agents."""
        status = data.get("status", "")
        specialist = data.get("specialist", "unknown")
        finding = data.get("finding", {})

        if not self._v:
            sc = data.get("scan_context", "")
            if sc:
                self._v = create_emitter("AgenticValidator", sc)

        self._stats["total_received"] = self._stats.get("total_received", 0) + 1

        if self._v:
            self._v.emit("validation.finding.received", {
                "specialist": specialist, "status": status,
                "type": finding.get("type", "unknown"), "param": finding.get("parameter", ""),
            })

        if status != ValidationStatus.PENDING_VALIDATION.value:
            self._stats["skipped_confirmed"] = self._stats.get("skipped_confirmed", 0) + 1
            logger.debug(f"[{self.name}] Skipping {specialist} finding (status={status})")
            return

        # Structural deduplication
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        vuln_type = finding.get("type", specialist).upper()

        struct_key = generate_structural_key(vuln_type, url, param)

        async with self._structural_lock:
            if struct_key in self._structural_keys:
                self._stats["cdp_skipped_duplicate"] += 1
                if self._v:
                    self._v.emit("validation.finding.dedup_skipped", {
                        "type": vuln_type, "param": param, "struct_key": struct_key,
                    })
                logger.info(f"[{self.name}] STRUCTURAL DEDUPLICATION: Skipping redundant {vuln_type} on {param}")
                return

            self._structural_keys.add(struct_key)

        self._stats["queued_for_cdp"] = self._stats.get("queued_for_cdp", 0) + 1
        logger.info(f"[{self.name}] Queuing {specialist} finding for CDP validation ({vuln_type} on {param})")

        await self._pending_queue.put({
            "specialist": specialist, "finding": finding,
            "scan_context": data.get("scan_context", ""),
        })

        if self._v:
            self._v.emit("validation.finding.queued", {
                "specialist": specialist, "type": vuln_type, "param": param,
                "queue_depth": self._pending_queue.qsize(),
            })

    # =====================================================================
    # QUEUE PROCESSOR
    # =====================================================================

    async def start_queue_processor(self) -> None:
        """Start the background queue processor."""
        if self._queue_processor_task is None or self._queue_processor_task.done():
            self._queue_processor_task = asyncio.create_task(self._process_pending_queue())
            if self._v:
                self._v.emit("validation.started", {"queue_size": self._pending_queue.qsize()})
            logger.info(f"[{self.name}] Started queue processor")

    async def stop_queue_processor(self) -> None:
        """Stop the background queue processor."""
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

        validation_metrics.log_reduction_summary()

    async def _process_pending_queue(self) -> None:
        """Process PENDING_VALIDATION findings from queue."""
        while True:
            try:
                item = await asyncio.wait_for(self._pending_queue.get(), timeout=30.0)
                await self._validate_and_emit(item)
                self._pending_queue.task_done()
            except asyncio.TimeoutError:
                if self._cancellation_token.get("cancelled", False):
                    break
            except asyncio.CancelledError:
                logger.info(f"[{self.name}] Queue processor cancelled")
                break
            except Exception as e:
                logger.error(f"[{self.name}] Error in queue processor: {e}", exc_info=True)
                if self._pending_queue.qsize() > 0:
                    self._pending_queue.task_done()

    # =====================================================================
    # VALIDATION PIPELINE
    # =====================================================================

    async def _validate_and_emit(self, item: Dict[str, Any]) -> None:
        """Validate a finding via CDP and emit result event."""
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

        finding_with_full_payload = self._ensure_full_payload(finding)

        finding_for_validation = {
            "url": finding_with_full_payload.get("url", ""),
            "payload": finding_with_full_payload.get("payload", ""),
            "parameter": finding_with_full_payload.get("parameter", ""),
            "type": finding_with_full_payload.get("type", specialist.upper()),
            "evidence": finding_with_full_payload.get("evidence", {}),
            "_report_files": finding_with_full_payload.get("_report_files", {}),
        }

        # Static XSS check
        static_result = await validate_static_xss(finding_for_validation)
        if static_result:
            if self._v:
                self._v.emit("validation.static.result", {"validated": True, "specialist": specialist})
            logger.info(f"[{self.name}] Static XSS validated. Skipping browser.")
            result = static_result
        else:
            result = await self.validate_finding_agentically(finding_for_validation)

        # Emit result
        if result.get("validated", False):
            event_type = EventType.FINDING_VALIDATED
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
            self._stats["cdp_rejected"] = self._stats.get("cdp_rejected", 0) + 1
            if self._v:
                self._v.emit("validation.finding.rejected", {
                    "specialist": specialist,
                    "type": finding.get("type", specialist).upper(),
                    "param": finding.get("parameter", ""),
                    "reason": result.get("reasoning", "")[:100],
                })

        status = "VALIDATED" if result.get("validated", False) else "REJECTED_FP"

        if self._event_bus:
            await self._event_bus.emit(event_type, {
                "specialist": specialist, "finding": finding,
                "validation_result": {
                    "status": status,
                    "reasoning": result.get("reasoning", ""),
                    "screenshot_path": result.get("screenshot_path"),
                    "confidence": result.get("confidence", 0.0),
                },
                "scan_context": scan_context,
            })
            logger.info(f"[{self.name}] Emitted {event_type.value} for {specialist}")

    def _ensure_full_payload(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure finding has full payload loaded from JSON report."""
        original_payload = finding.get("payload", "")
        original_len = len(original_payload)

        if original_len < 199:
            return finding

        if not finding.get("_report_files"):
            logger.warning(
                f"[AgenticValidator] Payload is {original_len} chars but no _report_files metadata."
            )
            return finding

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
                    f"[AgenticValidator] Loaded FULL payload from JSON: "
                    f"{full_len} chars (was {original_len} chars truncated)"
                )
                return full_finding
            else:
                return finding
        except Exception as e:
            logger.error(f"[AgenticValidator] Failed to load full payload from JSON: {e}", exc_info=True)
            return finding

    def _prepare_context(self, finding: Dict[str, Any]) -> Tuple[str, Optional[str], str, Optional[str]]:
        """Prepare validation context from finding."""
        finding = self._ensure_full_payload(finding)

        url = finding.get("url")
        payload = finding.get("payload")
        param = finding.get("parameter") or finding.get("param")
        vuln_type = detect_vuln_type(finding)

        if finding.get("verification_methods"):
            url, payload = select_best_verification_method(finding, url)

        return url, payload, vuln_type, param

    async def validate_finding_agentically(
        self, finding: Dict[str, Any], _recursion_depth: int = 0,
    ) -> Dict[str, Any]:
        """V3 Reproduction Flow - validates findings using CDP events and vision."""
        if self._cancellation_token.get("cancelled", False):
            return {"validated": False, "reasoning": "Validation cancelled by user"}

        if _recursion_depth >= self.MAX_FEEDBACK_DEPTH:
            return {"validated": False, "reasoning": "Max feedback retries exceeded"}

        start_time = time.time()
        url, payload, vuln_type, param = self._prepare_context(finding)

        if not url:
            return {"validated": False, "reasoning": "Missing target URL"}

        # Check cache
        if self.ENABLE_CACHE:
            cached = self._cache.get(url, payload)
            if cached:
                self._stats["cache_hits"] += 1
                if self._v:
                    self._v.emit("validation.cache.hit", {"url": url[:80]})
                logger.info(f"Cache hit for {url[:50]}...")
                return cached
            if self._v:
                self._v.emit("validation.cache.miss", {"url": url[:80]})

        self.think(f"Auditing {vuln_type} on {url}")
        self._stats["queued_for_cdp"] = self._stats.get("queued_for_cdp", 0) + 1

        if self._v:
            self._v.emit("validation.browser.launching", {
                "vuln_type": vuln_type, "url": url[:100], "param": param or "",
            })

        # Execute with semaphore
        start_time = time.time()
        async with self._validation_semaphore:
            try:
                screenshot_path, logs, triggered, alert_msg = await asyncio.wait_for(
                    execute_payload_optimized(url, payload, vuln_type, param, verbose_emitter=self._v),
                    timeout=self.FAST_VALIDATION_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.warning(f"Validation timeout for {url[:50]}...")
                screenshot_path, logs, triggered, alert_msg = None, ["TIMEOUT"], False, None
            except Exception as e:
                logger.error(f"Validation error: {e}", exc_info=True)
                screenshot_path, logs, triggered, alert_msg = None, [], False, None

            confirmed = triggered or check_logs_for_execution(logs, vuln_type) or (alert_msg is not None)

            return await self._process_validation_result(
                screenshot_path, logs, confirmed, finding, url, payload, start_time, alert_msg
            )

    async def _process_validation_result(
        self, screenshot_path, logs, basic_triggered, finding, url, payload, start_time, alert_message=None
    ) -> Dict[str, Any]:
        """Process validation result and build final response."""
        impact_analysis = None
        if alert_message:
            impact_analysis = validate_alert_impact(alert_message, url)
            logger.info(f"Impact Analysis: {impact_analysis}")

        if basic_triggered:
            if self._v:
                self._v.emit("validation.cdp.confirmed", {
                    "url": url[:100], "events": len(logs),
                    "alert": alert_message[:50] if alert_message else None,
                    "impact": impact_analysis.get("impact") if impact_analysis else None,
                })
            self._stats["cdp_confirmed"] += 1
            result = {
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "reasoning": f"Execution CONFIRMED: Low-level event triggered. Logs: {logs}",
                "screenshot_path": None,
                "logs": logs,
            }
            if self.ENABLE_CACHE:
                self._cache.set(url, payload, result)
            elapsed = (time.time() - start_time) * 1000
            self._update_stats(elapsed)
            logger.info(f"CDP confirmed in {elapsed:.0f}ms (skipped vision API)")
            if impact_analysis:
                result["impact"] = impact_analysis["impact"]
                result["reasoning"] += f" | {impact_analysis['reason']}"
            return result

        # Vision fallback
        if self._v:
            self._v.emit("validation.cdp.silent", {
                "url": url[:100],
                "has_screenshot": bool(screenshot_path and Path(screenshot_path).exists()),
                "console_events": len(logs),
            })
        if screenshot_path and Path(screenshot_path).exists():
            return await self._analyze_with_vision(finding, screenshot_path, logs)

        return {
            "validated": False,
            "status": "VALIDATED_FALSE_POSITIVE",
            "reasoning": "No execution evidence found in CDP logs or visual capture."
        }

    async def _analyze_with_vision(self, finding, screenshot_path, logs):
        """Analyze screenshot with vision and build result."""
        self.think("CDP silent. Invoking Vision Analysis...")
        self._stats["vision_analyzed"] += 1

        if self._v:
            self._v.emit("validation.vision.started", {
                "type": finding.get("type", "unknown"), "url": finding.get("url", "")[:100],
            })

        vision_result = await self.validate_with_vision(finding, screenshot_path)
        confidence = vision_result.get("confidence", 0.0)
        validated = vision_result.get("validated", False)

        if self._v:
            self._v.emit("validation.vision.result", {
                "validated": validated, "confidence": confidence,
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
            result["reasoning"] = generate_manual_review_brief(finding, vision_result, logs)
            self.think(f"SUSPICIOUS ({confidence:.0%}) - flagging for manual review")
        else:
            result["status"] = "VALIDATED_FALSE_POSITIVE"
            result["reasoning"] = vision_result.get("reasoning", "No evidence of execution found.")

        return result

    async def validate_with_vision(self, finding: Dict[str, Any], screenshot_path: str) -> Dict[str, Any]:
        """Use a vision LLM to analyze the screenshot and validate the finding."""
        vuln_type = detect_vuln_type(finding)
        prompt = self.validation_prompts.get(vuln_type, self.validation_prompts["general"])

        try:
            response = await call_vision_model(prompt, screenshot_path)
            result = parse_vision_response(response)

            finding["validated"] = result.get("success", False)
            finding["confidence"] = result.get("confidence", 0.0)
            finding["reasoning"] = result.get("evidence", "No clear evidence found in screenshot.")
            finding["validator_notes"] = response

            if finding["validated"]:
                self.think(f"CONFIRMED: {finding.get('url')} (confidence: {result.get('confidence')})")
            else:
                self.think(f"Could not confirm via vision: {finding.get('url')}")

        except Exception as e:
            logger.error(f"Vision validation failed: {e}", exc_info=True)
            finding["validated"] = False
            finding["reasoning"] = f"Vision validation error: {str(e)}"

        return finding

    # =====================================================================
    # BATCH VALIDATION
    # =====================================================================

    async def validate_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate a batch of findings using parallel processing."""
        start_time = time.time()
        total = len(findings)
        self.think(f"Starting PARALLEL validation for {total} findings (concurrency={self.MAX_CONCURRENT_VALIDATIONS})")

        pre_validated, needs_validation, skipped = batch_filter_findings(findings)
        self._stats["skipped_prevalidated"] += len(pre_validated)

        logger.info(f"Batch breakdown: {len(pre_validated)} pre-validated, {len(skipped)} skipped, {len(needs_validation)} to validate")
        dashboard.log(f"Fast-path: {len(pre_validated)} already validated, {len(needs_validation)} queued for audit", "INFO")

        if self._cancellation_token.get("cancelled", False):
            return pre_validated + skipped

        # Parallel validation
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
                tasks, timeout=self.MAX_TOTAL_VALIDATION_TIME, return_when=asyncio.ALL_COMPLETED,
            )
            for task in done:
                idx = int(task.get_name().split("_")[1])
                try:
                    validated_results[idx] = task.result()
                except Exception as e:
                    validated_results[idx] = e

            if pending:
                logger.warning(f"Batch validation timed out. {len(pending)} tasks pending.")
                for task in pending:
                    idx = int(task.get_name().split("_")[1])
                    task.cancel()
                    validated_results[idx] = RuntimeError("Validation Timeout")

        except Exception as e:
            logger.error(f"Batch validation failed: {e}", exc_info=True)
            for i, r in enumerate(validated_results):
                if r is None:
                    validated_results[i] = RuntimeError(f"Batch Error: {e}")

        # Process results
        validated_findings = []
        for i, result in enumerate(validated_results):
            if result is None or isinstance(result, Exception):
                original = needs_validation[i]
                original["validated"] = False
                original["status"] = "VALIDATION_ERROR"
                original["reasoning"] = f"Exception: {result}"
                validated_findings.append(original)
            else:
                validated_findings.append(result)

        all_results = pre_validated + skipped + validated_findings
        elapsed = time.time() - start_time

        stats = self.get_stats()
        logger.info(
            f"AGENTIC VALIDATOR BATCH COMPLETE: "
            f"Total={total}, Pre-validated={len(pre_validated)}, "
            f"Validated={len(validated_findings)}, "
            f"Cache={stats['cache_hits']}, CDP={stats['cdp_confirmed']}, "
            f"Vision={stats['vision_analyzed']}, "
            f"Avg={stats['avg_time_ms']:.0f}ms, Total={elapsed:.1f}s"
        )
        dashboard.log(f"Batch validation complete: {elapsed:.1f}s total, {stats['avg_time_ms']:.0f}ms avg", "SUCCESS")

        return all_results

    async def _batch_validate_single(self, finding: Dict, index: int, total: int) -> Dict:
        """Wrapper for single validation with error handling."""
        try:
            dashboard.update_task("AgenticValidator", status=f"Validating {index+1}/{total}: {finding.get('type', 'unknown')}")
            return await self.validate_finding_agentically(finding)
        except Exception as e:
            logger.error(f"Validation failed for {finding.get('url', 'unknown')}: {e}", exc_info=True)
            finding["validated"] = False
            finding["reasoning"] = f"Validation error: {str(e)}"
            return finding

    async def validate_batch_parallel(self, findings: List[Dict[str, Any]], max_concurrent: int = None) -> List[Dict[str, Any]]:
        """Alternative batch validation with custom concurrency."""
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

    # =====================================================================
    # LIFECYCLE
    # =====================================================================

    async def run_loop(self):
        """Typically triggered by orchestrator, not continuous."""
        pass

    async def stop(self):
        """Stop agent and queue processor."""
        await super().stop()
        await self.stop_queue_processor()

    # =====================================================================
    # STATS
    # =====================================================================

    def _update_stats(self, elapsed_ms: float):
        """Update validation statistics."""
        self._stats["total_validated"] += 1
        self._stats["total_time_ms"] += elapsed_ms
        self._stats["avg_time_ms"] = self._stats["total_time_ms"] / self._stats["total_validated"]

    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        total = self._stats.get("total_received", 0)
        cdp_processed = self._stats.get("queued_for_cdp", 0)
        cdp_load = (cdp_processed / total * 100) if total > 0 else 0.0

        return {
            **self._stats,
            "cache_size": len(self._cache),
            "cdp_load_percent": round(cdp_load, 2),
            "cdp_target_met": cdp_load <= 1.0,
        }

    def clear_cache(self):
        """Clear the validation cache."""
        self._cache.clear()
        logger.info("Validation cache cleared")

    def reset_stats(self):
        """Reset validation statistics."""
        self._stats = {
            "total_validated": 0, "cache_hits": 0, "cdp_confirmed": 0,
            "vision_analyzed": 0, "skipped_prevalidated": 0,
            "avg_time_ms": 0, "total_time_ms": 0,
        }


# Singleton instance for convenience
agentic_validator = AgenticValidator()
