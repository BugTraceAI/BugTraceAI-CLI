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

class ValidatorQueueMixin:
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

    async def run_loop(self):
        """Typically triggered by orchestrator, not continuous."""
        pass

    async def stop(self):
        """Stop agent and queue processor (v2.6 fix: proper lifecycle management)."""
        await super().stop()
        await self.stop_queue_processor()
