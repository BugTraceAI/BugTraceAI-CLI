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

class ValidatorValidateMixin:
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
