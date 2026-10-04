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

class ValidatorAgenticMixin:
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
