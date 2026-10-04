"""LLM client shell mixin — extracted from llm_client for size policy."""

from __future__ import annotations

import os
import re
import time
import hashlib
import aiohttp
import json
import asyncio
import aiofiles
from typing import Optional, Dict, Any, List
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    LLMError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMParseError,
    LLMServiceUnavailableError,
    NetworkError,
    TimeoutError as BugTraceTimeoutError,
    ConnectionError as BugTraceConnectionError,
    JSONParseError,
    is_transient,
)
from bugtrace.core.llm_shell.types import (
    LLMHealthState,
    CB_FAILURE_THRESHOLD,
    CB_COOLDOWN_SECONDS,
    CB_DEGRADED_DELAY,
    CB_SUCCESS_THRESHOLD,
    LLM_TOTAL_TIMEOUT,
    LLM_CONNECT_TIMEOUT,
    ModelMetrics,
    TokenUsageTracker,
    VULNERABILITY_SCHEMA,
    _ProviderRateLimiter,
    _parse_rpm,
    sanitize_text,
)

logger = get_logger("core.llm_client")


class LLMCircuitMixin:
    def _check_circuit_breaker(self) -> tuple[bool, Optional[str]]:
        """Check circuit breaker state before making API call.

        Returns:
            Tuple of (should_proceed, reason_if_blocked)
            - (True, None): Proceed with API call
            - (False, "CIRCUIT_OPEN"): Circuit is open, use fallback
            - (True, "HALF_OPEN"): Circuit is half-open, probe request allowed
        """
        if self.health_state == LLMHealthState.CRITICAL:
            if time.time() < self.circuit_open_until:
                remaining = int(self.circuit_open_until - time.time())
                logger.warning(f"[Circuit Breaker] OPEN - {remaining}s remaining until probe")
                return (False, "CIRCUIT_OPEN")
            else:
                # Half-open: allow probe request
                logger.info("[Circuit Breaker] HALF-OPEN - Probing API...")
                return (True, "HALF_OPEN")

        return (True, None)

    async def _apply_degraded_throttling(self):
        """Apply throttling when in DEGRADED state."""
        if self.health_state == LLMHealthState.DEGRADED:
            logger.debug(f"[Circuit Breaker] DEGRADED state - throttling {CB_DEGRADED_DELAY}s")
            await asyncio.sleep(CB_DEGRADED_DELAY)

    def _record_circuit_failure(self, error: Exception):
        """Record failure and transition state machine if threshold reached."""
        self.consecutive_errors += 1
        self.consecutive_successes = 0
        self.last_failure_time = time.time()

        logger.error(
            f"[Circuit Breaker] Error detected ({self.consecutive_errors}/{CB_FAILURE_THRESHOLD}): {error}"
        )

        # State transitions based on consecutive errors
        if self.consecutive_errors >= CB_FAILURE_THRESHOLD:
            if self.health_state != LLMHealthState.CRITICAL:
                self.health_state = LLMHealthState.CRITICAL
                self.circuit_open_until = time.time() + CB_COOLDOWN_SECONDS
                dashboard.log(
                    f"[LLM] 🔴 API Unstable. Circuit Breaker OPEN for {CB_COOLDOWN_SECONDS}s.",
                    "ERROR"
                )
                logger.warning(
                    f"[Circuit Breaker] Transitioned to CRITICAL - circuit open until "
                    f"{time.strftime('%H:%M:%S', time.localtime(self.circuit_open_until))}"
                )
        elif self.consecutive_errors >= 2 and self.health_state == LLMHealthState.HEALTHY:
            # Transition to DEGRADED after 2 consecutive errors
            self.health_state = LLMHealthState.DEGRADED
            dashboard.log("[LLM] ⚠️ API Degraded. Throttling requests.", "WARN")
            logger.warning("[Circuit Breaker] Transitioned to DEGRADED")

    def _record_circuit_success(self):
        """Record success and potentially recover from degraded states."""
        previous_state = self.health_state
        self.consecutive_successes += 1
        self.consecutive_errors = 0

        # Recovery logic
        if self.health_state == LLMHealthState.CRITICAL:
            # Single success in half-open transitions to DEGRADED
            self.health_state = LLMHealthState.DEGRADED
            dashboard.log("[LLM] ⚠️ API Recovering. Moving to DEGRADED.", "WARN")
            logger.info("[Circuit Breaker] Transitioned from CRITICAL to DEGRADED (probe success)")

        elif self.health_state == LLMHealthState.DEGRADED:
            if self.consecutive_successes >= CB_SUCCESS_THRESHOLD:
                self.health_state = LLMHealthState.HEALTHY
                self.consecutive_successes = 0
                dashboard.log("[LLM] 🟢 API Recovered. Resuming normal operations.", "SUCCESS")
                logger.info("[Circuit Breaker] Transitioned to HEALTHY (full recovery)")

        if previous_state != self.health_state:
            logger.info(f"[Circuit Breaker] State transition: {previous_state} → {self.health_state}")

    def _get_fallback_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate safe fallback responses when circuit is open.

        Uses prompt keywords to determine appropriate fallback that won't break
        downstream JSON parsing or logic.
        """
        prompt_lower = prompt.lower()
        system_lower = (system_prompt or "").lower()
        combined = prompt_lower + " " + system_lower

        # CVSS scoring tasks - return conservative medium score (must check BEFORE payload/severity)
        if "cvss" in combined:
            logger.debug("[Fallback] CVSS scoring - returning conservative medium")
            return '{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "score": 5.4, "severity": "MEDIUM", "rationale": "LLM unavailable - conservative estimate", "cwe": null, "cve": null}'

        # Deduplication tasks - return empty findings to not filter anything
        if "deduplication" in combined or "dedupe" in combined or "duplicate" in combined:
            logger.debug("[Fallback] Deduplication task - returning empty findings")
            return '{"findings": [], "deduplicated": []}'

        # Validation/skeptic tasks - FAIL OPEN (assume real to not lose vulnerabilities)
        if any(kw in combined for kw in ["skeptic", "false positive", "validate", "confirm", "verify"]):
            logger.debug("[Fallback] Validation task - FAIL OPEN (CONFIRMED)")
            return '{"result": "CONFIRMED", "confidence": 1.0, "reason": "LLM unavailable - fail open"}'

        # Payload generation tasks
        if ("payload" in combined or "generate" in combined) and "xss" in combined:
            logger.debug("[Fallback] Payload generation - returning generic payloads")
            return '{"payloads": ["<script>alert(1)</script>", "{{7*7}}", "${7*7}"]}'

        # Analysis/classification tasks
        if "analyze" in combined or "classify" in combined:
            logger.debug("[Fallback] Analysis task - returning uncertain response")
            return '{"result": "uncertain", "confidence": 0.5, "reason": "LLM unavailable"}'

        # Risk assessment - return medium risk (conservative)
        if "risk" in combined or "severity" in combined:
            logger.debug("[Fallback] Risk assessment - returning medium")
            return '{"severity": "medium", "confidence": 0.5}'

        # Default: empty JSON object (safest)
        logger.debug("[Fallback] Unknown task type - returning empty JSON")
        return "{}"

    def get_health_status(self) -> Dict[str, Any]:
        """Get current circuit breaker health status for monitoring."""
        status = {
            "state": self.health_state,
            "consecutive_errors": self.consecutive_errors,
            "consecutive_successes": self.consecutive_successes,
        }

        if self.health_state == LLMHealthState.CRITICAL:
            remaining = max(0, self.circuit_open_until - time.time())
            status["circuit_open_remaining_seconds"] = int(remaining)

        if self.last_failure_time > 0:
            status["last_failure_ago_seconds"] = int(time.time() - self.last_failure_time)

        return status
