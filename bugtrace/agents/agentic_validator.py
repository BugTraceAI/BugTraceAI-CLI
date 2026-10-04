"""AgenticValidator — thin shell (mixins under agentic_validator_shell)."""

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

from bugtrace.agents.agentic_validator_shell.types import ValidationCache, VerifierPool, _verifier_pool
from bugtrace.agents.agentic_validator_shell.prompts import ValidatorPromptsMixin
from bugtrace.agents.agentic_validator_shell.queue import ValidatorQueueMixin
from bugtrace.agents.agentic_validator_shell.validate import ValidatorValidateMixin
from bugtrace.agents.agentic_validator_shell.agentic import ValidatorAgenticMixin
from bugtrace.agents.agentic_validator_shell.execute import ValidatorExecuteMixin
from bugtrace.agents.agentic_validator_shell.batch import ValidatorBatchMixin


class AgenticValidator(
    ValidatorPromptsMixin,
    ValidatorQueueMixin,
    ValidatorValidateMixin,
    ValidatorAgenticMixin,
    ValidatorExecuteMixin,
    ValidatorBatchMixin,
    BaseAgent,
):
    """Agentic validation specialist (composed mixins)."""

    # Fallback concurrency when phase_semaphores unavailable (stable peel)
    MAX_CONCURRENT_VALIDATIONS = 3

    # CDP validation tunables — read via self.* by the shell mixins (batch/agentic/
    # validate/execute). The peel dropped these from the class body; without them the
    # whole CDP confirm/reject stage AttributeError'd and every finding degraded to
    # VALIDATION_ERROR. Restored at stable values (agentic_validator.py:170-174).
    SKIP_VISION_ON_CDP_CONFIRM = True    # early-exit optimization once CDP confirms
    ENABLE_CACHE = True                  # result caching
    FAST_VALIDATION_TIMEOUT = 20.0       # per-finding fast-path timeout (s)
    MAX_TOTAL_VALIDATION_TIME = 600.0    # global CDP validation budget (s)
    MAX_FEEDBACK_DEPTH = 2               # max recursion depth for the feedback loop

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

__all__ = ["AgenticValidator", "ValidationCache", "VerifierPool", "_verifier_pool"]
