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

class ValidatorBatchMixin:
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
        """Process validation results and handle exceptions.

        FUNCTIONAL MERGE (bug fix): the per-finding CDP result dicts produced by
        ``validate_finding_agentically`` only carry the verdict
        ({validated, status, reasoning, screenshot_path, logs}) and NOT the
        finding's identity keys (url/parameter/type). The downstream
        ``ValidationEngine._apply_cdp_results`` re-maps results back onto findings
        by ``(url, parameter, type)``; without these keys every result collapsed to
        ``("", "", "")``, the lookup always missed and a freshly CDP-CONFIRMED
        finding was overwritten to VALIDATED_FALSE_POSITIVE. We therefore overlay
        the verdict onto a *copy* of the original finding (no mutation) so the
        identity keys survive and the mapping resolves correctly.
        """
        validated_findings = []
        for i, result in enumerate(validated_results):
            original = needs_validation[i]
            if result is None or isinstance(result, Exception):
                error_msg = str(result) if result else "Unknown error"
                logger.error(f"Task {i} failed: {error_msg}")
                validated_findings.append({
                    **original,
                    "validated": False,
                    "status": "VALIDATION_ERROR",
                    "reasoning": f"Exception: {error_msg}",
                })
            else:
                validated_findings.append({**original, **result})
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
