"""
Consolidation Agent

Thin orchestrator for the ThinkingConsolidationAgent.
Delegates pure logic to core.py, prompts.py, and I/O to processing.py.

Extracted from thinking_consolidation_agent.py for modularity.
"""

import asyncio
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.queue import queue_manager, SPECIALIST_QUEUES
from bugtrace.core.config import settings
from bugtrace.core.dedup_metrics import dedup_metrics, get_dedup_summary

from bugtrace.agents.consolidation.core import (
    DeduplicationCache,
    classify_finding as _classify_finding,
    classify_and_prioritize as _classify_and_prioritize,
)
from bugtrace.agents.consolidation.prompts import (
    initialize_embeddings as _initialize_embeddings,
    classify_with_embeddings as _classify_with_embeddings,
)
from bugtrace.agents.consolidation.processing import (
    process_finding as _process_finding,
    process_batch_items as _process_batch_items,
)


class ThinkingConsolidationAgent(BaseAgent):
    """
    Evaluation phase coordinator for the v2.3 5-phase pipeline.

    Subscribes to url_analyzed events, deduplicates findings,
    classifies by vulnerability type, prioritizes, and distributes
    to specialist queues.

    This is a thin orchestrator that delegates:
    - Pure classification/priority logic to consolidation.core
    - Embeddings classification to consolidation.prompts
    - I/O operations to consolidation.processing
    """

    def __init__(self, scan_context: str = None, scan_dir: Path = None):
        super().__init__(
            name="ThinkingConsolidationAgent",
            role="Evaluation Coordinator",
            agent_id="thinking_consolidation_agent"
        )

        self.scan_context = scan_context or f"thinking_{id(self)}"
        self.scan_id: Optional[int] = None

        # Scan directory for persistence
        self.scan_dir = scan_dir
        self._queues_dir_cached = None
        self._queues_initialized = False

        # Deduplication cache
        self._dedup_cache = DeduplicationCache(
            max_size=settings.THINKING_DEDUP_WINDOW
        )

        # Processing mode
        self._mode = settings.THINKING_MODE  # "streaming" or "batch"

        # Batch processing buffer
        self._batch_buffer: List[Dict[str, Any]] = []
        self._batch_lock = asyncio.Lock()
        self._queue_write_lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None

        # Statistics
        self._stats = {
            "total_received": 0,
            "duplicates_filtered": 0,
            "fp_filtered": 0,
            "distributed": 0,
            "by_specialist": {},
            "classification_methods": {
                "keyword_exact": 0,
                "keyword_substring": 0,
                "embeddings_high_confidence": 0,
                "embeddings_medium_confidence": 0,
                "embeddings_low_confidence": 0,
                "unknown": 0,
            }
        }

        # Embeddings infrastructure (lazy loaded)
        self._embedding_manager = None
        self._specialist_embeddings = {}
        self._embeddings_initialized = False

        logger.info(f"[{self.name}] Initialized in {self._mode} mode")

    # =====================================================================
    # QUEUE DIRECTORY MANAGEMENT
    # =====================================================================

    def _get_queues_dir(self):
        """Helper to find and ensure specialists/wet directory."""
        if self._queues_dir_cached:
            return self._queues_dir_cached

        if self.scan_dir:
            found_dir = self.scan_dir
        else:
            logger.error(
                f"[{self.name}] CRITICAL: scan_dir not set! "
                f"ThinkingConsolidationAgent requires scan_dir from TeamOrchestrator. "
                f"scan_context={self.scan_context}"
            )
            report_dir = settings.REPORT_DIR
            found_dir = report_dir / f"emergency_{self.scan_context or 'unknown'}"
            found_dir.mkdir(parents=True, exist_ok=True)
            logger.warning(f"[{self.name}] Using emergency fallback dir: {found_dir}")

        specialists_dir = found_dir / "specialists"
        specialists_dir.mkdir(exist_ok=True)
        wet_dir = specialists_dir / "wet"
        wet_dir.mkdir(exist_ok=True)

        self._queues_dir_cached = wet_dir

        if not self._queues_initialized:
            queue_manager.initialize_file_queues(wet_dir)
            self._queues_initialized = True

        return wet_dir

    # =====================================================================
    # EMBEDDINGS
    # =====================================================================

    def _initialize_embeddings(self) -> bool:
        """Lazy load embeddings model."""
        if self._embeddings_initialized:
            return True

        manager, specialist_embs, success = _initialize_embeddings(
            use_embeddings=settings.USE_EMBEDDINGS_CLASSIFICATION,
            agent_name=self.name,
        )
        if success:
            self._embedding_manager = manager
            self._specialist_embeddings = specialist_embs
            self._embeddings_initialized = True
        return success

    def _classify_with_embeddings(self, finding: Dict[str, Any]):
        """Classify using embeddings."""
        if not self._embeddings_initialized or not self._embedding_manager:
            return None
        return _classify_with_embeddings(
            finding,
            self._embedding_manager,
            self._specialist_embeddings,
            log_confidence=settings.EMBEDDINGS_LOG_CONFIDENCE,
            agent_name=self.name,
        )

    # =====================================================================
    # CLASSIFY KWARGS (shared between all processing calls)
    # =====================================================================

    def _classify_kwargs(self) -> Dict[str, Any]:
        """Build kwargs for classify_finding calls."""
        return {
            "embeddings_classify_fn": self._classify_with_embeddings,
            "embeddings_initialized": self._embeddings_initialized,
            "embeddings_init_fn": self._initialize_embeddings,
            "use_embeddings": settings.USE_EMBEDDINGS_CLASSIFICATION,
            "confidence_threshold": settings.EMBEDDINGS_CONFIDENCE_THRESHOLD,
            "manual_review_threshold": settings.EMBEDDINGS_MANUAL_REVIEW_THRESHOLD,
            "log_confidence": settings.EMBEDDINGS_LOG_CONFIDENCE,
        }

    # =====================================================================
    # EVENT SUBSCRIPTIONS
    # =====================================================================

    def _setup_event_subscriptions(self):
        """Subscribe to url_analyzed events."""
        logger.info(f"[{self.name}] Event subscriptions disabled (batch mode)")

    def _cleanup_event_subscriptions(self):
        """Unsubscribe from events on shutdown."""
        self.event_bus.unsubscribe(EventType.URL_ANALYZED.value, self._handle_url_analyzed)
        dedup_metrics.log_summary()
        logger.info(f"[{self.name}] Unsubscribed from events")

    # =====================================================================
    # EVENT HANDLING
    # =====================================================================

    async def _handle_url_analyzed(self, data: Dict[str, Any]) -> None:
        """Handle url_analyzed event from DASTySASTAgent."""
        url = data.get("url", "unknown")
        scan_context = data.get("scan_context", self.scan_context)
        findings = data.get("findings", [])
        report_files = data.get("report_files", {})

        logger.info(f"[{self.name}] Processing batch: {len(findings)} findings from {url[:50]}")
        self._stats["total_received"] += len(findings)

        if self._mode == "streaming":
            for i, finding in enumerate(findings):
                finding["_report_files"] = report_files
                logger.info(f"[{self.name}] Processing finding {i+1}/{len(findings)}: {finding.get('type')}")
                await self._process_single_finding(finding, scan_context)
                logger.info(f"[{self.name}] Completed finding {i+1}/{len(findings)}")
            logger.info(f"[{self.name}] All findings processed for {url[:50]}")
        else:
            batch_to_process = None
            async with self._batch_lock:
                for finding in findings:
                    finding_with_context = finding.copy()
                    finding_with_context["_scan_context"] = scan_context
                    finding_with_context["_report_files"] = report_files
                    self._batch_buffer.append(finding_with_context)

                if len(self._batch_buffer) >= settings.THINKING_BATCH_SIZE:
                    batch_to_process = self._batch_buffer[:settings.THINKING_BATCH_SIZE]
                    self._batch_buffer = self._batch_buffer[settings.THINKING_BATCH_SIZE:]

            if batch_to_process:
                await self._process_batch(batch_to_process)

    # =====================================================================
    # SINGLE FINDING PROCESSING (delegates to processing module)
    # =====================================================================

    async def _process_single_finding(self, finding: Dict[str, Any], scan_context: str) -> None:
        """Process a single finding through the full pipeline."""
        await _process_finding(
            finding=finding,
            scan_context=scan_context,
            dedup_cache=self._dedup_cache,
            stats=self._stats,
            scan_id=self.scan_id,
            get_queues_dir_fn=self._get_queues_dir,
            queue_write_lock=self._queue_write_lock,
            event_bus=self.event_bus,
            fp_threshold=settings.THINKING_FP_THRESHOLD,
            backpressure_retries=settings.THINKING_BACKPRESSURE_RETRIES,
            backpressure_delay=settings.THINKING_BACKPRESSURE_DELAY,
            emit_events=settings.THINKING_EMIT_EVENTS,
            verbose_emitter=getattr(self, '_v', None),
            agent_name=self.name,
            **self._classify_kwargs(),
        )

    # =====================================================================
    # BATCH PROCESSING (delegates to processing module)
    # =====================================================================

    async def _process_batch(self, batch: List[Dict[str, Any]]) -> None:
        """Process a batch of findings."""
        await _process_batch_items(
            batch=batch,
            scan_context=self.scan_context,
            dedup_cache=self._dedup_cache,
            stats=self._stats,
            scan_id=self.scan_id,
            get_queues_dir_fn=self._get_queues_dir,
            queue_write_lock=self._queue_write_lock,
            event_bus=self.event_bus,
            fp_threshold=settings.THINKING_FP_THRESHOLD,
            backpressure_retries=settings.THINKING_BACKPRESSURE_RETRIES,
            backpressure_delay=settings.THINKING_BACKPRESSURE_DELAY,
            emit_events=settings.THINKING_EMIT_EVENTS,
            verbose_emitter=getattr(self, '_v', None),
            agent_name=self.name,
            **self._classify_kwargs(),
        )

    # =====================================================================
    # RUN LOOP
    # =====================================================================

    async def run_loop(self):
        """Main agent loop - manages batch processing if in batch mode."""
        if self._mode == "batch":
            self._batch_task = asyncio.create_task(self._batch_processor())
            logger.info(f"[{self.name}] Started batch processor")

        while self.running:
            await asyncio.sleep(1.0)
            await self.check_pause()

        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass

    async def _batch_processor(self):
        """Background task for batch mode processing."""
        while self.running:
            try:
                await asyncio.sleep(settings.THINKING_BATCH_TIMEOUT)

                batch_to_process = None
                async with self._batch_lock:
                    if self._batch_buffer:
                        count = min(len(self._batch_buffer), settings.THINKING_BATCH_SIZE)
                        if count > 0:
                            logger.debug(
                                f"[{self.name}] Batch timeout: processing {count} buffered"
                            )
                            batch_to_process = self._batch_buffer[:count]
                            self._batch_buffer = self._batch_buffer[count:]

                if batch_to_process:
                    await self._process_batch(batch_to_process)

            except asyncio.CancelledError:
                logger.info(f"[{self.name}] Batch processor cancelled")
                break
            except Exception as e:
                logger.error(f"[{self.name}] Batch processor error: {e}")

    # =====================================================================
    # PUBLIC API
    # =====================================================================

    async def flush_batch(self) -> int:
        """Flush any remaining findings in the batch buffer."""
        all_items = []
        async with self._batch_lock:
            all_items = self._batch_buffer[:]
            self._batch_buffer = []

        initial_count = len(all_items)

        chunk_size = settings.THINKING_BATCH_SIZE
        for i in range(0, len(all_items), chunk_size):
            chunk = all_items[i:i + chunk_size]
            await self._process_batch(chunk)

        return initial_count

    async def process_batch_from_list(
        self, findings: List[Dict[str, Any]], scan_context: str = None
    ) -> int:
        """Process a batch of findings from a Python list (not events)."""
        if not findings:
            logger.info(f"[{self.name}] No findings to process")
            return 0

        scan_ctx = scan_context or self.scan_context
        self._v = create_emitter("ThinkingAgent", scan_ctx)
        self._v.emit("strategy.thinking.batch_started", {"batch_size": len(findings)})
        logger.info(f"[{self.name}] Processing batch of {len(findings)} findings from list")

        for finding in findings:
            if "_scan_context" not in finding:
                finding["_scan_context"] = scan_ctx

        await self._process_batch(findings)

        distributed = self._stats.get("distributed", 0)
        self._v.emit("strategy.thinking.batch_completed", {
            "processed": len(findings), "distributed": distributed,
        })
        self._v.emit("strategy.distribution_summary", {
            "received": self._stats.get("total_received", len(findings)),
            "fp_filtered": self._stats.get("fp_filtered", 0),
            "duplicates": self._stats.get("duplicates_filtered", 0),
            "distributed": distributed,
            "by_specialist": self._stats.get("by_specialist", {}),
        })
        logger.info(f"[{self.name}] Distributed {distributed} findings to specialist queues")
        return distributed

    def set_mode(self, mode: str) -> None:
        """Change processing mode at runtime."""
        if mode not in ("streaming", "batch"):
            raise ValueError(f"Invalid mode: {mode}. Must be 'streaming' or 'batch'")

        old_mode = self._mode
        self._mode = mode
        logger.info(f"[{self.name}] Mode changed: {old_mode} -> {mode}")

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
            "by_specialist": {},
            "classification_methods": {
                "keyword_exact": 0,
                "keyword_substring": 0,
                "embeddings_high_confidence": 0,
                "embeddings_medium_confidence": 0,
                "embeddings_low_confidence": 0,
                "unknown": 0,
            }
        }
        self._dedup_cache.clear()
