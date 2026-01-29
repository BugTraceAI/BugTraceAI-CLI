"""
Worker Pool - Generic async worker pool for specialist agents.
Enables parallel payload testing by consuming items from specialist queues.

Author: BugtraceAI Team
Date: 2026-01-29
Version: 1.0.0

Exports:
    WorkerPool: Main pool class managing multiple workers
    Worker: Individual worker that processes queue items
    WorkerConfig: Configuration dataclass for worker pools
"""

import asyncio
import time
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, field

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.queue import SpecialistQueue, queue_manager
from bugtrace.core.parallelization_metrics import parallelization_metrics, get_parallelization_summary

logger = get_logger("worker_pool")


@dataclass
class WorkerConfig:
    """Configuration for a worker pool."""

    specialist: str  # Queue name (e.g., "xss", "sqli")
    pool_size: int  # Number of concurrent workers
    process_func: Callable  # Async function to process each item
    on_result: Optional[Callable] = None  # Callback when processing completes
    shutdown_timeout: float = field(default_factory=lambda: settings.WORKER_POOL_SHUTDOWN_TIMEOUT)
    dequeue_timeout: float = field(default_factory=lambda: settings.WORKER_POOL_DEQUEUE_TIMEOUT)


class Worker:
    """
    Individual worker that consumes items from a specialist queue.

    Each worker runs in its own asyncio task, continuously dequeuing
    items and processing them with the configured process function.

    Statistics tracked:
    - items_processed: Total items successfully processed
    - errors: Total processing errors
    - total_latency: Cumulative processing time (for avg calculation)
    """

    def __init__(self, worker_id: int, specialist: str):
        self.worker_id = worker_id
        self.specialist = specialist
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Statistics
        self._stats: Dict[str, Any] = {
            "items_processed": 0,
            "errors": 0,
            "total_latency": 0.0,
            "last_item_at": None,
        }

        # Worker loop dependencies (set on start)
        self._queue: Optional[SpecialistQueue] = None
        self._process_func: Optional[Callable] = None
        self._on_result: Optional[Callable] = None
        self._dequeue_timeout: float = settings.WORKER_POOL_DEQUEUE_TIMEOUT

        logger.debug(f"Worker {worker_id} created for '{specialist}'")

    async def start(
        self,
        queue: SpecialistQueue,
        process_func: Callable,
        on_result: Optional[Callable] = None,
        dequeue_timeout: float = None,
    ) -> None:
        """
        Start the worker loop.

        Args:
            queue: SpecialistQueue to consume from
            process_func: Async function(item) -> result
            on_result: Optional async callback(item, result)
            dequeue_timeout: Seconds to wait for queue item
        """
        self._queue = queue
        self._process_func = process_func
        self._on_result = on_result
        self._dequeue_timeout = dequeue_timeout or settings.WORKER_POOL_DEQUEUE_TIMEOUT
        self._running = True

        self._task = asyncio.create_task(self._worker_loop())
        logger.info(f"Worker {self.worker_id} started for '{self.specialist}'")

    async def stop(self) -> None:
        """
        Signal worker to stop and wait for current item to complete.

        This is a graceful shutdown - the worker finishes processing
        its current item before stopping.
        """
        self._running = False

        if self._task is not None:
            try:
                # Wait for task to complete with timeout
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning(f"Worker {self.worker_id} stop timed out, cancelling")
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            except asyncio.CancelledError:
                pass

        logger.info(f"Worker {self.worker_id} stopped for '{self.specialist}'")

    async def _worker_loop(self) -> None:
        """
        Main worker loop - dequeue, process, callback.

        Runs continuously until _running is False, processing items
        from the queue and invoking callbacks on completion.
        """
        while self._running:
            try:
                # Try to get item from queue with timeout
                item = await self._queue.dequeue(timeout=self._dequeue_timeout)

                if item is None:
                    # Timeout - check _running and retry
                    continue

                # Record worker start for parallelization metrics
                parallelization_metrics.record_worker_start(self.specialist, self.worker_id)

                start = time.monotonic()
                try:
                    # Process the item
                    result = await self._process_func(item)

                    # Invoke callback if configured
                    if self._on_result is not None:
                        await self._on_result(item, result)

                    self._stats["items_processed"] += 1
                    self._stats["last_item_at"] = time.time()

                except Exception as e:
                    logger.error(f"Worker {self.worker_id} error processing item: {e}")
                    self._stats["errors"] += 1

                finally:
                    latency = time.monotonic() - start
                    self._update_latency(latency)
                    # Record worker stop for parallelization metrics
                    parallelization_metrics.record_worker_stop(self.specialist, self.worker_id)

            except asyncio.CancelledError:
                logger.debug(f"Worker {self.worker_id} cancelled")
                break
            except Exception as e:
                logger.error(f"Worker {self.worker_id} loop error: {e}")
                # Small delay to avoid tight error loops
                await asyncio.sleep(0.1)

    def _update_latency(self, latency: float) -> None:
        """Update latency statistics."""
        self._stats["total_latency"] += latency

    def get_stats(self) -> Dict[str, Any]:
        """
        Get worker statistics.

        Returns:
            Dict with items_processed, errors, avg_latency_ms
        """
        items = self._stats["items_processed"]
        avg_latency = (
            self._stats["total_latency"] / items if items > 0 else 0.0
        )

        return {
            "worker_id": self.worker_id,
            "specialist": self.specialist,
            "running": self._running,
            "items_processed": items,
            "errors": self._stats["errors"],
            "avg_latency_ms": round(avg_latency * 1000, 2),
            "last_item_at": self._stats["last_item_at"],
        }


class WorkerPool:
    """
    Manages a pool of workers for a specialist queue.

    Features:
    - Spawns N concurrent workers
    - Graceful shutdown with configurable timeout
    - Dynamic scaling (add/remove workers)
    - Aggregated statistics across all workers

    Usage:
        config = WorkerConfig(
            specialist="xss",
            pool_size=8,
            process_func=xss_agent.process_payload
        )
        pool = WorkerPool(config)
        await pool.start()
        # ... processing happens ...
        await pool.stop()
    """

    def __init__(self, config: WorkerConfig, queue: SpecialistQueue = None):
        """
        Initialize worker pool.

        Args:
            config: WorkerConfig with pool settings
            queue: Optional SpecialistQueue (defaults to queue_manager.get_queue)
        """
        self.config = config
        self._workers: List[Worker] = []
        self._queue = queue or queue_manager.get_queue(config.specialist)
        self._running = False
        self._started_at: Optional[float] = None
        self._next_worker_id = 0

        logger.info(
            f"WorkerPool created for '{config.specialist}': "
            f"pool_size={config.pool_size}, shutdown_timeout={config.shutdown_timeout}s"
        )

    async def start(self) -> None:
        """
        Start the worker pool.

        Spawns config.pool_size workers and starts them all.
        """
        if self._running:
            logger.warning(f"WorkerPool '{self.config.specialist}' already running")
            return

        self._running = True
        self._started_at = time.monotonic()

        # Spawn workers
        for _ in range(self.config.pool_size):
            worker = Worker(self._next_worker_id, self.config.specialist)
            self._next_worker_id += 1
            self._workers.append(worker)

            await worker.start(
                queue=self._queue,
                process_func=self.config.process_func,
                on_result=self.config.on_result,
                dequeue_timeout=self.config.dequeue_timeout,
            )

        logger.info(
            f"WorkerPool '{self.config.specialist}' started with {len(self._workers)} workers"
        )

    async def stop(self) -> None:
        """
        Stop the worker pool gracefully.

        Signals all workers to stop and waits up to shutdown_timeout
        for them to complete their current items.
        """
        if not self._running:
            return

        self._running = False
        logger.info(f"WorkerPool '{self.config.specialist}' stopping...")

        # Stop all workers with timeout
        try:
            async with asyncio.timeout(self.config.shutdown_timeout):
                stop_tasks = [worker.stop() for worker in self._workers]
                await asyncio.gather(*stop_tasks, return_exceptions=True)
        except asyncio.TimeoutError:
            logger.warning(
                f"WorkerPool '{self.config.specialist}' shutdown timed out "
                f"after {self.config.shutdown_timeout}s"
            )

        logger.info(f"WorkerPool '{self.config.specialist}' stopped")

    async def drain(self) -> None:
        """
        Wait until the queue is empty.

        Useful for graceful shutdown when you want to ensure
        all queued items are processed before stopping.
        """
        while self._queue.depth() > 0:
            await asyncio.sleep(0.1)

        logger.info(f"WorkerPool '{self.config.specialist}' queue drained")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get aggregated statistics from all workers.

        Returns:
            Dict with total items_processed, errors, avg_latency,
            worker count, and uptime.
        """
        total_processed = 0
        total_errors = 0
        total_latency = 0.0

        worker_stats = []
        for worker in self._workers:
            stats = worker.get_stats()
            worker_stats.append(stats)
            total_processed += stats["items_processed"]
            total_errors += stats["errors"]
            # Reconstruct total latency from avg * items
            if stats["items_processed"] > 0:
                total_latency += (stats["avg_latency_ms"] / 1000) * stats["items_processed"]

        avg_latency = total_latency / total_processed if total_processed > 0 else 0.0

        uptime = time.monotonic() - self._started_at if self._started_at else 0.0

        # Get parallelization data for this specialist
        parallelization_data = get_parallelization_summary().get("by_specialist", {}).get(self.config.specialist, {})

        return {
            "specialist": self.config.specialist,
            "running": self._running,
            "worker_count": len(self._workers),
            "pool_size": self.config.pool_size,
            "total_items_processed": total_processed,
            "total_errors": total_errors,
            "avg_latency_ms": round(avg_latency * 1000, 2),
            "uptime_seconds": round(uptime, 2),
            "queue_depth": self._queue.depth(),
            "parallelization": parallelization_data,
            "workers": worker_stats,
        }

    async def scale(self, new_size: int) -> None:
        """
        Dynamically adjust pool size.

        Args:
            new_size: Target number of workers

        If new_size > current: Add workers
        If new_size < current: Remove workers (gracefully)
        """
        if new_size < 1:
            raise ValueError("Pool size must be at least 1")

        current_size = len(self._workers)

        if new_size == current_size:
            return

        if new_size > current_size:
            # Scale up - add workers
            workers_to_add = new_size - current_size
            logger.info(
                f"WorkerPool '{self.config.specialist}' scaling up: "
                f"{current_size} -> {new_size} (+{workers_to_add})"
            )

            for _ in range(workers_to_add):
                worker = Worker(self._next_worker_id, self.config.specialist)
                self._next_worker_id += 1
                self._workers.append(worker)

                if self._running:
                    await worker.start(
                        queue=self._queue,
                        process_func=self.config.process_func,
                        on_result=self.config.on_result,
                        dequeue_timeout=self.config.dequeue_timeout,
                    )

        else:
            # Scale down - remove workers
            workers_to_remove = current_size - new_size
            logger.info(
                f"WorkerPool '{self.config.specialist}' scaling down: "
                f"{current_size} -> {new_size} (-{workers_to_remove})"
            )

            # Stop and remove workers from the end
            for _ in range(workers_to_remove):
                worker = self._workers.pop()
                await worker.stop()

        self.config.pool_size = new_size


# Module exports
__all__ = ["WorkerPool", "Worker", "WorkerConfig"]
