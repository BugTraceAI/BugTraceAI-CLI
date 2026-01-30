"""
Queue System - Per-specialist async queues with backpressure and rate limiting.
Supports agent coordination for v2.3 Pipeline Architecture.

Author: BugtraceAI Team
Date: 2026-01-29
Version: 1.0.0
"""

import asyncio
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("queue")


@dataclass
class QueueItem:
    """Wrapper for items in specialist queue."""
    payload: Dict[str, Any]
    scan_context: str
    enqueued_at: float = field(default_factory=time.monotonic)


@dataclass
class QueueStats:
    """
    Statistics for a specialist queue.

    Tracks:
    - Depth: Current queue size
    - Throughput: Items processed per second
    - Latency: Time from enqueue to dequeue

    All timing uses monotonic clock for accuracy.
    """
    # Counters
    total_enqueued: int = 0
    total_dequeued: int = 0
    total_rejected: int = 0  # Rejected due to backpressure

    # Timing windows (for throughput calculation)
    _enqueue_times: List[float] = field(default_factory=list)
    _dequeue_times: List[float] = field(default_factory=list)
    _latencies: List[float] = field(default_factory=list)

    # Window size for rolling calculations
    _window_seconds: float = 60.0
    _max_samples: int = 1000

    def record_enqueue(self) -> None:
        """Record an enqueue event."""
        self.total_enqueued += 1
        now = time.monotonic()
        self._enqueue_times.append(now)
        self._prune_old_samples()

    def record_dequeue(self, enqueued_at: float) -> None:
        """Record a dequeue event with latency."""
        self.total_dequeued += 1
        now = time.monotonic()
        self._dequeue_times.append(now)

        # Calculate latency
        latency = now - enqueued_at
        self._latencies.append(latency)
        self._prune_old_samples()

    def record_rejected(self) -> None:
        """Record a rejected enqueue (backpressure)."""
        self.total_rejected += 1

    def _prune_old_samples(self) -> None:
        """Remove samples older than window."""
        now = time.monotonic()
        cutoff = now - self._window_seconds

        # Prune old timestamps
        self._enqueue_times = [t for t in self._enqueue_times if t > cutoff][-self._max_samples:]
        self._dequeue_times = [t for t in self._dequeue_times if t > cutoff][-self._max_samples:]
        self._latencies = self._latencies[-self._max_samples:]

    @property
    def enqueue_throughput(self) -> float:
        """Items enqueued per second (rolling window)."""
        if not self._enqueue_times:
            return 0.0
        window = time.monotonic() - self._enqueue_times[0]
        if window <= 0:
            return 0.0
        return len(self._enqueue_times) / window

    @property
    def dequeue_throughput(self) -> float:
        """Items dequeued per second (rolling window)."""
        if not self._dequeue_times:
            return 0.0
        window = time.monotonic() - self._dequeue_times[0]
        if window <= 0:
            return 0.0
        return len(self._dequeue_times) / window

    @property
    def avg_latency(self) -> float:
        """Average latency in seconds."""
        if not self._latencies:
            return 0.0
        return sum(self._latencies) / len(self._latencies)

    @property
    def p95_latency(self) -> float:
        """95th percentile latency in seconds."""
        if not self._latencies:
            return 0.0
        sorted_latencies = sorted(self._latencies)
        idx = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    @property
    def max_latency(self) -> float:
        """Maximum latency in seconds."""
        if not self._latencies:
            return 0.0
        return max(self._latencies)

    def to_dict(self) -> Dict[str, Any]:
        """Export stats as dictionary."""
        return {
            "total_enqueued": self.total_enqueued,
            "total_dequeued": self.total_dequeued,
            "total_rejected": self.total_rejected,
            "enqueue_throughput": round(self.enqueue_throughput, 2),
            "dequeue_throughput": round(self.dequeue_throughput, 2),
            "avg_latency_ms": round(self.avg_latency * 1000, 2),
            "p95_latency_ms": round(self.p95_latency * 1000, 2),
            "max_latency_ms": round(self.max_latency * 1000, 2),
        }

    def reset(self) -> None:
        """Reset all statistics."""
        self.total_enqueued = 0
        self.total_dequeued = 0
        self.total_rejected = 0
        self._enqueue_times.clear()
        self._dequeue_times.clear()
        self._latencies.clear()


class SpecialistQueue:
    """
    Async queue for specialist agents with backpressure and rate limiting.

    Features:
    - Max depth enforcement (backpressure)
    - Token bucket rate limiting
    - Scan context tracking for ordering
    """

    def __init__(self, name: str, max_depth: int = None, rate_limit: float = None):
        self.name = name
        self.max_depth = max_depth or settings.QUEUE_DEFAULT_MAX_DEPTH
        self.rate_limit = rate_limit if rate_limit is not None else settings.QUEUE_DEFAULT_RATE_LIMIT

        self._queue: asyncio.Queue = asyncio.Queue()
        self._lock = asyncio.Lock()

        # Token bucket for rate limiting
        self._tokens = self.rate_limit if self.rate_limit > 0 else float('inf')
        self._last_replenish = time.monotonic()

        # Statistics tracking
        self._stats = QueueStats()

        logger.info(f"Queue '{name}' created: max_depth={self.max_depth}, rate_limit={self.rate_limit}/s")

    async def enqueue(self, item: dict, scan_context: str) -> bool:
        """
        Add item to queue with backpressure check.

        Args:
            item: Payload to enqueue
            scan_context: Scan context identifier for ordering

        Returns:
            True if enqueued successfully, False if queue is full (backpressure)
        """
        # Check backpressure first
        if self.is_full():
            self._stats.record_rejected()
            logger.warning(f"Queue '{self.name}' is full ({self.depth()}/{self.max_depth}), backpressure triggered")
            return False

        # Apply rate limiting (token bucket)
        if self.rate_limit > 0:
            await self._wait_for_token()

        # Enqueue the item
        queue_item = QueueItem(
            payload=item,
            scan_context=scan_context,
            enqueued_at=time.monotonic()
        )
        await self._queue.put(queue_item)
        self._stats.record_enqueue()
        logger.debug(f"Queue '{self.name}' enqueued item (depth: {self.depth()})")
        return True

    async def dequeue(self, timeout: float = None) -> Optional[dict]:
        """
        Get next item from queue.

        Args:
            timeout: Maximum time to wait for item (None = wait forever)

        Returns:
            Item payload dict, or None if timeout reached
        """
        try:
            if timeout is not None:
                queue_item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            else:
                queue_item = await self._queue.get()

            self._stats.record_dequeue(queue_item.enqueued_at)
            logger.debug(f"Queue '{self.name}' dequeued item (depth: {self.depth()})")
            return queue_item.payload
        except asyncio.TimeoutError:
            logger.debug(f"Queue '{self.name}' dequeue timeout after {timeout}s")
            return None

    def depth(self) -> int:
        """Get current queue depth."""
        return self._queue.qsize()

    def is_full(self) -> bool:
        """Check if queue is at max capacity (backpressure)."""
        return self.depth() >= self.max_depth

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        stats = self._stats.to_dict()
        stats["name"] = self.name
        stats["current_depth"] = self.depth()
        stats["max_depth"] = self.max_depth
        stats["rate_limit"] = self.rate_limit
        stats["is_full"] = self.is_full()
        return stats

    def reset_stats(self) -> None:
        """Reset queue statistics."""
        self._stats.reset()
        logger.debug(f"Queue '{self.name}' stats reset")

    async def _wait_for_token(self) -> None:
        """
        Wait for rate limit token (token bucket algorithm).
        Tokens replenish at rate_limit/second.
        """
        async with self._lock:
            # Replenish tokens based on elapsed time
            now = time.monotonic()
            elapsed = now - self._last_replenish
            self._tokens = min(self.rate_limit, self._tokens + (elapsed * self.rate_limit))
            self._last_replenish = now

            # Wait until we have at least 1 token
            while self._tokens < 1.0:
                await asyncio.sleep(0.01)  # Small sleep to avoid busy wait
                now = time.monotonic()
                elapsed = now - self._last_replenish
                self._tokens = min(self.rate_limit, self._tokens + (elapsed * self.rate_limit))
                self._last_replenish = now

            # Consume 1 token
            self._tokens -= 1.0


class QueueManager:
    """Manages per-specialist queues."""

    def __init__(self):
        self._queues: Dict[str, SpecialistQueue] = {}
        self._lock = asyncio.Lock()
        logger.info("QueueManager initialized")

    def get_queue(self, specialist: str) -> SpecialistQueue:
        """Get or create queue for specialist."""
        if specialist not in self._queues:
            self._queues[specialist] = SpecialistQueue(specialist)
        return self._queues[specialist]

    def list_queues(self) -> List[str]:
        """List all queue names."""
        return list(self._queues.keys())

    def reset(self):
        """Clear all queues (for testing)."""
        self._queues.clear()
        logger.info("QueueManager reset")

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get statistics for all queues.

        Returns:
            Dict mapping queue name to stats dict
        """
        return {name: queue.get_stats() for name, queue in self._queues.items()}

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """
        Get aggregate statistics across all queues.

        Returns:
            Dict with totals and averages across all queues
        """
        all_stats = self.get_all_stats()

        if not all_stats:
            return {
                "total_queues": 0,
                "total_enqueued": 0,
                "total_dequeued": 0,
                "total_rejected": 0,
                "total_depth": 0,
                "avg_enqueue_throughput": 0.0,
                "avg_dequeue_throughput": 0.0,
                "avg_latency_ms": 0.0,
                "max_latency_ms": 0.0,
            }

        total_enqueued = sum(s["total_enqueued"] for s in all_stats.values())
        total_dequeued = sum(s["total_dequeued"] for s in all_stats.values())
        total_rejected = sum(s["total_rejected"] for s in all_stats.values())
        total_depth = sum(s["current_depth"] for s in all_stats.values())

        enqueue_throughputs = [s["enqueue_throughput"] for s in all_stats.values() if s["enqueue_throughput"] > 0]
        dequeue_throughputs = [s["dequeue_throughput"] for s in all_stats.values() if s["dequeue_throughput"] > 0]
        latencies = [s["avg_latency_ms"] for s in all_stats.values() if s["avg_latency_ms"] > 0]
        max_latencies = [s["max_latency_ms"] for s in all_stats.values()]

        return {
            "total_queues": len(all_stats),
            "total_enqueued": total_enqueued,
            "total_dequeued": total_dequeued,
            "total_rejected": total_rejected,
            "total_depth": total_depth,
            "avg_enqueue_throughput": round(sum(enqueue_throughputs) / len(enqueue_throughputs), 2) if enqueue_throughputs else 0.0,
            "avg_dequeue_throughput": round(sum(dequeue_throughputs) / len(dequeue_throughputs), 2) if dequeue_throughputs else 0.0,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            "max_latency_ms": round(max(max_latencies), 2) if max_latencies else 0.0,
            "queues_with_backpressure": sum(1 for s in all_stats.values() if s["is_full"]),
        }

    def reset_all_stats(self) -> None:
        """Reset statistics for all queues."""
        for queue in self._queues.values():
            queue.reset_stats()
        logger.info("All queue stats reset")


# Pre-defined specialist names
SPECIALIST_QUEUES = [
    "xss", "sqli", "csti", "lfi", "idor", "rce",
    "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution",
    "file_upload", "chain_discovery", "api_security", "header_injection"
]


# Singleton instance
queue_manager = QueueManager()


# Module exports
__all__ = ["SpecialistQueue", "QueueManager", "queue_manager", "SPECIALIST_QUEUES", "QueueStats", "QueueItem"]
