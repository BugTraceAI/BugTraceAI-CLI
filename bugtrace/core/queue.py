"""
Queue System - Per-specialist async queues with backpressure and rate limiting.
Supports agent coordination for v2.3 Pipeline Architecture.

Author: BugtraceAI Team
Date: 2026-01-29
Version: 1.0.0
"""

import asyncio
import time
import json
from pathlib import Path
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

        # File-based mode state
        self._file_mode = False
        self.file_path: Optional[Path] = None
        self._tail_task: Optional[asyncio.Task] = None
        self._check_file_event = asyncio.Event()

    def enable_file_mode(self, file_path: Path):
        """Enable file-based mode: tail file and disable manual enqueue.

        If already in file mode (e.g., from a previous scan), updates the file path
        and restarts the tailer to watch the new scan's WET directory.
        """
        if self._file_mode:
            # Multi-scan support: update path and restart tailer for new scan directory
            if self.file_path != file_path:
                logger.info(f"Queue '{self.name}' switching file mode: {self.file_path} -> {file_path}")
                self.file_path = file_path
                # Cancel old tailer and start new one
                if self._tail_task and not self._tail_task.done():
                    self._tail_task.cancel()
                # Drain any stale items from previous scan
                while not self._queue.empty():
                    try:
                        self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                loop = asyncio.get_event_loop()
                self._tail_task = loop.create_task(self._tail_file_loop())
            return
        self._file_mode = True
        self.file_path = file_path
        logger.info(f"Queue '{self.name}' enabled file mode: {file_path}")

        # Start background tailing task
        loop = asyncio.get_event_loop()
        self._tail_task = loop.create_task(self._tail_file_loop())

    async def _tail_file_loop(self):
        """Continuously read JSON Lines queue items from file and populate the queue.

        v3.2 Format (JSON Lines - one JSON object per line):
            {"timestamp": 123.456, "specialist": "xss", "scan_context": "scan_xyz", "finding": {...}}

        This replaces the legacy XML format used in v3.1.
        """
        cursor = 0

        while True:
            try:
                # Wait for signal (enqueue) or timeout (poll)
                try:
                    await asyncio.wait_for(self._check_file_event.wait(), timeout=0.5)
                    self._check_file_event.clear()
                except asyncio.TimeoutError:
                    pass

                if not self.file_path.exists():
                    await asyncio.sleep(0.1)
                    continue

                # Read new content from file (blocking IO in thread)
                content, new_cursor = await asyncio.to_thread(self._read_content_safe, self.file_path, cursor)

                if not content:
                    continue

                cursor = new_cursor

                # Parse JSON Lines format (v3.2)
                # Each line is a complete JSON object:
                #   {"timestamp": 123.456, "specialist": "xss", "scan_context": "ctx", "finding": {...}}
                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)

                        # Extract fields from JSON Lines format
                        ts = entry.get("timestamp", time.monotonic())
                        ctx = entry.get("scan_context", "unknown")
                        finding_data = entry.get("finding", {})

                        # Build payload structure that specialists expect
                        # Specialists expect: {"finding": {...}, "scan_context": "..."}
                        payload = {
                            "finding": finding_data,
                            "scan_context": ctx
                        }

                        item = QueueItem(
                            payload=payload,
                            scan_context=ctx,
                            enqueued_at=ts
                        )

                        # Put into internal async queue (buffer)
                        await self._queue.put(item)
                        self._stats.record_enqueue()
                        logger.debug(f"Queue '{self.name}' parsed JSON Lines item: {finding_data.get('type', 'unknown')}")

                    except json.JSONDecodeError as e:
                        # Skip invalid JSON lines (could be partial writes)
                        logger.debug(f"Queue '{self.name}' skipping invalid JSON line: {e}")
                    except Exception as e:
                        logger.warning(f"Queue '{self.name}' failed to parse queue item: {e}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queue '{self.name}' tail loop error: {e}")
                await asyncio.sleep(1)

    def _read_content_safe(self, path, offset):
        """Helper to read content from offset."""
        with open(path, "r", encoding="utf-8") as f:
            f.seek(offset)
            content = f.read()
            return content, f.tell()

    def _read_lines_safe(self, path, offset):
        """DEPRECATED: Use _read_content_safe for XML parsing."""
        return self._read_content_safe(path, offset)

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
            # In File Mode, we don't block enqueue because the producer writes to disk.
            # We return True to satisfy the caller (ThinkingAgent) that the item is "safe".
            if self._file_mode:
                return True
                
            self._stats.record_rejected()
            logger.warning(f"Queue '{self.name}' is full ({self.depth()}/{self.max_depth}), backpressure triggered")
            return False

        # In File Mode, enqueue is a no-op for the caller because 
        # the queue is fed by the file tailer.
        if self._file_mode:
            # Signal the tailer to read the file immediately
            self._check_file_event.set()
            return True

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
        # In file mode, check the file size instead of memory queue
        # This prevents race conditions where the file has data but tailer hasn't read it yet
        if self._file_mode and self.file_path and self.file_path.exists():
            try:
                # Count non-empty lines in file
                with open(self.file_path, 'r') as f:
                    count = sum(1 for line in f if line.strip())
                return count
            except Exception as e:
                logger.warning(f"Queue '{self.name}' failed to read file depth: {e}")
                return self._queue.qsize()

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

        IMPORTANT: Sleep happens OUTSIDE the lock to prevent deadlock when
        multiple coroutines try to enqueue to the same queue simultaneously.
        """
        while True:
            async with self._lock:
                # Replenish tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self._last_replenish
                self._tokens = min(self.rate_limit, self._tokens + (elapsed * self.rate_limit))
                self._last_replenish = now

                # Check if we have a token available
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return  # Got token, exit

            # No token available - sleep OUTSIDE the lock to allow other coroutines
            await asyncio.sleep(0.01)


class QueueManager:
    """Manages per-specialist queues."""

    def __init__(self):
        self._queues: Dict[str, SpecialistQueue] = {}
        self._lock = asyncio.Lock()
        self._status_log_task: Optional[asyncio.Task] = None
        logger.info("QueueManager initialized")

    def start_status_logging(self, interval: float = 10.0):
        """Start periodic status logging task."""
        if self._status_log_task is None or self._status_log_task.done():
            try:
                loop = asyncio.get_event_loop()
                self._status_log_task = loop.create_task(self._log_status_periodically(interval))
                logger.debug("QueueManager status logging started")
            except RuntimeError:
                pass  # No event loop running yet

    def stop_status_logging(self):
        """Stop periodic status logging task."""
        if self._status_log_task and not self._status_log_task.done():
            self._status_log_task.cancel()
            self._status_log_task = None

    async def _log_status_periodically(self, interval: float = 10.0):
        """
        Periodically log queue status with detailed breakdown.

        Logs format: "Queue status: 15 pending (SQLi: 5, XSS: 8, CSTI: 2)"
        Only logs when there are pending items to avoid log noise.
        """
        while True:
            try:
                await asyncio.sleep(interval)

                # Collect queue depths
                details = []
                total_pending = 0

                for name, queue in self._queues.items():
                    depth = queue.depth()
                    if depth > 0:
                        # Capitalize first letter for display
                        display_name = name.upper() if len(name) <= 4 else name.capitalize()
                        details.append(f"{display_name}: {depth}")
                        total_pending += depth

                # Only log if there are pending items
                if total_pending > 0:
                    detail_str = ", ".join(details)
                    logger.info(f"Queue status: {total_pending} pending ({detail_str})")

                    # Also update dashboard if available
                    try:
                        from bugtrace.core.ui import dashboard
                        dashboard.log(f"Queues: {total_pending} pending ({detail_str})", "INFO")
                    except Exception:
                        pass

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queue status logging error: {e}")

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

    def initialize_file_queues(self, queue_dir: Path):
        """
        Initialize file-based mode for all known specialist queues using the given directory.

        Args:
            queue_dir: Directory containing {specialist}.json files (v3.2 JSON Lines format)
        """
        from pathlib import Path
        for specialist in SPECIALIST_QUEUES:
            queue = self.get_queue(specialist)
            file_path = queue_dir / f"{specialist}.json"
            queue.enable_file_mode(file_path)
        logger.info(f"Initialized file queues in {queue_dir}")

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
    "file_upload", "chain_discovery", "api_security", "header_injection",
    "mass_assignment"
]


# Singleton instance
queue_manager = QueueManager()


# Module exports
__all__ = ["SpecialistQueue", "QueueManager", "queue_manager", "SPECIALIST_QUEUES", "QueueStats", "QueueItem"]
