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


# Pre-defined specialist names
SPECIALIST_QUEUES = [
    "xss", "sqli", "csti", "lfi", "idor", "rce",
    "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution",
    "file_upload", "chain_discovery", "api_security"
]


# Singleton instance
queue_manager = QueueManager()


# Module exports
__all__ = ["SpecialistQueue", "QueueManager", "queue_manager", "SPECIALIST_QUEUES"]
