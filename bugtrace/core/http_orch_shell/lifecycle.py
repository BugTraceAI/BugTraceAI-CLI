"""HTTP orchestrator shell module — extracted for size policy."""

from __future__ import annotations

import aiohttp
import asyncio
import random
import time
from enum import Enum
from typing import Optional, Dict, Any, Tuple, Callable, List
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from collections import deque

from bugtrace.utils.logger import get_logger

logger = get_logger("core.http_orchestrator")


class ConnectionState(Enum):
    """State of a tracked connection."""
    ACTIVE = "active"      # Request in progress
    CLOSING = "closing"    # Close initiated but not confirmed
    CLOSED = "closed"      # Successfully closed
    GHOST = "ghost"        # Failed to close in time (PROBLEM!)


@dataclass
class TrackedConnection:
    """A tracked HTTP connection."""
    request_id: str
    host: str
    destination: str
    opened_at: float
    closed_at: Optional[float] = None
    state: ConnectionState = ConnectionState.ACTIVE

    @property
    def age_seconds(self) -> float:
        """How long since connection was opened."""
        return time.time() - self.opened_at

    @property
    def close_duration_ms(self) -> Optional[float]:
        """How long it took to close (if closed)."""
        if self.closed_at:
            return (self.closed_at - self.opened_at) * 1000
        return None


class ConnectionLifecycleTracker:
    """
    Tracks connection lifecycle to detect ghost connections.

    Ghost connections are requests that:
    - Were opened but never closed
    - Took too long to close (stuck in CLOSE_WAIT)

    This tracker implements backpressure: if too many ghosts exist,
    new connections are blocked until ghosts are cleaned up.

    Key insight: The problem isn't opens, it's closes that don't happen!
    """

    # Configuration
    GHOST_THRESHOLD_SECONDS = 120.0  # Connection becomes ghost after 2 min
    MAX_GHOSTS_BEFORE_BLOCK = 5      # Block new requests if this many ghosts
    CLEANUP_INTERVAL = 30.0          # Check for ghosts every 30s

    def __init__(self):
        self._connections: Dict[str, TrackedConnection] = {}
        self._ghost_count = 0
        self._total_opened = 0
        self._total_closed = 0
        self._total_ghosts = 0
        self._blocked_requests = 0
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start the ghost detection background task."""
        if self._running:
            return
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("[ConnectionLifecycle] Ghost detection started")

    async def stop(self):
        """Stop the ghost detection task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info(f"[ConnectionLifecycle] Stopped. Stats: opened={self._total_opened}, "
                   f"closed={self._total_closed}, ghosts={self._total_ghosts}")

    async def _cleanup_loop(self):
        """Background loop to detect and count ghost connections."""
        while self._running:
            try:
                await asyncio.sleep(self.CLEANUP_INTERVAL)
                await self._detect_ghosts()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[ConnectionLifecycle] Cleanup error: {e}")

    async def _detect_ghosts(self):
        """Scan for connections that should have closed but didn't."""
        async with self._lock:
            now = time.time()
            new_ghosts = 0

            for req_id, conn in list(self._connections.items()):
                if conn.state == ConnectionState.ACTIVE:
                    age = now - conn.opened_at
                    if age > self.GHOST_THRESHOLD_SECONDS:
                        # This connection is a ghost!
                        conn.state = ConnectionState.GHOST
                        new_ghosts += 1
                        self._total_ghosts += 1
                        logger.warning(
                            f"[ConnectionLifecycle] GHOST detected: {conn.host} "
                            f"(age={age:.1f}s, req={req_id[:8]})"
                        )

            # Update ghost count
            self._ghost_count = sum(
                1 for c in self._connections.values()
                if c.state == ConnectionState.GHOST
            )

            if new_ghosts > 0:
                logger.warning(f"[ConnectionLifecycle] {new_ghosts} new ghost(s), "
                              f"total active ghosts: {self._ghost_count}")

            # Clean up old closed connections (keep last 1000)
            closed = [
                (req_id, conn) for req_id, conn in self._connections.items()
                if conn.state == ConnectionState.CLOSED
            ]
            if len(closed) > 1000:
                for req_id, _ in closed[:-1000]:
                    del self._connections[req_id]

    def can_open_connection(self) -> Tuple[bool, str]:
        """
        Check if we can open a new connection.

        Returns:
            (allowed, reason) - False if too many ghosts
        """
        if self._ghost_count >= self.MAX_GHOSTS_BEFORE_BLOCK:
            self._blocked_requests += 1
            return False, f"Too many ghost connections ({self._ghost_count}). Waiting for cleanup."
        return True, ""

    async def wait_for_capacity(self, timeout: float = 5.0, interval: float = 0.25) -> bool:
        """Wait briefly for ghost backpressure to clear."""
        deadline = time.time() + timeout
        while True:
            can_open, _ = self.can_open_connection()
            if can_open:
                return True
            if time.time() >= deadline:
                return False
            await asyncio.sleep(interval)

    async def register_open(
        self,
        request_id: str,
        host: str,
        destination: str
    ) -> bool:
        """
        Register a new connection being opened.

        Returns:
            True if allowed, False if blocked due to ghosts
        """
        can_open, reason = self.can_open_connection()
        if not can_open:
            logger.warning(f"[ConnectionLifecycle] BLOCKED: {reason}")
            return False

        async with self._lock:
            self._connections[request_id] = TrackedConnection(
                request_id=request_id,
                host=host,
                destination=destination,
                opened_at=time.time(),
            )
            self._total_opened += 1

        return True

    async def register_close(self, request_id: str):
        """Register a connection being closed successfully."""
        async with self._lock:
            if request_id in self._connections:
                conn = self._connections[request_id]
                if conn.state == ConnectionState.CLOSED:
                    return
                was_ghost = conn.state == ConnectionState.GHOST
                conn.closed_at = time.time()
                conn.state = ConnectionState.CLOSED
                self._total_closed += 1

                if was_ghost:
                    self._ghost_count = max(0, self._ghost_count - 1)

    async def register_close_failed(self, request_id: str, error: str):
        """Register a connection that failed to close properly."""
        async with self._lock:
            if request_id in self._connections:
                conn = self._connections[request_id]
                if conn.state == ConnectionState.GHOST:
                    return
                conn.state = ConnectionState.GHOST
                self._ghost_count += 1
                self._total_ghosts += 1
                logger.warning(f"[ConnectionLifecycle] Close failed for {conn.host}: {error}")

    def get_stats(self) -> Dict[str, Any]:
        """Get lifecycle statistics."""
        active = sum(1 for c in self._connections.values() if c.state == ConnectionState.ACTIVE)
        return {
            "active_connections": active,
            "ghost_connections": self._ghost_count,
            "total_opened": self._total_opened,
            "total_closed": self._total_closed,
            "total_ghosts_detected": self._total_ghosts,
            "blocked_requests": self._blocked_requests,
            "close_rate": (self._total_closed / self._total_opened * 100) if self._total_opened > 0 else 100.0,
            "ghost_rate": (self._total_ghosts / self._total_opened * 100) if self._total_opened > 0 else 0.0,
        }

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of currently active connections."""
        return [
            {
                "request_id": c.request_id[:8],
                "host": c.host,
                "destination": c.destination,
                "age_seconds": c.age_seconds,
                "state": c.state.value,
            }
            for c in self._connections.values()
            if c.state in (ConnectionState.ACTIVE, ConnectionState.GHOST)
        ]


# Global connection lifecycle tracker
connection_lifecycle = ConnectionLifecycleTracker()
