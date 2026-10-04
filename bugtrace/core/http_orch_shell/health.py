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

from bugtrace.core.http_orch_shell.types import DestinationType
from bugtrace.core.http_orch_shell.client import DestinationClient

class HealthMonitor:
    """
    Watchdog for monitoring client health and recovering zombie sessions.

    Runs as a background task, checking session health periodically.
    """

    def __init__(
        self,
        clients: Dict[DestinationType, DestinationClient],
        check_interval: float = 30.0,
        max_session_age: float = 3600.0,  # 1 hour
        max_idle_time: float = 300.0,     # 5 minutes
    ):
        self._clients = clients
        self._check_interval = check_interval
        self._max_session_age = max_session_age
        self._max_idle_time = max_idle_time
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_check: float = 0
        self._restarts: Dict[DestinationType, int] = {dt: 0 for dt in DestinationType}

    async def start(self):
        """Start the health monitor background task."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("[HealthMonitor] Started")

    async def stop(self):
        """Stop the health monitor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[HealthMonitor] Stopped")

    async def _monitor_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                await self._check_all_clients()
                self._last_check = time.time()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[HealthMonitor] Error in monitor loop: {e}")

    async def _check_all_clients(self):
        """Check health of all clients."""
        for dest_type, client in self._clients.items():
            try:
                await self._check_client(dest_type, client)
            except Exception as e:
                logger.warning(f"[HealthMonitor] Error checking {dest_type.value}: {e}")

    async def _check_client(self, dest_type: DestinationType, client: DestinationClient):
        """Check health of a single client."""
        now = time.time()

        # Check if session is dead
        if client._session is None or client._session.closed:
            logger.warning(f"[HealthMonitor] {dest_type.value} session dead, restarting...")
            await client.start()
            self._restarts[dest_type] += 1
            return

        # Check session age — but NEVER recycle a session that has in-flight requests.
        # shutdown() closes the session + connector; doing that under an active request
        # aborts it as a CancelledError. When the active request is a long reporting-
        # enrichment LLM call, that abort propagates out of reporting and is mislabeled as
        # a scan cancellation (scan 62 root cause: report left un-enriched). Recycling is
        # only connection hygiene, so defer it until the session is idle; the next health
        # check retries.
        if client._created_at > 0 and (now - client._created_at) > self._max_session_age:
            inflight = client.inflight_requests()
            if inflight > 0:
                logger.debug(
                    f"[HealthMonitor] {dest_type.value} session aged out but has {inflight} "
                    f"in-flight request(s); deferring recycle until idle."
                )
                return
            logger.info(f"[HealthMonitor] {dest_type.value} session aged out, recycling...")
            await client.shutdown()
            await client.start()
            self._restarts[dest_type] += 1
            return

        # Check connector health
        if client._connector and client._connector.closed:
            logger.warning(f"[HealthMonitor] {dest_type.value} connector closed, restarting...")
            await client.shutdown()
            await client.start()
            self._restarts[dest_type] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get health monitor statistics."""
        return {
            "running": self._running,
            "last_check": self._last_check,
            "check_interval": self._check_interval,
            "restarts": dict(self._restarts),
            "total_restarts": sum(self._restarts.values()),
        }
