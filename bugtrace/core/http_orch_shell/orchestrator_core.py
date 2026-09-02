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

from bugtrace.core.http_orch_shell.types import (
    DestinationType,
    DESTINATION_CONFIGS,
)
from bugtrace.core.http_orch_shell.client import DestinationClient
from bugtrace.core.http_orch_shell.metrics import MetricsCollector, RequestMetrics
from bugtrace.core.http_orch_shell.health import HealthMonitor
from bugtrace.core.http_orch_shell.adaptive import adaptive_retry
from bugtrace.core.http_orch_shell.lifecycle import connection_lifecycle
from bugtrace.core.http_orch_shell.errors import OrchestratorNotStartedError

class HTTPClientOrchestrator:
    """
    Centralized HTTP client orchestrator.

    Manages destination-specific clients with retry, circuit breaker,
    and health monitoring.

    Usage:
        # Start at application startup
        await orchestrator.start()

        # Make requests
        status, body = await orchestrator.get(url, DestinationType.TARGET)

        # Or with context manager for raw session access
        async with orchestrator.session(DestinationType.LLM) as session:
            async with session.post(url, json=data) as resp:
                result = await resp.json()

        # Shutdown at application exit
        await orchestrator.shutdown()
    """

    _instance: Optional["HTTPClientOrchestrator"] = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._metrics = MetricsCollector()
        self._clients: Dict[DestinationType, DestinationClient] = {}
        self._health_monitor: Optional[HealthMonitor] = None
        self._started = False
        self._initialized = True

        # Initialize clients (but don't start sessions yet)
        for dest_type in DestinationType:
            config = DESTINATION_CONFIGS[dest_type]
            self._clients[dest_type] = DestinationClient(dest_type, config, self._metrics)

        logger.info("[HTTPClientOrchestrator] Initialized (lazy startup)")

    async def start(self):
        """
        Start the orchestrator and all clients.

        Call this during application startup.
        """
        async with self._lock:
            if self._started:
                return

            # Start connection lifecycle tracker (ghost detection)
            await connection_lifecycle.start()

            # Start all destination clients
            for dest_type, client in self._clients.items():
                await client.start()

            # Start health monitor
            self._health_monitor = HealthMonitor(self._clients)
            await self._health_monitor.start()

            self._started = True
            logger.info(f"[HTTPClientOrchestrator] Started with {len(DestinationType)} destinations")

    async def shutdown(self):
        """
        Shutdown the orchestrator and all clients.

        Call this during application shutdown.
        """
        async with self._lock:
            # Stop health monitor
            if self._health_monitor:
                await self._health_monitor.stop()

            # Shutdown all clients
            for client in self._clients.values():
                await client.shutdown()

            # Stop connection lifecycle tracker and log final stats
            await connection_lifecycle.stop()

            self._started = False
            logger.info("[HTTPClientOrchestrator] Shutdown complete")

    def _ensure_started(self):
        """Ensure orchestrator is started."""
        if not self._started:
            raise OrchestratorNotStartedError(
                "HTTPClientOrchestrator not started. Call await orchestrator.start() first."
            )

    async def get(
        self,
        url: str,
        destination: DestinationType = DestinationType.TARGET,
        **kwargs
    ) -> Tuple[int, str]:
        """
        Perform GET request.

        Args:
            url: URL to fetch
            destination: Destination type for routing
            **kwargs: Additional aiohttp kwargs

        Returns:
            Tuple of (status_code, body)
        """
        if not self._started:
            await self.start()
        return await self._clients[destination].get(url, **kwargs)

    async def post(
        self,
        url: str,
        destination: DestinationType = DestinationType.TARGET,
        **kwargs
    ) -> Tuple[int, str]:
        """
        Perform POST request.

        Args:
            url: URL to post to
            destination: Destination type for routing
            **kwargs: Additional aiohttp kwargs (data, json, etc.)

        Returns:
            Tuple of (status_code, body)
        """
        if not self._started:
            await self.start()
        return await self._clients[destination].post(url, **kwargs)

    async def head(
        self,
        url: str,
        destination: DestinationType = DestinationType.PROBE,
        **kwargs
    ) -> int:
        """
        Perform HEAD request.

        Returns:
            HTTP status code (0 for timeout, -1 for error)
        """
        if not self._started:
            await self.start()
        return await self._clients[destination].head(url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        destination: DestinationType = DestinationType.TARGET,
        **kwargs
    ) -> Tuple[int, str, RequestMetrics]:
        """
        Perform arbitrary HTTP request with full metrics.

        Returns:
            Tuple of (status_code, body, metrics)
        """
        if not self._started:
            await self.start()
        return await self._clients[destination].request(method, url, **kwargs)

    @asynccontextmanager
    async def session(
        self,
        destination: DestinationType = DestinationType.TARGET
    ):
        """
        Get raw aiohttp session for custom operations.

        Note: Bypass retry and circuit breaker when using raw session.
        Auto-starts orchestrator if not already started.

        Usage:
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(url, json=data) as resp:
                    result = await resp.json()
        """
        # Auto-start if needed (safe for boot checks and lazy initialization)
        if not self._started:
            await self.start()

        client = self._clients[destination]
        session = await client._ensure_session()
        yield session

    @asynccontextmanager
    async def isolated_session(
        self,
        destination: DestinationType = DestinationType.TARGET,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        """
        Create isolated session not part of the pool.

        Use for one-off requests needing custom configuration.
        """
        config = DESTINATION_CONFIGS[destination]

        connector = aiohttp.TCPConnector(
            limit=10,
            enable_cleanup_closed=True,
            force_close=True,
        )

        session = aiohttp.ClientSession(
            timeout=config.timeout.to_aiohttp(),
            connector=connector,
            headers=headers,
            **kwargs
        )

        try:
            yield session
        finally:
            await session.close()
            await connector.close()

    def get_health_report(self) -> Dict[str, Any]:
        """
        Get comprehensive health report.

        Returns:
            Health report with metrics, circuit breakers, adaptive retry, lifecycle, and client stats
        """
        return {
            "started": self._started,
            "metrics": self._metrics.get_all_stats(),
            "clients": {
                dest.value: client.get_stats()
                for dest, client in self._clients.items()
            },
            "health_monitor": self._health_monitor.get_stats() if self._health_monitor else None,
            "adaptive_retry": adaptive_retry.get_all_stats(),
            "connection_lifecycle": connection_lifecycle.get_stats(),
            "active_connections": connection_lifecycle.get_active_connections(),
        }

    def get_client(self, destination: DestinationType) -> DestinationClient:
        """Get destination client for advanced operations."""
        return self._clients[destination]

    def set_default_headers(self, headers: Optional[Dict[str, str]]) -> None:
        """Apply scan-level default headers to TARGET and PROBE destinations.

        Called by the orchestrator (or a scan bootstrap) after authentication
        has been resolved but before any specialist agent issues HTTP traffic.
        Recreates active sessions so the headers actually take effect — aiohttp
        freezes session headers at construction time.

        IMPORTANT: LLM and SERVICE destinations are EXPLICITLY EXCLUDED. The
        scan target may carry a per-user Authorization header; if that leaked
        into DestinationType.LLM we would forward the user's bug-bounty token
        to OpenRouter / Anthropic, which is a serious credential-misrouting
        bug. SERVICE (internal Interactsh / Manipulator) is also excluded:
        those backends have their own auth contract and should never receive
        arbitrary scan headers.

        Args:
            headers: A header dict, or None to clear the defaults.
        """
        normalized = dict(headers) if headers else None
        # Whitelist of destination types that receive scan-level headers. A
        # whitelist is safer than a blacklist: adding a new destination in
        # the future does NOT silently inherit the leak.
        _SCAN_HEADER_DESTINATIONS = frozenset(
            {DestinationType.TARGET, DestinationType.PROBE}
        )
        for dest_type, client in self._clients.items():
            if dest_type not in _SCAN_HEADER_DESTINATIONS:
                # Defensive: also clear any previously-set default on these
                # destinations so a stale value from a prior call cannot
                # leak across scans.
                client._default_headers = None
                continue
            client._default_headers = normalized
            # Mark the session dirty so the next request rebuilds it with the
            # new defaults. _ensure_session will re-create on demand.
            if client._session is not None:
                client._session = None
                if client._connector is not None:
                    # Best-effort close; ignore errors during recreation.
                    try:
                        # Schedule close on the running loop if available.
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(client._connector.close())
                        else:
                            # Fallback: schedule without awaiting.
                            asyncio.ensure_future(client._connector.close())
                    except Exception:
                        pass
                    client._connector = None
