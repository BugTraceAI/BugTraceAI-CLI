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
    DestinationConfig,
    TimeoutConfig,
)
from bugtrace.core.http_orch_shell.circuit import HostCircuitBreakerRegistry
from bugtrace.core.http_orch_shell.metrics import MetricsCollector, RequestMetrics
from bugtrace.core.http_orch_shell.adaptive import adaptive_retry
from bugtrace.core.http_orch_shell.lifecycle import connection_lifecycle
from bugtrace.core.http_orch_shell.errors import CircuitOpenError, ConnectionBlockedError

class DestinationClient:
    """
    HTTP client for a specific destination type.

    Manages session, retries, and circuit breaker for one destination.
    """

    def __init__(
        self,
        destination: DestinationType,
        config: DestinationConfig,
        metrics: MetricsCollector,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self.destination = destination
        self.config = config
        self.metrics = metrics
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._circuit_registry = HostCircuitBreakerRegistry(config.circuit_breaker)
        self._lock = asyncio.Lock()
        self._created_at: float = 0
        self._request_count = 0
        self._default_headers: Optional[Dict[str, str]] = default_headers

    async def start(self):
        """Initialize the client session."""
        async with self._lock:
            if self._session is not None and not self._session.closed:
                return

            # Build connector kwargs
            connector_kwargs = {
                "limit": self.config.pool_size,
                "limit_per_host": max(1, self.config.pool_size // 2),
                "ttl_dns_cache": 300,
                "enable_cleanup_closed": True,
            }

            if self.config.keepalive == 0:
                connector_kwargs["force_close"] = True
            else:
                connector_kwargs["keepalive_timeout"] = self.config.keepalive

            self._connector = aiohttp.TCPConnector(**connector_kwargs)

            # Merge User-Agent with any scan-level default headers. The per-call
            # `headers=` argument (kwargs) still wins over session defaults.
            session_headers = {"User-Agent": self.config.user_agent}
            if self._default_headers:
                session_headers.update(self._default_headers)

            self._session = aiohttp.ClientSession(
                timeout=self.config.timeout.to_aiohttp(),
                connector=self._connector,
                headers=session_headers,
            )

            self._created_at = time.time()
            self._request_count = 0

            logger.info(f"[DestinationClient:{self.destination.value}] Started "
                       f"(pool={self.config.pool_size}, timeout={self.config.timeout.total}s)")

    async def shutdown(self):
        """Close the client session."""
        async with self._lock:
            if self._session:
                try:
                    await self._session.close()
                except Exception as e:
                    logger.warning(f"[DestinationClient:{self.destination.value}] "
                                  f"Error closing session: {e}")
            if self._connector:
                try:
                    await self._connector.close()
                except Exception as e:
                    logger.warning(f"[DestinationClient:{self.destination.value}] "
                                  f"Error closing connector: {e}")

            self._session = None
            self._connector = None
            logger.debug(f"[DestinationClient:{self.destination.value}] Shutdown complete")

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure session is available and healthy, with auto-recovery."""
        if self._session is None or self._session.closed:
            await self.start()
            return self._session

        # Check if the session's event loop is still valid
        # This can happen if playwright or other code corrupts the loop
        try:
            loop = asyncio.get_running_loop()
            # Verify the connector is still usable by checking its internal state
            if self._connector and hasattr(self._connector, '_loop'):
                connector_loop = getattr(self._connector, '_loop', None)
                if connector_loop is not None and connector_loop != loop:
                    logger.warning(f"[DestinationClient:{self.destination.value}] "
                                  f"Event loop mismatch detected, recreating session")
                    await self._force_recreate_session()
        except RuntimeError as e:
            if "closed" in str(e).lower():
                logger.warning(f"[DestinationClient:{self.destination.value}] "
                              f"Event loop closed, recreating session")
                await self._force_recreate_session()

        return self._session

    async def _force_recreate_session(self):
        """Force recreate session when event loop issues detected."""
        async with self._lock:
            # Close old resources if possible
            if self._session:
                try:
                    await self._session.close()
                except Exception:
                    pass
            if self._connector:
                try:
                    await self._connector.close()
                except Exception:
                    pass

            self._session = None
            self._connector = None

        # Recreate
        await self.start()
        logger.info(f"[DestinationClient:{self.destination.value}] Session recreated after event loop issue")

    def _extract_host(self, url: str) -> str:
        """Extract host from URL for circuit breaker."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or "unknown"

    def _get_current_load(self) -> float:
        """Calculate current system load (0.0 - 1.0)."""
        if not self._connector:
            return 0.0
        try:
            active = len(self._connector._acquired) if hasattr(self._connector, '_acquired') else 0
            limit = self._connector.limit
            return active / limit if limit > 0 else 0.0
        except Exception:
            return 0.0

    def inflight_requests(self) -> int:
        """Number of connections currently checked out — i.e. in-flight requests.

        Used by the health monitor to avoid recycling a session while requests are
        still running on it (closing the connector under an active request aborts it).
        """
        if self._connector and hasattr(self._connector, "_acquired"):
            try:
                return len(self._connector._acquired)
            except Exception:
                return 0
        return 0

    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Tuple[int, str, RequestMetrics]:
        """
        Execute HTTP request with ADAPTIVE retry, circuit breaker, and lifecycle tracking.

        Retry count is dynamically calculated based on:
        - Host historical success rate
        - Response latency trends
        - Circuit breaker state
        - Current system load

        Lifecycle tracking ensures:
        - Ghost connections are detected
        - New requests are blocked if too many ghosts exist
        - All connections are properly closed

        Returns:
            Tuple of (status_code, body, metrics)
        """
        host = self._extract_host(url)
        circuit = await self._circuit_registry.get(host)
        retry_policy = self.config.retry

        # Generate unique request ID for lifecycle tracking
        request_id = f"{self.destination.value}-{time.time()}-{self._request_count}"

        # Check if we can open a new connection (ghost backpressure)
        can_open, block_reason = connection_lifecycle.can_open_connection()
        if not can_open:
            logger.warning(
                f"[DestinationClient:{self.destination.value}] "
                f"Waiting for connection capacity: {block_reason}"
            )
            if not await connection_lifecycle.wait_for_capacity():
                raise ConnectionBlockedError(f"Connection blocked: {block_reason}")

        # Calculate adaptive retry count based on current conditions
        current_load = self._get_current_load()
        max_retries = adaptive_retry.calculate_retries(
            host=host,
            base_policy=retry_policy,
            circuit_state=circuit.state,
            current_load=current_load,
        )

        metrics = RequestMetrics(start_time=time.time())
        last_error: Optional[Exception] = None

        # Register connection opening
        await connection_lifecycle.register_open(request_id, host, self.destination.value)

        try:
            for attempt in range(max_retries + 1):
                metrics.retry_count = attempt

                # Check circuit breaker
                if not await circuit.can_execute():
                    metrics.end_time = time.time()
                    metrics.error = "circuit_open"
                    await self.metrics.record(self.destination, metrics)
                    await adaptive_retry.record_result(host, False, 0, 0)
                    raise CircuitOpenError(f"Circuit breaker open for {host}")

                attempt_start = time.time()
                try:
                    session = await self._ensure_session()
                    self._request_count += 1

                    async with session.request(method, url, ssl=False, **kwargs) as resp:
                        body = await resp.text()
                        metrics.status_code = resp.status
                        metrics.end_time = time.time()
                        latency_ms = (metrics.end_time - attempt_start) * 1000

                        # Check if status is retryable
                        if retry_policy.should_retry_status(resp.status):
                            await adaptive_retry.record_result(host, False, latency_ms, resp.status)

                            if attempt < max_retries:
                                # Use Retry-After header for 429 if available
                                if resp.status == 429:
                                    retry_after = resp.headers.get("Retry-After")
                                    if retry_after:
                                        try:
                                            delay = float(retry_after)
                                        except ValueError:
                                            delay = retry_policy.get_delay(attempt)
                                    else:
                                        delay = retry_policy.get_delay(attempt)
                                else:
                                    delay = retry_policy.get_delay(attempt)
                                # Add jitter to prevent thundering herd
                                delay *= random.uniform(0.8, 1.2)
                                logger.debug(f"[DestinationClient:{self.destination.value}] "
                                            f"Retrying {url[:50]}... (status={resp.status}, "
                                            f"attempt={attempt+1}/{max_retries+1}, delay={delay:.1f}s)")
                                await asyncio.sleep(delay)
                                continue

                        # Success or non-retryable status
                        metrics.success = 200 <= resp.status < 400
                        await adaptive_retry.record_result(host, metrics.success, latency_ms, resp.status)

                        if metrics.success:
                            await circuit.record_success()
                        else:
                            await circuit.record_failure()

                        await self.metrics.record(self.destination, metrics)
                        return resp.status, body, metrics

                except Exception as e:
                    last_error = e
                    metrics.error = str(e)[:100]
                    latency_ms = (time.time() - attempt_start) * 1000

                    await adaptive_retry.record_result(host, False, latency_ms, 0)

                    if retry_policy.should_retry_exception(e):
                        if attempt < max_retries:
                            delay = retry_policy.get_delay(attempt)
                            logger.debug(f"[DestinationClient:{self.destination.value}] "
                                        f"Retrying {url[:50]}... (error={type(e).__name__}, "
                                        f"attempt={attempt+1}/{max_retries+1}, delay={delay:.1f}s)")
                            await asyncio.sleep(delay)
                            continue

                    await circuit.record_failure()
                    break

            # All retries exhausted
            metrics.end_time = time.time()
            metrics.success = False
            await self.metrics.record(self.destination, metrics)

            if last_error:
                raise last_error
            raise RuntimeError(f"Request failed after {max_retries + 1} attempts")

        finally:
            # CRITICAL: Always register connection close
            await connection_lifecycle.register_close(request_id)

    async def get(self, url: str, **kwargs) -> Tuple[int, str]:
        """GET request with retry."""
        status, body, _ = await self.request("GET", url, **kwargs)
        return status, body

    async def post(self, url: str, **kwargs) -> Tuple[int, str]:
        """POST request with retry."""
        status, body, _ = await self.request("POST", url, **kwargs)
        return status, body

    async def head(self, url: str, **kwargs) -> int:
        """HEAD request (no retry, fast fail) - with lifecycle tracking."""
        host = self._extract_host(url)
        request_id = f"{self.destination.value}-head-{time.time()}-{self._request_count}"

        # Check ghost backpressure (but don't block for HEAD - just warn)
        can_open, _ = connection_lifecycle.can_open_connection()
        if not can_open:
            logger.warning(f"[DestinationClient:{self.destination.value}] "
                          f"HEAD request during ghost backpressure: {host}")

        # Register connection
        await connection_lifecycle.register_open(request_id, host, self.destination.value)
        start_time = time.time()

        try:
            session = await self._ensure_session()
            async with session.head(url, ssl=False, allow_redirects=True, **kwargs) as resp:
                latency_ms = (time.time() - start_time) * 1000
                success = 200 <= resp.status < 400
                await adaptive_retry.record_result(host, success, latency_ms, resp.status)
                return resp.status
        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            await adaptive_retry.record_result(host, False, latency_ms, 0)
            return 0
        except Exception:
            latency_ms = (time.time() - start_time) * 1000
            await adaptive_retry.record_result(host, False, latency_ms, 0)
            return -1
        finally:
            # CRITICAL: Always register close
            await connection_lifecycle.register_close(request_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        connector_stats = {}
        if self._connector:
            connector_stats = {
                "limit": self._connector.limit,
                "active": len(self._connector._acquired) if hasattr(self._connector, '_acquired') else 0,
            }

        return {
            "destination": self.destination.value,
            "created_at": self._created_at,
            "request_count": self._request_count,
            "session_alive": self._session is not None and not self._session.closed,
            "connector": connector_stats,
            "circuit_breakers": self._circuit_registry.get_all_stats(),
        }
