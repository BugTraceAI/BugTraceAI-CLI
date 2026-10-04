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
    CircuitState,
    CircuitBreakerConfig,
)

class CircuitBreaker:
    """
    Circuit breaker implementation for preventing cascade failures.

    States:
        CLOSED: Normal operation, requests pass through
        OPEN: Too many failures, requests are rejected immediately
        HALF_OPEN: Testing recovery, limited requests allowed
    """

    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Get logical current state without mutating breaker internals."""
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.config.timeout:
                return CircuitState.HALF_OPEN
        return self._state

    def _transition_open_timeout_locked(self) -> None:
        if (
            self._state == CircuitState.OPEN
            and time.time() - self._last_failure_time >= self.config.timeout
        ):
            self._state = CircuitState.HALF_OPEN
            self._half_open_calls = 0
            logger.info(f"[CircuitBreaker:{self.name}] OPEN -> HALF_OPEN (timeout expired)")

    async def can_execute(self) -> bool:
        """Check if request can proceed."""
        async with self._lock:
            self._transition_open_timeout_locked()
            state = self._state

            if state == CircuitState.CLOSED:
                return True

            if state == CircuitState.OPEN:
                return False

            # HALF_OPEN: allow limited calls
            if self._half_open_calls < self.config.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

    async def record_success(self):
        """Record a successful request."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"[CircuitBreaker:{self.name}] HALF_OPEN -> CLOSED (recovered)")
            else:
                # In CLOSED state, reset failure count on success
                self._failure_count = max(0, self._failure_count - 1)

    async def record_failure(self):
        """Record a failed request."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open reopens circuit
                self._state = CircuitState.OPEN
                self._success_count = 0
                logger.warning(f"[CircuitBreaker:{self.name}] HALF_OPEN -> OPEN (failure during recovery)")

            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning(f"[CircuitBreaker:{self.name}] CLOSED -> OPEN "
                                  f"(failures={self._failure_count})")

    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "state": self.state.value,
            "failures": self._failure_count,
            "successes": self._success_count,
            "last_failure": self._last_failure_time,
        }


# =============================================================================
# Per-Host Circuit Breakers
# =============================================================================

class HostCircuitBreakerRegistry:
    """
    Registry of circuit breakers per host.

    Allows fine-grained control: if one host fails, others continue working.
    """

    def __init__(self, default_config: CircuitBreakerConfig):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._default_config = default_config
        self._lock = asyncio.Lock()

    async def get(self, host: str) -> CircuitBreaker:
        """Get or create circuit breaker for host."""
        if host not in self._breakers:
            async with self._lock:
                if host not in self._breakers:
                    self._breakers[host] = CircuitBreaker(host, self._default_config)
        return self._breakers[host]

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get stats for all circuit breakers."""
        return {host: cb.get_stats() for host, cb in self._breakers.items()}
