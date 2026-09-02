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


class DestinationType(Enum):
    """
    Destination types for HTTP requests.

    Each type has optimized settings for its specific use case.
    """
    LLM = "llm"          # OpenRouter, AI APIs - high value, must succeed
    TARGET = "target"    # Scan targets - potentially hostile, circuit breaker
    SERVICE = "service"  # Internal services (Interarsh, Manipulator)
    PROBE = "probe"      # Fast checks, OOB callbacks - minimal overhead

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered

@dataclass(frozen=True)
class TimeoutConfig:
    """Timeout configuration for a destination type."""
    total: float           # Total request timeout
    connect: float         # Connection establishment timeout
    sock_read: float       # Socket read timeout
    sock_connect: float    # Socket connection timeout

    def to_aiohttp(self) -> aiohttp.ClientTimeout:
        """Convert to aiohttp ClientTimeout."""
        return aiohttp.ClientTimeout(
            total=self.total,
            connect=self.connect,
            sock_read=self.sock_read,
            sock_connect=self.sock_connect
        )

@dataclass
class RetryPolicy:
    """
    Base retry policy with exponential backoff.

    Attributes:
        max_retries: Maximum number of retry attempts (baseline)
        base_delay: Initial delay between retries (seconds)
        max_delay: Maximum delay cap (seconds)
        exponential_base: Multiplier for exponential backoff
        retryable_statuses: HTTP status codes that trigger retry
        retryable_exceptions: Exception types that trigger retry
    """
    max_retries: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    exponential_base: float = 2.0
    retryable_statuses: Tuple[int, ...] = (429, 500, 502, 503, 504)
    retryable_exceptions: Tuple[type, ...] = (
        asyncio.TimeoutError,
        aiohttp.ClientConnectorError,
        aiohttp.ServerDisconnectedError,
        ConnectionResetError,
    )

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number (0-indexed)."""
        delay = self.base_delay * (self.exponential_base ** attempt)
        return min(delay, self.max_delay)

    def should_retry_status(self, status: int) -> bool:
        """Check if HTTP status should trigger retry."""
        return status in self.retryable_statuses

    def should_retry_exception(self, exc: Exception) -> bool:
        """Check if exception should trigger retry."""
        return isinstance(exc, self.retryable_exceptions)

@dataclass
class CircuitBreakerConfig:
    """
    Circuit breaker configuration.

    Attributes:
        failure_threshold: Failures before opening circuit
        success_threshold: Successes in half-open before closing
        timeout: Seconds before attempting recovery (open -> half-open)
        half_open_max_calls: Max concurrent calls in half-open state
    """
    failure_threshold: int = 5
    success_threshold: int = 2
    timeout: float = 30.0
    half_open_max_calls: int = 1

@dataclass
class DestinationConfig:
    """Complete configuration for a destination type."""
    timeout: TimeoutConfig
    retry: RetryPolicy
    circuit_breaker: CircuitBreakerConfig
    pool_size: int = 20
    keepalive: float = 0  # 0 = disabled
    user_agent: str = "BugTraceAI/2.5 Security Scanner"

DESTINATION_CONFIGS: Dict[DestinationType, DestinationConfig] = {
    DestinationType.LLM: DestinationConfig(
        timeout=TimeoutConfig(
            total=120.0,
            connect=10.0,
            sock_read=110.0,
            sock_connect=10.0
        ),
        retry=RetryPolicy(
            max_retries=3,
            base_delay=1.0,
            max_delay=30.0,
            retryable_statuses=(429, 500, 502, 503, 504, 520, 521, 522, 523, 524),
        ),
        circuit_breaker=CircuitBreakerConfig(
            failure_threshold=10,  # LLM APIs can be flaky
            timeout=60.0,
        ),
        pool_size=5,
        keepalive=60.0,
    ),
    DestinationType.TARGET: DestinationConfig(
        timeout=TimeoutConfig(
            total=30.0,
            connect=5.0,
            sock_read=25.0,
            sock_connect=5.0
        ),
        retry=RetryPolicy(
            max_retries=1,  # Don't hammer targets
            base_delay=0.5,
        ),
        circuit_breaker=CircuitBreakerConfig(
            failure_threshold=5,
            timeout=30.0,
        ),
        pool_size=50,
        keepalive=0,  # No keepalive for potentially hostile targets
    ),
    DestinationType.SERVICE: DestinationConfig(
        timeout=TimeoutConfig(
            total=60.0,
            connect=5.0,
            sock_read=55.0,
            sock_connect=5.0
        ),
        retry=RetryPolicy(
            max_retries=2,
            base_delay=0.5,
        ),
        circuit_breaker=CircuitBreakerConfig(
            failure_threshold=3,
            timeout=15.0,
        ),
        pool_size=10,
        keepalive=30.0,
    ),
    DestinationType.PROBE: DestinationConfig(
        timeout=TimeoutConfig(
            total=10.0,
            connect=3.0,
            sock_read=8.0,
            sock_connect=3.0
        ),
        retry=RetryPolicy(
            max_retries=0,  # Probes should fail fast
            base_delay=0.1,
        ),
        circuit_breaker=CircuitBreakerConfig(
            failure_threshold=20,  # High tolerance for probes
            timeout=10.0,
        ),
        pool_size=30,
        keepalive=0,
    ),
}
