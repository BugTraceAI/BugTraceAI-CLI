"""
HTTP Client Orchestrator for BugTraceAI.

Production-grade HTTP client management with:
- Destination-based client isolation (LLM, Target, Service, Probe)
- Retry policies with exponential backoff
- Circuit breaker pattern for failing endpoints
- Health monitoring with automatic session recovery
- Per-destination metrics and statistics

Architecture:
    HTTPClientOrchestrator (Singleton)
    ├── DestinationType (enum)
    │   ├── LLM       - OpenRouter, AI APIs (high retry, long timeout)
    │   ├── TARGET    - Scan targets (circuit breaker, no keepalive)
    │   ├── SERVICE   - Internal services (Interarsh, Manipulator)
    │   └── PROBE     - Fast checks, callbacks (minimal retry)
    ├── RetryPolicy   - Configurable retry with backoff
    ├── CircuitBreaker - Prevents hammering dead endpoints
    ├── HealthMonitor - Watchdog for zombie sessions
    └── DestinationClient - Per-destination session management

Usage:
    from bugtrace.core.http_orchestrator import orchestrator, DestinationType

    # Simple request with automatic retry
    status, body = await orchestrator.get(url, DestinationType.TARGET)

    # With circuit breaker awareness
    async with orchestrator.request(DestinationType.LLM) as client:
        async with client.post(url, json=data) as resp:
            result = await resp.json()

    # Check health
    health = orchestrator.get_health_report()

Author: BugtraceAI Team
Version: 2.5.0
Date: 2026-01-31
"""

import aiohttp
import asyncio
import time
from enum import Enum
from typing import Optional, Dict, Any, Tuple, Callable, List
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from collections import deque
from bugtrace.utils.logger import get_logger

logger = get_logger("core.http_orchestrator")


# =============================================================================
# Enums and Configuration
# =============================================================================

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


class AdaptiveRetryCalculator:
    """
    Calculates optimal retry count based on real-time metrics.

    Adapts retry behavior based on:
    - Host success rate (historical performance)
    - Response latency (slow servers get fewer retries)
    - Circuit breaker state (half-open = minimal retries)
    - System load (backpressure reduces retries)

    This is NOT ML/AI - it's simple heuristics based on statistics.
    """

    # Thresholds for adaptive decisions
    SUCCESS_RATE_EXCELLENT = 95.0  # Almost never fails
    SUCCESS_RATE_GOOD = 80.0       # Occasionally fails
    SUCCESS_RATE_POOR = 50.0       # Frequently fails

    LATENCY_SLOW_THRESHOLD_MS = 5000   # Server is slow
    LATENCY_VERY_SLOW_MS = 10000       # Server is very slow

    LOAD_HIGH_THRESHOLD = 0.8  # 80% capacity

    def __init__(self):
        self._host_metrics: Dict[str, deque] = {}  # host -> recent results
        self._window_size = 100  # Track last N requests per host
        self._lock = asyncio.Lock()

    async def record_result(
        self,
        host: str,
        success: bool,
        latency_ms: float,
        status_code: int = 0
    ):
        """Record a request result for a host."""
        async with self._lock:
            if host not in self._host_metrics:
                self._host_metrics[host] = deque(maxlen=self._window_size)

            self._host_metrics[host].append({
                "success": success,
                "latency_ms": latency_ms,
                "status": status_code,
                "time": time.time(),
            })

    def get_host_stats(self, host: str) -> Dict[str, Any]:
        """Get statistics for a host."""
        if host not in self._host_metrics or not self._host_metrics[host]:
            return {
                "success_rate": 100.0,  # Assume good until proven otherwise
                "avg_latency_ms": 0,
                "p95_latency_ms": 0,
                "sample_count": 0,
            }

        metrics = list(self._host_metrics[host])
        successes = sum(1 for m in metrics if m["success"])
        latencies = [m["latency_ms"] for m in metrics if m["latency_ms"] > 0]

        # Calculate P95
        p95 = 0
        if latencies:
            sorted_lat = sorted(latencies)
            p95_idx = int(len(sorted_lat) * 0.95)
            p95 = sorted_lat[min(p95_idx, len(sorted_lat) - 1)]

        return {
            "success_rate": (successes / len(metrics)) * 100 if metrics else 100.0,
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0,
            "p95_latency_ms": p95,
            "sample_count": len(metrics),
        }

    def calculate_retries(
        self,
        host: str,
        base_policy: RetryPolicy,
        circuit_state: Optional['CircuitState'] = None,
        current_load: float = 0.0,
    ) -> int:
        """
        Calculate optimal retry count based on current conditions.

        Args:
            host: Target host
            base_policy: Base retry policy with max_retries
            circuit_state: Current circuit breaker state
            current_load: Current system load (0.0 - 1.0)

        Returns:
            Adapted number of retries (0 to base_policy.max_retries)
        """
        max_retries = base_policy.max_retries
        stats = self.get_host_stats(host)

        # Not enough data yet - use base policy
        if stats["sample_count"] < 5:
            return max_retries

        success_rate = stats["success_rate"]
        p95_latency = stats["p95_latency_ms"]

        # === Adaptive Rules ===

        # Rule 1: Success rate based adjustment
        if success_rate >= self.SUCCESS_RATE_EXCELLENT:
            # Almost never fails - minimal retries needed
            max_retries = min(max_retries, 1)
        elif success_rate >= self.SUCCESS_RATE_GOOD:
            # Occasionally fails - moderate retries
            max_retries = min(max_retries, 2)
        elif success_rate < self.SUCCESS_RATE_POOR:
            # Frequently fails - don't waste time retrying
            max_retries = 0
            logger.debug(f"[AdaptiveRetry] {host}: success_rate={success_rate:.1f}% - skipping retries")

        # Rule 2: Latency based adjustment
        if p95_latency > self.LATENCY_VERY_SLOW_MS:
            # Very slow server - reduce retries significantly
            max_retries = min(max_retries, 1)
        elif p95_latency > self.LATENCY_SLOW_THRESHOLD_MS:
            # Slow server - reduce retries
            max_retries = min(max_retries, 2)

        # Rule 3: Circuit breaker state
        if circuit_state == CircuitState.HALF_OPEN:
            # Testing recovery - minimal retries
            max_retries = min(max_retries, 1)
        elif circuit_state == CircuitState.OPEN:
            # Circuit open - no retries
            max_retries = 0

        # Rule 4: System load (backpressure)
        if current_load > self.LOAD_HIGH_THRESHOLD:
            # System under pressure - reduce retries
            max_retries = max(0, max_retries - 1)

        return max_retries

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get stats for all tracked hosts."""
        return {host: self.get_host_stats(host) for host in self._host_metrics}


# Global adaptive retry calculator (shared across all clients)
adaptive_retry = AdaptiveRetryCalculator()


# =============================================================================
# Connection Lifecycle Tracker - Detects ghost connections
# =============================================================================

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
                conn.closed_at = time.time()
                conn.state = ConnectionState.CLOSED
                self._total_closed += 1

                # If it was a ghost, decrement ghost count
                if conn.state == ConnectionState.GHOST:
                    self._ghost_count = max(0, self._ghost_count - 1)

    async def register_close_failed(self, request_id: str, error: str):
        """Register a connection that failed to close properly."""
        async with self._lock:
            if request_id in self._connections:
                conn = self._connections[request_id]
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


# Default configurations per destination type
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


# =============================================================================
# Circuit Breaker
# =============================================================================

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
        """Get current state, checking for timeout transition."""
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.config.timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(f"[CircuitBreaker:{self.name}] OPEN -> HALF_OPEN (timeout expired)")
        return self._state

    async def can_execute(self) -> bool:
        """Check if request can proceed."""
        async with self._lock:
            state = self.state

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


# =============================================================================
# Request Metrics
# =============================================================================

@dataclass
class RequestMetrics:
    """Metrics for a single request."""
    start_time: float
    end_time: float = 0
    status_code: int = 0
    success: bool = False
    retry_count: int = 0
    error: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        """Request duration in milliseconds."""
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0


class MetricsCollector:
    """
    Collects and aggregates request metrics per destination.

    Maintains a sliding window of recent requests for statistics.
    """

    def __init__(self, window_size: int = 1000):
        self._metrics: Dict[DestinationType, deque] = {
            dt: deque(maxlen=window_size) for dt in DestinationType
        }
        self._total_requests: Dict[DestinationType, int] = {
            dt: 0 for dt in DestinationType
        }
        self._total_failures: Dict[DestinationType, int] = {
            dt: 0 for dt in DestinationType
        }
        self._lock = asyncio.Lock()

    async def record(self, destination: DestinationType, metrics: RequestMetrics):
        """Record request metrics."""
        async with self._lock:
            self._metrics[destination].append(metrics)
            self._total_requests[destination] += 1
            if not metrics.success:
                self._total_failures[destination] += 1

    def get_stats(self, destination: DestinationType) -> Dict[str, Any]:
        """Get statistics for a destination type."""
        metrics = list(self._metrics[destination])
        if not metrics:
            return {
                "total_requests": 0,
                "success_rate": 0.0,
                "avg_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
                "error_rate": 0.0,
            }

        durations = [m.duration_ms for m in metrics if m.duration_ms > 0]
        successes = sum(1 for m in metrics if m.success)

        # Calculate p95
        sorted_durations = sorted(durations)
        p95_idx = int(len(sorted_durations) * 0.95)
        p95 = sorted_durations[p95_idx] if sorted_durations else 0

        return {
            "total_requests": self._total_requests[destination],
            "recent_requests": len(metrics),
            "success_rate": (successes / len(metrics)) * 100 if metrics else 0,
            "avg_latency_ms": sum(durations) / len(durations) if durations else 0,
            "p95_latency_ms": p95,
            "error_rate": ((len(metrics) - successes) / len(metrics)) * 100 if metrics else 0,
        }

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all destinations."""
        return {dt.value: self.get_stats(dt) for dt in DestinationType}


# =============================================================================
# Destination Client
# =============================================================================

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

            self._session = aiohttp.ClientSession(
                timeout=self.config.timeout.to_aiohttp(),
                connector=self._connector,
                headers={"User-Agent": self.config.user_agent}
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
        """Ensure session is available and healthy."""
        if self._session is None or self._session.closed:
            await self.start()
        return self._session

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
                                delay = retry_policy.get_delay(attempt)
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


# =============================================================================
# Health Monitor
# =============================================================================

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

        # Check session age
        if client._created_at > 0 and (now - client._created_at) > self._max_session_age:
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


# =============================================================================
# Custom Exceptions
# =============================================================================

class CircuitOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


class ConnectionBlockedError(Exception):
    """Raised when new connections are blocked due to ghost connections."""
    pass


class OrchestratorNotStartedError(Exception):
    """Raised when orchestrator is used before start()."""
    pass


# =============================================================================
# HTTP Client Orchestrator (Main Entry Point)
# =============================================================================

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
        self._ensure_started()
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
        self._ensure_started()
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
        self._ensure_started()
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
        self._ensure_started()
        return await self._clients[destination].request(method, url, **kwargs)

    @asynccontextmanager
    async def session(
        self,
        destination: DestinationType = DestinationType.TARGET
    ):
        """
        Get raw aiohttp session for custom operations.

        Note: Bypass retry and circuit breaker when using raw session.

        Usage:
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.post(url, json=data) as resp:
                    result = await resp.json()
        """
        self._ensure_started()
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


# =============================================================================
# Global Singleton Instance
# =============================================================================

orchestrator = HTTPClientOrchestrator()


# =============================================================================
# Backward Compatibility with http_manager
# =============================================================================

# Map old ConnectionProfile to new DestinationType
_PROFILE_TO_DESTINATION = {
    "probe": DestinationType.PROBE,
    "standard": DestinationType.TARGET,
    "extended": DestinationType.TARGET,
    "llm": DestinationType.LLM,
}


class HTTPClientManagerCompat:
    """
    Compatibility wrapper for old http_manager API.

    Allows gradual migration from http_manager to orchestrator.
    """

    def __init__(self, orch: HTTPClientOrchestrator):
        self._orch = orch

    async def start(self):
        await self._orch.start()

    async def shutdown(self):
        await self._orch.shutdown()

    def _map_profile(self, profile) -> DestinationType:
        """Map ConnectionProfile to DestinationType."""
        if hasattr(profile, 'value'):
            profile_value = profile.value
        else:
            profile_value = str(profile)
        return _PROFILE_TO_DESTINATION.get(profile_value, DestinationType.TARGET)

    @asynccontextmanager
    async def session(self, profile=None, headers=None):
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        async with self._orch.session(dest) as session:
            yield session

    @asynccontextmanager
    async def isolated_session(self, profile=None, headers=None, **kwargs):
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        async with self._orch.isolated_session(dest, headers, **kwargs) as session:
            yield session

    async def get(self, url: str, profile=None, **kwargs) -> Tuple[int, str]:
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        return await self._orch.get(url, dest, **kwargs)

    async def post(self, url: str, data=None, json=None, profile=None, **kwargs) -> Tuple[int, str]:
        dest = self._map_profile(profile) if profile else DestinationType.TARGET
        if data:
            kwargs['data'] = data
        if json:
            kwargs['json'] = json
        return await self._orch.post(url, dest, **kwargs)

    async def head(self, url: str, profile=None, **kwargs) -> int:
        dest = self._map_profile(profile) if profile else DestinationType.PROBE
        return await self._orch.head(url, dest, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        return self._orch.get_health_report()


# Backward-compatible alias
http_manager_compat = HTTPClientManagerCompat(orchestrator)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Main orchestrator
    'orchestrator',
    'HTTPClientOrchestrator',

    # Types
    'DestinationType',
    'CircuitState',

    # Configuration
    'TimeoutConfig',
    'RetryPolicy',
    'CircuitBreakerConfig',
    'DestinationConfig',
    'DESTINATION_CONFIGS',

    # Components
    'CircuitBreaker',
    'DestinationClient',
    'HealthMonitor',
    'MetricsCollector',
    'RequestMetrics',

    # Adaptive Retry
    'AdaptiveRetryCalculator',
    'adaptive_retry',

    # Connection Lifecycle (Ghost Detection)
    'ConnectionLifecycleTracker',
    'connection_lifecycle',
    'ConnectionState',
    'TrackedConnection',

    # Exceptions
    'CircuitOpenError',
    'ConnectionBlockedError',
    'OrchestratorNotStartedError',

    # Backward compatibility
    'http_manager_compat',
    'HTTPClientManagerCompat',
]
