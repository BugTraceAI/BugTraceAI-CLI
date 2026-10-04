"""HTTP orchestrator shell — public surface remains bugtrace.core.http_orchestrator."""

from bugtrace.core.http_orch_shell.types import (
    DestinationType,
    CircuitState,
    TimeoutConfig,
    RetryPolicy,
    CircuitBreakerConfig,
    DestinationConfig,
    DESTINATION_CONFIGS,
)
from bugtrace.core.http_orch_shell.adaptive import AdaptiveRetryCalculator, adaptive_retry
from bugtrace.core.http_orch_shell.lifecycle import (
    ConnectionState,
    TrackedConnection,
    ConnectionLifecycleTracker,
    connection_lifecycle,
)
from bugtrace.core.http_orch_shell.circuit import CircuitBreaker, HostCircuitBreakerRegistry
from bugtrace.core.http_orch_shell.metrics import RequestMetrics, MetricsCollector
from bugtrace.core.http_orch_shell.errors import (
    CircuitOpenError,
    ConnectionBlockedError,
    OrchestratorNotStartedError,
)
from bugtrace.core.http_orch_shell.client import DestinationClient
from bugtrace.core.http_orch_shell.health import HealthMonitor
from bugtrace.core.http_orch_shell.orchestrator_core import HTTPClientOrchestrator
from bugtrace.core.http_orch_shell.compat import (
    HTTPClientManagerCompat,
    _PROFILE_TO_DESTINATION,
)

__all__ = [
    "DestinationType",
    "CircuitState",
    "TimeoutConfig",
    "RetryPolicy",
    "CircuitBreakerConfig",
    "DestinationConfig",
    "DESTINATION_CONFIGS",
    "AdaptiveRetryCalculator",
    "adaptive_retry",
    "ConnectionState",
    "TrackedConnection",
    "ConnectionLifecycleTracker",
    "connection_lifecycle",
    "CircuitBreaker",
    "HostCircuitBreakerRegistry",
    "RequestMetrics",
    "MetricsCollector",
    "CircuitOpenError",
    "ConnectionBlockedError",
    "OrchestratorNotStartedError",
    "DestinationClient",
    "HealthMonitor",
    "HTTPClientOrchestrator",
    "HTTPClientManagerCompat",
]
