"""
HTTP Client Orchestrator for BugTraceAI.

Thin facade — implementation lives in ``bugtrace.core.http_orch_shell``.
Public import path unchanged:

    from bugtrace.core.http_orchestrator import orchestrator, DestinationType
"""

from bugtrace.core.http_orch_shell import (
    DestinationType,
    CircuitState,
    TimeoutConfig,
    RetryPolicy,
    CircuitBreakerConfig,
    DestinationConfig,
    DESTINATION_CONFIGS,
    AdaptiveRetryCalculator,
    adaptive_retry,
    ConnectionState,
    TrackedConnection,
    ConnectionLifecycleTracker,
    connection_lifecycle,
    CircuitBreaker,
    HostCircuitBreakerRegistry,
    RequestMetrics,
    MetricsCollector,
    CircuitOpenError,
    ConnectionBlockedError,
    OrchestratorNotStartedError,
    DestinationClient,
    HealthMonitor,
    HTTPClientOrchestrator,
    HTTPClientManagerCompat,
)

# Global singleton
orchestrator = HTTPClientOrchestrator()

# Backward-compatible alias
http_manager_compat = HTTPClientManagerCompat(orchestrator)

__all__ = [
    "orchestrator",
    "HTTPClientOrchestrator",
    "DestinationType",
    "CircuitState",
    "TimeoutConfig",
    "RetryPolicy",
    "CircuitBreakerConfig",
    "DestinationConfig",
    "DESTINATION_CONFIGS",
    "CircuitBreaker",
    "DestinationClient",
    "HealthMonitor",
    "MetricsCollector",
    "RequestMetrics",
    "AdaptiveRetryCalculator",
    "adaptive_retry",
    "ConnectionLifecycleTracker",
    "connection_lifecycle",
    "ConnectionState",
    "TrackedConnection",
    "CircuitOpenError",
    "ConnectionBlockedError",
    "OrchestratorNotStartedError",
    "http_manager_compat",
    "HTTPClientManagerCompat",
]
