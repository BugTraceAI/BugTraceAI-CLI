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
from bugtrace.core.http_orch_shell.types import CircuitState, RetryPolicy

logger = get_logger("core.http_orchestrator")


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
