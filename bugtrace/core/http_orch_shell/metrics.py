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
from bugtrace.core.http_orch_shell.types import DestinationType

logger = get_logger("core.http_orchestrator")


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
