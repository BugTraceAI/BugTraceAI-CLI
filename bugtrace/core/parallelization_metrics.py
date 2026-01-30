"""
Parallelization Metrics - Track concurrent worker activity.

Purpose: Measure parallelization factor for PERF-02.
Tracks how many specialist workers are active simultaneously.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Any, Set
from collections import defaultdict
from loguru import logger

from bugtrace.core.config import settings


@dataclass
class ParallelizationMetrics:
    """Track concurrent worker activity across specialists."""

    # Currently active workers by specialist
    _active_workers: Dict[str, Set[int]] = field(default_factory=lambda: defaultdict(set))

    # Peak concurrent workers (overall and per-specialist)
    _peak_concurrent: int = 0
    _peak_by_specialist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Total worker-seconds (for utilization calculation)
    _worker_start_times: Dict[str, Dict[int, float]] = field(default_factory=lambda: defaultdict(dict))
    _total_worker_seconds: Dict[str, float] = field(default_factory=lambda: defaultdict(float))

    # Scan timing
    _scan_start: float = field(default_factory=time.time)

    def record_worker_start(self, specialist: str, worker_id: int) -> None:
        """Record a worker starting work."""
        self._active_workers[specialist].add(worker_id)
        self._worker_start_times[specialist][worker_id] = time.monotonic()

        # Update peaks
        specialist_count = len(self._active_workers[specialist])
        total_count = sum(len(w) for w in self._active_workers.values())

        if specialist_count > self._peak_by_specialist[specialist]:
            self._peak_by_specialist[specialist] = specialist_count

        if total_count > self._peak_concurrent:
            self._peak_concurrent = total_count

        if settings.PERF_PARALLEL_LOG_ENABLED:
            logger.debug(f"[Parallelization] Worker started: {specialist}:{worker_id} "
                        f"(concurrent: {total_count}, peak: {self._peak_concurrent})")

    def record_worker_stop(self, specialist: str, worker_id: int) -> None:
        """Record a worker completing work."""
        self._active_workers[specialist].discard(worker_id)

        # Calculate worker-seconds
        start_time = self._worker_start_times[specialist].pop(worker_id, None)
        if start_time:
            duration = time.monotonic() - start_time
            self._total_worker_seconds[specialist] += duration

    def get_current_concurrent(self) -> int:
        """Get current number of concurrent workers."""
        return sum(len(w) for w in self._active_workers.values())

    def get_peak_concurrent(self) -> int:
        """Get peak number of concurrent workers."""
        return self._peak_concurrent

    def get_parallelization_factor(self) -> float:
        """
        Calculate average parallelization factor.

        Returns: Average concurrent workers during scan.
        Calculated as: total_worker_seconds / scan_duration
        """
        scan_duration = time.time() - self._scan_start
        if scan_duration <= 0:
            return 0.0

        total_seconds = sum(self._total_worker_seconds.values())
        return total_seconds / scan_duration

    def get_summary(self) -> Dict[str, Any]:
        """Get full parallelization metrics summary."""
        scan_duration = time.time() - self._scan_start

        # Import phase semaphore stats
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores
            phase_stats = phase_semaphores.get_stats()
        except ImportError:
            phase_stats = {}

        return {
            "current_concurrent": self.get_current_concurrent(),
            "peak_concurrent": self._peak_concurrent,
            "parallelization_factor": round(self.get_parallelization_factor(), 2),
            "scan_duration_seconds": round(scan_duration, 1),
            "by_specialist": {
                specialist: {
                    "current_workers": len(workers),
                    "peak_workers": self._peak_by_specialist.get(specialist, 0),
                    "total_worker_seconds": round(self._total_worker_seconds.get(specialist, 0), 2),
                }
                for specialist, workers in self._active_workers.items()
            },
            # Phase semaphore statistics (v2.4)
            "by_phase": phase_stats,
        }

    def log_summary(self) -> None:
        """Log parallelization summary."""
        if not settings.PERF_PARALLEL_LOG_ENABLED:
            return

        summary = self.get_summary()
        logger.info(
            f"[Parallelization Metrics] Scan Complete\n"
            f"  - Peak concurrent workers: {summary['peak_concurrent']}\n"
            f"  - Average parallelization: {summary['parallelization_factor']:.1f}x\n"
            f"  - Scan duration: {summary['scan_duration_seconds']:.1f}s"
        )

    def reset(self) -> None:
        """Reset all metrics for new scan."""
        self._active_workers.clear()
        self._peak_concurrent = 0
        self._peak_by_specialist.clear()
        self._worker_start_times.clear()
        self._total_worker_seconds.clear()
        self._scan_start = time.time()


# Global singleton
parallelization_metrics = ParallelizationMetrics()


def get_parallelization_summary() -> Dict[str, Any]:
    """Convenience function to get parallelization summary."""
    return parallelization_metrics.get_summary()


__all__ = ["ParallelizationMetrics", "parallelization_metrics", "get_parallelization_summary"]
