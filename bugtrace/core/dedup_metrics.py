"""
Deduplication Metrics - Track finding deduplication effectiveness.

Purpose: Measure deduplication effectiveness for PERF-03.
Tracks how many duplicate findings are eliminated before specialist processing.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Any, List
from collections import defaultdict
from loguru import logger

from bugtrace.core.config import settings


@dataclass
class DeduplicationMetrics:
    """Track deduplication effectiveness in ThinkingConsolidationAgent."""

    # Total findings received (before dedup)
    _total_received: int = 0

    # Deduplicated findings (eliminated as duplicates)
    _total_deduplicated: int = 0

    # FP filtered (eliminated by skeptical/fp_confidence)
    _total_fp_filtered: int = 0

    # Successfully distributed to queues
    _total_distributed: int = 0

    # Per-specialist breakdown
    _received_by_specialist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _deduplicated_by_specialist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _distributed_by_specialist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Duplicate key tracking (for analysis)
    _duplicate_keys: List[str] = field(default_factory=list)
    _max_duplicate_keys: int = 100  # Keep last N for debugging

    # Timing
    _scan_start: float = field(default_factory=time.time)

    def record_received(self, specialist: str = None) -> None:
        """Record a finding received for processing."""
        self._total_received += 1
        if specialist:
            self._received_by_specialist[specialist] += 1

    def record_duplicate(self, specialist: str, dedup_key: str) -> None:
        """Record a finding eliminated as duplicate."""
        self._total_deduplicated += 1
        self._deduplicated_by_specialist[specialist] += 1

        # Track duplicate keys for debugging
        if len(self._duplicate_keys) < self._max_duplicate_keys:
            self._duplicate_keys.append(dedup_key)

        if settings.PERF_DEDUP_LOG_ENABLED:
            logger.debug(f"[Dedup] Duplicate eliminated: {dedup_key[:50]}... "
                        f"(total: {self._total_deduplicated})")

    def record_fp_filtered(self) -> None:
        """Record a finding eliminated by FP confidence filter."""
        self._total_fp_filtered += 1

    def record_distributed(self, specialist: str) -> None:
        """Record a finding successfully distributed to queue."""
        self._total_distributed += 1
        self._distributed_by_specialist[specialist] += 1

    def get_dedup_effectiveness(self) -> float:
        """
        Calculate deduplication effectiveness percentage.

        Returns: Percentage of received findings that were duplicates.
        Formula: (deduplicated / received) * 100
        """
        if self._total_received == 0:
            return 0.0
        return (self._total_deduplicated / self._total_received) * 100

    def get_overall_reduction(self) -> float:
        """
        Calculate overall reduction (dedup + FP filtering).

        Returns: Percentage of received findings NOT distributed.
        Formula: ((received - distributed) / received) * 100
        """
        if self._total_received == 0:
            return 0.0
        eliminated = self._total_received - self._total_distributed
        return (eliminated / self._total_received) * 100

    def get_summary(self) -> Dict[str, Any]:
        """Get full deduplication metrics summary."""
        scan_duration = time.time() - self._scan_start

        return {
            "total_received": self._total_received,
            "total_deduplicated": self._total_deduplicated,
            "total_fp_filtered": self._total_fp_filtered,
            "total_distributed": self._total_distributed,
            "dedup_effectiveness_percent": round(self.get_dedup_effectiveness(), 1),
            "overall_reduction_percent": round(self.get_overall_reduction(), 1),
            "scan_duration_seconds": round(scan_duration, 1),
            "by_specialist": {
                specialist: {
                    "received": self._received_by_specialist.get(specialist, 0),
                    "deduplicated": self._deduplicated_by_specialist.get(specialist, 0),
                    "distributed": self._distributed_by_specialist.get(specialist, 0),
                }
                for specialist in set(self._received_by_specialist.keys()) |
                                 set(self._deduplicated_by_specialist.keys()) |
                                 set(self._distributed_by_specialist.keys())
            },
            "recent_duplicate_keys": self._duplicate_keys[-10:],  # Last 10 for debugging
        }

    def log_summary(self) -> None:
        """Log deduplication summary."""
        if not settings.PERF_DEDUP_LOG_ENABLED:
            return

        summary = self.get_summary()
        logger.info(
            f"[Deduplication Metrics] Scan Complete\n"
            f"  - Total received: {summary['total_received']}\n"
            f"  - Duplicates eliminated: {summary['total_deduplicated']} "
            f"({summary['dedup_effectiveness_percent']:.1f}%)\n"
            f"  - FP filtered: {summary['total_fp_filtered']}\n"
            f"  - Distributed to queues: {summary['total_distributed']}\n"
            f"  - Overall reduction: {summary['overall_reduction_percent']:.1f}%"
        )

    def reset(self) -> None:
        """Reset all metrics for new scan."""
        self._total_received = 0
        self._total_deduplicated = 0
        self._total_fp_filtered = 0
        self._total_distributed = 0
        self._received_by_specialist.clear()
        self._deduplicated_by_specialist.clear()
        self._distributed_by_specialist.clear()
        self._duplicate_keys.clear()
        self._scan_start = time.time()


# Global singleton
dedup_metrics = DeduplicationMetrics()


def get_dedup_summary() -> Dict[str, Any]:
    """Convenience function to get deduplication summary."""
    return dedup_metrics.get_summary()


__all__ = ["DeduplicationMetrics", "dedup_metrics", "get_dedup_summary"]
