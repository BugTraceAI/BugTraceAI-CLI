"""
Metrics API Routes - Performance metrics endpoints for PERF-04.

Provides real-time metrics for dashboard visualization:
- Queue depths and throughput
- CDP validation reduction
- Parallelization factor
- Deduplication effectiveness
"""

from typing import Dict, Any
from fastapi import APIRouter

from bugtrace.core.queue import queue_manager
from bugtrace.core.validation_metrics import validation_metrics, get_cdp_reduction_summary
from bugtrace.core.parallelization_metrics import parallelization_metrics, get_parallelization_summary
from bugtrace.core.dedup_metrics import dedup_metrics, get_dedup_summary

router = APIRouter()


@router.get("/metrics")
async def get_all_metrics() -> Dict[str, Any]:
    """
    Get all performance metrics.

    Returns:
        Combined metrics from all subsystems:
        - cdp: CDP validation reduction metrics
        - parallelization: Worker concurrency metrics
        - deduplication: Finding dedup metrics
        - queues: Queue depth and throughput summary
    """
    return {
        "cdp": get_cdp_reduction_summary(),
        "parallelization": get_parallelization_summary(),
        "deduplication": get_dedup_summary(),
        "queues": queue_manager.get_aggregate_stats(),
    }


@router.get("/metrics/queues")
async def get_queue_metrics() -> Dict[str, Any]:
    """
    Get detailed queue metrics for all specialist queues.

    Returns:
        Per-queue statistics:
        - current_depth: Items waiting in queue
        - total_enqueued/dequeued: Throughput counters
        - avg_latency_ms: Processing time
        - is_full: Backpressure status
    """
    return {
        "aggregate": queue_manager.get_aggregate_stats(),
        "by_queue": queue_manager.get_all_stats(),
    }


@router.get("/metrics/cdp")
async def get_cdp_metrics() -> Dict[str, Any]:
    """
    Get CDP validation reduction metrics.

    Returns:
        - reduction_percent: Percentage of findings that skipped CDP
        - target_met: Whether 99% reduction target achieved
        - by_specialist: Per-specialist breakdown
    """
    return get_cdp_reduction_summary()


@router.get("/metrics/parallelization")
async def get_parallelization_metrics() -> Dict[str, Any]:
    """
    Get worker parallelization metrics.

    Returns:
        - current_concurrent: Active workers now
        - peak_concurrent: Maximum concurrent workers
        - parallelization_factor: Average concurrency
        - by_specialist: Per-specialist worker stats
    """
    return get_parallelization_summary()


@router.get("/metrics/deduplication")
async def get_deduplication_metrics() -> Dict[str, Any]:
    """
    Get deduplication effectiveness metrics.

    Returns:
        - total_received: Findings before dedup
        - total_deduplicated: Duplicates eliminated
        - dedup_effectiveness_percent: Duplicate rate
        - by_specialist: Per-specialist breakdown
    """
    return get_dedup_summary()


@router.post("/metrics/reset")
async def reset_metrics() -> Dict[str, str]:
    """
    Reset all performance metrics.

    Use at scan start for clean measurements.
    """
    validation_metrics.reset()
    parallelization_metrics.reset()
    dedup_metrics.reset()
    queue_manager.reset_all_stats()

    return {"status": "reset", "message": "All metrics reset successfully"}
