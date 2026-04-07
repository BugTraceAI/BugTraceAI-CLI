"""
Validation Metrics - Track CDP validation load reduction.

Purpose: Measure whether specialist self-validation achieves <1% CDP target (VAL-02).

The validation optimization strategy (Phase 21) aims to reduce CDP (Chrome DevTools Protocol)
validation load by 99%+ through smart classification:
- VALIDATED_CONFIRMED: High confidence findings that skip CDP validation
- PENDING_VALIDATION: Edge cases that require CDP validation (<1% of findings)

This module provides centralized metrics tracking to verify the <1% CDP load target.

Usage:
    from bugtrace.core.validation_metrics import ValidationMetrics, validation_metrics

    # Record findings as they are classified
    validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
    validation_metrics.record_finding("xss", "PENDING_VALIDATION")

    # Check if target is met
    if validation_metrics.is_target_met():
        print("CDP load target (<1%) achieved!")

    # Get full summary
    print(validation_metrics.get_summary())
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List
from collections import defaultdict
import time
from loguru import logger

from bugtrace.core.config import settings


@dataclass
class ValidationMetrics:
    """Track validation status distribution across specialists."""

    # Per-specialist counters
    _confirmed_by_specialist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _pending_by_specialist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Global counters
    _total_findings: int = 0
    _total_confirmed: int = 0  # VALIDATED_CONFIRMED (skipped CDP)
    _total_pending: int = 0    # PENDING_VALIDATION (sent to CDP)
    _total_cdp_validated: int = 0  # CDP confirmed
    _total_cdp_rejected: int = 0   # CDP rejected as FP

    # Timing
    _start_time: float = field(default_factory=time.time)
    _last_log_time: float = field(default_factory=time.time)

    def record_finding(self, specialist: str, status: str) -> None:
        """
        Record a finding with its validation status.

        Args:
            specialist: Name of the specialist agent (e.g., "xss", "sqli")
            status: Validation status - "VALIDATED_CONFIRMED" or "PENDING_VALIDATION"
        """
        self._total_findings += 1

        if status == "VALIDATED_CONFIRMED":
            self._confirmed_by_specialist[specialist] += 1
            self._total_confirmed += 1
        elif status == "PENDING_VALIDATION":
            self._pending_by_specialist[specialist] += 1
            self._total_pending += 1

        # Log periodically
        if settings.VALIDATION_METRICS_ENABLED:
            if self._total_findings % settings.VALIDATION_LOG_INTERVAL == 0:
                self._log_metrics()

    def record_cdp_result(self, validated: bool) -> None:
        """
        Record CDP validation result.

        Args:
            validated: True if CDP confirmed the vulnerability, False if rejected as FP
        """
        if validated:
            self._total_cdp_validated += 1
        else:
            self._total_cdp_rejected += 1

    def get_cdp_load(self) -> float:
        """
        Calculate CDP load percentage.

        Returns:
            Percentage of findings sent to CDP validation (0-100)
        """
        if self._total_findings == 0:
            return 0.0
        return (self._total_pending / self._total_findings) * 100

    def is_target_met(self) -> bool:
        """
        Check if CDP load is below target (<1%).

        Returns:
            True if CDP load percentage <= target (default 1%)
        """
        return self.get_cdp_load() <= (settings.CDP_LOAD_TARGET * 100)

    def get_summary(self) -> Dict[str, Any]:
        """
        Get full metrics summary.

        Returns:
            Dictionary with all metrics including:
            - total_findings: Total findings processed
            - validated_confirmed: Findings that skipped CDP
            - pending_validation: Findings sent to CDP
            - cdp_validated: CDP confirmed vulnerabilities
            - cdp_rejected: CDP rejected false positives
            - cdp_load_percent: Percentage of findings sent to CDP
            - target_met: Whether <1% target is achieved
            - by_specialist: Breakdown by specialist agent
            - elapsed_seconds: Time since metrics started
        """
        cdp_load = self.get_cdp_load()
        elapsed = time.time() - self._start_time

        return {
            "total_findings": self._total_findings,
            "validated_confirmed": self._total_confirmed,
            "pending_validation": self._total_pending,
            "cdp_validated": self._total_cdp_validated,
            "cdp_rejected": self._total_cdp_rejected,
            "cdp_load_percent": round(cdp_load, 2),
            "target_met": self.is_target_met(),
            "target_percent": settings.CDP_LOAD_TARGET * 100,
            "by_specialist": {
                "confirmed": dict(self._confirmed_by_specialist),
                "pending": dict(self._pending_by_specialist),
            },
            "elapsed_seconds": round(elapsed, 1),
        }

    def _log_metrics(self) -> None:
        """Log current metrics (periodic progress logging)."""
        summary = self.get_summary()
        status = "MET" if summary["target_met"] else "NOT MET"
        logger.info(
            f"ValidationMetrics: {summary['total_findings']} findings | "
            f"CDP Load: {summary['cdp_load_percent']:.2f}% | Target (<1%): {status}"
        )

    def get_reduction_percent(self) -> float:
        """
        Calculate CDP reduction percentage.

        Returns:
            Percentage of findings that SKIPPED CDP (complement of CDP load).
            Example: if 1% went to CDP, reduction = 99%
        """
        if self._total_findings == 0:
            return 100.0  # No findings = 100% reduction (no CDP needed)
        return (1 - (self._total_pending / self._total_findings)) * 100

    def is_reduction_target_met(self) -> bool:
        """
        Check if reduction meets target (>=99%, i.e., CDP load <= 1%).

        Returns:
            True if reduction >= 99% (CDP load <= target)
        """
        return self.get_cdp_load() <= (settings.CDP_LOAD_TARGET * 100)

    def get_reduction_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive reduction metrics for API consumption.

        Returns:
            Dictionary with:
            - reduction_percent: Percentage of findings that skipped CDP
            - target_met: Whether reduction >= 99%
            - target_percent: Target percentage (99%)
            - total_findings: Total findings processed
            - skipped_cdp: Findings that skipped CDP (VALIDATED_CONFIRMED)
            - sent_to_cdp: Findings sent to CDP (PENDING_VALIDATION)
            - cdp_validated: CDP confirmed vulnerabilities
            - cdp_rejected: CDP rejected as FP
            - cdp_load_percent: Percentage of findings sent to CDP
            - per_specialist: Breakdown by specialist agent
            - elapsed_seconds: Time since metrics started
        """
        reduction = self.get_reduction_percent()
        target_met = self.is_reduction_target_met()
        elapsed = time.time() - self._start_time

        # Build per-specialist breakdown
        all_specialists = set(self._confirmed_by_specialist.keys()) | set(self._pending_by_specialist.keys())
        per_specialist = {}
        for specialist in sorted(all_specialists):
            per_specialist[specialist] = {
                "confirmed": self._confirmed_by_specialist.get(specialist, 0),
                "pending": self._pending_by_specialist.get(specialist, 0),
            }

        return {
            "reduction_percent": round(reduction, 2),
            "target_met": target_met,
            "target_percent": (1 - settings.CDP_LOAD_TARGET) * 100,  # 99%
            "total_findings": self._total_findings,
            "skipped_cdp": self._total_confirmed,
            "sent_to_cdp": self._total_pending,
            "cdp_validated": self._total_cdp_validated,
            "cdp_rejected": self._total_cdp_rejected,
            "cdp_load_percent": round(self.get_cdp_load(), 2),
            "per_specialist": per_specialist,
            "elapsed_seconds": round(elapsed, 1),
        }

    def log_reduction_summary(self) -> None:
        """
        Log formatted CDP reduction summary.

        Only logs if PERF_CDP_LOG_ENABLED is True in settings.
        Outputs structured log with:
        - Total findings breakdown
        - CDP reduction percentage
        - Target comparison (>=99%)
        - Per-specialist breakdown
        """
        if not getattr(settings, 'PERF_CDP_LOG_ENABLED', True):
            return

        summary = self.get_reduction_summary()
        status = "TARGET_MET" if summary["target_met"] else "TARGET_MISSED"

        # Build per-specialist string
        specialist_parts = []
        for name, counts in summary["per_specialist"].items():
            specialist_parts.append(f"{name}={counts['confirmed']}/{counts['pending']}")
        specialist_str = ", ".join(specialist_parts) if specialist_parts else "none"

        logger.info(
            f"\n"
            f"[CDP Metrics] Scan Complete\n"
            f"  - Total findings: {summary['total_findings']}\n"
            f"  - Skipped CDP (VALIDATED_CONFIRMED): {summary['skipped_cdp']}\n"
            f"  - Sent to CDP (PENDING_VALIDATION): {summary['sent_to_cdp']}\n"
            f"  - CDP reduction: {summary['reduction_percent']:.1f}% (target: >=99%)\n"
            f"  - Status: {status}\n"
            f"  - Per-specialist (confirmed/pending): {specialist_str}"
        )

    def reset(self) -> None:
        """Reset all metrics."""
        self._confirmed_by_specialist.clear()
        self._pending_by_specialist.clear()
        self._total_findings = 0
        self._total_confirmed = 0
        self._total_pending = 0
        self._total_cdp_validated = 0
        self._total_cdp_rejected = 0
        self._start_time = time.time()


# Global singleton
validation_metrics = ValidationMetrics()


def get_cdp_reduction_summary() -> Dict[str, Any]:
    """
    Convenience function to get CDP reduction summary from global singleton.

    Returns:
        Dictionary with reduction metrics (see ValidationMetrics.get_reduction_summary())
    """
    return validation_metrics.get_reduction_summary()


__all__ = ["ValidationMetrics", "validation_metrics", "get_cdp_reduction_summary"]
