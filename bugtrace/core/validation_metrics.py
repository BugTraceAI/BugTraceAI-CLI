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
from typing import Dict, Any
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
        """Log current metrics."""
        summary = self.get_summary()
        status = "MET" if summary["target_met"] else "NOT MET"
        logger.info(
            f"ValidationMetrics: {summary['total_findings']} findings | "
            f"CDP Load: {summary['cdp_load_percent']:.2f}% | Target (<1%): {status}"
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


__all__ = ["ValidationMetrics", "validation_metrics"]
