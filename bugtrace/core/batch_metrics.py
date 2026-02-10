"""
Batch Processing Metrics for V3 Pipeline.

Tracks:
- Scan duration (sequential baseline vs batch)
- Deduplication effectiveness
- Parallelization factor
- Queue throughput
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from loguru import logger


@dataclass
class BatchMetrics:
    """Metrics for batch processing performance."""

    # Timing
    start_time: float = 0.0
    dast_start_time: float = 0.0
    dast_end_time: float = 0.0
    queue_drain_start_time: float = 0.0
    queue_drain_end_time: float = 0.0
    end_time: float = 0.0

    # Counts
    urls_discovered: int = 0
    urls_analyzed: int = 0
    findings_before_dedup: int = 0
    findings_after_dedup: int = 0
    findings_distributed: int = 0
    findings_exploited: int = 0

    # Finding sources (for integrity verification)
    findings_dast: int = 0          # DASTySAST findings only
    findings_auth: int = 0          # AuthDiscovery findings only

    # WET→DRY tracking (integrity verification)
    wet_processed: int = 0  # Total WET items consumed by specialists
    dry_generated: int = 0  # Total DRY items produced after dedup

    # Per-specialist
    by_specialist: Dict[str, int] = field(default_factory=dict)
    wet_by_specialist: Dict[str, int] = field(default_factory=dict)
    dry_by_specialist: Dict[str, int] = field(default_factory=dict)

    def start_scan(self):
        """Mark scan start."""
        self.start_time = time.monotonic()

    def start_dast(self):
        """Mark DAST batch start."""
        self.dast_start_time = time.monotonic()

    def end_dast(self, urls_analyzed: int, findings_count: int):
        """Mark DAST batch end."""
        self.dast_end_time = time.monotonic()
        self.urls_analyzed = urls_analyzed
        self.findings_before_dedup = findings_count
        self.findings_dast = findings_count  # Track DAST separately

    def add_auth_findings(self, count: int):
        """Record AuthDiscovery findings count."""
        self.findings_auth = count
        self.findings_before_dedup += count

    def start_queue_drain(self):
        """Mark queue drain wait start."""
        self.queue_drain_start_time = time.monotonic()

    def end_queue_drain(self, findings_distributed: int, by_specialist: Dict[str, int]):
        """Mark queue drain wait end."""
        self.queue_drain_end_time = time.monotonic()
        self.findings_distributed = findings_distributed
        self.by_specialist = by_specialist

    def record_specialist_wet_dry(self, specialist: str, wet_count: int, dry_count: int):
        """
        Record WET→DRY processing for a specialist.

        Called by specialists after Phase A (dedup) completes.

        Args:
            specialist: Specialist name (e.g., 'xss', 'sqli')
            wet_count: Number of WET items consumed
            dry_count: Number of DRY items produced after dedup
        """
        self.wet_processed += wet_count
        self.dry_generated += dry_count
        self.wet_by_specialist[specialist] = self.wet_by_specialist.get(specialist, 0) + wet_count
        self.dry_by_specialist[specialist] = self.dry_by_specialist.get(specialist, 0) + dry_count
        logger.debug(f"[BatchMetrics] {specialist}: WET={wet_count} → DRY={dry_count}")

    def end_scan(self, findings_exploited: int):
        """Mark scan end."""
        self.end_time = time.monotonic()
        self.findings_exploited = findings_exploited

    @property
    def dast_duration(self) -> float:
        """DAST batch duration in seconds."""
        if self.dast_end_time > 0 and self.dast_start_time > 0:
            return self.dast_end_time - self.dast_start_time
        return 0.0

    @property
    def queue_drain_duration(self) -> float:
        """Queue drain duration in seconds."""
        if self.queue_drain_end_time > 0 and self.queue_drain_start_time > 0:
            return self.queue_drain_end_time - self.queue_drain_start_time
        return 0.0

    @property
    def total_duration(self) -> float:
        """Total scan duration in seconds."""
        if self.end_time > 0 and self.start_time > 0:
            return self.end_time - self.start_time
        return 0.0

    @property
    def dedup_effectiveness(self) -> float:
        """Percentage of findings deduplicated."""
        if self.findings_before_dedup > 0:
            deduped = self.findings_before_dedup - self.findings_distributed
            return (deduped / self.findings_before_dedup) * 100
        return 0.0

    @property
    def estimated_sequential_time(self) -> float:
        """Estimated time if processed sequentially (90s per URL)."""
        return self.urls_analyzed * 90.0

    @property
    def time_saved_percent(self) -> float:
        """Percentage of time saved vs sequential processing."""
        estimated = self.estimated_sequential_time
        if estimated > 0 and self.total_duration > 0:
            return ((estimated - self.total_duration) / estimated) * 100
        return 0.0

    def log_summary(self):
        """Log comprehensive performance summary."""
        logger.info("=" * 60)
        logger.info("BATCH PROCESSING PERFORMANCE SUMMARY")
        logger.info("=" * 60)
        logger.info(f"URLs analyzed: {self.urls_analyzed}")
        logger.info(f"DAST batch duration: {self.dast_duration:.1f}s")
        logger.info(f"Queue drain duration: {self.queue_drain_duration:.1f}s")
        logger.info(f"Total duration: {self.total_duration:.1f}s")
        logger.info("-" * 60)
        logger.info(f"Findings before dedup: {self.findings_before_dedup}")
        logger.info(f"Findings distributed: {self.findings_distributed}")
        logger.info(f"Dedup effectiveness: {self.dedup_effectiveness:.1f}%")
        logger.info("-" * 60)
        logger.info(f"WET processed: {self.wet_processed}")
        logger.info(f"DRY generated: {self.dry_generated}")
        if self.wet_processed > 0:
            specialist_dedup = ((self.wet_processed - self.dry_generated) / self.wet_processed) * 100
            logger.info(f"Specialist dedup rate: {specialist_dedup:.1f}%")
        logger.info("-" * 60)
        logger.info(f"Estimated sequential time: {self.estimated_sequential_time:.1f}s")
        logger.info(f"TIME SAVED: {self.time_saved_percent:.1f}%")
        logger.info("=" * 60)

        for specialist, count in sorted(self.by_specialist.items()):
            wet = self.wet_by_specialist.get(specialist, 0)
            dry = self.dry_by_specialist.get(specialist, 0)
            logger.info(f"  {specialist}: {count} distributed, WET={wet} → DRY={dry}")


# Global singleton
batch_metrics = BatchMetrics()


def get_batch_metrics() -> BatchMetrics:
    """Get global batch metrics instance."""
    return batch_metrics


def reset_batch_metrics():
    """Reset metrics for new scan (in-place to preserve all references)."""
    fresh = BatchMetrics()
    for attr_name, attr_value in vars(fresh).items():
        setattr(batch_metrics, attr_name, attr_value)
