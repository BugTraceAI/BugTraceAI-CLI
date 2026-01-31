"""
Phase-Specific Semaphore Manager for Granular Parallelization Control.

Provides separate semaphores for each scan phase, enabling independent
concurrency control for Discovery, Analysis, Exploitation, and Validation.

Author: BugtraceAI Team
Version: 1.0.0
Date: 2026-01-30
"""

import asyncio
import time
from enum import Enum
from typing import Dict, Any
from dataclasses import dataclass, field
from loguru import logger


class ScanPhase(str, Enum):
    """Enumeration of scan phases with independent concurrency."""
    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    LLM_GLOBAL = "llm_global"  # Backward compatibility


@dataclass
class PhaseStats:
    """Statistics for a single phase's semaphore usage."""
    acquisitions: int = 0
    releases: int = 0
    current_active: int = 0
    peak_active: int = 0
    total_wait_time_ms: float = 0.0

    @property
    def avg_wait_time_ms(self) -> float:
        return self.total_wait_time_ms / self.acquisitions if self.acquisitions > 0 else 0.0


class PhaseSemaphoreManager:
    """
    Manages phase-specific semaphores for granular parallelization control.

    Usage:
        async with phase_semaphores.acquire(ScanPhase.ANALYSIS):
            # Do analysis work
            pass
    """

    def __init__(self):
        self._semaphores: Dict[ScanPhase, asyncio.Semaphore] = {}
        self._stats: Dict[ScanPhase, PhaseStats] = {}
        self._initialized = False

    def initialize(self):
        """Initialize semaphores from settings. Call once at startup."""
        if self._initialized:
            return

        # Import here to avoid circular imports
        from bugtrace.core.config import settings

        # Create semaphores with phase-specific limits
        self._semaphores = {
            ScanPhase.DISCOVERY: asyncio.Semaphore(settings.MAX_CONCURRENT_DISCOVERY),
            ScanPhase.ANALYSIS: asyncio.Semaphore(settings.MAX_CONCURRENT_ANALYSIS),
            ScanPhase.EXPLOITATION: asyncio.Semaphore(settings.MAX_CONCURRENT_SPECIALISTS),
            # HARDCODED: CDP only supports 1 concurrent session (crashes with more)
            ScanPhase.VALIDATION: asyncio.Semaphore(1),  # DO NOT CHANGE - CDP limitation
            ScanPhase.LLM_GLOBAL: asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS),
        }

        # Initialize stats
        self._stats = {phase: PhaseStats() for phase in ScanPhase}

        self._initialized = True
        logger.info(
            f"[PhaseSemaphores] Initialized: "
            f"Discovery={settings.MAX_CONCURRENT_DISCOVERY}, "
            f"Analysis={settings.MAX_CONCURRENT_ANALYSIS}, "
            f"Specialists={settings.MAX_CONCURRENT_SPECIALISTS}, "
            f"Validation=1 (CDP hardcoded)"
        )

    def get_semaphore(self, phase: ScanPhase) -> asyncio.Semaphore:
        """Get the semaphore for a specific phase."""
        if not self._initialized:
            self.initialize()
        return self._semaphores[phase]

    def acquire(self, phase: ScanPhase) -> "PhaseSemaphoreContext":
        """Acquire a phase semaphore (async context manager)."""
        if not self._initialized:
            self.initialize()
        return PhaseSemaphoreContext(self, phase)

    def _record_acquire(self, phase: ScanPhase, wait_time_ms: float):
        """Record acquisition statistics."""
        stats = self._stats[phase]
        stats.acquisitions += 1
        stats.current_active += 1
        stats.total_wait_time_ms += wait_time_ms
        if stats.current_active > stats.peak_active:
            stats.peak_active = stats.current_active

    def _record_release(self, phase: ScanPhase):
        """Record release statistics."""
        stats = self._stats[phase]
        stats.releases += 1
        stats.current_active -= 1

    def get_stats(self) -> Dict[str, Dict]:
        """Get statistics for all phases."""
        return {
            phase.value: {
                "acquisitions": self._stats[phase].acquisitions,
                "current_active": self._stats[phase].current_active,
                "peak_active": self._stats[phase].peak_active,
                "avg_wait_time_ms": round(self._stats[phase].avg_wait_time_ms, 2),
            }
            for phase in ScanPhase
        }

    def reset_stats(self):
        """Reset all statistics."""
        for phase in ScanPhase:
            self._stats[phase] = PhaseStats()

    def reset(self):
        """Reset manager for new scan."""
        self._initialized = False
        self._semaphores = {}
        self._stats = {}


class PhaseSemaphoreContext:
    """Async context manager for phase semaphore acquisition."""

    def __init__(self, manager: PhaseSemaphoreManager, phase: ScanPhase):
        self._manager = manager
        self._phase = phase
        self._semaphore = manager.get_semaphore(phase)
        self._start_time: float = 0

    async def __aenter__(self):
        self._start_time = time.monotonic()
        await self._semaphore.acquire()
        wait_time_ms = (time.monotonic() - self._start_time) * 1000
        self._manager._record_acquire(self._phase, wait_time_ms)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._semaphore.release()
        self._manager._record_release(self._phase)
        return False


# Global singleton instance
phase_semaphores = PhaseSemaphoreManager()


# Convenience functions
def get_discovery_semaphore() -> asyncio.Semaphore:
    """Get the discovery phase semaphore."""
    return phase_semaphores.get_semaphore(ScanPhase.DISCOVERY)

def get_analysis_semaphore() -> asyncio.Semaphore:
    """Get the analysis phase semaphore."""
    return phase_semaphores.get_semaphore(ScanPhase.ANALYSIS)

def get_exploitation_semaphore() -> asyncio.Semaphore:
    """Get the exploitation/specialists phase semaphore."""
    return phase_semaphores.get_semaphore(ScanPhase.EXPLOITATION)

def get_validation_semaphore() -> asyncio.Semaphore:
    """Get the validation phase semaphore."""
    return phase_semaphores.get_semaphore(ScanPhase.VALIDATION)


__all__ = [
    "ScanPhase",
    "PhaseSemaphoreManager",
    "phase_semaphores",
    "get_discovery_semaphore",
    "get_analysis_semaphore",
    "get_exploitation_semaphore",
    "get_validation_semaphore",
]
