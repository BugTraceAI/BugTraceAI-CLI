"""
Pipeline Phase State Machine - 6-Phase Execution Model

This module provides the foundational infrastructure for the pipeline orchestration
system (ORCH-01). It defines the phases of vulnerability scanning, transition rules,
and state tracking for the TeamOrchestrator.

The 6-phase execution model:
1. RECONNAISSANCE - Asset discovery (GoSpider, tech stack detection)
2. DISCOVERY  - DAST probing (DASTySASTAgent analyzing URLs)
3. STRATEGY - ThinkingConsolidationAgent deduplicating and classifying findings
4. EXPLOITATION - Specialist agents (XSS, SQLi, etc.) testing payloads
5. VALIDATION - AgenticValidator processing PENDING_VALIDATION findings via CDP
6. REPORTING  - ReportingAgent generating deliverables

Additional states:
- IDLE     - Pipeline not started
- COMPLETE - Pipeline finished successfully
- ERROR    - Unrecoverable failure occurred
- PAUSED   - User-requested pause

Transition Rules:
- Normal flow: IDLE -> RECONNAISSANCE -> DISCOVERY -> STRATEGY -> EXPLOITATION -> VALIDATION -> REPORTING -> COMPLETE
- Any phase can transition to PAUSED or ERROR
- PAUSED can resume to any active phase
- COMPLETE and ERROR can only transition to IDLE (restart/reset)

Author: BugTraceAI Team
Date: 2026-01-29
Version: 2.0.0

Exports:
    PipelinePhase: Enum of all pipeline phases
    PipelineTransition: Dataclass recording phase transitions
    PipelineState: State machine with transition logic
    PipelineLifecycle: Graceful lifecycle operations (pause, resume, shutdown)
    VALID_TRANSITIONS: Dict mapping phases to valid next phases

Note: PipelineOrchestrator was removed in Sprint 5 refactoring.
TeamOrchestrator now manages pipeline state directly via PipelineState.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, TYPE_CHECKING

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

if TYPE_CHECKING:
    from bugtrace.agents.worker_pool import WorkerPool
    from bugtrace.core.event_bus import EventBus

logger = get_logger("pipeline")

__all__ = [
    "PipelinePhase", "PipelineState", "PipelineTransition",
    "VALID_TRANSITIONS", "PipelineLifecycle",
]


class PipelinePhase(str, Enum):
    """
    Pipeline phases for 6-phase execution model.

    Inherits from str for JSON serialization compatibility.
    Each phase corresponds to a stage in vulnerability scanning.
    """
    # Not started
    IDLE = "idle"

    # Active phases (6-phase model)
    RECONNAISSANCE = "reconnaissance" # Asset discovery (GoSpider, tech detection)
    DISCOVERY = "discovery"           # DAST probing (DASTySASTAgent)
    STRATEGY = "strategy"             # ThinkingConsolidationAgent deduplicating, classifying
    EXPLOITATION = "exploitation"     # Specialist agents testing payloads
    VALIDATION = "validation"         # AgenticValidator processing PENDING_VALIDATION
    REPORTING = "reporting"           # ReportingAgent generating deliverables

    # Terminal states
    COMPLETE = "complete"  # Pipeline finished
    ERROR = "error"        # Unrecoverable failure

    # Control states
    PAUSED = "paused"      # User-requested pause


@dataclass
class PipelineTransition:
    """
    Record of a phase transition.

    Captures the transition details for debugging and metrics.
    """
    from_phase: PipelinePhase
    to_phase: PipelinePhase
    reason: str
    timestamp: float = field(default_factory=time.monotonic)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "from_phase": self.from_phase.value,
            "to_phase": self.to_phase.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "metrics": self.metrics
        }


# Valid transitions from each phase
VALID_TRANSITIONS: Dict[PipelinePhase, List[PipelinePhase]] = {
    # IDLE can only start reconnaissance
    PipelinePhase.IDLE: [PipelinePhase.RECONNAISSANCE],

    # Active phases follow linear progression with pause/error exits
    PipelinePhase.RECONNAISSANCE: [
        PipelinePhase.DISCOVERY,
        PipelinePhase.PAUSED,
        PipelinePhase.ERROR
    ],
    PipelinePhase.DISCOVERY: [
        PipelinePhase.STRATEGY,
        PipelinePhase.PAUSED,
        PipelinePhase.ERROR
    ],
    PipelinePhase.STRATEGY: [
        PipelinePhase.EXPLOITATION,
        PipelinePhase.PAUSED,
        PipelinePhase.ERROR
    ],
    PipelinePhase.EXPLOITATION: [
        PipelinePhase.VALIDATION,
        PipelinePhase.PAUSED,
        PipelinePhase.ERROR
    ],
    PipelinePhase.VALIDATION: [
        PipelinePhase.REPORTING,
        PipelinePhase.PAUSED,
        PipelinePhase.ERROR
    ],
    PipelinePhase.REPORTING: [
        PipelinePhase.COMPLETE,
        PipelinePhase.ERROR
    ],

    # PAUSED can resume to any active phase
    PipelinePhase.PAUSED: [
        PipelinePhase.RECONNAISSANCE,
        PipelinePhase.DISCOVERY,
        PipelinePhase.STRATEGY,
        PipelinePhase.EXPLOITATION,
        PipelinePhase.VALIDATION,
        PipelinePhase.REPORTING
    ],

    # Terminal states can only reset to IDLE
    PipelinePhase.COMPLETE: [PipelinePhase.IDLE],
    PipelinePhase.ERROR: [PipelinePhase.IDLE]
}


@dataclass
class PipelineState:
    """
    Pipeline state machine with transition tracking.

    Tracks the current phase, transition history, and timing for a scan.
    Enforces valid transitions via VALID_TRANSITIONS rules.
    """
    scan_id: str
    current_phase: PipelinePhase = PipelinePhase.IDLE
    previous_phase: Optional[PipelinePhase] = None
    started_at: float = field(default_factory=time.monotonic)
    phase_started_at: float = field(default_factory=time.monotonic)
    transitions: List[PipelineTransition] = field(default_factory=list)
    paused: bool = False
    pause_reason: Optional[str] = None
    error: Optional[str] = None

    def can_transition(self, to_phase: PipelinePhase) -> bool:
        """
        Check if transition to target phase is valid.

        Args:
            to_phase: Target phase to transition to

        Returns:
            True if transition is valid, False otherwise
        """
        valid_targets = VALID_TRANSITIONS.get(self.current_phase, [])
        return to_phase in valid_targets

    def transition(
        self,
        to_phase: PipelinePhase,
        reason: str,
        metrics: Optional[Dict[str, Any]] = None
    ) -> PipelineTransition:
        """
        Transition to a new phase.

        Args:
            to_phase: Target phase
            reason: Why the transition occurred
            metrics: Optional phase metrics (e.g., items_processed)

        Returns:
            PipelineTransition record

        Raises:
            ValueError: If transition is invalid
        """
        if not self.can_transition(to_phase):
            valid_targets = VALID_TRANSITIONS.get(self.current_phase, [])
            raise ValueError(
                f"Invalid transition: {self.current_phase.value} -> {to_phase.value}. "
                f"Valid targets: {[p.value for p in valid_targets]}"
            )

        # Create transition record
        transition = PipelineTransition(
            from_phase=self.current_phase,
            to_phase=to_phase,
            reason=reason,
            metrics=metrics or {}
        )

        # Update state
        self.previous_phase = self.current_phase
        self.current_phase = to_phase
        self.phase_started_at = time.monotonic()
        self.transitions.append(transition)

        # Handle pause/error state flags
        if to_phase == PipelinePhase.PAUSED:
            self.paused = True
            self.pause_reason = reason
        elif self.paused and to_phase != PipelinePhase.PAUSED:
            self.paused = False
            self.pause_reason = None

        if to_phase == PipelinePhase.ERROR:
            self.error = reason
        elif to_phase == PipelinePhase.IDLE:
            # Reset clears error
            self.error = None

        logger.info(
            f"Pipeline transition: {transition.from_phase.value} -> "
            f"{transition.to_phase.value} ({reason})"
        )

        return transition

    def get_phase_duration(self) -> float:
        """
        Get duration of current phase in seconds.

        Returns:
            Seconds since current phase started
        """
        return time.monotonic() - self.phase_started_at

    def get_total_duration(self) -> float:
        """
        Get total pipeline duration in seconds.

        Returns:
            Seconds since pipeline started
        """
        return time.monotonic() - self.started_at

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert state to dictionary for JSON serialization.

        Returns:
            Dictionary representation of pipeline state
        """
        return {
            "scan_id": self.scan_id,
            "current_phase": self.current_phase.value,
            "previous_phase": self.previous_phase.value if self.previous_phase else None,
            "started_at": self.started_at,
            "phase_started_at": self.phase_started_at,
            "phase_duration": self.get_phase_duration(),
            "total_duration": self.get_total_duration(),
            "transitions": [t.to_dict() for t in self.transitions],
            "transition_count": len(self.transitions),
            "paused": self.paused,
            "pause_reason": self.pause_reason,
            "error": self.error
        }


class PipelineLifecycle:
    """
    Manages graceful pipeline lifecycle operations.

    Graceful Shutdown:
    1. Signal all worker pools to stop accepting new items
    2. Wait for active workers to complete current items
    3. Drain remaining queue items (with timeout)
    4. Emit shutdown complete event

    Pause/Resume:
    - Pause: Set pause flag, wait for current phase boundary
    - Resume: Clear pause flag, continue from paused phase
    - Phase boundary = point between phases where no work is in-progress
    """

    def __init__(self, state: PipelineState, event_bus: "EventBus" = None):
        """
        Initialize pipeline lifecycle manager.

        Args:
            state: PipelineState instance to manage
            event_bus: Optional EventBus (defaults to global singleton)
        """
        self.state = state

        # Import event bus lazily to avoid circular imports
        if event_bus is None:
            from bugtrace.core.event_bus import event_bus as global_event_bus
            self.event_bus = global_event_bus
        else:
            self.event_bus = event_bus

        # Worker pool registry
        self._worker_pools: Dict[str, "WorkerPool"] = {}

        # Control flags
        self._shutdown_requested = False
        self._pause_requested = False
        self._lock = asyncio.Lock()

        logger.info(f"[Pipeline] Lifecycle manager initialized for scan: {state.scan_id}")

    def register_worker_pool(self, specialist: str, pool: "WorkerPool") -> None:
        """
        Register a worker pool for lifecycle management.

        Called by orchestrator when creating specialist workers.

        Args:
            specialist: Specialist name (e.g., "xss", "sqli")
            pool: WorkerPool instance
        """
        self._worker_pools[specialist] = pool
        logger.debug(f"[Pipeline] Registered worker pool: {specialist}")

    def unregister_worker_pool(self, specialist: str) -> None:
        """
        Remove a worker pool from management.

        Args:
            specialist: Specialist name to remove
        """
        if specialist in self._worker_pools:
            del self._worker_pools[specialist]
            logger.debug(f"[Pipeline] Unregistered worker pool: {specialist}")

    async def drain_queues(self, timeout: float = None) -> Dict[str, int]:
        """
        Drain all specialist queues.

        Waits until all registered queues are empty or timeout expires.
        Now includes worker health check to detect dead workers early.

        Args:
            timeout: Max seconds to wait (defaults to PIPELINE_DRAIN_TIMEOUT)

        Returns:
            Dict mapping queue name to items drained count
        """
        timeout = timeout or settings.PIPELINE_DRAIN_TIMEOUT

        # Import queue_manager lazily
        from bugtrace.core.queue import queue_manager

        result: Dict[str, int] = {}
        start_time = time.monotonic()
        stall_check_counter = 0  # Check worker health every N iterations

        queue_names = queue_manager.list_queues()
        if not queue_names:
            logger.info("[Pipeline] No queues to drain")
            return result

        logger.info(f"[Pipeline] Draining {len(queue_names)} queues (timeout: {timeout}s)")

        for queue_name in queue_names:
            queue = queue_manager.get_queue(queue_name)
            initial_depth = queue.depth()
            result[queue_name] = 0
            last_depth = initial_depth

            while queue.depth() > 0:
                elapsed = time.monotonic() - start_time
                if elapsed >= timeout:
                    logger.warning(
                        f"[Pipeline] Drain timeout reached, {queue_name} has "
                        f"{queue.depth()} items remaining"
                    )
                    break

                # Worker health check: every 10 iterations (~1 second)
                stall_check_counter += 1
                if stall_check_counter >= 10:
                    stall_check_counter = 0
                    current_depth = queue.depth()

                    # Count active workers
                    workers_active = 0
                    for pool in self._worker_pools.values():
                        try:
                            stats = pool.get_stats()
                            if stats.get("running"):
                                workers_active += stats.get("worker_count", 0)
                        except Exception:
                            pass  # Pool may be stopping

                    # CRITICAL: Queue has items but no workers to process them
                    if current_depth > 0 and workers_active == 0:
                        logger.error(
                            f"[Pipeline] STALL DETECTED: {queue_name} has {current_depth} items "
                            f"but 0 active workers. Aborting drain to prevent infinite wait."
                        )
                        break

                    # Check if queue is stalled (same depth after 1 second with workers running)
                    if current_depth == last_depth and workers_active > 0:
                        logger.warning(
                            f"[Pipeline] Queue '{queue_name}' appears stalled at depth {current_depth}"
                        )

                    last_depth = current_depth

                await asyncio.sleep(0.1)  # Check every 100ms

            drained = initial_depth - queue.depth()
            result[queue_name] = drained
            logger.debug(f"[Pipeline] Queue '{queue_name}' drained: {drained} items")

        total_drained = sum(result.values())
        logger.info(f"[Pipeline] Drain complete: {total_drained} items total")

        return result

    async def graceful_shutdown(self, timeout: float = None) -> bool:
        """
        Perform graceful shutdown of the pipeline.

        1. Sets shutdown flag
        2. Stops all registered worker pools
        3. Drains remaining queue items
        4. Emits PIPELINE_SHUTDOWN event

        Args:
            timeout: Max seconds for entire shutdown (defaults to PIPELINE_DRAIN_TIMEOUT)

        Returns:
            True if clean shutdown, False if timeout
        """
        timeout = timeout or settings.PIPELINE_DRAIN_TIMEOUT

        async with self._lock:
            self._shutdown_requested = True
            logger.info("[Pipeline] Graceful shutdown initiated")

        start_time = time.monotonic()
        clean_shutdown = True

        # Stop all worker pools first
        if self._worker_pools:
            logger.info(f"[Pipeline] Stopping {len(self._worker_pools)} worker pools")
            stop_tasks = []
            for specialist, pool in self._worker_pools.items():
                logger.debug(f"[Pipeline] Stopping pool: {specialist}")
                stop_tasks.append(pool.stop())

            try:
                remaining_timeout = timeout - (time.monotonic() - start_time)
                await asyncio.wait_for(
                    asyncio.gather(*stop_tasks, return_exceptions=True),
                    timeout=max(1.0, remaining_timeout)
                )
            except asyncio.TimeoutError:
                logger.warning("[Pipeline] Worker pool shutdown timed out")
                clean_shutdown = False

        # Drain queues
        remaining_timeout = timeout - (time.monotonic() - start_time)
        if remaining_timeout > 0:
            await self.drain_queues(timeout=remaining_timeout)
        else:
            logger.warning("[Pipeline] No time remaining for queue drain")
            clean_shutdown = False

        # Emit shutdown event
        from bugtrace.core.event_bus import EventType
        await self.event_bus.emit(EventType.PIPELINE_SHUTDOWN, {
            "scan_context": self.state.scan_id,
            "clean": clean_shutdown,
            "duration": time.monotonic() - start_time,
            "timestamp": time.time()
        })

        logger.info(
            f"[Pipeline] Shutdown complete: {'clean' if clean_shutdown else 'with timeout'}"
        )

        return clean_shutdown

    async def pause_at_boundary(self, reason: str = "User requested") -> bool:
        """
        Pause the pipeline at the next phase boundary.

        Sets pause flag and waits for current phase to reach a clean
        stopping point (no work in-progress).

        Args:
            reason: Reason for pausing (for logging/debugging)

        Returns:
            True when successfully paused
        """
        async with self._lock:
            if self._pause_requested:
                logger.warning("[Pipeline] Pause already requested")
                return False

            self._pause_requested = True
            self.state.paused = True
            self.state.pause_reason = reason

        logger.info(f"[Pipeline] Pause requested: {reason}")

        # Wait for phase boundary
        current_phase = self.state.current_phase
        await self.wait_for_phase_boundary(current_phase)

        # Transition to PAUSED state if not already
        if self.state.current_phase != PipelinePhase.PAUSED:
            if self.state.can_transition(PipelinePhase.PAUSED):
                self.state.transition(PipelinePhase.PAUSED, reason)

        # Emit pause event
        from bugtrace.core.event_bus import EventType
        await self.event_bus.emit(EventType.PIPELINE_PAUSED, {
            "scan_context": self.state.scan_id,
            "reason": reason,
            "paused_at_phase": current_phase.value,
            "timestamp": time.time()
        })

        logger.info(f"[Pipeline] Paused at phase boundary: {current_phase.value}")
        return True

    async def resume(self) -> bool:
        """
        Resume the pipeline from paused state.

        Returns:
            True if resumed successfully, False if not paused
        """
        if not self.state.paused:
            logger.warning("[Pipeline] Cannot resume: not paused")
            return False

        async with self._lock:
            self._pause_requested = False

        # Get the phase to resume to
        resume_phase = self.state.previous_phase
        if resume_phase is None or resume_phase == PipelinePhase.IDLE:
            resume_phase = PipelinePhase.DISCOVERY

        # Transition from PAUSED back to active phase
        if self.state.current_phase == PipelinePhase.PAUSED:
            if self.state.can_transition(resume_phase):
                self.state.transition(resume_phase, "Resumed from pause")

        self.state.paused = False
        self.state.pause_reason = None

        # Emit resume event
        from bugtrace.core.event_bus import EventType
        await self.event_bus.emit(EventType.PIPELINE_RESUMED, {
            "scan_context": self.state.scan_id,
            "resumed_to_phase": resume_phase.value,
            "timestamp": time.time()
        })

        logger.info(f"[Pipeline] Resumed to phase: {resume_phase.value}")
        return True

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self._shutdown_requested

    def is_pause_requested(self) -> bool:
        """Check if pause has been requested."""
        return self._pause_requested

    async def wait_for_phase_boundary(
        self, phase: PipelinePhase, timeout: float = 30.0
    ) -> bool:
        """
        Wait until current phase reaches a boundary (completes).

        A phase boundary is reached when:
        - The phase changes to a different phase
        - All queues for that phase are empty
        - All workers for that phase are idle

        Args:
            phase: The phase to wait for completion
            timeout: Max seconds to wait

        Returns:
            True if boundary reached, False if timeout
        """
        start_time = time.monotonic()
        check_interval = settings.PIPELINE_PAUSE_CHECK_INTERVAL

        logger.debug(f"[Pipeline] Waiting for phase boundary: {phase.value}")

        while True:
            # Check if phase has changed
            if self.state.current_phase != phase:
                logger.debug(f"[Pipeline] Phase changed from {phase.value}")
                return True

            # Check timeout
            elapsed = time.monotonic() - start_time
            if elapsed >= timeout:
                logger.warning(
                    f"[Pipeline] Phase boundary wait timeout after {elapsed:.1f}s"
                )
                return False

            # Sleep before next check
            await asyncio.sleep(check_interval)

        return True

    def get_shutdown_progress(self) -> Dict[str, Any]:
        """
        Get current shutdown progress information.

        Returns:
            Dict with queues_remaining, workers_active, etc.
        """
        from bugtrace.core.queue import queue_manager

        # Count queues with items remaining
        queues_with_items = 0
        total_items_remaining = 0
        for queue_name in queue_manager.list_queues():
            queue = queue_manager.get_queue(queue_name)
            depth = queue.depth()
            if depth > 0:
                queues_with_items += 1
                total_items_remaining += depth

        # Count active workers
        workers_active = 0
        for pool in self._worker_pools.values():
            stats = pool.get_stats()
            if stats.get("running"):
                workers_active += stats.get("worker_count", 0)

        return {
            "shutdown_requested": self._shutdown_requested,
            "pause_requested": self._pause_requested,
            "queues_with_items": queues_with_items,
            "total_items_remaining": total_items_remaining,
            "workers_active": workers_active,
            "registered_pools": len(self._worker_pools),
            "current_phase": self.state.current_phase.value,
        }

    async def check_pause_point(self) -> bool:
        """
        Check if pause was requested and wait if so.

        Agents should call this between processing units (e.g., between URLs,
        between findings) to allow clean pausing at boundaries.

        Returns:
            True if paused (caller should stop processing)
            False if not paused (caller continues)

        Example usage in agent:
            for url in urls_to_process:
                if await lifecycle.check_pause_point():
                    return  # Paused, stop processing
                await process_url(url)
        """
        if not self._pause_requested:
            return False

        # Log that we're pausing
        logger.info("[Pipeline] Pause requested, entering pause state")

        # Wait until resumed or shutdown
        while self._pause_requested and not self._shutdown_requested:
            await asyncio.sleep(settings.PIPELINE_PAUSE_CHECK_INTERVAL)

        return self._shutdown_requested  # Return True only if shutting down

    async def signal_phase_complete(
        self, phase: PipelinePhase, metrics: Dict[str, Any] = None
    ) -> None:
        """
        Signal that a phase has completed its work.

        Emits the appropriate PHASE_COMPLETE_* event for the phase.

        Args:
            phase: The phase that completed
            metrics: Optional metrics dict (items_processed, duration, etc.)
        """
        from bugtrace.core.event_bus import EventType

        event_map = {
            PipelinePhase.RECONNAISSANCE: EventType.PHASE_COMPLETE_RECONNAISSANCE,
            PipelinePhase.DISCOVERY: EventType.PHASE_COMPLETE_DISCOVERY,
            PipelinePhase.STRATEGY: EventType.PHASE_COMPLETE_STRATEGY,
            PipelinePhase.EXPLOITATION: EventType.PHASE_COMPLETE_EXPLOITATION,
            PipelinePhase.VALIDATION: EventType.PHASE_COMPLETE_VALIDATION,
            PipelinePhase.REPORTING: EventType.PHASE_COMPLETE_REPORTING,
        }

        event_type = event_map.get(phase)
        if not event_type:
            logger.warning(f"[Pipeline] No completion event for phase: {phase}")
            return

        event_data = {
            "scan_context": self.state.scan_id,
            "phase": phase.value,
            "timestamp": time.time(),
            **(metrics or {})
        }

        await self.event_bus.emit(event_type, event_data)
        logger.info(f"[Pipeline] Phase complete: {phase.value}")
