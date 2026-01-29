"""
Pipeline Phase State Machine - 5-Phase Execution Model

This module provides the foundational infrastructure for the pipeline orchestration
system (ORCH-01). It defines the phases of vulnerability scanning, transition rules,
and state tracking for the TeamOrchestrator.

The 5-phase execution model:
1. DISCOVERY  - SASTDASTAgent analyzing URLs, emitting url_analyzed events
2. EVALUATION - ThinkingConsolidationAgent deduplicating and classifying findings
3. EXPLOITATION - Specialist agents (XSS, SQLi, etc.) testing payloads
4. VALIDATION - AgenticValidator processing PENDING_VALIDATION findings via CDP
5. REPORTING  - ReportingAgent generating deliverables

Additional states:
- IDLE     - Pipeline not started
- COMPLETE - Pipeline finished successfully
- ERROR    - Unrecoverable failure occurred
- PAUSED   - User-requested pause

Transition Rules:
- Normal flow: IDLE -> DISCOVERY -> EVALUATION -> EXPLOITATION -> VALIDATION -> REPORTING -> COMPLETE
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
    VALID_TRANSITIONS: Dict mapping phases to valid next phases
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

from bugtrace.utils.logger import get_logger

logger = get_logger("pipeline")

__all__ = ["PipelinePhase", "PipelineState", "PipelineTransition", "VALID_TRANSITIONS"]


class PipelinePhase(str, Enum):
    """
    Pipeline phases for 5-phase execution model.

    Inherits from str for JSON serialization compatibility.
    Each phase corresponds to a stage in vulnerability scanning.
    """
    # Not started
    IDLE = "idle"

    # Active phases (5-phase model)
    DISCOVERY = "discovery"       # SASTDASTAgent analyzing URLs
    EVALUATION = "evaluation"     # ThinkingConsolidationAgent deduplicating, classifying
    EXPLOITATION = "exploitation" # Specialist agents testing payloads
    VALIDATION = "validation"     # AgenticValidator processing PENDING_VALIDATION
    REPORTING = "reporting"       # ReportingAgent generating deliverables

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
    # IDLE can only start discovery
    PipelinePhase.IDLE: [PipelinePhase.DISCOVERY],

    # Active phases follow linear progression with pause/error exits
    PipelinePhase.DISCOVERY: [
        PipelinePhase.EVALUATION,
        PipelinePhase.PAUSED,
        PipelinePhase.ERROR
    ],
    PipelinePhase.EVALUATION: [
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
        PipelinePhase.DISCOVERY,
        PipelinePhase.EVALUATION,
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
