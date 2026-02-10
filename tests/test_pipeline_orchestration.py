"""
Unit tests for Pipeline Orchestration (Phase 23).

Tests cover:
1. PipelinePhase enum and state machine
2. PipelineState transitions and validation
3. PipelineLifecycle graceful shutdown and pause/resume

Note: PipelineOrchestrator was removed in Sprint 5 refactoring.
      TeamOrchestrator now manages phase transitions directly via PipelineState.
"""

import pytest
import asyncio
import time
from bugtrace.core.pipeline import (
    PipelinePhase, PipelineState, PipelineTransition, VALID_TRANSITIONS,
    PipelineLifecycle
)
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.config import settings


class TestPipelinePhase:
    """Tests for PipelinePhase enum."""

    def test_all_phases_defined(self):
        """Verify all 10 phases are defined (6-phase model + control states)."""
        phases = list(PipelinePhase)
        assert len(phases) == 10
        # Control states
        assert PipelinePhase.IDLE in phases
        assert PipelinePhase.PAUSED in phases
        assert PipelinePhase.COMPLETE in phases
        assert PipelinePhase.ERROR in phases
        # 6-phase model
        assert PipelinePhase.RECONNAISSANCE in phases
        assert PipelinePhase.DISCOVERY in phases
        assert PipelinePhase.STRATEGY in phases  # Was EVALUATION in v1
        assert PipelinePhase.EXPLOITATION in phases
        assert PipelinePhase.VALIDATION in phases
        assert PipelinePhase.REPORTING in phases

    def test_phase_string_values(self):
        """Phases have correct string values."""
        assert PipelinePhase.DISCOVERY.value == "discovery"
        assert PipelinePhase.COMPLETE.value == "complete"

    def test_phase_is_string_subclass(self):
        """PipelinePhase inherits from str for JSON serialization."""
        assert isinstance(PipelinePhase.DISCOVERY, str)
        assert PipelinePhase.DISCOVERY == "discovery"


class TestPipelineState:
    """Tests for PipelineState state machine."""

    def test_initial_state(self):
        """State starts in IDLE."""
        state = PipelineState(scan_id="test123")
        assert state.current_phase == PipelinePhase.IDLE
        assert state.previous_phase is None
        assert len(state.transitions) == 0

    def test_valid_transition(self):
        """Valid transitions succeed."""
        state = PipelineState(scan_id="test123")
        # IDLE -> RECONNAISSANCE is the first valid transition
        state.transition(PipelinePhase.RECONNAISSANCE, "Starting scan")
        assert state.current_phase == PipelinePhase.RECONNAISSANCE
        assert state.previous_phase == PipelinePhase.IDLE
        assert len(state.transitions) == 1

    def test_invalid_transition_raises(self):
        """Invalid transitions raise ValueError."""
        state = PipelineState(scan_id="test123")
        with pytest.raises(ValueError) as exc:
            state.transition(PipelinePhase.REPORTING, "Skip ahead")
        assert "Invalid transition" in str(exc.value)

    def test_transition_history(self):
        """Transitions are recorded with metadata."""
        state = PipelineState(scan_id="test123")
        state.transition(PipelinePhase.RECONNAISSANCE, "Start", {"urls": 10})

        t = state.transitions[0]
        assert t.from_phase == PipelinePhase.IDLE
        assert t.to_phase == PipelinePhase.RECONNAISSANCE
        assert t.reason == "Start"
        assert t.metrics.get("urls") == 10

    def test_can_transition(self):
        """can_transition checks validity without modifying state."""
        state = PipelineState(scan_id="test123")
        # IDLE can only go to RECONNAISSANCE
        assert state.can_transition(PipelinePhase.RECONNAISSANCE) is True
        assert state.can_transition(PipelinePhase.REPORTING) is False

    def test_to_dict_serialization(self):
        """State serializes to dict."""
        state = PipelineState(scan_id="test123")
        state.transition(PipelinePhase.RECONNAISSANCE, "Test")

        d = state.to_dict()
        assert d["scan_id"] == "test123"
        assert d["current_phase"] == "reconnaissance"
        assert len(d["transitions"]) == 1

    def test_pause_state_tracking(self):
        """Paused state is tracked correctly."""
        state = PipelineState(scan_id="test123")
        state.transition(PipelinePhase.RECONNAISSANCE, "Start")
        state.transition(PipelinePhase.DISCOVERY, "Next phase")
        assert state.paused is False

        state.transition(PipelinePhase.PAUSED, "User requested")
        assert state.paused is True
        assert state.pause_reason == "User requested"

    def test_error_state_tracking(self):
        """Error state is tracked correctly."""
        state = PipelineState(scan_id="test123")
        state.transition(PipelinePhase.RECONNAISSANCE, "Start")
        state.transition(PipelinePhase.DISCOVERY, "Next phase")

        state.transition(PipelinePhase.ERROR, "Something went wrong")
        assert state.error == "Something went wrong"

    def test_phase_duration_tracking(self):
        """Phase duration is calculated correctly."""
        state = PipelineState(scan_id="test123")
        state.transition(PipelinePhase.RECONNAISSANCE, "Start")

        time.sleep(0.1)
        duration = state.get_phase_duration()
        assert duration >= 0.1

    def test_total_duration_tracking(self):
        """Total duration is calculated correctly."""
        state = PipelineState(scan_id="test123")
        time.sleep(0.1)
        duration = state.get_total_duration()
        assert duration >= 0.1


class TestPipelineLifecycle:
    """Tests for PipelineLifecycle graceful shutdown and pause."""

    @pytest.fixture
    def lifecycle(self):
        """Create lifecycle with fresh state."""
        state = PipelineState(scan_id="test_life")
        state.transition(PipelinePhase.RECONNAISSANCE, "Test start")
        state.transition(PipelinePhase.DISCOVERY, "Discovery phase")
        return PipelineLifecycle(state)

    @pytest.mark.asyncio
    async def test_drain_queues_empty(self, lifecycle):
        """drain_queues returns immediately for empty queues."""
        result = await lifecycle.drain_queues(timeout=1.0)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_pause_flag(self, lifecycle):
        """Pause flag is tracked correctly."""
        assert lifecycle.is_pause_requested() is False
        lifecycle._pause_requested = True
        assert lifecycle.is_pause_requested() is True

    @pytest.mark.asyncio
    async def test_shutdown_flag(self, lifecycle):
        """Shutdown flag is tracked correctly."""
        assert lifecycle.is_shutdown_requested() is False
        lifecycle._shutdown_requested = True
        assert lifecycle.is_shutdown_requested() is True

    @pytest.mark.asyncio
    async def test_check_pause_point_not_paused(self, lifecycle):
        """check_pause_point returns False when not paused."""
        result = await lifecycle.check_pause_point()
        assert result is False

    @pytest.mark.asyncio
    async def test_signal_phase_complete_emits_event(self, lifecycle):
        """signal_phase_complete emits correct event."""
        received = []

        async def handler(data):
            received.append(data)

        event_bus.subscribe(EventType.PHASE_COMPLETE_DISCOVERY.value, handler)

        await lifecycle.signal_phase_complete(
            PipelinePhase.DISCOVERY,
            {"urls_analyzed": 10}
        )

        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0]["phase"] == "discovery"
        assert received[0]["urls_analyzed"] == 10

        event_bus.unsubscribe(EventType.PHASE_COMPLETE_DISCOVERY.value, handler)

    @pytest.mark.asyncio
    async def test_get_shutdown_progress(self, lifecycle):
        """get_shutdown_progress returns status dict."""
        progress = lifecycle.get_shutdown_progress()

        assert isinstance(progress, dict)
        assert "shutdown_requested" in progress
        assert "pause_requested" in progress
        assert "queues_with_items" in progress
        assert "current_phase" in progress


class TestValidTransitions:
    """Tests for VALID_TRANSITIONS rules (6-phase model)."""

    def test_idle_to_reconnaissance(self):
        """IDLE can only go to RECONNAISSANCE."""
        valid = VALID_TRANSITIONS[PipelinePhase.IDLE]
        assert valid == [PipelinePhase.RECONNAISSANCE]

    def test_reconnaissance_transitions(self):
        """RECONNAISSANCE can go to DISCOVERY, PAUSED, or ERROR."""
        valid = VALID_TRANSITIONS[PipelinePhase.RECONNAISSANCE]
        assert PipelinePhase.DISCOVERY in valid
        assert PipelinePhase.PAUSED in valid
        assert PipelinePhase.ERROR in valid

    def test_discovery_transitions(self):
        """DISCOVERY can go to STRATEGY, PAUSED, or ERROR."""
        valid = VALID_TRANSITIONS[PipelinePhase.DISCOVERY]
        assert PipelinePhase.STRATEGY in valid
        assert PipelinePhase.PAUSED in valid
        assert PipelinePhase.ERROR in valid
        assert PipelinePhase.REPORTING not in valid

    def test_complete_only_to_idle(self):
        """COMPLETE can only go to IDLE (restart)."""
        valid = VALID_TRANSITIONS[PipelinePhase.COMPLETE]
        assert valid == [PipelinePhase.IDLE]

    def test_paused_can_resume_to_any_phase(self):
        """PAUSED can resume to any active phase."""
        valid = VALID_TRANSITIONS[PipelinePhase.PAUSED]
        assert PipelinePhase.RECONNAISSANCE in valid
        assert PipelinePhase.DISCOVERY in valid
        assert PipelinePhase.STRATEGY in valid
        assert PipelinePhase.EXPLOITATION in valid
        assert PipelinePhase.VALIDATION in valid
        assert PipelinePhase.REPORTING in valid

    def test_error_only_to_idle(self):
        """ERROR can only transition to IDLE (reset)."""
        valid = VALID_TRANSITIONS[PipelinePhase.ERROR]
        assert valid == [PipelinePhase.IDLE]

    def test_linear_phase_progression(self):
        """Active phases follow linear 6-phase progression."""
        # IDLE -> RECONNAISSANCE
        assert PipelinePhase.RECONNAISSANCE in VALID_TRANSITIONS[PipelinePhase.IDLE]
        # RECONNAISSANCE -> DISCOVERY
        assert PipelinePhase.DISCOVERY in VALID_TRANSITIONS[PipelinePhase.RECONNAISSANCE]
        # DISCOVERY -> STRATEGY
        assert PipelinePhase.STRATEGY in VALID_TRANSITIONS[PipelinePhase.DISCOVERY]
        # STRATEGY -> EXPLOITATION
        assert PipelinePhase.EXPLOITATION in VALID_TRANSITIONS[PipelinePhase.STRATEGY]
        # EXPLOITATION -> VALIDATION
        assert PipelinePhase.VALIDATION in VALID_TRANSITIONS[PipelinePhase.EXPLOITATION]
        # VALIDATION -> REPORTING
        assert PipelinePhase.REPORTING in VALID_TRANSITIONS[PipelinePhase.VALIDATION]
        # REPORTING -> COMPLETE
        assert PipelinePhase.COMPLETE in VALID_TRANSITIONS[PipelinePhase.REPORTING]


class TestPipelineTransition:
    """Tests for PipelineTransition dataclass."""

    def test_transition_creation(self):
        """Transitions are created with correct fields."""
        t = PipelineTransition(
            from_phase=PipelinePhase.IDLE,
            to_phase=PipelinePhase.DISCOVERY,
            reason="Test transition",
            metrics={"test": 1}
        )

        assert t.from_phase == PipelinePhase.IDLE
        assert t.to_phase == PipelinePhase.DISCOVERY
        assert t.reason == "Test transition"
        assert t.metrics == {"test": 1}
        assert t.timestamp > 0

    def test_transition_to_dict(self):
        """Transitions serialize to dict correctly."""
        t = PipelineTransition(
            from_phase=PipelinePhase.IDLE,
            to_phase=PipelinePhase.DISCOVERY,
            reason="Test",
            metrics={}
        )

        d = t.to_dict()
        assert d["from_phase"] == "idle"
        assert d["to_phase"] == "discovery"
        assert d["reason"] == "Test"
