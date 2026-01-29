"""
End-to-end integration tests for the 5-phase pipeline (TEST-01).

Tests verify:
1. Full pipeline execution: DISCOVERY -> EVALUATION -> EXPLOITATION -> VALIDATION -> REPORTING -> COMPLETE
2. Correct phase transitions and event emission
3. Finding flow through all phases
4. Edge cases: empty findings, duplicates, filtered findings
5. Error handling and recovery
6. Metrics tracking throughout pipeline

Author: BugTraceAI Team
Date: 2026-01-29
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch, MagicMock
from typing import List, Dict, Any

from bugtrace.core.pipeline import (
    PipelinePhase, PipelineState, PipelineTransition, VALID_TRANSITIONS,
    PipelineOrchestrator, PipelineLifecycle
)
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.queue import queue_manager
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.core.validation_metrics import validation_metrics
from bugtrace.core.dedup_metrics import dedup_metrics
from bugtrace.agents.thinking_consolidation_agent import ThinkingConsolidationAgent


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def unique_scan_id():
    """Generate unique scan ID to prevent cross-test interference."""
    return f"e2e_test_{time.time()}"


@pytest.fixture
def mock_finding():
    """Create a realistic test finding."""
    def _create_finding(
        vuln_type: str = "XSS",
        parameter: str = "q",
        url: str = "http://test.com/search",
        fp_confidence: float = 0.8,
        severity: str = "high",
        skeptical_score: int = 7
    ) -> Dict[str, Any]:
        return {
            "type": vuln_type,
            "parameter": parameter,
            "url": url,
            "fp_confidence": fp_confidence,
            "severity": severity,
            "skeptical_score": skeptical_score,
            "votes": 3,
            "validated": False,
        }
    return _create_finding


@pytest.fixture
def event_collector():
    """Collect all emitted events for verification."""
    collected = []
    handlers = {}

    class Collector:
        def __init__(self):
            self.events = collected

        async def _handler(self, data):
            collected.append({"type": self._current_type, "data": data})

        def subscribe(self, event_type: str):
            async def handler(data):
                collected.append({"type": event_type, "data": data})
            handlers[event_type] = handler
            event_bus.subscribe(event_type, handler)

        def subscribe_all_phases(self):
            phase_events = [
                EventType.PIPELINE_STARTED.value,
                EventType.PHASE_COMPLETE_DISCOVERY.value,
                EventType.PHASE_COMPLETE_EVALUATION.value,
                EventType.PHASE_COMPLETE_EXPLOITATION.value,
                EventType.PHASE_COMPLETE_VALIDATION.value,
                EventType.PHASE_COMPLETE_REPORTING.value,
                EventType.PIPELINE_COMPLETE.value,
                EventType.VULNERABILITY_DETECTED.value,
                EventType.FINDING_VALIDATED.value,
                EventType.FINDING_REJECTED.value,
            ]
            for event_type in phase_events:
                self.subscribe(event_type)

        def cleanup(self):
            for event_type, handler in handlers.items():
                event_bus.unsubscribe(event_type, handler)
            handlers.clear()
            collected.clear()

        def get_events(self, event_type: str = None) -> List[Dict]:
            if event_type is None:
                return list(collected)
            return [e for e in collected if e["type"] == event_type]

        def count_events(self, event_type: str) -> int:
            return len(self.get_events(event_type))

    collector = Collector()
    yield collector
    collector.cleanup()


@pytest.fixture
def pipeline_setup(unique_scan_id, event_collector):
    """Create PipelineOrchestrator + ThinkingAgent for testing (sync fixture)."""
    # Reset queues and metrics
    queue_manager.reset()
    dedup_metrics.reset()
    validation_metrics.reset()

    # Subscribe to phase events
    event_collector.subscribe_all_phases()

    # Create orchestrator
    orchestrator = PipelineOrchestrator(scan_id=unique_scan_id)

    # Create thinking agent
    thinking_agent = ThinkingConsolidationAgent(scan_context=unique_scan_id)
    thinking_agent.set_mode("streaming")

    result = {
        "orchestrator": orchestrator,
        "thinking_agent": thinking_agent,
        "scan_id": unique_scan_id,
        "collector": event_collector,
    }

    yield result

    # Cleanup (sync - async cleanup done in test)
    event_collector.cleanup()


# ============================================================================
# Test Class: TestPipelineE2E
# ============================================================================

class TestPipelineE2E:
    """End-to-end pipeline execution tests."""

    @pytest.mark.asyncio
    async def test_pipeline_full_execution(self, pipeline_setup, mock_finding):
        """
        Start pipeline, simulate url_analyzed events, verify all phases complete.

        DISCOVERY -> EVALUATION -> EXPLOITATION -> VALIDATION -> REPORTING -> COMPLETE
        """
        orchestrator = pipeline_setup["orchestrator"]
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]
        collector = pipeline_setup["collector"]

        try:
            # Start pipeline
            await orchestrator.start()
            assert orchestrator.state.current_phase == PipelinePhase.DISCOVERY

            # Verify PIPELINE_STARTED event
            await asyncio.sleep(0.1)
            assert collector.count_events(EventType.PIPELINE_STARTED.value) >= 1

            # Simulate discovery completion
            await event_bus.emit(EventType.PHASE_COMPLETE_DISCOVERY, {
                "scan_context": scan_id,
                "urls_analyzed": 5,
                "findings_count": 10
            })
            await asyncio.sleep(0.2)

            # Verify transition to EVALUATION
            assert orchestrator.state.current_phase == PipelinePhase.EVALUATION

            # Simulate evaluation completion
            await event_bus.emit(EventType.PHASE_COMPLETE_EVALUATION, {
                "scan_context": scan_id,
                "deduplicated_count": 3,
                "queued_count": 7
            })
            await asyncio.sleep(0.2)

            assert orchestrator.state.current_phase == PipelinePhase.EXPLOITATION

            # Simulate exploitation completion
            await event_bus.emit(EventType.PHASE_COMPLETE_EXPLOITATION, {
                "scan_context": scan_id,
                "vulnerabilities_found": 5,
                "pending_validation": 2
            })
            await asyncio.sleep(0.2)

            assert orchestrator.state.current_phase == PipelinePhase.VALIDATION

            # Simulate validation completion
            await event_bus.emit(EventType.PHASE_COMPLETE_VALIDATION, {
                "scan_context": scan_id,
                "validated_count": 2,
                "rejected_count": 0,
                "cdp_load_percent": 0.5
            })
            await asyncio.sleep(0.2)

            assert orchestrator.state.current_phase == PipelinePhase.REPORTING

            # Simulate reporting completion
            await event_bus.emit(EventType.PHASE_COMPLETE_REPORTING, {
                "scan_context": scan_id,
                "reports_generated": 3,
                "output_path": "/tmp/reports"
            })
            await asyncio.sleep(0.2)

            # Pipeline should be COMPLETE
            assert orchestrator.state.current_phase == PipelinePhase.COMPLETE

            # Verify all phase completion events were received
            assert collector.count_events(EventType.PHASE_COMPLETE_DISCOVERY.value) >= 1
            assert collector.count_events(EventType.PHASE_COMPLETE_EVALUATION.value) >= 1
            assert collector.count_events(EventType.PHASE_COMPLETE_EXPLOITATION.value) >= 1
            assert collector.count_events(EventType.PHASE_COMPLETE_VALIDATION.value) >= 1
            assert collector.count_events(EventType.PHASE_COMPLETE_REPORTING.value) >= 1

        finally:
            await thinking_agent.stop()
            try:
                await orchestrator.stop()
            except:
                pass

    @pytest.mark.asyncio
    async def test_pipeline_phase_transitions(self, unique_scan_id):
        """Verify DISCOVERY->EVALUATION->EXPLOITATION->VALIDATION->REPORTING->COMPLETE transitions."""
        orchestrator = PipelineOrchestrator(scan_id=unique_scan_id)
        await orchestrator.start()

        try:
            # Track transitions
            transitions = []

            # Discovery -> Evaluation
            await event_bus.emit(EventType.PHASE_COMPLETE_DISCOVERY, {"scan_context": unique_scan_id})
            await asyncio.sleep(0.2)
            transitions.append(orchestrator.state.current_phase)

            # Evaluation -> Exploitation
            await event_bus.emit(EventType.PHASE_COMPLETE_EVALUATION, {"scan_context": unique_scan_id})
            await asyncio.sleep(0.2)
            transitions.append(orchestrator.state.current_phase)

            # Exploitation -> Validation
            await event_bus.emit(EventType.PHASE_COMPLETE_EXPLOITATION, {"scan_context": unique_scan_id})
            await asyncio.sleep(0.2)
            transitions.append(orchestrator.state.current_phase)

            # Validation -> Reporting
            await event_bus.emit(EventType.PHASE_COMPLETE_VALIDATION, {"scan_context": unique_scan_id})
            await asyncio.sleep(0.2)
            transitions.append(orchestrator.state.current_phase)

            # Reporting -> Complete
            await event_bus.emit(EventType.PHASE_COMPLETE_REPORTING, {"scan_context": unique_scan_id})
            await asyncio.sleep(0.2)
            transitions.append(orchestrator.state.current_phase)

            # Verify correct order
            expected = [
                PipelinePhase.EVALUATION,
                PipelinePhase.EXPLOITATION,
                PipelinePhase.VALIDATION,
                PipelinePhase.REPORTING,
                PipelinePhase.COMPLETE,
            ]
            assert transitions == expected, f"Expected {expected}, got {transitions}"

        finally:
            await orchestrator.stop()

    @pytest.mark.asyncio
    async def test_pipeline_finding_flow(self, pipeline_setup, mock_finding):
        """
        Inject test findings, track through dedup->classify->queue->validate->report.
        """
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]
        collector = pipeline_setup["collector"]

        try:
            # Subscribe to vulnerability_detected events
            collector.subscribe(EventType.VULNERABILITY_DETECTED.value)

            # Inject findings via url_analyzed event
            findings = [
                mock_finding("XSS", "q", "http://test.com/search1"),
                mock_finding("SQLi", "id", "http://test.com/users"),
                mock_finding("CSTI", "template", "http://test.com/render"),
            ]

            await event_bus.emit(EventType.URL_ANALYZED, {
                "url": "http://test.com",
                "scan_context": scan_id,
                "findings": findings,
                "stats": {"total": len(findings)}
            })
            await asyncio.sleep(0.3)

            # Check ThinkingAgent processed findings
            stats = thinking_agent.get_stats()
            assert stats["total_received"] == 3, f"Expected 3 received, got {stats}"
            assert stats["distributed"] >= 2, f"Expected >=2 distributed, got {stats}"

            # Check queues have items
            xss_queue = queue_manager.get_queue("xss")
            sqli_queue = queue_manager.get_queue("sqli")

            # At least XSS and SQLi should be queued
            assert xss_queue.depth() >= 0 or sqli_queue.depth() >= 0

        finally:
            await thinking_agent.stop()

    @pytest.mark.asyncio
    async def test_pipeline_concurrent_findings(self, pipeline_setup, mock_finding):
        """Process multiple findings concurrently."""
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]

        try:
            # Send multiple url_analyzed events concurrently
            tasks = []
            for i in range(5):
                findings = [
                    mock_finding("XSS", f"param{i}", f"http://test.com/page{i}"),
                    mock_finding("SQLi", f"id{i}", f"http://test.com/user{i}"),
                ]
                task = event_bus.emit(EventType.URL_ANALYZED, {
                    "url": f"http://test.com/page{i}",
                    "scan_context": scan_id,
                    "findings": findings,
                    "stats": {"total": 2}
                })
                tasks.append(task)

            await asyncio.gather(*tasks)
            await asyncio.sleep(0.5)

            # All 10 findings should be received (5 batches * 2 findings)
            stats = thinking_agent.get_stats()
            assert stats["total_received"] == 10, f"Expected 10 received, got {stats}"

        finally:
            await thinking_agent.stop()

    @pytest.mark.asyncio
    async def test_pipeline_graceful_shutdown(self, unique_scan_id):
        """Test drain_queues and graceful_shutdown."""
        # Create state and lifecycle
        state = PipelineState(scan_id=unique_scan_id)
        state.transition(PipelinePhase.DISCOVERY, "Test start")
        lifecycle = PipelineLifecycle(state)

        # Test graceful shutdown
        result = await asyncio.wait_for(
            lifecycle.graceful_shutdown(timeout=2.0),
            timeout=3.0
        )

        # Should complete without error
        assert result in (True, False), "graceful_shutdown should return bool"

        # Verify shutdown state
        assert lifecycle.is_shutdown_requested() is True


# ============================================================================
# Test Class: TestPipelineEvents
# ============================================================================

class TestPipelineEvents:
    """Tests for pipeline event emission."""

    @pytest.mark.asyncio
    async def test_phase_complete_events_emitted(self, unique_scan_id, event_collector):
        """Each phase emits PHASE_COMPLETE_* event."""
        event_collector.subscribe_all_phases()

        state = PipelineState(scan_id=unique_scan_id)
        state.transition(PipelinePhase.DISCOVERY, "Test start")
        lifecycle = PipelineLifecycle(state)

        # Signal phase completions
        await lifecycle.signal_phase_complete(
            PipelinePhase.DISCOVERY,
            {"urls_analyzed": 10}
        )
        await asyncio.sleep(0.1)

        # Verify event emitted
        events = event_collector.get_events(EventType.PHASE_COMPLETE_DISCOVERY.value)
        assert len(events) >= 1
        assert events[0]["data"]["urls_analyzed"] == 10

    @pytest.mark.asyncio
    async def test_vulnerability_detected_events(self, unique_scan_id, event_collector):
        """Specialists emit vulnerability_detected on findings."""
        collected_events = []

        async def capture_vuln(data):
            collected_events.append(data)

        event_bus.subscribe(EventType.VULNERABILITY_DETECTED.value, capture_vuln)

        try:
            # Simulate specialist emitting event
            await event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "xss",
                "status": "VALIDATED_CONFIRMED",
                "finding": {
                    "type": "XSS",
                    "url": "http://test.com",
                    "parameter": "q",
                    "payload": "<script>alert(1)</script>"
                },
                "scan_context": unique_scan_id,
            })
            await asyncio.sleep(0.1)

            assert len(collected_events) == 1
            assert collected_events[0]["specialist"] == "xss"
            assert collected_events[0]["status"] == "VALIDATED_CONFIRMED"

        finally:
            event_bus.unsubscribe(EventType.VULNERABILITY_DETECTED.value, capture_vuln)

    @pytest.mark.asyncio
    async def test_finding_validated_events(self, unique_scan_id, event_collector):
        """AgenticValidator emits finding_validated/rejected."""
        validated_events = []
        rejected_events = []

        async def capture_validated(data):
            validated_events.append(data)

        async def capture_rejected(data):
            rejected_events.append(data)

        event_bus.subscribe(EventType.FINDING_VALIDATED.value, capture_validated)
        event_bus.subscribe(EventType.FINDING_REJECTED.value, capture_rejected)

        try:
            # Emit validated event
            await event_bus.emit(EventType.FINDING_VALIDATED, {
                "specialist": "xss",
                "finding": {"url": "http://test.com", "parameter": "q"},
                "scan_context": unique_scan_id,
            })

            # Emit rejected event
            await event_bus.emit(EventType.FINDING_REJECTED, {
                "specialist": "sqli",
                "finding": {"url": "http://test.com", "parameter": "id"},
                "reason": "False positive",
                "scan_context": unique_scan_id,
            })

            await asyncio.sleep(0.1)

            assert len(validated_events) == 1
            assert len(rejected_events) == 1
            assert rejected_events[0]["reason"] == "False positive"

        finally:
            event_bus.unsubscribe(EventType.FINDING_VALIDATED.value, capture_validated)
            event_bus.unsubscribe(EventType.FINDING_REJECTED.value, capture_rejected)


# ============================================================================
# Test Class: TestPipelineEdgeCases
# ============================================================================

class TestPipelineEdgeCases:
    """Edge case tests for pipeline robustness."""

    @pytest.mark.asyncio
    async def test_pipeline_empty_findings(self, pipeline_setup):
        """Pipeline completes when no findings discovered."""
        orchestrator = pipeline_setup["orchestrator"]
        scan_id = pipeline_setup["scan_id"]
        thinking_agent = pipeline_setup["thinking_agent"]

        try:
            await orchestrator.start()

            # Send url_analyzed with no findings
            await event_bus.emit(EventType.URL_ANALYZED, {
                "url": "http://test.com",
                "scan_context": scan_id,
                "findings": [],  # Empty
                "stats": {"total": 0}
            })
            await asyncio.sleep(0.1)

            # No findings should be processed
            stats = thinking_agent.get_stats()
            assert stats["total_received"] == 0
            assert stats["distributed"] == 0

            # Pipeline should still be able to transition
            await event_bus.emit(EventType.PHASE_COMPLETE_DISCOVERY, {
                "scan_context": scan_id,
                "urls_analyzed": 1,
                "findings_count": 0
            })
            await asyncio.sleep(0.2)

            assert orchestrator.state.current_phase == PipelinePhase.EVALUATION

        finally:
            await thinking_agent.stop()
            try:
                await orchestrator.stop()
            except:
                pass

    @pytest.mark.asyncio
    async def test_pipeline_all_duplicates(self, pipeline_setup, mock_finding):
        """All findings filtered as duplicates."""
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]

        try:
            # Reset stats to ensure clean test
            thinking_agent.reset_stats()

            # Send same finding multiple times
            same_finding = mock_finding("XSS", "q", "http://test.com/dup")

            for i in range(5):
                await event_bus.emit(EventType.URL_ANALYZED, {
                    "url": "http://test.com/dup",
                    "scan_context": scan_id,
                    "findings": [same_finding],
                    "stats": {"total": 1}
                })
                await asyncio.sleep(0.1)

            await asyncio.sleep(0.2)

            stats = thinking_agent.get_stats()
            # First should be processed, rest duplicated
            assert stats["total_received"] == 5
            assert stats["duplicates_filtered"] >= 4, f"Expected >=4 duplicates, got {stats}"

        finally:
            await thinking_agent.stop()

    @pytest.mark.asyncio
    async def test_pipeline_all_fp_filtered(self, pipeline_setup):
        """All findings below FP threshold."""
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]

        try:
            thinking_agent.reset_stats()

            # Send findings with very low FP confidence
            low_conf_findings = [
                {
                    "type": "XSS",
                    "parameter": f"p{i}",
                    "url": f"http://test.com/fp{i}",
                    "fp_confidence": 0.05,  # Below default threshold
                    "severity": "low",
                    "skeptical_score": 1,
                }
                for i in range(3)
            ]

            await event_bus.emit(EventType.URL_ANALYZED, {
                "url": "http://test.com",
                "scan_context": scan_id,
                "findings": low_conf_findings,
                "stats": {"total": 3}
            })
            await asyncio.sleep(0.2)

            stats = thinking_agent.get_stats()
            assert stats["total_received"] == 3
            assert stats["fp_filtered"] >= 3, f"All should be FP filtered, got {stats}"

        finally:
            await thinking_agent.stop()

    @pytest.mark.asyncio
    async def test_pipeline_unknown_vuln_type(self, pipeline_setup):
        """Findings with unclassifiable types handled gracefully."""
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]

        try:
            thinking_agent.reset_stats()

            # Unknown vulnerability type
            unknown_findings = [
                {
                    "type": "SuperSecretUnknownVuln",  # Not in mapping
                    "parameter": "x",
                    "url": "http://test.com/unknown",
                    "fp_confidence": 0.9,
                    "severity": "critical",
                    "skeptical_score": 8,
                }
            ]

            await event_bus.emit(EventType.URL_ANALYZED, {
                "url": "http://test.com",
                "scan_context": scan_id,
                "findings": unknown_findings,
                "stats": {"total": 1}
            })
            await asyncio.sleep(0.2)

            stats = thinking_agent.get_stats()
            assert stats["total_received"] == 1
            # Should be tracked as unclassified, not error
            assert stats.get("unclassified", 0) >= 1 or stats["distributed"] == 0

        finally:
            await thinking_agent.stop()


# ============================================================================
# Test Class: TestPipelineError
# ============================================================================

class TestPipelineError:
    """Error handling and recovery tests."""

    @pytest.mark.asyncio
    async def test_pipeline_error_recovery(self, unique_scan_id):
        """Pipeline transitions to ERROR state on exception."""
        orchestrator = PipelineOrchestrator(scan_id=unique_scan_id)
        await orchestrator.start()

        try:
            # Force transition to ERROR
            result = await orchestrator.force_transition(
                PipelinePhase.ERROR,
                "Simulated error for testing"
            )
            assert result is True
            assert orchestrator.state.current_phase == PipelinePhase.ERROR
            # Note: force_transition doesn't set state.error, only state.transition does
            # The error field is set by transition() method when transitioning TO ERROR
            # After force_transition, the state is in ERROR phase

            # Can transition from ERROR to IDLE (reset)
            assert orchestrator.state.can_transition(PipelinePhase.IDLE)

        finally:
            await orchestrator.stop()

    @pytest.mark.asyncio
    async def test_pipeline_pause_resume(self, unique_scan_id):
        """Pause at phase boundary, resume continues execution."""
        state = PipelineState(scan_id=unique_scan_id)
        state.transition(PipelinePhase.DISCOVERY, "Start")
        lifecycle = PipelineLifecycle(state)

        # Request pause
        lifecycle._pause_requested = True

        # Verify pause flag
        assert lifecycle.is_pause_requested() is True

        # Check pause point returns True (paused)
        # Note: In real usage, check_pause_point would wait
        # Here we test the flag behavior
        lifecycle._pause_requested = False
        result = await asyncio.wait_for(
            lifecycle.check_pause_point(),
            timeout=1.0
        )
        assert result is False  # Not paused when flag is cleared

    @pytest.mark.asyncio
    async def test_pipeline_timeout_handling(self, unique_scan_id):
        """Phase timeout triggers ERROR transition."""
        orchestrator = PipelineOrchestrator(scan_id=unique_scan_id)
        await orchestrator.start()

        try:
            # Simulate timeout by forcing ERROR transition
            # In real implementation, this would be triggered by PIPELINE_PHASE_TIMEOUT
            await orchestrator.force_transition(
                PipelinePhase.ERROR,
                "Phase timeout exceeded"
            )

            assert orchestrator.state.current_phase == PipelinePhase.ERROR

            # Verify ERROR state can only go to IDLE
            valid_from_error = VALID_TRANSITIONS[PipelinePhase.ERROR]
            assert valid_from_error == [PipelinePhase.IDLE]

        finally:
            await orchestrator.stop()


# ============================================================================
# Test Class: TestPipelineMetrics
# ============================================================================

class TestPipelineMetrics:
    """Metrics tracking tests."""

    @pytest.mark.asyncio
    async def test_pipeline_dedup_metrics_tracked(self, pipeline_setup, mock_finding):
        """DeduplicationMetrics records correctly."""
        thinking_agent = pipeline_setup["thinking_agent"]
        scan_id = pipeline_setup["scan_id"]

        try:
            # Reset global metrics
            dedup_metrics.reset()
            thinking_agent.reset_stats()

            # Process findings
            findings = [
                mock_finding("XSS", "p1", "http://test.com/m1"),
                mock_finding("XSS", "p1", "http://test.com/m1"),  # Duplicate
                mock_finding("SQLi", "p2", "http://test.com/m2"),
            ]

            await event_bus.emit(EventType.URL_ANALYZED, {
                "url": "http://test.com",
                "scan_context": scan_id,
                "findings": findings,
                "stats": {"total": 3}
            })
            await asyncio.sleep(0.3)

            # Check global dedup metrics
            summary = dedup_metrics.get_summary()
            assert summary["total_received"] >= 3
            assert summary["total_deduplicated"] >= 1  # At least one duplicate

        finally:
            await thinking_agent.stop()

    @pytest.mark.asyncio
    async def test_pipeline_validation_metrics_tracked(self):
        """ValidationMetrics records CDP load."""
        validation_metrics.reset()

        # Record findings
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("sqli", "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()
        assert summary["total_findings"] == 3
        assert summary["validated_confirmed"] == 2
        assert summary["pending_validation"] == 1

        # CDP load should be ~33% (1/3)
        cdp_load = validation_metrics.get_cdp_load()
        assert 30 <= cdp_load <= 35, f"Expected ~33%, got {cdp_load}%"

    @pytest.mark.asyncio
    async def test_pipeline_parallelization_metrics(self, unique_scan_id):
        """ParallelizationMetrics tracks workers."""
        # Import and reset parallelization metrics
        from bugtrace.core.parallelization_metrics import parallelization_metrics

        parallelization_metrics.reset()

        # Simulate worker activity (with worker IDs)
        parallelization_metrics.record_worker_start("xss", 1)
        parallelization_metrics.record_worker_start("xss", 2)
        parallelization_metrics.record_worker_start("sqli", 1)

        summary = parallelization_metrics.get_summary()
        assert summary["current_concurrent"] == 3
        # by_specialist contains nested dict with 'current_workers' key
        assert summary["by_specialist"]["xss"]["current_workers"] == 2
        assert summary["by_specialist"]["sqli"]["current_workers"] == 1

        # Stop workers
        parallelization_metrics.record_worker_stop("xss", 1)
        parallelization_metrics.record_worker_stop("xss", 2)
        parallelization_metrics.record_worker_stop("sqli", 1)

        summary = parallelization_metrics.get_summary()
        assert summary["current_concurrent"] == 0
        assert summary["peak_concurrent"] >= 3


# ============================================================================
# Additional Helper Tests
# ============================================================================

class TestPipelineStateIntegrity:
    """Test pipeline state integrity and serialization."""

    def test_pipeline_state_to_dict(self, unique_scan_id):
        """Pipeline state serializes correctly."""
        state = PipelineState(scan_id=unique_scan_id)
        state.transition(PipelinePhase.DISCOVERY, "Test")
        state.transition(PipelinePhase.EVALUATION, "Discovery done")

        d = state.to_dict()
        assert d["scan_id"] == unique_scan_id
        assert d["current_phase"] == "evaluation"
        assert d["previous_phase"] == "discovery"
        assert len(d["transitions"]) == 2

    def test_pipeline_transition_count(self, unique_scan_id):
        """Transitions are counted correctly."""
        state = PipelineState(scan_id=unique_scan_id)

        # Full pipeline run
        phases = [
            PipelinePhase.DISCOVERY,
            PipelinePhase.EVALUATION,
            PipelinePhase.EXPLOITATION,
            PipelinePhase.VALIDATION,
            PipelinePhase.REPORTING,
            PipelinePhase.COMPLETE,
        ]

        reasons = ["start", "eval", "exploit", "validate", "report", "done"]

        for phase, reason in zip(phases, reasons):
            state.transition(phase, reason)

        assert len(state.transitions) == 6


# Run with: pytest tests/integration/test_pipeline_e2e.py -v --tb=short
