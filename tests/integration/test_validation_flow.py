"""
Integration Tests for Validation Flow (TEST-05)

Tests the validation optimization flow:
- VALIDATED_CONFIRMED findings skip CDP validation
- PENDING_VALIDATION findings go through AgenticValidator CDP queue
- ValidationMetrics accurately tracks CDP load percentage
- End-to-end flow from specialist to report

Requirement coverage:
- EXPL-05: Specialists tag confirmed findings as VALIDATED_CONFIRMED
- EXPL-06: Specialists tag edge cases as PENDING_VALIDATION
- VAL-01: AgenticValidator processes only PENDING_VALIDATION
- VAL-02: AgenticValidator receives <1% of findings
- VAL-04: AgenticValidator emits finding_validated/finding_rejected
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, List

from bugtrace.core.validation_status import (
    ValidationStatus,
    EDGE_CASE_PATTERNS,
    requires_cdp_validation,
    get_validation_status,
)
from bugtrace.core.validation_metrics import ValidationMetrics, validation_metrics
from bugtrace.core.event_bus import EventBus, EventType


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def reset_validation_metrics():
    """Reset validation metrics before and after each test."""
    validation_metrics.reset()
    yield
    validation_metrics.reset()


@pytest.fixture
def fresh_event_bus():
    """Create a fresh EventBus instance for testing."""
    bus = EventBus()
    return bus


@pytest.fixture
def agentic_validator_instance(fresh_event_bus):
    """Create a fresh AgenticValidator with mocked queue and event bus."""
    from bugtrace.agents.agentic_validator import AgenticValidator

    av = AgenticValidator(event_bus=fresh_event_bus)
    av._pending_queue = asyncio.Queue()
    # Reset stats for clean test
    av._stats = {
        "total_validated": 0,
        "cache_hits": 0,
        "cdp_confirmed": 0,
        "vision_analyzed": 0,
        "skipped_prevalidated": 0,
        "avg_time_ms": 0,
        "total_time_ms": 0,
        "total_received": 0,
        "skipped_confirmed": 0,
        "queued_for_cdp": 0,
        "cdp_rejected": 0,
    }
    return av


@pytest.fixture
def confirmed_finding_factory():
    """Factory for creating VALIDATED_CONFIRMED findings."""
    def _create(specialist: str = "xss", url: str = None, **extra) -> Dict[str, Any]:
        return {
            "specialist": specialist,
            "status": ValidationStatus.VALIDATED_CONFIRMED.value,
            "finding": {
                "url": url or f"http://test.com/{specialist}",
                "type": specialist.upper(),
                "payload": "<script>alert(1)</script>",
                "evidence": {"dialog_detected": True},
                **extra.get("finding_extra", {}),
            },
            "scan_context": extra.get("scan_context", "test_scan"),
            "validation_requires_cdp": False,
        }
    return _create


@pytest.fixture
def pending_finding_factory():
    """Factory for creating PENDING_VALIDATION findings."""
    def _create(specialist: str = "xss", url: str = None, **extra) -> Dict[str, Any]:
        return {
            "specialist": specialist,
            "status": ValidationStatus.PENDING_VALIDATION.value,
            "finding": {
                "url": url or f"http://test.com/{specialist}/edge",
                "type": specialist.upper(),
                "payload": extra.get("payload", "<input autofocus onfocus=alert(1)>"),
                "evidence": {},
                **extra.get("finding_extra", {}),
            },
            "scan_context": extra.get("scan_context", "test_scan"),
            "validation_requires_cdp": True,
        }
    return _create


# =============================================================================
# TestValidationFlow - Core validation routing tests
# =============================================================================

class TestValidationFlow:
    """Test core validation routing logic."""

    @pytest.mark.asyncio
    async def test_validated_confirmed_skips_cdp(self, agentic_validator_instance, confirmed_finding_factory):
        """
        VAL-01: VALIDATED_CONFIRMED findings skip CDP validation.

        When a specialist emits a VALIDATED_CONFIRMED finding,
        AgenticValidator should NOT queue it for CDP validation.
        """
        av = agentic_validator_instance
        finding = confirmed_finding_factory("xss")

        await av.handle_vulnerability_detected(finding)

        # Queue should remain empty (finding skipped)
        assert av._pending_queue.empty(), "VALIDATED_CONFIRMED should not be queued"
        assert av._stats["skipped_confirmed"] == 1, "Should track skipped_confirmed"
        assert av._stats["queued_for_cdp"] == 0, "Should not queue for CDP"
        assert av._stats["total_received"] == 1, "Should track total received"

    @pytest.mark.asyncio
    async def test_pending_validation_queued_for_cdp(self, agentic_validator_instance, pending_finding_factory):
        """
        VAL-01: PENDING_VALIDATION findings are queued for CDP validation.

        When a specialist emits a PENDING_VALIDATION finding,
        AgenticValidator should queue it for CDP validation.
        """
        av = agentic_validator_instance
        finding = pending_finding_factory("xss")

        await av.handle_vulnerability_detected(finding)

        # Queue should have the finding
        assert not av._pending_queue.empty(), "PENDING_VALIDATION should be queued"
        assert av._stats["queued_for_cdp"] == 1, "Should track queued_for_cdp"
        assert av._stats["skipped_confirmed"] == 0, "Should not skip"

        # Verify queue content
        queued_item = await av._pending_queue.get()
        assert queued_item["specialist"] == "xss"
        assert queued_item["finding"]["type"] == "XSS"

    @pytest.mark.asyncio
    async def test_mixed_findings_correct_routing(self, agentic_validator_instance, confirmed_finding_factory, pending_finding_factory):
        """
        Test mixed VALIDATED_CONFIRMED and PENDING_VALIDATION findings.

        90 VALIDATED_CONFIRMED, 10 PENDING_VALIDATION should result in:
        - 90 skipped
        - 10 queued
        - 10% CDP load
        """
        av = agentic_validator_instance

        # Send 90 confirmed findings
        for i in range(90):
            finding = confirmed_finding_factory("xss", url=f"http://test.com/confirmed/{i}")
            await av.handle_vulnerability_detected(finding)

        # Send 10 pending findings
        for i in range(10):
            finding = pending_finding_factory("xss", url=f"http://test.com/pending/{i}")
            await av.handle_vulnerability_detected(finding)

        # Verify routing
        assert av._stats["skipped_confirmed"] == 90, "90 findings should be skipped"
        assert av._stats["queued_for_cdp"] == 10, "10 findings should be queued"
        assert av._stats["total_received"] == 100, "100 total received"

        # Verify CDP load percentage
        stats = av.get_stats()
        assert stats["cdp_load_percent"] == 10.0, "CDP load should be 10%"
        assert stats["cdp_target_met"] == False, "Target (<1%) should not be met"

    @pytest.mark.asyncio
    async def test_validation_metrics_accuracy(self, agentic_validator_instance, confirmed_finding_factory, pending_finding_factory):
        """
        ValidationMetrics should accurately track CDP load.

        Process 100 findings and verify get_summary() matches actual routing.
        """
        av = agentic_validator_instance

        # Process 100 findings (95 confirmed, 5 pending)
        for i in range(95):
            # Also record in global metrics
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
            finding = confirmed_finding_factory("xss", url=f"http://test.com/c/{i}")
            await av.handle_vulnerability_detected(finding)

        for i in range(5):
            validation_metrics.record_finding("xss", "PENDING_VALIDATION")
            finding = pending_finding_factory("xss", url=f"http://test.com/p/{i}")
            await av.handle_vulnerability_detected(finding)

        # Check ValidationMetrics
        summary = validation_metrics.get_summary()
        assert summary["total_findings"] == 100
        assert summary["validated_confirmed"] == 95
        assert summary["pending_validation"] == 5
        assert summary["cdp_load_percent"] == 5.0

        # Cross-check with AgenticValidator stats
        stats = av.get_stats()
        assert stats["skipped_confirmed"] == 95
        assert stats["queued_for_cdp"] == 5
        assert stats["cdp_load_percent"] == 5.0

    @pytest.mark.asyncio
    async def test_cdp_load_target_met(self, agentic_validator_instance, confirmed_finding_factory, pending_finding_factory):
        """
        VAL-02: <1% CDP load target should be achievable.

        999 VALIDATED_CONFIRMED, 1 PENDING_VALIDATION should result in:
        - CDP load = 0.1%
        - is_target_met() = True
        """
        av = agentic_validator_instance

        # Send 999 confirmed findings
        for i in range(999):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
            finding = confirmed_finding_factory("xss", url=f"http://test.com/c/{i}")
            await av.handle_vulnerability_detected(finding)

        # Send 1 pending finding
        validation_metrics.record_finding("xss", "PENDING_VALIDATION")
        finding = pending_finding_factory("xss", url="http://test.com/edge")
        await av.handle_vulnerability_detected(finding)

        # Verify target met
        summary = validation_metrics.get_summary()
        assert summary["cdp_load_percent"] == 0.1
        assert summary["target_met"] == True
        assert validation_metrics.is_target_met() == True

        # Cross-check AgenticValidator
        stats = av.get_stats()
        assert stats["cdp_load_percent"] == 0.1
        assert stats["cdp_target_met"] == True


# =============================================================================
# TestCDPSkipping - Edge case detection tests
# =============================================================================

class TestCDPSkipping:
    """Test that specific evidence types correctly skip/require CDP."""

    def test_interactsh_confirmed_skips_cdp(self):
        """
        OOB callback confirmed findings should skip CDP.

        Interactsh hit = high confidence, no need for CDP validation.
        """
        finding = {
            "validation_method": "interactsh",
            "evidence": {"interactsh_hit": True},
            "context": "reflected",
        }

        # Should NOT require CDP
        assert requires_cdp_validation(finding) == False

        # Should be VALIDATED_CONFIRMED
        status = get_validation_status(finding)
        assert status == ValidationStatus.VALIDATED_CONFIRMED

    def test_dialog_detected_skips_cdp(self):
        """
        Visual dialog detection should skip CDP.

        Dialog detected = high confidence, no need for CDP validation.
        """
        finding = {
            "evidence": {"dialog_detected": True},
            "context": "html_text",
        }

        assert requires_cdp_validation(finding) == False
        status = get_validation_status(finding)
        assert status == ValidationStatus.VALIDATED_CONFIRMED

    def test_dom_xss_requires_cdp(self):
        """
        DOM-based XSS with location.hash should require CDP.

        DOM XSS requires JavaScript execution context to verify.
        """
        finding = {
            "payload": "location.hash.substring(1)",
            "context": "script",
            "evidence": {},
        }

        assert requires_cdp_validation(finding) == True
        status = get_validation_status(finding, confidence=0.5)
        assert status == ValidationStatus.PENDING_VALIDATION

    def test_autofocus_requires_cdp(self):
        """
        Autofocus onfocus payloads require CDP validation.

        These bypass WAFs but need visual confirmation.
        """
        finding = {
            "payload": "<input autofocus onfocus=alert(1)>",
            "context": "html",
            "evidence": {},
        }

        assert requires_cdp_validation(finding) == True
        status = get_validation_status(finding, confidence=0.5)
        assert status == ValidationStatus.PENDING_VALIDATION

    def test_time_based_sqli_requires_cdp(self):
        """
        Time-based blind SQLi should require CDP validation.

        Time-based detection is less reliable and needs verification.
        """
        finding = {
            "vuln_type": "sqli_time_based",
            "detection_method": "time-based",
            "payload": "'; WAITFOR DELAY '0:0:5'--",
            "evidence": {},
        }

        # Time-based doesn't match edge case patterns, but confidence is low
        status = get_validation_status(finding, confidence=0.6)
        assert status == ValidationStatus.PENDING_VALIDATION

    def test_dom_mutation_proof_skips_cdp(self):
        """DOM mutation proof should skip CDP validation."""
        finding = {
            "evidence": {"dom_mutation_proof": True},
            "context": "reflected",
        }

        assert requires_cdp_validation(finding) == False
        status = get_validation_status(finding)
        assert status == ValidationStatus.VALIDATED_CONFIRMED

    def test_console_execution_proof_skips_cdp(self):
        """Console execution proof should skip CDP validation."""
        finding = {
            "evidence": {"console_execution_proof": True},
            "context": "reflected",
        }

        assert requires_cdp_validation(finding) == False
        status = get_validation_status(finding)
        assert status == ValidationStatus.VALIDATED_CONFIRMED

    def test_innerhtml_sink_requires_cdp(self):
        """innerHTML sink detection should require CDP validation."""
        finding = {
            "payload": "elem.innerHTML = user_input",
            "context": "script",
            "evidence": {},
        }

        assert requires_cdp_validation(finding) == True

    def test_eval_sink_requires_cdp(self):
        """eval() sink detection should require CDP validation."""
        finding = {
            "payload": "eval(user_data)",
            "context": "script",
            "evidence": {},
        }

        assert requires_cdp_validation(finding) == True


# =============================================================================
# TestValidationE2E - End-to-end flow tests
# =============================================================================

class TestValidationE2E:
    """Test end-to-end validation flow from specialist to report."""

    @pytest.mark.asyncio
    async def test_xss_validation_flow_confirmed(self, fresh_event_bus, confirmed_finding_factory):
        """
        Test XSS finding with dialog_detected flows correctly.

        Flow: Specialist emits VALIDATED_CONFIRMED -> ReportingAgent receives it
        """
        from bugtrace.agents.agentic_validator import AgenticValidator
        from bugtrace.agents.reporting import ReportingAgent
        from pathlib import Path
        import tempfile

        # Setup
        with tempfile.TemporaryDirectory() as tmpdir:
            reporting = ReportingAgent(
                scan_id=1,
                target_url="http://test.com",
                output_dir=Path(tmpdir)
            )
            reporting._event_bus = fresh_event_bus

            # Subscribe ReportingAgent to events
            fresh_event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                reporting._handle_vulnerability_detected
            )

            # Create confirmed finding
            finding_data = confirmed_finding_factory("xss")

            # Emit event
            await fresh_event_bus.emit(EventType.VULNERABILITY_DETECTED, finding_data)

            # Allow event processing
            await asyncio.sleep(0.05)

            # Verify ReportingAgent collected the finding
            collected = reporting.get_validated_findings()
            assert len(collected) == 1, "ReportingAgent should collect VALIDATED_CONFIRMED"
            assert collected[0]["status"] == "VALIDATED_CONFIRMED"
            assert collected[0]["event_source"] == "vulnerability_detected"

    @pytest.mark.asyncio
    async def test_sqli_validation_flow_pending(self, fresh_event_bus, pending_finding_factory):
        """
        Test SQLi finding with time-based technique flows through CDP.

        Flow: Specialist emits PENDING_VALIDATION -> AgenticValidator queues
              -> Mock CDP validates -> Emits FINDING_VALIDATED -> ReportingAgent
        """
        from bugtrace.agents.agentic_validator import AgenticValidator
        from bugtrace.agents.reporting import ReportingAgent
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup AgenticValidator
            av = AgenticValidator(event_bus=fresh_event_bus)
            av._pending_queue = asyncio.Queue()

            # Setup ReportingAgent
            reporting = ReportingAgent(
                scan_id=1,
                target_url="http://test.com",
                output_dir=Path(tmpdir)
            )
            reporting._event_bus = fresh_event_bus

            # Subscribe ReportingAgent to finding_validated
            fresh_event_bus.subscribe(
                EventType.FINDING_VALIDATED.value,
                reporting._handle_finding_validated
            )

            # Create pending finding
            finding_data = pending_finding_factory(
                "sqli",
                payload="'; WAITFOR DELAY '0:0:5'--"
            )

            # Send to AgenticValidator
            await av.handle_vulnerability_detected(finding_data)

            # Verify queued for CDP
            assert not av._pending_queue.empty()

            # Simulate CDP validation completing (mock the emit)
            await fresh_event_bus.emit(EventType.FINDING_VALIDATED, {
                "specialist": "sqli",
                "finding": finding_data["finding"],
                "validation_result": {
                    "status": "VALIDATED",
                    "reasoning": "CDP confirmed SQL injection",
                    "confidence": 0.95,
                },
                "scan_context": "test_scan",
            })

            # Allow event processing
            await asyncio.sleep(0.05)

            # Verify ReportingAgent collected CDP-validated finding
            collected = reporting.get_validated_findings()
            assert len(collected) == 1, "ReportingAgent should collect CDP-validated"
            assert collected[0]["cdp_validated"] == True
            assert collected[0]["event_source"] == "finding_validated"

    @pytest.mark.asyncio
    async def test_validation_events_chain(self, fresh_event_bus):
        """
        Test full event chain from vulnerability_detected to finding_validated.

        Verifies events are emitted in correct order.
        """
        events_received = []

        async def track_event(event_type: str):
            async def handler(data):
                events_received.append({
                    "event": event_type,
                    "status": data.get("status", data.get("validation_result", {}).get("status")),
                })
            return handler

        # Subscribe to track events
        fresh_event_bus.subscribe(
            EventType.VULNERABILITY_DETECTED.value,
            await track_event("vulnerability_detected")
        )
        fresh_event_bus.subscribe(
            EventType.FINDING_VALIDATED.value,
            await track_event("finding_validated")
        )
        fresh_event_bus.subscribe(
            EventType.FINDING_REJECTED.value,
            await track_event("finding_rejected")
        )

        # Emit vulnerability_detected (PENDING_VALIDATION)
        await fresh_event_bus.emit(EventType.VULNERABILITY_DETECTED, {
            "specialist": "xss",
            "status": "PENDING_VALIDATION",
            "finding": {"url": "http://test.com"},
        })

        # Emit finding_validated (simulating CDP completion)
        await fresh_event_bus.emit(EventType.FINDING_VALIDATED, {
            "specialist": "xss",
            "finding": {"url": "http://test.com"},
            "validation_result": {"status": "VALIDATED"},
        })

        await asyncio.sleep(0.05)

        # Verify event chain
        assert len(events_received) == 2
        assert events_received[0]["event"] == "vulnerability_detected"
        assert events_received[1]["event"] == "finding_validated"

    @pytest.mark.asyncio
    async def test_reporting_receives_both_types(self, fresh_event_bus, confirmed_finding_factory, pending_finding_factory):
        """
        ReportingAgent should receive both validation types.

        - VALIDATED_CONFIRMED from vulnerability_detected
        - VALIDATED from finding_validated (CDP)
        """
        from bugtrace.agents.reporting import ReportingAgent
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            reporting = ReportingAgent(
                scan_id=1,
                target_url="http://test.com",
                output_dir=Path(tmpdir)
            )
            reporting._event_bus = fresh_event_bus

            # Subscribe to both event types
            fresh_event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                reporting._handle_vulnerability_detected
            )
            fresh_event_bus.subscribe(
                EventType.FINDING_VALIDATED.value,
                reporting._handle_finding_validated
            )

            # Emit VALIDATED_CONFIRMED (specialist self-validated)
            await fresh_event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "xss",
                "status": "VALIDATED_CONFIRMED",
                "finding": {"url": "http://test.com/1", "type": "XSS"},
            })

            # Emit finding_validated (CDP validated)
            await fresh_event_bus.emit(EventType.FINDING_VALIDATED, {
                "specialist": "sqli",
                "finding": {"url": "http://test.com/2", "type": "SQLI"},
                "validation_result": {"status": "VALIDATED", "confidence": 0.9},
            })

            await asyncio.sleep(0.05)

            # Verify both received
            collected = reporting.get_validated_findings()
            assert len(collected) == 2

            # Check one is VALIDATED_CONFIRMED, one is VALIDATED (CDP)
            statuses = {f["status"] for f in collected}
            assert "VALIDATED_CONFIRMED" in statuses
            assert "VALIDATED" in statuses

            # Check event sources
            sources = {f["event_source"] for f in collected}
            assert "vulnerability_detected" in sources
            assert "finding_validated" in sources


# =============================================================================
# TestEdgeCaseValidation - Error handling tests
# =============================================================================

class TestEdgeCaseValidation:
    """Test edge case and error handling in validation flow."""

    @pytest.mark.asyncio
    async def test_validation_error_handling_missing_status(self, agentic_validator_instance):
        """
        Missing status field should be handled gracefully.

        Default behavior: treat as non-PENDING_VALIDATION (skip).
        """
        av = agentic_validator_instance

        # Missing status field
        await av.handle_vulnerability_detected({
            "specialist": "xss",
            # No status field
            "finding": {"url": "http://test.com"},
        })

        # Should be skipped (status != PENDING_VALIDATION)
        assert av._pending_queue.empty()
        assert av._stats["skipped_confirmed"] == 1

    @pytest.mark.asyncio
    async def test_validation_error_handling_missing_finding(self, agentic_validator_instance):
        """
        Missing finding field should be handled gracefully.
        """
        av = agentic_validator_instance

        # Empty finding
        await av.handle_vulnerability_detected({
            "specialist": "xss",
            "status": "PENDING_VALIDATION",
            "finding": {},  # Empty but present
        })

        # Should still queue (status matches)
        assert av._stats["queued_for_cdp"] == 1

        # Queue item should have empty finding
        item = await av._pending_queue.get()
        assert item["finding"] == {}

    @pytest.mark.asyncio
    async def test_validation_status_unknown(self, agentic_validator_instance):
        """
        Unknown status should be treated as non-PENDING (skipped).
        """
        av = agentic_validator_instance

        await av.handle_vulnerability_detected({
            "specialist": "xss",
            "status": "UNKNOWN_STATUS",
            "finding": {"url": "http://test.com"},
        })

        # Unknown status should be skipped
        assert av._pending_queue.empty()
        assert av._stats["skipped_confirmed"] == 1

    @pytest.mark.asyncio
    async def test_duplicate_events_handled(self, agentic_validator_instance, pending_finding_factory):
        """
        Same finding received twice should queue twice.

        Deduplication happens at ReportingAgent level, not AgenticValidator.
        """
        av = agentic_validator_instance

        finding = pending_finding_factory("xss", url="http://test.com/dup")

        # Send same finding twice
        await av.handle_vulnerability_detected(finding)
        await av.handle_vulnerability_detected(finding)

        # Both should be queued (no dedup at this level)
        assert av._stats["queued_for_cdp"] == 2
        assert av._pending_queue.qsize() == 2


# =============================================================================
# TestValidationCDPLoad - CDP load tracking tests
# =============================================================================

class TestValidationCDPLoad:
    """Test CDP load tracking and logging."""

    def test_realistic_scan_cdp_load(self):
        """
        Simulate realistic scan distribution to verify <1% target.

        Distribution:
        - XSS: 400 confirmed, 4 pending (1%)
        - SQLi: 200 confirmed, 2 pending (1%)
        - Others: 394 confirmed
        Total: 1000 findings, 6 pending = 0.6% CDP load
        """
        # XSS findings
        for _ in range(400):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        for _ in range(4):
            validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        # SQLi findings
        for _ in range(200):
            validation_metrics.record_finding("sqli", "VALIDATED_CONFIRMED")
        for _ in range(2):
            validation_metrics.record_finding("sqli", "PENDING_VALIDATION")

        # Other specialists (all confirmed)
        for _ in range(394):
            validation_metrics.record_finding("other", "VALIDATED_CONFIRMED")

        summary = validation_metrics.get_summary()

        assert summary["total_findings"] == 1000
        assert summary["validated_confirmed"] == 994
        assert summary["pending_validation"] == 6
        assert summary["cdp_load_percent"] == 0.6
        assert summary["target_met"] == True

    def test_cdp_load_logging_called(self):
        """
        CDP load should be logged at scan completion.
        """
        # Record some findings
        for _ in range(100):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")

        # Verify log_reduction_summary doesn't crash
        with patch('bugtrace.core.validation_metrics.logger') as mock_logger:
            validation_metrics.log_reduction_summary()
            # Should have called logger.info
            assert mock_logger.info.called

    def test_cdp_target_exceeded_check(self):
        """
        Verify is_target_met() returns False when target exceeded.
        """
        # 90 confirmed, 10 pending = 10% CDP load
        for _ in range(90):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        for _ in range(10):
            validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        assert validation_metrics.is_target_met() == False
        assert validation_metrics.get_cdp_load() == 10.0

    def test_reduction_percent_calculation(self):
        """
        Test reduction percentage calculation.

        If 1% goes to CDP, reduction = 99%
        """
        # 99 confirmed, 1 pending
        for _ in range(99):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        # CDP load = 1%, reduction = 99%
        assert validation_metrics.get_cdp_load() == 1.0
        assert validation_metrics.get_reduction_percent() == 99.0
        assert validation_metrics.is_reduction_target_met() == True

    def test_zero_findings_metrics(self):
        """
        Zero findings should result in safe default metrics.
        """
        summary = validation_metrics.get_summary()

        assert summary["total_findings"] == 0
        assert summary["cdp_load_percent"] == 0.0
        assert summary["target_met"] == True  # 0% <= 1% target

        # Reduction should be 100% (no CDP needed)
        assert validation_metrics.get_reduction_percent() == 100.0

    def test_all_pending_scenario(self):
        """
        All findings being PENDING_VALIDATION = 100% CDP load.

        This is an edge case that should be detectable.
        """
        for _ in range(10):
            validation_metrics.record_finding("dom_xss", "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()

        assert summary["cdp_load_percent"] == 100.0
        assert summary["target_met"] == False
        assert validation_metrics.get_reduction_percent() == 0.0
