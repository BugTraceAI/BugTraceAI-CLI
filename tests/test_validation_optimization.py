"""
Tests for Phase 21: Validation Optimization

Verifies:
- EXPL-05: Specialists tag confirmed findings as VALIDATED_CONFIRMED
- EXPL-06: Specialists tag edge cases as PENDING_VALIDATION
- VAL-01: AgenticValidator processes only PENDING_VALIDATION
- VAL-02: AgenticValidator receives <1% of findings
- VAL-04: AgenticValidator emits finding_validated/finding_rejected
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from bugtrace.core.validation_status import (
    ValidationStatus,
    EDGE_CASE_PATTERNS,
    requires_cdp_validation,
)
from bugtrace.core.validation_metrics import ValidationMetrics, validation_metrics


class TestValidationStatus:
    """Test ValidationStatus enum and helpers."""

    def test_validation_status_values(self):
        """EXPL-05/06: Verify status values exist."""
        assert ValidationStatus.VALIDATED_CONFIRMED.value == "VALIDATED_CONFIRMED"
        assert ValidationStatus.PENDING_VALIDATION.value == "PENDING_VALIDATION"
        assert ValidationStatus.FINDING_VALIDATED.value == "FINDING_VALIDATED"
        assert ValidationStatus.FINDING_REJECTED.value == "FINDING_REJECTED"

    def test_validation_error_status(self):
        """Verify VALIDATION_ERROR status exists."""
        assert ValidationStatus.VALIDATION_ERROR.value == "VALIDATION_ERROR"

    def test_edge_case_patterns_defined(self):
        """VAL-03: Edge case patterns for DOM XSS, event handlers, sinks."""
        assert "dom_based_xss" in EDGE_CASE_PATTERNS
        assert "complex_event_handlers" in EDGE_CASE_PATTERNS
        assert "sink_analysis" in EDGE_CASE_PATTERNS

        # Verify specific patterns
        assert "location.hash" in EDGE_CASE_PATTERNS["dom_based_xss"]
        assert "autofocus" in EDGE_CASE_PATTERNS["complex_event_handlers"]
        assert "innerHTML" in EDGE_CASE_PATTERNS["sink_analysis"]

    def test_edge_case_pattern_completeness(self):
        """Verify edge case patterns are comprehensive."""
        # DOM-based XSS sources
        dom_xss = EDGE_CASE_PATTERNS["dom_based_xss"]
        assert "document.URL" in dom_xss
        assert "document.referrer" in dom_xss
        assert "window.name" in dom_xss
        assert "postMessage" in dom_xss

        # Complex event handlers
        events = EDGE_CASE_PATTERNS["complex_event_handlers"]
        assert "onfocus" in events
        assert "onblur" in events
        assert "onanimationend" in events

        # Dangerous sinks
        sinks = EDGE_CASE_PATTERNS["sink_analysis"]
        assert "eval(" in sinks
        assert "document.write" in sinks
        assert "setTimeout(" in sinks


class TestRequiresCDPValidation:
    """Test edge case detection logic."""

    def test_dom_xss_requires_cdp(self):
        """DOM-based XSS should require CDP validation."""
        finding = {"context": "dom_xss", "payload": "location.hash"}
        assert requires_cdp_validation(finding) == True

    def test_document_url_requires_cdp(self):
        """document.URL source should require CDP validation."""
        finding = {"payload": "document.URL.substring(1)"}
        assert requires_cdp_validation(finding) == True

    def test_autofocus_requires_cdp(self):
        """Autofocus payload should require CDP validation."""
        finding = {"payload": "<input autofocus onfocus=alert(1)>"}
        assert requires_cdp_validation(finding) == True

    def test_eval_sink_requires_cdp(self):
        """Eval sink should require CDP validation."""
        finding = {"context": "script", "payload": "eval(user_input)"}
        assert requires_cdp_validation(finding) == True

    def test_innerhtml_sink_requires_cdp(self):
        """innerHTML sink should require CDP validation."""
        finding = {"payload": "elem.innerHTML = user_data"}
        assert requires_cdp_validation(finding) == True

    def test_interactsh_confirmed_skips_cdp(self):
        """Interactsh-confirmed findings should skip CDP."""
        finding = {
            "validation_method": "interactsh",
            "context": "reflected",
            "evidence": {"interactsh_hit": True},
        }
        assert requires_cdp_validation(finding) == False

    def test_dialog_detected_skips_cdp(self):
        """Dialog detection should skip CDP validation."""
        finding = {
            "context": "html_text",
            "evidence": {"dialog_detected": True},
        }
        assert requires_cdp_validation(finding) == False

    def test_dom_mutation_proof_skips_cdp(self):
        """DOM mutation proof should skip CDP validation."""
        finding = {
            "context": "reflected",
            "evidence": {"dom_mutation_proof": True},
        }
        assert requires_cdp_validation(finding) == False

    def test_console_execution_proof_skips_cdp(self):
        """Console execution proof should skip CDP validation."""
        finding = {
            "context": "reflected",
            "evidence": {"console_execution_proof": True},
        }
        assert requires_cdp_validation(finding) == False

    def test_simple_reflected_skips_cdp(self):
        """Simple reflected XSS with clear evidence skips CDP."""
        finding = {
            "context": "html_text",
            "validation_method": "vision",
            "evidence": {"dialog_detected": True},
        }
        assert requires_cdp_validation(finding) == False

    def test_fragment_xss_requires_cdp(self):
        """Fragment-based XSS should require CDP."""
        finding = {"vuln_type": "fragment_xss", "payload": "test"}
        assert requires_cdp_validation(finding) == True


class TestValidationMetrics:
    """Test ValidationMetrics tracking."""

    def setup_method(self):
        """Reset metrics before each test."""
        validation_metrics.reset()

    def test_record_finding_confirmed(self):
        """Record VALIDATED_CONFIRMED findings."""
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("sqli", "VALIDATED_CONFIRMED")

        summary = validation_metrics.get_summary()
        assert summary["total_findings"] == 2
        assert summary["validated_confirmed"] == 2
        assert summary["pending_validation"] == 0

    def test_record_finding_pending(self):
        """Record PENDING_VALIDATION findings."""
        validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()
        assert summary["pending_validation"] == 1

    def test_record_multiple_specialists(self):
        """Record findings from multiple specialists."""
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("sqli", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("csti", "PENDING_VALIDATION")
        validation_metrics.record_finding("lfi", "VALIDATED_CONFIRMED")

        summary = validation_metrics.get_summary()
        assert summary["total_findings"] == 4
        assert summary["validated_confirmed"] == 3
        assert summary["pending_validation"] == 1

    def test_cdp_load_calculation(self):
        """VAL-02: CDP load calculation."""
        # 99 confirmed, 1 pending = 1% CDP load
        for _ in range(99):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        assert validation_metrics.get_cdp_load() == 1.0
        assert validation_metrics.is_target_met() == True

    def test_cdp_load_zero_findings(self):
        """CDP load with zero findings should be 0%."""
        assert validation_metrics.get_cdp_load() == 0.0
        assert validation_metrics.is_target_met() == True

    def test_cdp_load_all_confirmed(self):
        """CDP load with all confirmed findings should be 0%."""
        for _ in range(100):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")

        assert validation_metrics.get_cdp_load() == 0.0
        assert validation_metrics.is_target_met() == True

    def test_cdp_load_target_exceeded(self):
        """CDP load exceeds 1% target."""
        # 90 confirmed, 10 pending = 10% CDP load
        for _ in range(90):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        for _ in range(10):
            validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        assert validation_metrics.get_cdp_load() == 10.0
        assert validation_metrics.is_target_met() == False

    def test_by_specialist_tracking(self):
        """Track metrics by specialist."""
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("sqli", "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()
        assert summary["by_specialist"]["confirmed"]["xss"] == 2
        assert summary["by_specialist"]["pending"]["sqli"] == 1

    def test_cdp_result_recording(self):
        """Test CDP validation result recording."""
        validation_metrics.record_cdp_result(validated=True)
        validation_metrics.record_cdp_result(validated=True)
        validation_metrics.record_cdp_result(validated=False)

        summary = validation_metrics.get_summary()
        assert summary["cdp_validated"] == 2
        assert summary["cdp_rejected"] == 1

    def test_reset_clears_all(self):
        """Reset should clear all metrics."""
        validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        validation_metrics.record_finding("sqli", "PENDING_VALIDATION")
        validation_metrics.record_cdp_result(validated=True)

        validation_metrics.reset()
        summary = validation_metrics.get_summary()

        assert summary["total_findings"] == 0
        assert summary["validated_confirmed"] == 0
        assert summary["pending_validation"] == 0
        assert summary["cdp_validated"] == 0
        assert summary["cdp_rejected"] == 0

    def test_summary_includes_target_percent(self):
        """Summary should include target percentage."""
        summary = validation_metrics.get_summary()
        assert "target_percent" in summary
        assert summary["target_percent"] == 1.0  # Default 1%

    def test_summary_includes_elapsed_time(self):
        """Summary should include elapsed time."""
        summary = validation_metrics.get_summary()
        assert "elapsed_seconds" in summary
        assert isinstance(summary["elapsed_seconds"], float)


class TestAgenticValidatorFiltering:
    """Test AgenticValidator PENDING_VALIDATION filtering."""

    @pytest.mark.asyncio
    async def test_handle_vulnerability_detected_filters_confirmed(self):
        """VAL-01: AgenticValidator skips VALIDATED_CONFIRMED."""
        from bugtrace.agents.agentic_validator import AgenticValidator

        av = AgenticValidator()
        av._pending_queue = asyncio.Queue()

        # Send VALIDATED_CONFIRMED - should be skipped
        await av.handle_vulnerability_detected({
            "specialist": "xss",
            "status": "VALIDATED_CONFIRMED",
            "finding": {"url": "http://test.com"},
        })

        # Queue should be empty
        assert av._pending_queue.empty()
        assert av._stats.get("skipped_confirmed", 0) == 1

    @pytest.mark.asyncio
    async def test_handle_vulnerability_detected_queues_pending(self):
        """VAL-01: AgenticValidator queues PENDING_VALIDATION."""
        from bugtrace.agents.agentic_validator import AgenticValidator

        av = AgenticValidator()
        av._pending_queue = asyncio.Queue()

        # Send PENDING_VALIDATION - should be queued
        await av.handle_vulnerability_detected({
            "specialist": "xss",
            "status": "PENDING_VALIDATION",
            "finding": {"url": "http://test.com"},
        })

        # Queue should have item
        assert not av._pending_queue.empty()
        assert av._stats.get("queued_for_cdp", 0) == 1

    @pytest.mark.asyncio
    async def test_handle_vulnerability_detected_tracks_total(self):
        """AgenticValidator tracks total received events."""
        from bugtrace.agents.agentic_validator import AgenticValidator

        av = AgenticValidator()
        av._pending_queue = asyncio.Queue()

        # Send multiple events
        await av.handle_vulnerability_detected({
            "specialist": "xss",
            "status": "VALIDATED_CONFIRMED",
            "finding": {"url": "http://test.com/1"},
        })
        await av.handle_vulnerability_detected({
            "specialist": "sqli",
            "status": "PENDING_VALIDATION",
            "finding": {"url": "http://test.com/2"},
        })

        assert av._stats.get("total_received", 0) == 2

    @pytest.mark.asyncio
    async def test_get_stats_includes_cdp_load(self):
        """AgenticValidator stats include CDP load percentage."""
        from bugtrace.agents.agentic_validator import AgenticValidator

        av = AgenticValidator()
        av._pending_queue = asyncio.Queue()

        # 9 confirmed, 1 pending = 10% load
        for i in range(9):
            await av.handle_vulnerability_detected({
                "specialist": "xss",
                "status": "VALIDATED_CONFIRMED",
                "finding": {"url": f"http://test.com/{i}"},
            })
        await av.handle_vulnerability_detected({
            "specialist": "xss",
            "status": "PENDING_VALIDATION",
            "finding": {"url": "http://test.com/pending"},
        })

        stats = av.get_stats()
        assert stats["cdp_load_percent"] == 10.0
        assert stats["cdp_target_met"] == False


class TestCDPLoadTarget:
    """Test <1% CDP load target is achievable."""

    def setup_method(self):
        """Reset metrics before each test."""
        validation_metrics.reset()

    def test_realistic_scan_distribution(self):
        """Simulate realistic scan with expected distribution."""
        # Simulate 1000 findings across specialists
        # Most XSS findings are definitive (Interactsh, dialog)
        for _ in range(400):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        for _ in range(4):  # ~1% edge cases (DOM XSS, autofocus)
            validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        # SQLi: error-based is definitive, time-based needs validation
        for _ in range(200):
            validation_metrics.record_finding("sqli", "VALIDATED_CONFIRMED")
        for _ in range(2):
            validation_metrics.record_finding("sqli", "PENDING_VALIDATION")

        # Other specialists: mostly definitive
        for _ in range(394):
            validation_metrics.record_finding("other", "VALIDATED_CONFIRMED")

        summary = validation_metrics.get_summary()
        print(f"\nRealistic scan simulation:")
        print(f"  Total: {summary['total_findings']}")
        print(f"  Confirmed: {summary['validated_confirmed']}")
        print(f"  Pending: {summary['pending_validation']}")
        print(f"  CDP Load: {summary['cdp_load_percent']}%")

        # Target: <1%
        assert summary["cdp_load_percent"] < 1.0
        assert summary["target_met"] == True

    def test_worst_case_still_low(self):
        """Even worst case should have reasonable CDP load."""
        # Assume 5% of findings are edge cases (pessimistic)
        for _ in range(950):
            validation_metrics.record_finding("xss", "VALIDATED_CONFIRMED")
        for _ in range(50):
            validation_metrics.record_finding("xss", "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()
        print(f"\nWorst case simulation:")
        print(f"  CDP Load: {summary['cdp_load_percent']}%")

        # Even 5% is acceptable for edge cases
        assert summary["cdp_load_percent"] == 5.0

    def test_all_edge_cases_scenario(self):
        """Scenario where all findings are edge cases (100% CDP)."""
        for _ in range(10):
            validation_metrics.record_finding("dom_xss", "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()
        assert summary["cdp_load_percent"] == 100.0
        assert summary["target_met"] == False

    def test_mixed_specialist_target(self):
        """Mixed specialists achieving target."""
        specialists = ["xss", "sqli", "csti", "lfi", "idor", "rce", "ssrf", "xxe", "jwt", "open_redirect", "prototype_pollution"]

        # Each specialist: 99% confirmed, 1% pending
        for specialist in specialists:
            for _ in range(99):
                validation_metrics.record_finding(specialist, "VALIDATED_CONFIRMED")
            validation_metrics.record_finding(specialist, "PENDING_VALIDATION")

        summary = validation_metrics.get_summary()
        total = 11 * 100  # 1100 findings

        assert summary["total_findings"] == total
        assert summary["cdp_load_percent"] == 1.0  # Exactly 1%
        assert summary["target_met"] == True  # 1% <= 1% target
