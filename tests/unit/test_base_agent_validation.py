"""
Tests for BaseAgent auto-validation functionality (Phase 1 Refactor).

Tests that specialists can self-validate findings before emitting them,
replacing Conductor's validation logic.
"""
import pytest
from unittest.mock import Mock, patch
from bugtrace.agents.base import BaseAgent


class TestAgent(BaseAgent):
    """Concrete test implementation of BaseAgent"""
    async def run_loop(self):
        pass


class TestBaseAgentValidation:
    """Test BaseAgent._validate_before_emit() and related methods"""

    def setup_method(self):
        """Create a test agent instance"""
        with patch('bugtrace.core.conductor.ConductorV2'):
            self.agent = TestAgent(name="TestAgent", role="test", event_bus=Mock())

    def test_validate_accepts_valid_finding(self):
        """Valid findings should pass validation"""
        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "parameter": "search",
            "payload": "<script>alert(1)</script>"
        }

        is_valid, error = self.agent._validate_before_emit(finding)

        assert is_valid is True
        assert error == ""

    def test_validate_rejects_missing_type(self):
        """Findings without type should be rejected"""
        finding = {
            "url": "https://example.com",
            "payload": "<script>alert(1)</script>"
        }

        is_valid, error = self.agent._validate_before_emit(finding)

        assert is_valid is False
        assert "type" in error.lower()

    def test_validate_rejects_missing_url(self):
        """Findings without URL should be rejected"""
        finding = {
            "type": "XSS",
            "payload": "<script>alert(1)</script>"
        }

        is_valid, error = self.agent._validate_before_emit(finding)

        assert is_valid is False
        assert "url" in error.lower()

    def test_validate_rejects_conversational_payload_navigate(self):
        """Payload starting with 'Navigate' should be rejected"""
        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "payload": "Navigate to: https://example.com?xss=<script>alert(1)</script>"
        }

        is_valid, error = self.agent._validate_before_emit(finding)

        assert is_valid is False
        assert "conversational" in error.lower()

    def test_validate_rejects_conversational_payload_try(self):
        """Payload starting with 'Try' should be rejected"""
        finding = {
            "type": "SQLi",
            "url": "https://example.com",
            "payload": "Try injecting: ' OR 1=1--"
        }

        is_valid, error = self.agent._validate_before_emit(finding)

        assert is_valid is False
        assert "conversational" in error.lower()

    def test_validate_rejects_conversational_payload_eg(self):
        """Payload with '(e.g.,' should be rejected"""
        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "payload": "Inject payload (e.g., <script>alert(1)</script>) into parameter"
        }

        is_valid, error = self.agent._validate_before_emit(finding)

        assert is_valid is False
        assert "conversational" in error.lower()


class TestConversationalDetection:
    """Test _is_conversational_payload() method"""

    def setup_method(self):
        with patch('bugtrace.core.conductor.ConductorV2'):
            self.agent = TestAgent(name="TestAgent", role="test", event_bus=Mock())

    def test_detects_navigate_prefix(self):
        """Should detect 'Navigate to' as conversational"""
        assert self.agent._is_conversational_payload("Navigate to https://example.com")

    def test_detects_try_prefix(self):
        """Should detect 'Try' as conversational"""
        assert self.agent._is_conversational_payload("Try this payload: <script>")

    def test_detects_inject_prefix(self):
        """Should detect 'Inject' as conversational"""
        assert self.agent._is_conversational_payload("Inject the following: ' OR 1=1")

    def test_detects_eg_marker(self):
        """Should detect '(e.g.,' as conversational"""
        assert self.agent._is_conversational_payload("Use payload (e.g., <script>alert(1)</script>)")

    def test_detects_to_verify_phrase(self):
        """Should detect 'to verify' as conversational"""
        assert self.agent._is_conversational_payload("Send payload to verify vulnerability")

    def test_accepts_technical_xss_payload(self):
        """Technical XSS payloads should NOT be flagged"""
        assert not self.agent._is_conversational_payload("<script>alert(1)</script>")
        assert not self.agent._is_conversational_payload("<img src=x onerror=alert(1)>")
        assert not self.agent._is_conversational_payload("';alert(1)//")

    def test_accepts_technical_sqli_payload(self):
        """Technical SQLi payloads should NOT be flagged"""
        assert not self.agent._is_conversational_payload("' OR 1=1--")
        assert not self.agent._is_conversational_payload("' UNION SELECT NULL,NULL--")
        assert not self.agent._is_conversational_payload("1' AND SLEEP(5)--")

    def test_accepts_technical_ssti_payload(self):
        """Technical SSTI payloads should NOT be flagged"""
        assert not self.agent._is_conversational_payload("{{7*7}}")
        assert not self.agent._is_conversational_payload("${7*7}")
        assert not self.agent._is_conversational_payload("{{config}}")

    def test_case_insensitive(self):
        """Detection should be case-insensitive"""
        assert self.agent._is_conversational_payload("NAVIGATE TO https://example.com")
        assert self.agent._is_conversational_payload("navigate to https://example.com")


class TestEmitFinding:
    """Test emit_finding() method"""

    def setup_method(self):
        with patch('bugtrace.core.conductor.ConductorV2'):
            self.mock_event_bus = Mock()
            self.agent = TestAgent(name="TestAgent", role="test", event_bus=self.mock_event_bus)

    def test_emits_valid_finding(self):
        """Valid findings should be emitted to event bus"""
        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "parameter": "search",
            "payload": "<script>alert(1)</script>"
        }

        result = self.agent.emit_finding(finding)

        assert result == finding
        self.mock_event_bus.emit.assert_called_once()

    def test_does_not_emit_invalid_finding(self):
        """Invalid findings should NOT be emitted"""
        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "payload": "Navigate to: https://example.com?xss=test"
        }

        result = self.agent.emit_finding(finding)

        assert result is None
        self.mock_event_bus.emit.assert_not_called()

    def test_does_not_emit_missing_type(self):
        """Findings without type should not be emitted"""
        finding = {
            "url": "https://example.com",
            "payload": "<script>alert(1)</script>"
        }

        result = self.agent.emit_finding(finding)

        assert result is None
        self.mock_event_bus.emit.assert_not_called()

    def test_handles_emit_exception_gracefully(self):
        """Should handle event bus exceptions gracefully"""
        self.mock_event_bus.emit.side_effect = Exception("Event bus error")

        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "payload": "<script>alert(1)</script>"
        }

        result = self.agent.emit_finding(finding)

        assert result is None


class TestSubclassValidation:
    """Test that subclasses can override _validate_before_emit()"""

    def test_subclass_can_add_custom_validation(self):
        """Subclasses should be able to add type-specific validation"""

        class XSSAgent(BaseAgent):
            """Test XSS agent with custom validation"""
            async def run_loop(self):
                pass

            def _validate_before_emit(self, finding):
                # Call parent validation first
                is_valid, error = super()._validate_before_emit(finding)
                if not is_valid:
                    return False, error

                # XSS-specific validation
                if not finding.get("evidence", {}).get("screenshot"):
                    return False, "XSS requires screenshot proof"

                return True, ""

        with patch('bugtrace.core.conductor.ConductorV2'):
            agent = XSSAgent(name="XSSAgent", role="exploit", event_bus=Mock())

        # Missing screenshot should fail
        finding = {
            "type": "XSS",
            "url": "https://example.com",
            "payload": "<script>alert(1)</script>",
            "evidence": {}
        }

        is_valid, error = agent._validate_before_emit(finding)
        assert is_valid is False
        assert "screenshot" in error.lower()

        # With screenshot should pass
        finding["evidence"]["screenshot"] = "/path/to/screenshot.png"
        is_valid, error = agent._validate_before_emit(finding)
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
