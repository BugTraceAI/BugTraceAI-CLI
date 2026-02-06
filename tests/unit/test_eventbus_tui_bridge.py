"""Test EventBus to TUI bridge in TeamOrchestrator."""
import asyncio
import pytest
from unittest.mock import Mock, patch, AsyncMock

from bugtrace.core.event_bus import event_bus, EventType


class TestEventBusTUIBridge:
    """Tests for VULNERABILITY_DETECTED -> TUI flow."""

    @pytest.fixture
    def mock_conductor(self):
        """Mock conductor with notify_finding."""
        # Patch at the source module (conductor.py) since team.py imports it locally
        with patch("bugtrace.core.conductor.conductor") as mock:
            mock.notify_finding = Mock()
            yield mock

    @pytest.fixture
    def orchestrator(self, mock_conductor, tmp_path):
        """Create TeamOrchestrator with mocked dependencies."""
        with patch("bugtrace.core.team.settings") as mock_settings:
            mock_settings.REPORT_DIR = tmp_path
            from bugtrace.core.team import TeamOrchestrator
            orch = TeamOrchestrator(
                target="https://example.com",
                resume=False,
                use_vertical_agents=False,
            )
            yield orch
            # Cleanup: unsubscribe the handler to prevent test pollution
            event_bus.unsubscribe(
                EventType.VULNERABILITY_DETECTED.value,
                orch._on_vulnerability_detected
            )

    @pytest.mark.asyncio
    async def test_finding_bridges_to_conductor(self, orchestrator, mock_conductor):
        """Verify VULNERABILITY_DETECTED events call conductor.notify_finding."""
        # Emit a finding via EventBus
        finding = {
            "type": "XSS",
            "details": "Reflected XSS in search param",
            "severity": "high",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "url": "https://example.com/search?q=test",
        }

        await event_bus.emit(EventType.VULNERABILITY_DETECTED, finding)

        # Allow async handlers to process
        await asyncio.sleep(0.1)

        # Verify conductor.notify_finding was called
        mock_conductor.notify_finding.assert_called_once()
        call_kwargs = mock_conductor.notify_finding.call_args

        # Check extracted fields
        assert call_kwargs[1]["finding_type"] == "XSS"
        assert call_kwargs[1]["severity"] == "high"
        assert call_kwargs[1]["param"] == "q"
        assert call_kwargs[1]["payload"] == "<script>alert(1)</script>"

    @pytest.mark.asyncio
    async def test_finding_with_alternate_keys(self, orchestrator, mock_conductor):
        """Verify handler works with alternate key names."""
        # Some specialists use "finding_type" instead of "type"
        finding = {
            "finding_type": "SQLi",
            "url": "https://example.com/api",
            "severity": "critical",
            "param": "id",  # Some use "param" instead of "parameter"
        }

        await event_bus.emit(EventType.VULNERABILITY_DETECTED, finding)
        await asyncio.sleep(0.1)

        mock_conductor.notify_finding.assert_called_once()
        call_kwargs = mock_conductor.notify_finding.call_args

        assert call_kwargs[1]["finding_type"] == "SQLi"
        assert call_kwargs[1]["details"] == "https://example.com/api"  # Falls back to url
