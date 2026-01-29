"""
Integration tests for XSSAgent queue consumer mode.
Tests EXPL-01 (queue consumption) and EXPL-02 (worker pool).
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from bugtrace.agents.xss_agent import XSSAgent, XSSFinding
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import event_bus, EventType


@pytest.fixture
def xss_agent():
    """Create XSSAgent instance."""
    agent = XSSAgent(url="http://testsite.local/search")
    yield agent


@pytest.fixture
def mock_queue():
    """Setup test queue with items."""
    queue_manager.reset()
    queue = queue_manager.get_queue("xss")
    return queue


@pytest.fixture
async def populated_queue(mock_queue):
    """Queue with test items."""
    items = [
        {
            "finding": {
                "type": "XSS",
                "url": "http://testsite.local/search",
                "parameter": "q",
                "context": "html_body",
            },
            "priority": 85.0,
            "scan_context": "test_scan",
        },
        {
            "finding": {
                "type": "XSS",
                "url": "http://testsite.local/comment",
                "parameter": "text",
                "context": "html_attribute",
            },
            "priority": 72.0,
            "scan_context": "test_scan",
        },
    ]
    for item in items:
        await mock_queue.enqueue(item, "test_scan")
    return mock_queue


class TestXSSQueueConsumer:
    """Tests for XSSAgent queue consumption mode."""

    @pytest.mark.asyncio
    async def test_start_queue_consumer_creates_pool(self, xss_agent):
        """Verify start_queue_consumer creates worker pool."""
        await xss_agent.start_queue_consumer("test_scan")

        assert xss_agent._queue_mode is True
        assert xss_agent._worker_pool is not None

        await xss_agent.stop_queue_consumer()

    @pytest.mark.asyncio
    async def test_queue_consumer_uses_xss_pool_size(self, xss_agent):
        """Verify pool uses WORKER_POOL_XSS_SIZE setting."""
        with patch('bugtrace.agents.xss_agent.settings') as mock_settings:
            mock_settings.WORKER_POOL_XSS_SIZE = 8
            mock_settings.WORKER_POOL_SHUTDOWN_TIMEOUT = 30.0
            mock_settings.WORKER_POOL_DEQUEUE_TIMEOUT = 5.0
            mock_settings.WORKER_POOL_EMIT_EVENTS = True

            await xss_agent.start_queue_consumer("test_scan")

            assert xss_agent._worker_pool.config.pool_size == 8
            await xss_agent.stop_queue_consumer()

    @pytest.mark.asyncio
    async def test_stop_queue_consumer_drains(self, xss_agent):
        """Verify stop_queue_consumer stops pool gracefully."""
        await xss_agent.start_queue_consumer("test_scan")
        assert xss_agent._queue_mode is True

        await xss_agent.stop_queue_consumer()

        assert xss_agent._queue_mode is False
        assert xss_agent._worker_pool is None

    @pytest.mark.asyncio
    async def test_emits_vulnerability_detected_on_confirm(self, xss_agent):
        """Verify vulnerability_detected event emitted on confirmed XSS."""
        events_received = []

        async def capture_event(data):
            events_received.append(data)

        event_bus.subscribe(EventType.VULNERABILITY_DETECTED.value, capture_event)

        # Create mock finding
        mock_finding = XSSFinding(
            url="http://test.com",
            parameter="q",
            payload="<script>alert(1)</script>",
            context="html_body",
            validation_method="http_analysis",
            evidence={"http_confirmed": True},
            confidence=0.95,
            status="VALIDATED_CONFIRMED",
            validated=True
        )

        xss_agent._scan_context = "test_scan"
        await xss_agent._handle_queue_result({}, mock_finding)

        # Wait for async event delivery
        await asyncio.sleep(0.1)

        assert len(events_received) == 1
        assert events_received[0]["specialist"] == "xss"
        assert events_received[0]["status"] == "VALIDATED_CONFIRMED"
        assert events_received[0]["finding"]["type"] == "XSS"

        event_bus.unsubscribe(EventType.VULNERABILITY_DETECTED.value, capture_event)

    @pytest.mark.asyncio
    async def test_get_queue_stats_returns_pool_stats(self, xss_agent):
        """Verify get_queue_stats returns worker pool statistics."""
        await xss_agent.start_queue_consumer("test_scan")

        stats = xss_agent.get_queue_stats()

        assert stats["mode"] == "queue"
        assert stats["queue_mode"] is True
        assert "worker_stats" in stats

        await xss_agent.stop_queue_consumer()

    @pytest.mark.asyncio
    async def test_direct_mode_still_works(self, xss_agent):
        """Verify direct mode (run_loop) still works when not in queue mode."""
        # Don't start queue consumer
        assert xss_agent._queue_mode is False

        stats = xss_agent.get_queue_stats()
        assert stats["mode"] == "direct"

    @pytest.mark.asyncio
    async def test_process_queue_item_invalid_item(self, xss_agent):
        """Verify invalid queue items are handled gracefully."""
        # Item without URL
        result = await xss_agent._process_queue_item({"finding": {"parameter": "q"}})
        assert result is None

        # Item without parameter
        result = await xss_agent._process_queue_item({"finding": {"url": "http://test.com"}})
        assert result is None

    @pytest.mark.asyncio
    async def test_handle_queue_result_no_finding(self, xss_agent):
        """Verify None results don't add to findings."""
        initial_count = len(xss_agent.findings)
        await xss_agent._handle_queue_result({}, None)
        assert len(xss_agent.findings) == initial_count

    @pytest.mark.asyncio
    async def test_on_work_queued_handler(self, xss_agent):
        """Verify work queued notification handler executes."""
        # Should not raise
        await xss_agent._on_work_queued({
            "finding": {"url": "http://test.com", "parameter": "q"}
        })

    @pytest.mark.asyncio
    async def test_test_single_param_from_queue_dedupes_payloads(self, xss_agent):
        """Verify payload deduplication in queue testing."""
        with patch.object(xss_agent, '_test_payload_from_queue', new_callable=AsyncMock) as mock_test:
            mock_test.return_value = None

            # Finding with suggested payload that matches a golden payload
            finding = {
                "type": "XSS",
                "context": "html_body",
                "payload": xss_agent.GOLDEN_PAYLOADS[0].replace("{{interactsh_url}}", "test.oast.live"),
            }

            await xss_agent._test_single_param_from_queue(
                "http://test.com", "q", finding
            )

            # Payloads should be deduplicated
            call_count = mock_test.call_count
            assert call_count <= 10  # Max 10 unique payloads


@pytest.mark.asyncio
async def test_xss_queue_stats_tracking():
    """Verify queue stats are tracked during processing."""
    agent = XSSAgent(url="http://testsite.local/search")

    await agent.start_queue_consumer("test_scan")

    stats = agent.get_queue_stats()
    assert stats["findings_confirmed"] == 0

    # Add a finding manually
    finding = XSSFinding(
        url="http://test.com",
        parameter="q",
        payload="<script>alert(1)</script>",
        context="html_body",
        validation_method="http_analysis",
        evidence={},
        confidence=0.95,
        status="VALIDATED_CONFIRMED",
        validated=True
    )
    agent.findings.append(finding)

    stats = agent.get_queue_stats()
    assert stats["findings_confirmed"] == 1

    await agent.stop_queue_consumer()
