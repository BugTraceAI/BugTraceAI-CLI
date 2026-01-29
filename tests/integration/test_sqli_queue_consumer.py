"""
Integration tests for SQLiAgent queue consumer mode.
Tests EXPL-01 (queue consumption) and EXPL-03 (SQLi worker pool).
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from bugtrace.agents.sqli_agent import SQLiAgent, SQLiFinding
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import event_bus, EventType


@pytest.fixture
def sqli_agent():
    """Create SQLiAgent instance."""
    agent = SQLiAgent(url="http://testsite.local/api")
    yield agent


@pytest.fixture
def mock_queue():
    """Setup test queue with items."""
    queue_manager.reset()
    queue = queue_manager.get_queue("sqli")
    return queue


class TestSQLiQueueConsumer:
    """Tests for SQLiAgent queue consumption mode."""

    @pytest.mark.asyncio
    async def test_start_queue_consumer_creates_pool(self, sqli_agent):
        """Verify start_queue_consumer creates worker pool."""
        await sqli_agent.start_queue_consumer("test_scan")

        assert sqli_agent._queue_mode is True
        assert sqli_agent._worker_pool is not None

        await sqli_agent.stop_queue_consumer()

    @pytest.mark.asyncio
    async def test_queue_consumer_uses_sqli_pool_size(self, sqli_agent):
        """Verify pool uses WORKER_POOL_SQLI_SIZE setting."""
        with patch('bugtrace.agents.sqli_agent.settings') as mock_settings:
            mock_settings.WORKER_POOL_SQLI_SIZE = 5
            mock_settings.WORKER_POOL_SHUTDOWN_TIMEOUT = 30.0
            mock_settings.WORKER_POOL_DEQUEUE_TIMEOUT = 5.0
            mock_settings.WORKER_POOL_EMIT_EVENTS = True

            await sqli_agent.start_queue_consumer("test_scan")

            assert sqli_agent._worker_pool.config.pool_size == 5
            await sqli_agent.stop_queue_consumer()

    @pytest.mark.asyncio
    async def test_stop_queue_consumer_drains(self, sqli_agent):
        """Verify stop_queue_consumer stops pool gracefully."""
        await sqli_agent.start_queue_consumer("test_scan")
        assert sqli_agent._queue_mode is True

        await sqli_agent.stop_queue_consumer()

        assert sqli_agent._queue_mode is False
        assert sqli_agent._worker_pool is None

    @pytest.mark.asyncio
    async def test_emits_vulnerability_detected_on_confirm(self, sqli_agent):
        """Verify vulnerability_detected event emitted on confirmed SQLi."""
        events_received = []

        async def capture_event(data):
            events_received.append(data)

        event_bus.subscribe(EventType.VULNERABILITY_DETECTED.value, capture_event)

        # Create mock finding
        mock_finding = SQLiFinding(
            url="http://test.com/api",
            parameter="id",
            injection_type="error-based",
            technique="error_based",
            working_payload="' OR '1'='1",
            dbms_detected="MySQL",
            validated=True,
            status="VALIDATED_CONFIRMED"
        )

        sqli_agent._scan_context = "test_scan"
        await sqli_agent._handle_queue_result({}, mock_finding)

        # Wait for async event delivery
        await asyncio.sleep(0.1)

        assert len(events_received) == 1
        assert events_received[0]["specialist"] == "sqli"
        assert events_received[0]["status"] == "VALIDATED_CONFIRMED"
        assert events_received[0]["finding"]["technique"] == "error-based"

        event_bus.unsubscribe(EventType.VULNERABILITY_DETECTED.value, capture_event)

    @pytest.mark.asyncio
    async def test_get_queue_stats_returns_pool_stats(self, sqli_agent):
        """Verify get_queue_stats returns worker pool statistics."""
        await sqli_agent.start_queue_consumer("test_scan")

        stats = sqli_agent.get_queue_stats()

        assert stats["mode"] == "queue"
        assert stats["queue_mode"] is True
        assert "worker_stats" in stats

        await sqli_agent.stop_queue_consumer()

    @pytest.mark.asyncio
    async def test_direct_mode_still_works(self, sqli_agent):
        """Verify direct mode (run_loop) still works when not in queue mode."""
        assert sqli_agent._queue_mode is False

        stats = sqli_agent.get_queue_stats()
        assert stats["mode"] == "direct"

    @pytest.mark.asyncio
    async def test_process_queue_item_invalid_item(self, sqli_agent):
        """Verify invalid queue items are handled gracefully."""
        # Item without URL
        result = await sqli_agent._process_queue_item({"finding": {"parameter": "id"}})
        assert result is None

        # Item without parameter
        result = await sqli_agent._process_queue_item({"finding": {"url": "http://test.com"}})
        assert result is None

    @pytest.mark.asyncio
    async def test_prepared_statement_early_exit(self, sqli_agent):
        """Verify prepared statement detection causes early exit."""
        sqli_agent._stats["prepared_statement_exits"] = 0

        # Mock the detection to return True
        with patch.object(sqli_agent, '_detect_prepared_statements', new_callable=AsyncMock) as mock_detect:
            mock_detect.return_value = True
            with patch.object(sqli_agent, '_initialize_baseline', new_callable=AsyncMock):
                result = await sqli_agent._test_single_param_from_queue(
                    "http://test.com", "id", {"type": "SQLI"}
                )

        # Should return None (early exit)
        assert result is None
