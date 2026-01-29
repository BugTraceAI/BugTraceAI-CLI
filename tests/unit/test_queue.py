"""
Unit tests for the queue system (Phase 16).

Tests:
- SpecialistQueue backpressure
- SpecialistQueue rate limiting
- QueueManager functionality
- QueueStats tracking

Author: BugtraceAI Team
Date: 2026-01-29
"""

import asyncio
import pytest
import time
from bugtrace.core.queue import (
    SpecialistQueue,
    QueueManager,
    queue_manager,
    QueueStats,
    QueueItem,
    SPECIALIST_QUEUES,
)


class TestSpecialistQueue:
    """Tests for SpecialistQueue class."""

    @pytest.fixture
    def queue(self):
        """Create a fresh queue for each test."""
        return SpecialistQueue("test_queue", max_depth=5, rate_limit=0)

    @pytest.mark.asyncio
    async def test_enqueue_dequeue_fifo(self, queue):
        """Test FIFO order is maintained."""
        for i in range(3):
            result = await queue.enqueue({"id": i}, "scan-001")
            assert result is True

        for i in range(3):
            item = await queue.dequeue()
            assert item["id"] == i

    @pytest.mark.asyncio
    async def test_backpressure_rejects_when_full(self, queue):
        """Test queue rejects items when at max_depth."""
        # Fill queue
        for i in range(5):
            result = await queue.enqueue({"id": i}, "scan-001")
            assert result is True

        # Next enqueue should fail
        result = await queue.enqueue({"id": 5}, "scan-001")
        assert result is False
        assert queue.is_full() is True

    @pytest.mark.asyncio
    async def test_backpressure_accepts_after_dequeue(self, queue):
        """Test queue accepts items after dequeue frees space."""
        # Fill queue
        for i in range(5):
            await queue.enqueue({"id": i}, "scan-001")

        # Dequeue one
        await queue.dequeue()
        assert queue.is_full() is False

        # Now enqueue should succeed
        result = await queue.enqueue({"id": 5}, "scan-001")
        assert result is True

    @pytest.mark.asyncio
    async def test_depth_tracking(self, queue):
        """Test depth() returns correct count."""
        assert queue.depth() == 0

        await queue.enqueue({"id": 1}, "scan-001")
        assert queue.depth() == 1

        await queue.enqueue({"id": 2}, "scan-001")
        assert queue.depth() == 2

        await queue.dequeue()
        assert queue.depth() == 1

    @pytest.mark.asyncio
    async def test_dequeue_timeout(self, queue):
        """Test dequeue returns None on timeout."""
        result = await queue.dequeue(timeout=0.1)
        assert result is None

    @pytest.mark.asyncio
    async def test_stats_tracking(self, queue):
        """Test statistics are tracked correctly."""
        # Enqueue items
        await queue.enqueue({"id": 1}, "scan-001")
        await queue.enqueue({"id": 2}, "scan-001")

        # Dequeue one
        await queue.dequeue()

        # Fill queue then try to enqueue (rejection)
        for i in range(4):
            await queue.enqueue({"id": i + 3}, "scan-001")
        await queue.enqueue({"id": 99}, "scan-001")  # Should be rejected

        stats = queue.get_stats()
        assert stats["total_enqueued"] == 6  # Only successful enqueues
        assert stats["total_dequeued"] == 1
        assert stats["total_rejected"] == 1
        assert stats["current_depth"] == 5


class TestSpecialistQueueRateLimiting:
    """Tests for rate limiting functionality."""

    @pytest.mark.asyncio
    async def test_rate_limiting_with_unlimited(self):
        """Test unlimited rate (rate_limit=0) allows immediate enqueue."""
        queue = SpecialistQueue("unlimited", max_depth=100, rate_limit=0)

        start = time.monotonic()
        for i in range(10):
            await queue.enqueue({"id": i}, "scan-001")
        elapsed = time.monotonic() - start

        # Should be nearly instant
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_rate_limiting_with_limit(self):
        """Test rate limiting enforces throughput limit."""
        # 10 items/second rate limit
        queue = SpecialistQueue("limited", max_depth=100, rate_limit=10)

        # First enqueue 10 items to drain the token bucket (starts with 10 tokens)
        for i in range(10):
            await queue.enqueue({"id": i}, "scan-001")

        # Now measure - should be rate limited
        start = time.monotonic()
        for i in range(5):
            await queue.enqueue({"id": i + 10}, "scan-001")
        elapsed = time.monotonic() - start

        # Should take at least ~0.4 seconds (5 items at 10/sec)
        # Adding tolerance for test environment
        assert elapsed >= 0.3


class TestQueueManager:
    """Tests for QueueManager class."""

    @pytest.fixture(autouse=True)
    def reset_manager(self):
        """Reset queue manager before each test."""
        queue_manager.reset()
        yield
        queue_manager.reset()

    @pytest.mark.asyncio
    async def test_get_queue_creates_new(self):
        """Test get_queue creates queue if not exists."""
        queue = queue_manager.get_queue("xss")
        assert queue.name == "xss"
        assert "xss" in queue_manager.list_queues()

    @pytest.mark.asyncio
    async def test_get_queue_returns_same_instance(self):
        """Test get_queue returns same instance for same name."""
        queue1 = queue_manager.get_queue("sqli")
        queue2 = queue_manager.get_queue("sqli")
        assert queue1 is queue2

    @pytest.mark.asyncio
    async def test_list_queues(self):
        """Test list_queues returns all queue names."""
        queue_manager.get_queue("xss")
        queue_manager.get_queue("sqli")
        queue_manager.get_queue("csti")

        queues = queue_manager.list_queues()
        assert "xss" in queues
        assert "sqli" in queues
        assert "csti" in queues

    @pytest.mark.asyncio
    async def test_reset_clears_all_queues(self):
        """Test reset clears all queues."""
        queue_manager.get_queue("xss")
        queue_manager.get_queue("sqli")
        assert len(queue_manager.list_queues()) == 2

        queue_manager.reset()
        assert len(queue_manager.list_queues()) == 0

    @pytest.mark.asyncio
    async def test_aggregate_stats(self):
        """Test get_aggregate_stats returns totals."""
        xss_q = queue_manager.get_queue("xss")
        sqli_q = queue_manager.get_queue("sqli")

        await xss_q.enqueue({"id": 1}, "scan-001")
        await xss_q.enqueue({"id": 2}, "scan-001")
        await sqli_q.enqueue({"id": 3}, "scan-001")
        await xss_q.dequeue()

        stats = queue_manager.get_aggregate_stats()
        assert stats["total_queues"] == 2
        assert stats["total_enqueued"] == 3
        assert stats["total_dequeued"] == 1
        assert stats["total_depth"] == 2


class TestQueueStats:
    """Tests for QueueStats class."""

    def test_record_enqueue(self):
        """Test enqueue recording."""
        stats = QueueStats()
        stats.record_enqueue()
        stats.record_enqueue()

        assert stats.total_enqueued == 2

    def test_record_dequeue_with_latency(self):
        """Test dequeue records latency."""
        stats = QueueStats()
        enqueued_at = time.monotonic() - 0.1  # 100ms ago

        stats.record_dequeue(enqueued_at)

        assert stats.total_dequeued == 1
        assert stats.avg_latency >= 0.09  # At least 90ms

    def test_record_rejected(self):
        """Test rejection recording."""
        stats = QueueStats()
        stats.record_rejected()
        stats.record_rejected()

        assert stats.total_rejected == 2

    def test_to_dict(self):
        """Test stats export to dict."""
        stats = QueueStats()
        stats.record_enqueue()
        stats.record_dequeue(time.monotonic() - 0.05)

        result = stats.to_dict()
        assert "total_enqueued" in result
        assert "total_dequeued" in result
        assert "avg_latency_ms" in result
        assert result["total_enqueued"] == 1
        assert result["total_dequeued"] == 1

    def test_reset(self):
        """Test stats reset."""
        stats = QueueStats()
        stats.record_enqueue()
        stats.record_rejected()

        stats.reset()

        assert stats.total_enqueued == 0
        assert stats.total_rejected == 0


class TestSpecialistQueuesConstant:
    """Tests for SPECIALIST_QUEUES constant."""

    def test_contains_expected_specialists(self):
        """Test SPECIALIST_QUEUES contains all expected specialists."""
        expected = ["xss", "sqli", "csti", "lfi", "idor", "rce", "ssrf", "xxe", "jwt"]
        for specialist in expected:
            assert specialist in SPECIALIST_QUEUES

    def test_no_duplicates(self):
        """Test SPECIALIST_QUEUES has no duplicates."""
        assert len(SPECIALIST_QUEUES) == len(set(SPECIALIST_QUEUES))
