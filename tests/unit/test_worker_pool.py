"""
Unit tests for WorkerPool module.

Tests cover:
- Worker spawning and lifecycle
- Item processing and callbacks
- Graceful shutdown
- Queue draining
- Statistics tracking
- Dynamic scaling
- Error handling

Author: BugtraceAI Team
Date: 2026-01-29
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from bugtrace.agents.worker_pool import WorkerPool, Worker, WorkerConfig
from bugtrace.core.queue import SpecialistQueue


@pytest.fixture
def mock_queue():
    """Create a mock SpecialistQueue for testing."""
    queue = SpecialistQueue("test", max_depth=100, rate_limit=0)
    return queue


@pytest.fixture
def mock_process_func():
    """Create a mock async process function."""
    async def process(item):
        return {"processed": True, "item": item}
    return process


@pytest.fixture
def mock_process_func_slow():
    """Create a slow mock async process function."""
    async def process(item):
        await asyncio.sleep(0.1)
        return {"processed": True, "item": item}
    return process


@pytest.fixture
def mock_process_func_error():
    """Create a mock async process function that raises errors."""
    async def process(item):
        raise ValueError("Processing failed")
    return process


class TestWorkerPoolStartsWorkers:
    """Test that worker pool spawns the correct number of workers."""

    @pytest.mark.asyncio
    async def test_worker_pool_starts_workers(self, mock_queue, mock_process_func):
        """Verify pool spawns correct number of workers."""
        config = WorkerConfig(
            specialist="test",
            pool_size=3,
            process_func=mock_process_func,
        )
        pool = WorkerPool(config, queue=mock_queue)

        await pool.start()

        assert len(pool._workers) == 3
        assert all(w._running for w in pool._workers)

        await pool.stop()


class TestWorkerProcessesItem:
    """Test that workers correctly process queue items."""

    @pytest.mark.asyncio
    async def test_worker_processes_item(self, mock_queue, mock_process_func):
        """Single item dequeued and processed."""
        config = WorkerConfig(
            specialist="test",
            pool_size=1,
            process_func=mock_process_func,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue item before starting
        await mock_queue.enqueue({"test": "data"}, "scan_1")

        await pool.start()

        # Wait for processing
        await asyncio.sleep(0.2)

        # Check item was processed
        stats = pool.get_stats()
        assert stats["total_items_processed"] == 1

        await pool.stop()


class TestWorkerCallsCallback:
    """Test that on_result callback is invoked correctly."""

    @pytest.mark.asyncio
    async def test_worker_calls_callback(self, mock_queue, mock_process_func):
        """on_result callback invoked with item and result."""
        callback_results = []

        async def on_result(item, result):
            callback_results.append((item, result))

        config = WorkerConfig(
            specialist="test",
            pool_size=1,
            process_func=mock_process_func,
            on_result=on_result,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue item
        test_item = {"test": "data"}
        await mock_queue.enqueue(test_item, "scan_1")

        await pool.start()

        # Wait for processing
        await asyncio.sleep(0.2)

        # Verify callback was invoked
        assert len(callback_results) == 1
        item, result = callback_results[0]
        assert item == test_item
        assert result["processed"] is True

        await pool.stop()


class TestPoolGracefulShutdown:
    """Test graceful shutdown behavior."""

    @pytest.mark.asyncio
    async def test_pool_graceful_shutdown(self, mock_queue, mock_process_func_slow):
        """Workers stop cleanly when pool.stop() called."""
        config = WorkerConfig(
            specialist="test",
            pool_size=2,
            process_func=mock_process_func_slow,
            shutdown_timeout=5.0,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue items
        await mock_queue.enqueue({"id": 1}, "scan_1")
        await mock_queue.enqueue({"id": 2}, "scan_1")

        await pool.start()

        # Let workers start processing
        await asyncio.sleep(0.05)

        # Stop pool
        await pool.stop()

        # Verify workers stopped
        assert not pool._running
        assert all(not w._running for w in pool._workers)


class TestPoolDrainWaits:
    """Test drain() waits until queue is empty."""

    @pytest.mark.asyncio
    async def test_pool_drain_waits(self, mock_queue, mock_process_func):
        """drain() blocks until queue empty."""
        config = WorkerConfig(
            specialist="test",
            pool_size=2,
            process_func=mock_process_func,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue multiple items
        for i in range(5):
            await mock_queue.enqueue({"id": i}, "scan_1")

        await pool.start()

        # Drain should wait until all processed
        await pool.drain()

        # Queue should be empty
        assert mock_queue.depth() == 0

        await pool.stop()


class TestWorkerStatsTracking:
    """Test statistics tracking."""

    @pytest.mark.asyncio
    async def test_worker_stats_tracking(self, mock_queue, mock_process_func):
        """items_processed and errors counted correctly."""
        config = WorkerConfig(
            specialist="test",
            pool_size=1,
            process_func=mock_process_func,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue items
        for i in range(3):
            await mock_queue.enqueue({"id": i}, "scan_1")

        await pool.start()

        # Wait for processing
        await asyncio.sleep(0.3)

        # Check stats
        stats = pool.get_stats()
        assert stats["total_items_processed"] == 3
        assert stats["total_errors"] == 0

        await pool.stop()


class TestPoolScaleUp:
    """Test dynamic scaling up."""

    @pytest.mark.asyncio
    async def test_pool_scale_up(self, mock_queue, mock_process_func):
        """scale() adds workers when increasing size."""
        config = WorkerConfig(
            specialist="test",
            pool_size=2,
            process_func=mock_process_func,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        await pool.start()
        assert len(pool._workers) == 2

        # Scale up
        await pool.scale(5)

        assert len(pool._workers) == 5
        assert pool.config.pool_size == 5

        await pool.stop()


class TestPoolScaleDown:
    """Test dynamic scaling down."""

    @pytest.mark.asyncio
    async def test_pool_scale_down(self, mock_queue, mock_process_func):
        """scale() removes workers when decreasing size."""
        config = WorkerConfig(
            specialist="test",
            pool_size=5,
            process_func=mock_process_func,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        await pool.start()
        assert len(pool._workers) == 5

        # Scale down
        await pool.scale(2)

        assert len(pool._workers) == 2
        assert pool.config.pool_size == 2

        await pool.stop()


class TestWorkerHandlesException:
    """Test error handling in workers."""

    @pytest.mark.asyncio
    async def test_worker_handles_exception(self, mock_queue, mock_process_func_error):
        """Errors in process_func don't crash worker."""
        config = WorkerConfig(
            specialist="test",
            pool_size=1,
            process_func=mock_process_func_error,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue items
        for i in range(3):
            await mock_queue.enqueue({"id": i}, "scan_1")

        await pool.start()

        # Wait for processing attempts
        await asyncio.sleep(0.3)

        # Worker should still be running despite errors
        stats = pool.get_stats()
        assert stats["total_errors"] == 3
        assert pool._workers[0]._running is True

        await pool.stop()


class TestPoolGetStats:
    """Test aggregated statistics."""

    @pytest.mark.asyncio
    async def test_pool_get_stats(self, mock_queue, mock_process_func):
        """Aggregate stats from all workers."""
        config = WorkerConfig(
            specialist="test",
            pool_size=3,
            process_func=mock_process_func,
            dequeue_timeout=1.0,
        )
        pool = WorkerPool(config, queue=mock_queue)

        # Enqueue items
        for i in range(6):
            await mock_queue.enqueue({"id": i}, "scan_1")

        await pool.start()

        # Wait for processing
        await asyncio.sleep(0.5)

        # Get stats
        stats = pool.get_stats()

        assert stats["specialist"] == "test"
        assert stats["running"] is True
        assert stats["worker_count"] == 3
        assert stats["total_items_processed"] == 6
        assert stats["total_errors"] == 0
        assert "workers" in stats
        assert len(stats["workers"]) == 3

        await pool.stop()
