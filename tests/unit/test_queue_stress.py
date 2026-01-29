"""
Stress tests for the queue system (Phase 25 - TEST-04).

Tests:
- High-volume concurrent enqueue operations
- Backpressure under flood conditions
- Rate limiting under load
- Statistics accuracy under concurrent updates
- Multiple queues working in parallel

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
    SPECIALIST_QUEUES,
)


class TestQueueStress:
    """Stress tests for concurrent queue operations."""

    @pytest.mark.asyncio
    async def test_concurrent_enqueue_100_items(self):
        """Test 100 concurrent enqueue operations."""
        queue = SpecialistQueue("stress_100", max_depth=50, rate_limit=0)

        async def enqueue_one(i):
            return await queue.enqueue({"id": i}, "stress_test")

        results = await asyncio.gather(*[enqueue_one(i) for i in range(100)])

        accepted = sum(1 for r in results if r is True)
        rejected = sum(1 for r in results if r is False)

        assert accepted + rejected == 100
        assert accepted <= 50  # max_depth
        assert queue.depth() <= 50
        assert rejected >= 50  # At least 50 should be rejected

    @pytest.mark.asyncio
    async def test_concurrent_enqueue_1000_items(self):
        """Test 1000 concurrent enqueue operations for higher volume."""
        queue = SpecialistQueue("stress_1000", max_depth=200, rate_limit=0)

        async def enqueue_one(i):
            return await queue.enqueue({"id": i}, "stress_test")

        start = time.monotonic()
        results = await asyncio.gather(*[enqueue_one(i) for i in range(1000)])
        elapsed = time.monotonic() - start

        accepted = sum(1 for r in results if r is True)
        rejected = sum(1 for r in results if r is False)

        assert accepted + rejected == 1000
        assert accepted <= 200  # max_depth
        assert rejected >= 800  # At least 800 should be rejected
        assert queue.depth() <= 200
        # Should complete reasonably fast (< 5 seconds for 1000 operations)
        assert elapsed < 5.0, f"Took too long: {elapsed}s"

    @pytest.mark.asyncio
    async def test_producer_consumer_balance(self):
        """Test multiple producers and consumers working together."""
        queue = SpecialistQueue("balance", max_depth=100, rate_limit=0)
        produced = 0
        consumed = 0
        stop_event = asyncio.Event()

        async def producer(producer_id):
            nonlocal produced
            for i in range(100):
                if stop_event.is_set():
                    break
                result = await queue.enqueue({"producer": producer_id, "item": i}, "stress_test")
                if result:
                    produced += 1
                await asyncio.sleep(0.001)  # Small delay to simulate work

        async def consumer(consumer_id):
            nonlocal consumed
            while not stop_event.is_set():
                item = await queue.dequeue(timeout=0.1)
                if item is not None:
                    consumed += 1

        # Start 5 producers and 3 consumers
        producers = [asyncio.create_task(producer(i)) for i in range(5)]
        consumers = [asyncio.create_task(consumer(i)) for i in range(3)]

        # Run for 5 seconds
        await asyncio.sleep(5)
        stop_event.set()

        # Wait for producers to finish
        await asyncio.gather(*producers, return_exceptions=True)

        # Give consumers a moment to finish draining
        await asyncio.sleep(0.5)

        # Cancel consumers
        for c in consumers:
            c.cancel()
        await asyncio.gather(*consumers, return_exceptions=True)

        # Verify no deadlock - all producers completed
        assert produced > 0, "No items produced"
        assert consumed > 0, "No items consumed"
        # Consumed + remaining should approximately equal produced
        assert consumed + queue.depth() <= produced + 10  # Allow small tolerance

    @pytest.mark.asyncio
    async def test_queue_throughput_measurement(self):
        """Measure sustained queue throughput."""
        # Use very large max_depth to avoid backpressure during measurement
        queue = SpecialistQueue("throughput", max_depth=100000, rate_limit=0)

        # Measure enqueue throughput over 2 seconds
        start = time.monotonic()
        count = 0
        success_count = 0
        while time.monotonic() - start < 2.0:
            result = await queue.enqueue({"id": count}, "throughput_test")
            count += 1
            if result:
                success_count += 1
        elapsed = time.monotonic() - start

        throughput = success_count / elapsed

        # Log throughput for baseline (should be > 1000/sec for in-memory queue)
        assert throughput > 100, f"Throughput too low: {throughput:.2f}/sec"
        # Verify all successful enqueues are in queue
        assert queue.depth() == success_count


class TestBackpressureStress:
    """Stress tests for backpressure handling."""

    @pytest.mark.asyncio
    async def test_backpressure_under_flood(self):
        """Test queue correctly rejects when flooded with 10x capacity."""
        max_depth = 100
        queue = SpecialistQueue("flood", max_depth=max_depth, rate_limit=0)

        async def enqueue_one(i):
            return await queue.enqueue({"id": i}, "flood_test")

        # Flood with 10x max_depth
        results = await asyncio.gather(*[enqueue_one(i) for i in range(1000)])

        accepted = sum(1 for r in results if r is True)
        rejected = sum(1 for r in results if r is False)

        # Exactly max_depth should be accepted
        assert accepted == max_depth, f"Expected {max_depth} accepted, got {accepted}"
        # Rest should be rejected
        assert rejected == 1000 - max_depth
        assert queue.depth() == max_depth

    @pytest.mark.asyncio
    async def test_backpressure_recovery(self):
        """Test queue recovers after draining - fill, drain half, refill cycles."""
        queue = SpecialistQueue("recovery", max_depth=50, rate_limit=0)

        for cycle in range(3):
            # Fill to max_depth
            for i in range(50):
                result = await queue.enqueue({"cycle": cycle, "id": i}, "recovery_test")
                assert result is True, f"Cycle {cycle}: Failed to fill queue at item {i}"

            # Verify full
            assert queue.is_full()

            # Dequeue half
            for _ in range(25):
                item = await queue.dequeue()
                assert item is not None

            # Verify not full
            assert not queue.is_full()
            assert queue.depth() == 25

            # Refill should succeed
            for i in range(25):
                result = await queue.enqueue({"cycle": cycle, "refill": i}, "recovery_test")
                assert result is True, f"Cycle {cycle}: Failed to refill at item {i}"

            # Drain completely for next cycle
            while queue.depth() > 0:
                await queue.dequeue()

    @pytest.mark.asyncio
    async def test_backpressure_concurrent_rejection(self):
        """Test concurrent enqueues to full queue all reject immediately."""
        queue = SpecialistQueue("concurrent_reject", max_depth=50, rate_limit=0)

        # Fill queue to max
        for i in range(50):
            await queue.enqueue({"id": i}, "fill_test")

        assert queue.is_full()

        # 50 concurrent enqueue attempts to full queue
        async def try_enqueue(i):
            start = time.monotonic()
            result = await queue.enqueue({"id": i + 50}, "reject_test")
            elapsed = time.monotonic() - start
            return result, elapsed

        results = await asyncio.gather(*[try_enqueue(i) for i in range(50)])

        # All should be rejected
        for result, elapsed in results:
            assert result is False, "Expected rejection for full queue"
            # Should be immediate (< 100ms) - no blocking
            assert elapsed < 0.1, f"Rejection took too long: {elapsed}s"


class TestBurstTraffic:
    """Tests for burst traffic patterns."""

    @pytest.mark.asyncio
    async def test_burst_pattern(self):
        """Test queue handles burst traffic correctly."""
        queue = SpecialistQueue("burst", max_depth=200, rate_limit=0)

        # Burst 1: 50 items in ~100ms
        start = time.monotonic()
        for i in range(50):
            await queue.enqueue({"burst": 1, "id": i}, "burst_test")
        burst1_time = time.monotonic() - start
        burst1_depth = queue.depth()

        # Pause 500ms (simulate traffic lull)
        await asyncio.sleep(0.5)

        # Burst 2: 50 items in ~100ms
        start = time.monotonic()
        for i in range(50):
            await queue.enqueue({"burst": 2, "id": i}, "burst_test")
        burst2_time = time.monotonic() - start

        # Verify bursts completed quickly
        assert burst1_time < 0.5, f"Burst 1 too slow: {burst1_time}s"
        assert burst2_time < 0.5, f"Burst 2 too slow: {burst2_time}s"
        assert burst1_depth == 50
        assert queue.depth() == 100  # Both bursts in queue

    @pytest.mark.asyncio
    async def test_sustained_load_with_bursts(self):
        """Test background load with periodic bursts for 10 seconds."""
        queue = SpecialistQueue("sustained", max_depth=500, rate_limit=0)
        stop_event = asyncio.Event()
        background_count = 0
        burst_count = 0

        async def background_producer():
            """Produce 10 items/sec continuously."""
            nonlocal background_count
            while not stop_event.is_set():
                await queue.enqueue({"type": "background", "id": background_count}, "sustained_test")
                background_count += 1
                await asyncio.sleep(0.1)  # 10/sec

        async def burst_producer():
            """Produce 100 items every 2 seconds."""
            nonlocal burst_count
            while not stop_event.is_set():
                for i in range(100):
                    if stop_event.is_set():
                        break
                    await queue.enqueue({"type": "burst", "id": burst_count}, "sustained_test")
                    burst_count += 1
                await asyncio.sleep(2)

        async def consumer():
            """Consume items to prevent queue overflow."""
            while not stop_event.is_set():
                await queue.dequeue(timeout=0.1)

        # Start all tasks
        bg_task = asyncio.create_task(background_producer())
        burst_task = asyncio.create_task(burst_producer())
        consumer_tasks = [asyncio.create_task(consumer()) for _ in range(3)]

        # Run for 10 seconds
        await asyncio.sleep(10)
        stop_event.set()

        # Wait for cleanup
        await asyncio.sleep(0.5)
        bg_task.cancel()
        burst_task.cancel()
        for t in consumer_tasks:
            t.cancel()

        await asyncio.gather(bg_task, burst_task, *consumer_tasks, return_exceptions=True)

        # Verify stability - we produced items and queue didn't overflow
        assert background_count > 50, f"Background too slow: {background_count}"
        assert burst_count > 200, f"Burst too slow: {burst_count}"
        # Queue should not have overflowed (max_depth=500)
        stats = queue.get_stats()
        assert stats["total_rejected"] == 0, f"Queue overflowed: {stats['total_rejected']} rejected"


class TestRateLimitStress:
    """Stress tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_enforced_under_load(self):
        """Test rate limiting enforced under high-volume enqueues."""
        # Queue with rate_limit=50 (50 items/sec)
        queue = SpecialistQueue("rate_stress", max_depth=500, rate_limit=50)

        # Drain the initial burst capacity (token bucket starts full)
        for i in range(50):
            await queue.enqueue({"drain": i}, "rate_test")

        # Now measure - should be rate limited
        start = time.monotonic()
        for i in range(100):
            await queue.enqueue({"id": i}, "rate_test")
        elapsed = time.monotonic() - start

        # 100 items at 50/sec should take ~2 seconds
        # Allow 20% tolerance for CI environments
        expected = 2.0
        assert elapsed >= expected * 0.8, f"Expected >= {expected * 0.8}s, got {elapsed}s"

    @pytest.mark.asyncio
    async def test_rate_limit_burst_allowance(self):
        """Test burst tokens work correctly (initial tokens allow fast start)."""
        queue = SpecialistQueue("burst_tokens", max_depth=100, rate_limit=20)

        # Fresh queue has burst capacity (tokens = rate_limit)
        start = time.monotonic()
        # First 20 items should be fast (use up initial tokens)
        for i in range(20):
            await queue.enqueue({"id": i}, "burst_test")
        initial_elapsed = time.monotonic() - start

        # Should be nearly instant (< 0.5s for 20 items using tokens)
        assert initial_elapsed < 0.5, f"Initial burst too slow: {initial_elapsed}s"

        # Subsequent items should be rate-limited
        start = time.monotonic()
        for i in range(20):
            await queue.enqueue({"id": i + 20}, "burst_test")
        limited_elapsed = time.monotonic() - start

        # Should take ~1 second (20 items at 20/sec)
        # Allow tolerance for CI
        assert limited_elapsed >= 0.8, f"Rate limiting not enforced: {limited_elapsed}s"

    @pytest.mark.asyncio
    async def test_rate_limit_recovery(self):
        """Test rate limit tokens regenerate after idle."""
        queue = SpecialistQueue("rate_recovery", max_depth=100, rate_limit=10)

        # Drain tokens by enqueuing 10 items quickly
        for i in range(10):
            await queue.enqueue({"drain": i}, "recovery_test")

        # Verify tokens are low by checking next enqueue is slow
        start = time.monotonic()
        await queue.enqueue({"slow": 1}, "recovery_test")
        slow_time = time.monotonic() - start

        # Should have waited for token regeneration
        assert slow_time >= 0.05, f"Expected rate limiting, got {slow_time}s"

        # Wait 1 second for tokens to regenerate
        await asyncio.sleep(1.0)

        # Now some items should be fast again
        start = time.monotonic()
        for i in range(5):  # Less than full token bucket
            await queue.enqueue({"fast": i}, "recovery_test")
        fast_time = time.monotonic() - start

        # Should be faster now that tokens regenerated
        assert fast_time < 0.5, f"Tokens didn't regenerate: {fast_time}s"


class TestStatisticsStress:
    """Stress tests for statistics accuracy."""

    @pytest.mark.asyncio
    async def test_stats_accuracy_under_load(self):
        """Test statistics match actual operations under load."""
        queue = SpecialistQueue("stats_load", max_depth=500, rate_limit=0)

        enqueue_count = 0
        dequeue_count = 0

        # Perform 500 enqueues
        for i in range(500):
            result = await queue.enqueue({"id": i}, "stats_test")
            if result:
                enqueue_count += 1

        # Perform 200 dequeues
        for _ in range(200):
            item = await queue.dequeue(timeout=0.01)
            if item is not None:
                dequeue_count += 1

        # Try 100 more enqueues (some may be rejected if queue full)
        rejected_count = 0
        for i in range(100):
            result = await queue.enqueue({"extra": i}, "stats_test")
            if not result:
                rejected_count += 1
            else:
                enqueue_count += 1

        stats = queue.get_stats()

        assert stats["total_enqueued"] == enqueue_count, \
            f"Enqueue mismatch: stats={stats['total_enqueued']}, actual={enqueue_count}"
        assert stats["total_dequeued"] == dequeue_count, \
            f"Dequeue mismatch: stats={stats['total_dequeued']}, actual={dequeue_count}"
        assert stats["total_rejected"] == rejected_count, \
            f"Rejected mismatch: stats={stats['total_rejected']}, actual={rejected_count}"

    @pytest.mark.asyncio
    async def test_stats_concurrent_updates(self):
        """Test stats handle concurrent updates correctly."""
        queue = SpecialistQueue("stats_concurrent", max_depth=1000, rate_limit=0)

        async def producer(count):
            for i in range(count):
                await queue.enqueue({"id": i}, "concurrent_test")

        async def consumer(count):
            consumed = 0
            for _ in range(count):
                item = await queue.dequeue(timeout=0.5)
                if item:
                    consumed += 1
            return consumed

        # Concurrent producers
        await asyncio.gather(*[producer(100) for _ in range(5)])

        # Verify enqueue count
        stats = queue.get_stats()
        assert stats["total_enqueued"] == 500

        # Concurrent consumers
        consumed_counts = await asyncio.gather(*[consumer(200) for _ in range(3)])
        total_consumed = sum(consumed_counts)

        stats = queue.get_stats()
        assert stats["total_dequeued"] == total_consumed
        assert stats["current_depth"] == 500 - total_consumed

    @pytest.mark.asyncio
    async def test_stats_latency_calculation(self):
        """Test latency tracked correctly under load."""
        queue = SpecialistQueue("stats_latency", max_depth=100, rate_limit=0)

        # Enqueue items with known delays
        for i in range(50):
            await queue.enqueue({"id": i}, "latency_test")
            await asyncio.sleep(0.01)  # 10ms delay between enqueues

        # Wait 100ms before dequeueing
        await asyncio.sleep(0.1)

        # Dequeue all
        for _ in range(50):
            await queue.dequeue(timeout=0.1)

        stats = queue.get_stats()

        # Average latency should be >= 100ms (the wait time)
        # Items enqueued first waited longer
        assert stats["avg_latency_ms"] >= 50, f"Latency too low: {stats['avg_latency_ms']}ms"
        assert stats["max_latency_ms"] >= stats["avg_latency_ms"], "Max should be >= avg"


class TestQueueManagerStress:
    """Stress tests for QueueManager with multiple queues."""

    @pytest.fixture(autouse=True)
    def reset_manager(self):
        """Reset queue manager before each test."""
        queue_manager.reset()
        yield
        queue_manager.reset()

    @pytest.mark.asyncio
    async def test_multiple_queues_concurrent(self):
        """Test multiple queues used concurrently without interference."""
        # Create queues for all specialist types
        specialists = ["xss", "sqli", "csti", "lfi", "idor", "rce",
                       "ssrf", "xxe", "jwt", "openredirect", "prototype_pollution"]

        async def use_queue(specialist):
            queue = queue_manager.get_queue(specialist)
            # Enqueue 50 items
            for i in range(50):
                await queue.enqueue({"specialist": specialist, "id": i}, "multi_test")
            # Dequeue 25 items
            for _ in range(25):
                await queue.dequeue(timeout=0.1)
            return specialist, queue.depth()

        results = await asyncio.gather(*[use_queue(s) for s in specialists])

        # Verify each queue has correct depth (50 enqueued - 25 dequeued = 25)
        for specialist, depth in results:
            assert depth == 25, f"Queue {specialist} has wrong depth: {depth}"

        # Verify no cross-queue interference - each queue has its own stats
        for specialist in specialists:
            stats = queue_manager.get_queue(specialist).get_stats()
            assert stats["total_enqueued"] == 50, f"{specialist} wrong enqueue count"
            assert stats["total_dequeued"] == 25, f"{specialist} wrong dequeue count"

    @pytest.mark.asyncio
    async def test_aggregate_stats_accuracy(self):
        """Test aggregate stats correct under load with multiple queues."""
        specialists = ["xss", "sqli", "csti", "lfi"]

        # Different operations on different queues
        xss_q = queue_manager.get_queue("xss")
        sqli_q = queue_manager.get_queue("sqli")
        csti_q = queue_manager.get_queue("csti")
        lfi_q = queue_manager.get_queue("lfi")

        # Enqueue different amounts
        for i in range(100):
            await xss_q.enqueue({"id": i}, "agg_test")
        for i in range(75):
            await sqli_q.enqueue({"id": i}, "agg_test")
        for i in range(50):
            await csti_q.enqueue({"id": i}, "agg_test")
        for i in range(25):
            await lfi_q.enqueue({"id": i}, "agg_test")

        # Dequeue some
        for _ in range(30):
            await xss_q.dequeue(timeout=0.01)
        for _ in range(25):
            await sqli_q.dequeue(timeout=0.01)

        agg = queue_manager.get_aggregate_stats()

        assert agg["total_queues"] == 4
        assert agg["total_enqueued"] == 100 + 75 + 50 + 25  # 250
        assert agg["total_dequeued"] == 30 + 25  # 55
        assert agg["total_depth"] == (100 - 30) + (75 - 25) + 50 + 25  # 195
        assert agg["total_rejected"] == 0  # No rejections
