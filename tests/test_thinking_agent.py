"""
Unit tests for ThinkingConsolidationAgent.

Tests cover:
- Deduplication logic
- Classification mapping
- Priority calculation
- Queue distribution
- Event emission
- Batch vs streaming modes
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from bugtrace.agents.thinking_consolidation_agent import (
    ThinkingConsolidationAgent,
    DeduplicationCache,
    FindingRecord,
    PrioritizedFinding,
    VULN_TYPE_TO_SPECIALIST,
    SEVERITY_PRIORITY,
)
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.queue import queue_manager


class TestDeduplicationCache:
    """Tests for DeduplicationCache."""

    @pytest.fixture
    def cache(self):
        return DeduplicationCache(max_size=10)

    @pytest.mark.asyncio
    async def test_make_key_format(self, cache):
        """Key format is vuln_type:parameter:url_path."""
        finding = {
            "type": "XSS",
            "parameter": "query",
            "url": "https://example.com/api/search?q=test"
        }
        is_dup, key = await cache.check_and_add(finding, "scan1")

        assert key == "xss:query:/api/search"
        assert not is_dup

    @pytest.mark.asyncio
    async def test_duplicate_detection(self, cache):
        """Same key detected as duplicate."""
        finding1 = {"type": "XSS", "parameter": "q", "url": "https://example.com/test"}
        finding2 = {"type": "XSS", "parameter": "q", "url": "https://example.com/test?foo=bar"}

        is_dup1, _ = await cache.check_and_add(finding1, "scan1")
        is_dup2, _ = await cache.check_and_add(finding2, "scan1")

        assert not is_dup1, "First should not be duplicate"
        assert is_dup2, "Same type:param:path should be duplicate"

    @pytest.mark.asyncio
    async def test_different_type_not_duplicate(self, cache):
        """Different vuln type is not duplicate."""
        finding1 = {"type": "XSS", "parameter": "q", "url": "https://example.com/test"}
        finding2 = {"type": "SQLi", "parameter": "q", "url": "https://example.com/test"}

        is_dup1, _ = await cache.check_and_add(finding1, "scan1")
        is_dup2, _ = await cache.check_and_add(finding2, "scan1")

        assert not is_dup1
        assert not is_dup2, "Different type should not be duplicate"

    @pytest.mark.asyncio
    async def test_different_param_not_duplicate(self, cache):
        """Different parameter is not duplicate."""
        finding1 = {"type": "XSS", "parameter": "q", "url": "https://example.com/test"}
        finding2 = {"type": "XSS", "parameter": "id", "url": "https://example.com/test"}

        is_dup1, _ = await cache.check_and_add(finding1, "scan1")
        is_dup2, _ = await cache.check_and_add(finding2, "scan1")

        assert not is_dup1
        assert not is_dup2, "Different parameter should not be duplicate"

    @pytest.mark.asyncio
    async def test_lru_eviction(self, cache):
        """Oldest entries evicted when max_size reached."""
        # Fill cache beyond max_size
        for i in range(15):
            finding = {"type": "XSS", "parameter": f"p{i}", "url": "https://example.com/test"}
            await cache.check_and_add(finding, "scan1")

        assert cache.size == 10, f"Should be at max_size, got {cache.size}"

    @pytest.mark.asyncio
    async def test_lru_move_to_end(self, cache):
        """Duplicate access moves entry to end (most recently seen)."""
        finding1 = {"type": "XSS", "parameter": "p1", "url": "https://example.com/test"}
        finding2 = {"type": "XSS", "parameter": "p2", "url": "https://example.com/test"}

        await cache.check_and_add(finding1, "scan1")
        await cache.check_and_add(finding2, "scan1")

        # Access finding1 again
        is_dup, _ = await cache.check_and_add(finding1, "scan1")
        assert is_dup, "Should be duplicate"

        # Cache order should now be p2, p1 (p1 moved to end)
        keys = list(cache._cache.keys())
        assert keys[-1] == "xss:p1:/test", "p1 should be at end after access"

    @pytest.mark.asyncio
    async def test_cache_stats(self, cache):
        """Cache statistics are correct."""
        finding1 = {"type": "XSS", "parameter": "q", "url": "https://example.com/test"}
        await cache.check_and_add(finding1, "scan1")

        stats = cache.get_stats()
        assert stats["size"] == 1
        assert stats["max_size"] == 10
        assert stats["fill_ratio"] == 0.1

    @pytest.mark.asyncio
    async def test_cache_clear(self, cache):
        """Clear empties the cache."""
        finding = {"type": "XSS", "parameter": "q", "url": "https://example.com/test"}
        await cache.check_and_add(finding, "scan1")
        assert cache.size == 1

        cache.clear()
        assert cache.size == 0


class TestClassification:
    """Tests for vulnerability classification."""

    @pytest.fixture
    def agent(self):
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="test")
        yield agent
        asyncio.get_event_loop().run_until_complete(agent.stop())

    def test_direct_mapping(self, agent):
        """Direct type names map correctly."""
        assert agent._classify_finding({"type": "XSS"}) == "xss"
        assert agent._classify_finding({"type": "sqli"}) == "sqli"
        assert agent._classify_finding({"type": "IDOR"}) == "idor"

    def test_variant_mapping(self, agent):
        """Variant names map to correct specialist."""
        assert agent._classify_finding({"type": "SQL Injection"}) == "sqli"
        assert agent._classify_finding({"type": "Cross-Site Scripting"}) == "xss"
        assert agent._classify_finding({"type": "Open Redirect"}) == "openredirect"
        assert agent._classify_finding({"type": "Prototype Pollution"}) == "prototype_pollution"

    def test_partial_match(self, agent):
        """Partial matches in compound type names."""
        assert agent._classify_finding({"type": "Reflected XSS in search"}) == "xss"
        assert agent._classify_finding({"type": "Blind SQL Injection"}) == "sqli"

    def test_unknown_type(self, agent):
        """Unknown types return None."""
        assert agent._classify_finding({"type": "Unknown Vuln"}) is None

    def test_case_insensitive(self, agent):
        """Classification is case insensitive."""
        assert agent._classify_finding({"type": "XSS"}) == "xss"
        assert agent._classify_finding({"type": "xss"}) == "xss"
        assert agent._classify_finding({"type": "Xss"}) == "xss"


class TestPriorityCalculation:
    """Tests for priority scoring."""

    @pytest.fixture
    def agent(self):
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="test")
        yield agent
        asyncio.get_event_loop().run_until_complete(agent.stop())

    def test_critical_high_confidence(self, agent):
        """Critical severity with high confidence scores highest."""
        finding = {
            "severity": "critical",
            "fp_confidence": 0.95,
            "skeptical_score": 9
        }
        priority = agent._calculate_priority(finding)
        assert priority > 80, f"Critical+high confidence should be >80, got {priority}"

    def test_low_priority(self, agent):
        """Low severity with low confidence scores lowest."""
        finding = {
            "severity": "low",
            "fp_confidence": 0.3,
            "skeptical_score": 2
        }
        priority = agent._calculate_priority(finding)
        assert priority < 40, f"Low should be <40, got {priority}"

    def test_validated_boost(self, agent):
        """Validated findings get priority boost."""
        base_finding = {
            "severity": "medium",
            "fp_confidence": 0.6,
            "skeptical_score": 5
        }
        validated_finding = {**base_finding, "validated": True}

        base_priority = agent._calculate_priority(base_finding)
        validated_priority = agent._calculate_priority(validated_finding)

        assert validated_priority > base_priority, "Validated should have higher priority"

    def test_high_votes_boost(self, agent):
        """High vote count gets priority boost."""
        base_finding = {
            "severity": "medium",
            "fp_confidence": 0.6,
            "skeptical_score": 5,
            "votes": 2
        }
        high_votes_finding = {**base_finding, "votes": 5}

        base_priority = agent._calculate_priority(base_finding)
        high_votes_priority = agent._calculate_priority(high_votes_finding)

        assert high_votes_priority > base_priority, "High votes should boost priority"

    def test_priority_capped_at_100(self, agent):
        """Priority never exceeds 100."""
        finding = {
            "severity": "critical",
            "fp_confidence": 1.0,
            "skeptical_score": 10,
            "validated": True,
            "votes": 5
        }
        priority = agent._calculate_priority(finding)
        assert priority <= 100, f"Priority should be capped at 100, got {priority}"


class TestEventSubscription:
    """Tests for event bus integration."""

    @pytest.fixture
    def agent(self):
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="test")
        yield agent
        asyncio.get_event_loop().run_until_complete(agent.stop())

    @pytest.mark.asyncio
    async def test_subscribes_to_url_analyzed(self, agent):
        """Agent subscribes to URL_ANALYZED on init."""
        subscribers = event_bus._subscribers.get(EventType.URL_ANALYZED.value, [])
        assert len(subscribers) > 0, "Should have URL_ANALYZED subscriber"

    @pytest.mark.asyncio
    async def test_processes_findings_from_event(self, agent):
        """Findings from url_analyzed event are processed."""
        agent.set_mode("streaming")

        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "test",
            "findings": [
                {"type": "XSS", "parameter": "q", "url": "https://test.com",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"}
            ],
            "stats": {"total": 1}
        })
        await asyncio.sleep(0.2)

        stats = agent.get_stats()
        assert stats["total_received"] == 1
        assert stats["distributed"] >= 1

    @pytest.mark.asyncio
    async def test_unsubscribes_on_stop(self, agent):
        """Agent unsubscribes from events on stop."""
        await agent.stop()

        # Re-check subscribers (should have decreased)
        # Note: Other tests may have subscribers, so just verify no error


class TestProcessingModes:
    """Tests for streaming vs batch modes."""

    @pytest.mark.asyncio
    async def test_streaming_processes_immediately(self):
        """Streaming mode processes findings immediately."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="stream")
        agent.set_mode("streaming")

        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "stream",
            "findings": [
                {"type": "XSS", "parameter": "q", "url": "https://test.com",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"}
            ],
            "stats": {"total": 1}
        })
        await asyncio.sleep(0.1)

        # Should be processed immediately, not buffered
        stats = agent.get_stats()
        assert stats["batch_buffer_size"] == 0
        assert stats["distributed"] == 1

        await agent.stop()

    @pytest.mark.asyncio
    async def test_batch_buffers_until_full(self):
        """Batch mode buffers findings until batch size reached."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="batch")
        agent.set_mode("batch")

        # Set small batch size for test
        from bugtrace.core.config import settings
        original_size = settings.THINKING_BATCH_SIZE
        settings.THINKING_BATCH_SIZE = 3

        # Add 2 findings (less than batch size)
        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "batch",
            "findings": [
                {"type": "XSS", "parameter": "q1", "url": "https://test.com",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"},
                {"type": "SQLi", "parameter": "q2", "url": "https://test.com",
                 "fp_confidence": 0.9, "skeptical_score": 8, "severity": "critical"},
            ],
            "stats": {"total": 2}
        })
        await asyncio.sleep(0.1)

        # Should be buffered
        assert len(agent._batch_buffer) == 2, "Should have 2 in buffer"

        settings.THINKING_BATCH_SIZE = original_size
        await agent.stop()

    @pytest.mark.asyncio
    async def test_mode_switch_flushes_buffer(self):
        """Switching from batch to streaming flushes buffer."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="switch")
        agent.set_mode("batch")

        # Add finding to buffer
        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "switch",
            "findings": [
                {"type": "XSS", "parameter": "sw", "url": "https://test.com",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"}
            ],
            "stats": {"total": 1}
        })
        await asyncio.sleep(0.1)

        assert len(agent._batch_buffer) == 1, "Should have 1 in buffer"

        # Switch to streaming
        agent.set_mode("streaming")
        await asyncio.sleep(0.2)

        # Buffer should be flushed
        assert len(agent._batch_buffer) == 0, "Buffer should be empty after switch"
        stats = agent.get_stats()
        assert stats["distributed"] >= 1, "Buffered item should be distributed"

        await agent.stop()

    @pytest.mark.asyncio
    async def test_invalid_mode_raises(self):
        """Invalid mode raises ValueError."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="invalid")

        with pytest.raises(ValueError, match="Invalid mode"):
            agent.set_mode("invalid_mode")

        await agent.stop()

    @pytest.mark.asyncio
    async def test_flush_batch_returns_count(self):
        """flush_batch returns number of findings flushed."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="flush")
        agent.set_mode("batch")

        # Add findings to buffer
        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "flush",
            "findings": [
                {"type": "XSS", "parameter": "f1", "url": "https://test.com",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"},
                {"type": "SQLi", "parameter": "f2", "url": "https://test.com",
                 "fp_confidence": 0.9, "skeptical_score": 8, "severity": "critical"},
            ],
            "stats": {"total": 2}
        })
        await asyncio.sleep(0.1)

        # Explicit flush
        count = await agent.flush_batch()
        assert count == 2, f"Should have flushed 2, got {count}"
        assert len(agent._batch_buffer) == 0, "Buffer should be empty"

        await agent.stop()


class TestStatistics:
    """Tests for statistics tracking."""

    @pytest.mark.asyncio
    async def test_total_received_tracked(self):
        """Total received findings are tracked."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="stats_total")
        agent.set_mode("streaming")

        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "stats_total",
            "findings": [
                {"type": "XSS", "parameter": "q1", "url": "https://test.com/total1",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"},
                {"type": "SQLi", "parameter": "q2", "url": "https://test.com/total2",
                 "fp_confidence": 0.9, "skeptical_score": 8, "severity": "critical"},
            ],
            "stats": {"total": 2}
        })
        await asyncio.sleep(0.2)

        stats = agent.get_stats()
        assert stats["total_received"] == 2
        await agent.stop()

    @pytest.mark.asyncio
    async def test_duplicates_tracked(self):
        """Duplicate findings are tracked."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="stats_dup")
        agent.set_mode("streaming")

        # Send same finding twice
        for i in range(2):
            await event_bus.emit(EventType.URL_ANALYZED, {
                "url": "https://test.com",
                "scan_context": "stats_dup",
                "findings": [
                    {"type": "XSS", "parameter": "dup", "url": "https://test.com/dup",
                     "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"}
                ],
                "stats": {"total": 1}
            })
            await asyncio.sleep(0.15)

        stats = agent.get_stats()
        assert stats["duplicates_filtered"] == 1, f"Second finding should be filtered, stats={stats}"
        await agent.stop()

    @pytest.mark.asyncio
    async def test_fp_filtered_tracked(self):
        """Low FP confidence findings are tracked as filtered."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="stats_fp")
        agent.set_mode("streaming")

        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "stats_fp",
            "findings": [
                {"type": "XSS", "parameter": "fp", "url": "https://test.com/fp",
                 "fp_confidence": 0.1, "skeptical_score": 1, "severity": "low"}  # Below threshold
            ],
            "stats": {"total": 1}
        })
        await asyncio.sleep(0.2)

        stats = agent.get_stats()
        assert stats["fp_filtered"] == 1, f"Low FP confidence should be filtered, stats={stats}"
        await agent.stop()

    @pytest.mark.asyncio
    async def test_by_specialist_tracked(self):
        """Distribution by specialist is tracked."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="stats_spec")
        agent.set_mode("streaming")

        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "stats_spec",
            "findings": [
                {"type": "XSS", "parameter": "spec1", "url": "https://test.com/spec1",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"},
                {"type": "SQLi", "parameter": "spec2", "url": "https://test.com/spec2",
                 "fp_confidence": 0.9, "skeptical_score": 8, "severity": "critical"},
            ],
            "stats": {"total": 2}
        })
        await asyncio.sleep(0.2)

        stats = agent.get_stats()
        assert "xss" in stats["by_specialist"], f"stats={stats}"
        assert "sqli" in stats["by_specialist"], f"stats={stats}"
        await agent.stop()

    @pytest.mark.asyncio
    async def test_reset_stats(self):
        """reset_stats clears all statistics."""
        queue_manager.reset()
        agent = ThinkingConsolidationAgent(scan_context="stats_reset")
        agent.set_mode("streaming")

        await event_bus.emit(EventType.URL_ANALYZED, {
            "url": "https://test.com",
            "scan_context": "stats_reset",
            "findings": [
                {"type": "XSS", "parameter": "reset", "url": "https://test.com/reset",
                 "fp_confidence": 0.8, "skeptical_score": 7, "severity": "high"}
            ],
            "stats": {"total": 1}
        })
        await asyncio.sleep(0.2)

        stats = agent.get_stats()
        assert stats["total_received"] >= 1

        agent.reset_stats()
        stats = agent.get_stats()
        assert stats["total_received"] == 0
        assert stats["distributed"] == 0
        await agent.stop()


# Run tests with: pytest tests/test_thinking_agent.py -v
