"""
Unit tests for the enhanced event bus (Phase 16).

Tests:
- EventType enum
- Pattern subscriptions
- Scan context ordering
- Event replay functionality

Author: BugtraceAI Team
Date: 2026-01-29
"""

import asyncio
import pytest
from bugtrace.core.event_bus import EventBus, EventType, event_bus


class TestEventType:
    """Tests for EventType enum."""

    def test_url_analyzed_value(self):
        """Test URL_ANALYZED has correct value."""
        assert EventType.URL_ANALYZED.value == "url_analyzed"

    def test_work_queued_events_exist(self):
        """Test all work_queued event types exist."""
        specialists = ["xss", "sqli", "csti", "lfi", "idor", "rce", "ssrf", "xxe", "jwt"]
        for spec in specialists:
            event_name = f"WORK_QUEUED_{spec.upper()}"
            assert hasattr(EventType, event_name), f"Missing {event_name}"

    def test_vulnerability_detected_value(self):
        """Test VULNERABILITY_DETECTED has correct value."""
        assert EventType.VULNERABILITY_DETECTED.value == "vulnerability_detected"

    def test_finding_validated_value(self):
        """Test FINDING_VALIDATED has correct value."""
        assert EventType.FINDING_VALIDATED.value == "finding_validated"


class TestPatternSubscription:
    """Tests for pattern-based subscriptions."""

    @pytest.fixture
    def bus(self):
        """Create fresh event bus for each test."""
        return EventBus()

    @pytest.mark.asyncio
    async def test_pattern_matches_work_queued(self, bus):
        """Test work_queued_* pattern matches specialist events."""
        results = []

        async def handler(data):
            results.append(data["specialist"])

        bus.subscribe_pattern("work_queued_*", handler)

        await bus.emit(EventType.WORK_QUEUED_XSS, {"specialist": "xss"})
        await bus.emit(EventType.WORK_QUEUED_SQLI, {"specialist": "sqli"})
        await bus.emit(EventType.URL_ANALYZED, {"specialist": "none"})  # Should not match

        await asyncio.sleep(0.1)

        assert "xss" in results
        assert "sqli" in results
        assert "none" not in results

    @pytest.mark.asyncio
    async def test_pattern_finding_asterisk(self, bus):
        """Test finding_* pattern matches finding events."""
        results = []

        async def handler(data):
            results.append(data["status"])

        bus.subscribe_pattern("finding_*", handler)

        await bus.emit(EventType.FINDING_VALIDATED, {"status": "validated"})
        await bus.emit(EventType.FINDING_REJECTED, {"status": "rejected"})

        await asyncio.sleep(0.1)

        assert "validated" in results
        assert "rejected" in results

    @pytest.mark.asyncio
    async def test_direct_and_pattern_both_fire(self, bus):
        """Test both direct and pattern subscribers receive event."""
        results = []

        async def direct_handler(data):
            results.append(("direct", data["id"]))

        async def pattern_handler(data):
            results.append(("pattern", data["id"]))

        bus.subscribe(EventType.WORK_QUEUED_XSS.value, direct_handler)
        bus.subscribe_pattern("work_queued_*", pattern_handler)

        await bus.emit(EventType.WORK_QUEUED_XSS, {"id": 1})
        await asyncio.sleep(0.1)

        assert ("direct", 1) in results
        assert ("pattern", 1) in results


class TestScanContextOrdering:
    """Tests for scan context message ordering."""

    @pytest.fixture
    def bus(self):
        """Create fresh event bus for each test."""
        return EventBus()

    @pytest.mark.asyncio
    async def test_events_delivered_in_order(self, bus):
        """Test events with same scan_context are delivered in order."""
        results = []

        async def handler(data):
            results.append(data["seq"])

        bus.subscribe(EventType.URL_ANALYZED.value, handler)

        # Emit events rapidly
        for i in range(10):
            await bus.emit(EventType.URL_ANALYZED, {"seq": i, "scan_context": "scan-001"})

        await asyncio.sleep(0.5)  # Wait for processing

        # Verify order
        assert results == list(range(10)), f"Expected [0-9], got {results}"

    @pytest.mark.asyncio
    async def test_different_contexts_processed_independently(self, bus):
        """Test different scan contexts don't block each other."""
        results_a = []
        results_b = []

        async def handler(data):
            if data["ctx"] == "A":
                results_a.append(data["seq"])
            else:
                results_b.append(data["seq"])

        bus.subscribe(EventType.URL_ANALYZED.value, handler)

        # Interleave events from two contexts
        await bus.emit(EventType.URL_ANALYZED, {"seq": 0, "ctx": "A", "scan_context": "scan-A"})
        await bus.emit(EventType.URL_ANALYZED, {"seq": 0, "ctx": "B", "scan_context": "scan-B"})
        await bus.emit(EventType.URL_ANALYZED, {"seq": 1, "ctx": "A", "scan_context": "scan-A"})
        await bus.emit(EventType.URL_ANALYZED, {"seq": 1, "ctx": "B", "scan_context": "scan-B"})

        await asyncio.sleep(0.3)

        assert results_a == [0, 1]
        assert results_b == [0, 1]

    @pytest.mark.asyncio
    async def test_events_without_context_immediate(self, bus):
        """Test events without scan_context are delivered immediately."""
        results = []

        async def handler(data):
            results.append(data["id"])

        bus.subscribe(EventType.URL_ANALYZED.value, handler)

        # No scan_context - should be immediate
        await bus.emit(EventType.URL_ANALYZED, {"id": 1})
        await bus.emit(EventType.URL_ANALYZED, {"id": 2})

        await asyncio.sleep(0.1)

        assert 1 in results
        assert 2 in results


class TestEventReplay:
    """Tests for event replay functionality."""

    @pytest.fixture
    def bus(self):
        """Create fresh event bus for each test."""
        return EventBus()

    @pytest.mark.asyncio
    async def test_enable_replay_records_events(self, bus):
        """Test enabling replay records events in history."""
        bus.enable_replay(True, max_history=100)

        await bus.emit(EventType.URL_ANALYZED, {"id": 1, "scan_context": "scan-001"})
        await bus.emit(EventType.URL_ANALYZED, {"id": 2, "scan_context": "scan-001"})

        await asyncio.sleep(0.1)

        history = bus.get_history()
        assert len(history) == 2

    @pytest.mark.asyncio
    async def test_filter_history_by_scan_context(self, bus):
        """Test filtering history by scan_context."""
        bus.enable_replay(True)

        await bus.emit(EventType.URL_ANALYZED, {"id": 1, "scan_context": "scan-001"})
        await bus.emit(EventType.URL_ANALYZED, {"id": 2, "scan_context": "scan-002"})
        await bus.emit(EventType.URL_ANALYZED, {"id": 3, "scan_context": "scan-001"})

        await asyncio.sleep(0.1)

        history = bus.get_history(scan_context="scan-001")
        assert len(history) == 2
        assert all(r.scan_context == "scan-001" for r in history)

    @pytest.mark.asyncio
    async def test_filter_history_by_event_type(self, bus):
        """Test filtering history by event type."""
        bus.enable_replay(True)

        await bus.emit(EventType.URL_ANALYZED, {"id": 1})
        await bus.emit(EventType.VULNERABILITY_DETECTED, {"id": 2})
        await bus.emit(EventType.URL_ANALYZED, {"id": 3})

        await asyncio.sleep(0.1)

        history = bus.get_history(event_type=EventType.URL_ANALYZED.value)
        assert len(history) == 2
        assert all(r.event == "url_analyzed" for r in history)

    @pytest.mark.asyncio
    async def test_replay_delivers_to_subscribers(self, bus):
        """Test replay delivers events to current subscribers."""
        bus.enable_replay(True)

        # Emit without subscribers
        await bus.emit(EventType.URL_ANALYZED, {"id": 1})
        await bus.emit(EventType.URL_ANALYZED, {"id": 2})

        await asyncio.sleep(0.1)

        # Now subscribe and replay
        results = []

        async def handler(data):
            results.append(data["id"])

        bus.subscribe(EventType.URL_ANALYZED.value, handler)

        replayed = await bus.replay()
        await asyncio.sleep(0.1)

        assert replayed == 2
        assert 1 in results
        assert 2 in results

    @pytest.mark.asyncio
    async def test_clear_history(self, bus):
        """Test clear_history removes all recorded events."""
        bus.enable_replay(True)

        await bus.emit(EventType.URL_ANALYZED, {"id": 1})
        await asyncio.sleep(0.1)
        assert len(bus.get_history()) == 1

        bus.clear_history()
        assert len(bus.get_history()) == 0

    @pytest.mark.asyncio
    async def test_history_max_limit(self, bus):
        """Test history respects max_history limit."""
        bus.enable_replay(True, max_history=5)

        for i in range(10):
            await bus.emit(EventType.URL_ANALYZED, {"id": i})

        await asyncio.sleep(0.1)

        history = bus.get_history()
        assert len(history) == 5
        # Should have most recent events
        ids = [r.data["id"] for r in history]
        assert ids == [5, 6, 7, 8, 9]


class TestEventBusBackwardCompatibility:
    """Tests for backward compatibility with existing code."""

    @pytest.mark.asyncio
    async def test_subscribe_still_works(self):
        """Test existing subscribe() still works."""
        bus = EventBus()
        results = []

        async def handler(data):
            results.append(data["value"])

        bus.subscribe("test_event", handler)
        await bus.emit("test_event", {"value": 42})

        await asyncio.sleep(0.1)
        assert 42 in results

    @pytest.mark.asyncio
    async def test_string_event_names_work(self):
        """Test string event names still work."""
        bus = EventBus()
        results = []

        async def handler(data):
            results.append(data["value"])

        bus.subscribe("new_input_discovered", handler)
        await bus.emit("new_input_discovered", {"value": "test"})

        await asyncio.sleep(0.1)
        assert "test" in results
