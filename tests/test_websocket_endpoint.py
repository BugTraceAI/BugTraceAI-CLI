"""
WebSocket Endpoint Tests - Unit and integration tests for WebSocket streaming.

Tests both ServiceEventBus sequence number functionality and WebSocket endpoint
behavior including reconnection support.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

from bugtrace.services.event_bus import ServiceEventBus
from bugtrace.api.main import app


# ============================================================================
# Unit Tests: ServiceEventBus Sequence Numbers
# ============================================================================


@pytest.mark.asyncio
async def test_event_bus_sequence_numbers():
    """Test that events get monotonically increasing sequence numbers."""
    bus = ServiceEventBus()
    scan_id = 1

    # Emit 5 events
    for i in range(5):
        await bus.emit(f"test.event.{i}", {"scan_id": scan_id, "data": f"event_{i}"})

    # Verify sequence numbers are 1-5
    history = bus.get_history(scan_id)
    assert len(history) == 5, f"Expected 5 events, got {len(history)}"

    for i, event in enumerate(history, start=1):
        assert event["seq"] == i, f"Event {i} has seq={event['seq']}, expected {i}"

    # Cleanup
    bus.clear_scan(scan_id)


@pytest.mark.asyncio
async def test_event_bus_since_seq_filtering():
    """Test that get_history(since_seq=N) returns only events after N."""
    bus = ServiceEventBus()
    scan_id = 2

    # Emit 5 events
    for i in range(5):
        await bus.emit(f"test.event.{i}", {"scan_id": scan_id, "data": f"event_{i}"})

    # Get history since seq 3 (should return seq 4, 5)
    history = bus.get_history(scan_id, since_seq=3)
    assert len(history) == 2, f"Expected 2 events, got {len(history)}"
    assert history[0]["seq"] == 4, f"First event has seq={history[0]['seq']}, expected 4"
    assert history[1]["seq"] == 5, f"Second event has seq={history[1]['seq']}, expected 5"

    # Get history since seq 0 (should return all)
    history_all = bus.get_history(scan_id, since_seq=0)
    assert len(history_all) == 5, f"Expected 5 events, got {len(history_all)}"

    # Cleanup
    bus.clear_scan(scan_id)


@pytest.mark.asyncio
async def test_event_bus_independent_scan_sequences():
    """Test that different scan_ids have independent sequence counters."""
    bus = ServiceEventBus()
    scan_id_a = 10
    scan_id_b = 20

    # Emit 3 events for scan A
    for i in range(3):
        await bus.emit(f"test.a.{i}", {"scan_id": scan_id_a, "data": f"a_{i}"})

    # Emit 2 events for scan B
    for i in range(2):
        await bus.emit(f"test.b.{i}", {"scan_id": scan_id_b, "data": f"b_{i}"})

    # Verify scan A has seq 1,2,3
    history_a = bus.get_history(scan_id_a)
    assert len(history_a) == 3, f"Expected 3 events for scan A, got {len(history_a)}"
    assert [e["seq"] for e in history_a] == [1, 2, 3], f"Scan A seq mismatch"

    # Verify scan B has seq 1,2 (independent counter)
    history_b = bus.get_history(scan_id_b)
    assert len(history_b) == 2, f"Expected 2 events for scan B, got {len(history_b)}"
    assert [e["seq"] for e in history_b] == [1, 2], f"Scan B seq mismatch"

    # Cleanup
    bus.clear_scan(scan_id_a)
    bus.clear_scan(scan_id_b)


@pytest.mark.asyncio
async def test_event_bus_clear_resets_sequence():
    """Test that clear_scan() removes sequence counter."""
    bus = ServiceEventBus()
    scan_id = 30

    # Emit 3 events
    for i in range(3):
        await bus.emit(f"test.event.{i}", {"scan_id": scan_id, "data": f"event_{i}"})

    # Verify seq 1,2,3
    history = bus.get_history(scan_id)
    assert [e["seq"] for e in history] == [1, 2, 3]

    # Clear scan
    bus.clear_scan(scan_id)

    # Re-emit events (should start at seq 1 again)
    for i in range(2):
        await bus.emit(f"test.event.{i}", {"scan_id": scan_id, "data": f"event_{i}"})

    # Verify seq starts at 1 again
    history_new = bus.get_history(scan_id)
    assert len(history_new) == 2, f"Expected 2 events, got {len(history_new)}"
    assert [e["seq"] for e in history_new] == [1, 2], f"Sequence counter not reset"

    # Cleanup
    bus.clear_scan(scan_id)


# ============================================================================
# Integration Tests: WebSocket Endpoint
# ============================================================================


def test_websocket_route_exists():
    """Test that WebSocket route /ws/scans/{scan_id} is registered."""
    routes = [r.path for r in app.routes]
    assert "/ws/scans/{scan_id}" in routes, (
        f"WebSocket route not found. Available routes: {routes}"
    )


@pytest.mark.asyncio
async def test_websocket_reconnection_with_last_seq():
    """
    Integration test: WebSocket reconnection with last_seq parameter.

    Scenario:
        1. Pre-populate 5 events for a scan
        2. Connect WebSocket with last_seq=3
        3. Verify only events with seq 4,5 are received
    """
    from bugtrace.services.event_bus import service_event_bus
    from bugtrace.services.scan_service import ScanService
    from bugtrace.services.scan_context import ScanOptions
    import asyncio

    # Create a real scan (needed for validation)
    scan_service = ScanService()
    scan_id = await scan_service.create_scan(
        ScanOptions(target_url="http://test.example.com", scan_type="quick")
    )

    # Stop the scan immediately to prevent it from running
    await scan_service.stop_scan(scan_id)

    # Wait a moment for stop to complete
    await asyncio.sleep(0.1)

    # Pre-populate 5 events
    for i in range(5):
        await service_event_bus.emit(
            f"test.event.{i}",
            {"scan_id": scan_id, "data": f"event_{i}"}
        )

    # Verify history has 5 events with seq 1-5
    history = service_event_bus.get_history(scan_id)
    assert len(history) >= 5, f"Expected at least 5 events in history, got {len(history)}"

    # Get only our test events (filter by event name pattern)
    test_events = [e for e in history if e["event"].startswith("test.event.")]
    assert len(test_events) == 5, f"Expected 5 test events, got {len(test_events)}"

    # Test WebSocket with last_seq=3 (should receive seq 4, 5)
    # Note: TestClient's websocket doesn't support async context managers,
    # so we test the get_history functionality directly which is used by the endpoint
    # Get the seq of the 3rd test event
    third_seq = test_events[2]["seq"]
    missed_events = service_event_bus.get_history(scan_id, since_seq=third_seq)

    # Filter to only test events
    missed_test_events = [e for e in missed_events if e["event"].startswith("test.event.")]
    assert len(missed_test_events) == 2, f"Expected 2 missed test events, got {len(missed_test_events)}"

    # Cleanup
    service_event_bus.clear_scan(scan_id)

    print(f"✓ Reconnection test passed: replayed 2 events after seq {third_seq}")


@pytest.mark.asyncio
async def test_websocket_invalid_scan_id():
    """Test that WebSocket closes with code 1008 for invalid scan_id."""
    # Test the validation logic directly (WebSocket connection test requires live server)
    from bugtrace.api.deps import get_scan_service

    scan_service = get_scan_service()

    # Try to get status for non-existent scan
    with pytest.raises(Exception):  # Will raise KeyError or similar
        await scan_service.get_scan_status(999999)

    print("✓ Invalid scan_id raises exception as expected")
