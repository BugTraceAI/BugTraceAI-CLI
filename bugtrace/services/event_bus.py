"""
Service Event Bus - Scan-scoped event history and streaming.

Wraps the existing core EventBus to add scan-scoped capabilities:
- Event history per scan_id for reconnection/replay
- Async streaming for real-time event consumption
- Automatic cleanup after scan completion

Solves INF-01 (event loop conflicts) by working with single asyncio event loop.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import asyncio
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Callable, Any, AsyncIterator
from bugtrace.core.event_bus import event_bus as core_event_bus
from bugtrace.utils.logger import get_logger

logger = get_logger("service_event_bus")


class ServiceEventBus:
    """
    Enhanced EventBus with scan-scoped event history and streaming.

    Wraps the existing core EventBus (bugtrace.core.event_bus) without modifying it,
    adding service-layer capabilities needed for concurrent scans:

    1. Event history per scan_id (for WebSocket reconnection in Phase 2)
    2. Async streaming via asyncio.Queue (for real-time consumption)
    3. Automatic history cap to prevent memory leaks

    This preserves backward compatibility with all existing agent code.
    """

    def __init__(self):
        """Initialize the service event bus wrapper."""
        # Reference to core singleton - do not modify it
        self._core_bus = core_event_bus

        # Scan-scoped event history: {scan_id: [event_dicts]}
        self._event_history: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

        # Scan-scoped stream queues: {scan_id: [queue1, queue2, ...]}
        self._scan_queues: Dict[int, List[asyncio.Queue]] = defaultdict(list)

        # Sequence number counters per scan: {scan_id: next_seq}
        self._seq_counters: Dict[int, int] = {}

        # Lock for thread-safe history/queue operations
        self._lock = asyncio.Lock()

        # History cap to prevent memory leaks (1000 events per scan)
        self._max_history_per_scan = 1000

        logger.info("Service Event Bus initialized")

    def subscribe(self, event: str, handler: Callable) -> None:
        """
        Subscribe to an event (delegates to core EventBus).

        Args:
            event: Event name
            handler: Async handler function
        """
        self._core_bus.subscribe(event, handler)

    async def emit(self, event: str, data: Dict[str, Any]) -> None:
        """
        Emit event to subscribers and store in scan-scoped history.

        Args:
            event: Event name
            data: Event payload (must include 'scan_id' for history storage)

        Behavior:
            1. Delegates to core EventBus for normal subscription handling
            2. If 'scan_id' in data, stores in event history
            3. Pushes to all stream() consumers for that scan_id
            4. Caps history at max_history_per_scan to prevent memory leak
        """
        # Delegate to core bus for existing handlers
        await self._core_bus.emit(event, data)

        # Store in scan-scoped history if scan_id present
        scan_id = data.get("scan_id")
        if scan_id is not None:
            async with self._lock:
                # Assign monotonically increasing sequence number
                current_seq = self._seq_counters.get(scan_id, 0) + 1
                self._seq_counters[scan_id] = current_seq

                # Map internal event names to WS-02 types
                event_type_mapping = {
                    "scan.created": "scan_started",
                    "scan.started": "scan_started",
                    "scan.completed": "scan_complete",
                    "scan.stopped": "scan_complete",
                    "scan.failed": "error",
                    "scan.error": "error",
                }

                # Check for event categories
                if event in event_type_mapping:
                    event_type = event_type_mapping[event]
                elif "agent" in event:
                    event_type = "agent_active"
                elif "finding" in event:
                    event_type = "finding_discovered"
                elif "phase" in event:
                    event_type = "phase_complete"
                else:
                    event_type = event  # Use original event name as-is

                # Create history entry
                history_entry = {
                    "event": event,
                    "data": data,
                    "timestamp": datetime.utcnow().isoformat(),
                    "seq": current_seq,
                    "event_type": event_type,
                }

                # Append to history with cap
                history = self._event_history[scan_id]
                history.append(history_entry)

                # Cap history to prevent memory leak
                if len(history) > self._max_history_per_scan:
                    self._event_history[scan_id] = history[-self._max_history_per_scan:]
                    logger.debug(f"Capped history for scan {scan_id} to {self._max_history_per_scan} events")

                # Push to all stream queues for this scan_id
                for queue in self._scan_queues[scan_id]:
                    try:
                        queue.put_nowait(history_entry)
                    except asyncio.QueueFull:
                        logger.warning(f"Queue full for scan {scan_id}, dropping event {event}")

    def get_history(self, scan_id: int, since_seq: int = 0) -> List[Dict[str, Any]]:
        """
        Get event history for a scan.

        Args:
            scan_id: Scan ID to get history for
            since_seq: Sequence number filter (returns events with seq > since_seq)

        Returns:
            List of event dictionaries after since_seq (or all if since_seq=0)

        Use cases:
            - WebSocket reconnection (Phase 2): Client sends last_seq, gets missed events
            - MCP polling (Phase 3): Poll for new events since last check
        """
        history = self._event_history.get(scan_id, [])

        # Backward compatible: if since_seq is 0, return all events
        if since_seq == 0:
            return history

        # Filter events by sequence number
        return [event for event in history if event.get("seq", 0) > since_seq]

    async def stream(self, scan_id: int) -> AsyncIterator[Dict[str, Any]]:
        """
        Stream events for a scan in real-time.

        Args:
            scan_id: Scan ID to stream events for

        Yields:
            Event dictionaries as they arrive

        Behavior:
            1. First yields all historical events (replay)
            2. Then yields new events as they arrive
            3. Cleans up queue on generator close

        Use cases:
            - WebSocket live feed (Phase 2)
            - Server-Sent Events (SSE) endpoint

        Example:
            async for event in service_event_bus.stream(scan_id=1):
                print(f"Event: {event['event']}, Data: {event['data']}")
        """
        # Create queue for this consumer
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)

        async with self._lock:
            # Add queue to scan's queue list
            self._scan_queues[scan_id].append(queue)

            # Yield historical events first (replay)
            for event in self._event_history[scan_id]:
                yield event

        try:
            # Yield new events as they arrive
            while True:
                event = await queue.get()
                yield event
        finally:
            # Cleanup: remove queue from scan's queue list
            async with self._lock:
                if queue in self._scan_queues[scan_id]:
                    self._scan_queues[scan_id].remove(queue)
                    logger.debug(f"Stream consumer disconnected from scan {scan_id}")

    def clear_scan(self, scan_id: int) -> None:
        """
        Clear event history and queues for a completed scan.

        Args:
            scan_id: Scan ID to clean up

        Use case:
            Called after scan completion + grace period (e.g., 1 hour)
            to prevent memory leak from long-lived process
        """
        if scan_id in self._event_history:
            event_count = len(self._event_history[scan_id])
            del self._event_history[scan_id]
            logger.info(f"Cleared {event_count} events for scan {scan_id}")

        if scan_id in self._scan_queues:
            queue_count = len(self._scan_queues[scan_id])
            del self._scan_queues[scan_id]
            logger.info(f"Cleared {queue_count} stream queues for scan {scan_id}")

        if scan_id in self._seq_counters:
            del self._seq_counters[scan_id]
            logger.debug(f"Cleared sequence counter for scan {scan_id}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the service event bus.

        Returns:
            Dictionary with core bus stats + scan history counts

        Use case:
            Health check endpoint, debugging, monitoring
        """
        core_stats = self._core_bus.get_stats()

        return {
            **core_stats,
            "scan_history_counts": {
                scan_id: len(events)
                for scan_id, events in self._event_history.items()
            },
            "active_stream_consumers": {
                scan_id: len(queues)
                for scan_id, queues in self._scan_queues.items()
            },
            "sequence_counters": dict(self._seq_counters),
            "total_scans_tracked": len(self._event_history),
        }

    def unsubscribe(self, event: str, handler: Callable) -> bool:
        """
        Unsubscribe from an event (delegates to core EventBus).

        Args:
            event: Event name
            handler: Handler to remove

        Returns:
            True if handler was removed, False otherwise
        """
        return self._core_bus.unsubscribe(event, handler)


# Singleton instance for service layer
service_event_bus = ServiceEventBus()
