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

    # Core event bus events to bridge into scan-scoped history/WebSocket streams
    _BRIDGED_EVENTS = [
        "pipeline_started",
        "pipeline_complete",
        "pipeline_error",
        "phase_complete_reconnaissance",
        "phase_complete_discovery",
        "phase_complete_strategy",
        "phase_complete_exploitation",
        "phase_complete_validation",
        "phase_complete_reporting",
        "url_analyzed",
        "vulnerability_detected",
        "finding_validated",
        "finding_rejected",
        "finding_verified",
        # Dashboard events (for WEB frontend widgets)
        "pipeline_progress",
        "agent_update",
        "metrics_update",
        "scan_complete_summary",
        # Log bridge (conductor.notify_log -> WebSocket)
        "scan_log",
    ]

    STREAM_IDLE_TIMEOUT_SECONDS = 30.0

    def __init__(self):
        """Initialize the service event bus wrapper."""
        # Reference to core singleton - do not modify it
        self._core_bus = core_event_bus

        # Scan-scoped event history: {scan_id: [event_dicts]}
        self._event_history: Dict[int, List[Dict[str, Any]]] = {}

        # Scan-scoped stream queues: {scan_id: [queue1, queue2, ...]}
        self._scan_queues: Dict[int, List[asyncio.Queue]] = {}

        # Sequence number counters per scan: {scan_id: next_seq}
        self._seq_counters: Dict[int, int] = {}

        # Lock for thread-safe history/queue operations
        self._lock = asyncio.Lock()

        # History cap to prevent memory leaks (5000 events per scan for verbose mode)
        self._max_history_per_scan = 5000

        # Bridge core event bus events into scan-scoped streams
        self._install_bridge()

        logger.info("Service Event Bus initialized")

    # Verbose event prefixes bridged via wildcard pattern matching
    _VERBOSE_PREFIXES = [
        "auth.*",  # Authentication phase events
        "pipeline.*", "recon.*", "discovery.*", "strategy.*",
        "exploit.*", "validation.*", "reporting.*",
    ]

    def _install_bridge(self):
        """Subscribe to core event bus events and forward them to scan-scoped streams."""
        # Explicit subscriptions for existing events (backward compat)
        for event_name in self._BRIDGED_EVENTS:
            handler = self._make_bridge_handler(event_name)
            self._core_bus.subscribe(event_name, handler)

        # Wildcard bridge for verbose events (e.g., "exploit.*" matches "exploit.xss.level.started")
        for prefix in self._VERBOSE_PREFIXES:
            handler = self._make_pattern_bridge_handler(prefix)
            self._core_bus.subscribe_pattern(prefix, handler)

    def _make_bridge_handler(self, event_name: str) -> Callable:
        """Create a bridge handler closure that captures the event name."""
        async def handler(data: Dict[str, Any]):
            await self._bridge_event(event_name, data)
        handler.__name__ = f"bridge_{event_name}"
        return handler

    def _make_pattern_bridge_handler(self, prefix: str) -> Callable:
        """Create a pattern bridge handler that reads _event from data payload."""
        async def handler(data: Dict[str, Any]):
            # VerboseEventEmitter always includes _event in payload
            event_name = data.get("_event", prefix)
            await self._bridge_event(event_name, data)
        handler.__name__ = f"bridge_{prefix.replace('*', 'all').replace('.', '_')}"
        return handler

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
                await self._store_event_in_history(scan_id, event, data)

    async def _store_event_in_history(self, scan_id: int, event: str, data: Dict[str, Any]):
        """Store event in scan-scoped history and push to streams."""
        from bugtrace.api.ws_envelope_policy import build_history_entry, map_event_type

        # Assign sequence number
        current_seq = self._seq_counters.get(scan_id, 0) + 1
        self._seq_counters[scan_id] = current_seq

        history_entry = build_history_entry(
            event,
            data,
            seq=current_seq,
            timestamp_iso=datetime.utcnow().isoformat(),
            event_type=map_event_type(event),
        )

        # Store and cap history
        self._append_to_history(scan_id, history_entry)

        # Push to stream queues
        self._push_to_queues(scan_id, event, history_entry)

    def _map_event_type(self, event: str) -> str:
        """Map internal event names to WS types. Pure owner: ws_envelope_policy."""
        from bugtrace.api.ws_envelope_policy import map_event_type

        return map_event_type(event)

    def _append_to_history(self, scan_id: int, history_entry: Dict[str, Any]):
        """Append entry to history with cap."""
        history = self._event_history.setdefault(scan_id, [])
        history.append(history_entry)

        # Cap history to prevent memory leak
        if len(history) > self._max_history_per_scan:
            self._event_history[scan_id] = history[-self._max_history_per_scan:]
            logger.debug(f"Capped history for scan {scan_id} to {self._max_history_per_scan} events")

    def _resolve_scan_id(self, data: Dict[str, Any]) -> int | None:
        """Extract numeric scan_id from event data.

        Tries multiple fields used by different layers:
        - "scan_id": service-layer events (numeric or numeric-string)
        - "scan_context": pipeline lifecycle/analysis events (str(scan_id) from DB)

        If no parseable scan_id is found, returns None. Event ownership must
        come from payload data, not from the current WebSocket consumer set.
        """
        for key in ("scan_id", "scan_context"):
            raw = data.get(key)
            if raw is not None:
                try:
                    return int(raw)
                except (TypeError, ValueError):
                    continue

        logger.debug(f"Dropping event without resolvable scan_id: {data.get('_event')}")
        return None

    async def _bridge_event(self, event_name: str, data: Dict[str, Any]):
        """Bridge handler: forward core event bus events to scan-scoped streams.

        Always stores events in history so WebSocket clients that connect later
        can replay them. Only pushes to live queues if consumers exist.
        """
        scan_id = self._resolve_scan_id(data)
        if scan_id is None:
            return

        # Always store in history (even without active consumers),
        # so late-connecting WebSocket clients get the full replay.
        async with self._lock:
            await self._store_event_in_history(scan_id, event_name, data)

    def _push_to_queues(self, scan_id: int, event: str, history_entry: Dict[str, Any]):
        """Push event to all stream queues for this scan."""
        for queue in self._scan_queues.get(scan_id, []):
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
        from bugtrace.api.ws_envelope_policy import events_after_seq

        history = self._event_history.get(scan_id, [])
        return events_after_seq(history, since_seq)

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
            self._scan_queues.setdefault(scan_id, []).append(queue)

            # Yield historical events first (replay)
            historical_events = list(self._event_history.get(scan_id, []))

        for event in historical_events:
            yield event

        try:
            # Yield new events as they arrive
            while True:
                try:
                    event = await asyncio.wait_for(
                        queue.get(),
                        timeout=self.STREAM_IDLE_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    yield {
                        "event": "heartbeat",
                        "data": {"scan_id": scan_id},
                        "timestamp": datetime.utcnow().isoformat(),
                        "seq": -1,
                        "event_type": "heartbeat",
                    }
                    continue
                yield event
        finally:
            # Cleanup: remove queue from scan's queue list
            async with self._lock:
                queues = self._scan_queues.get(scan_id, [])
                if queue in queues:
                    queues.remove(queue)
                    if not queues:
                        self._scan_queues.pop(scan_id, None)
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
