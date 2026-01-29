"""
Event Bus - Sistema de publicación/suscripción asíncrono
Permite comunicación desacoplada entre agentes.

Author: BugtraceAI Team
Date: 2026-01-01
Version: 2.0.0

Exports:
    EventBus: Main event bus class
    EventType: Standard event type enum
    event_bus: Global singleton instance
"""

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any, Optional
from enum import Enum
import fnmatch
import time

from bugtrace.utils.logger import get_logger

logger = get_logger("event_bus")


class EventType(str, Enum):
    """
    Standard event types for agent coordination.

    Discovery Phase:
    - URL_ANALYZED: SASTDASTAgent completed URL analysis

    Evaluation Phase:
    - WORK_QUEUED_XSS: ThinkingAgent queued work for XSS specialist
    - WORK_QUEUED_SQLI: ThinkingAgent queued work for SQLi specialist
    - WORK_QUEUED_CSTI: ThinkingAgent queued work for CSTI specialist
    - WORK_QUEUED_LFI: ThinkingAgent queued work for LFI specialist
    - WORK_QUEUED_IDOR: ThinkingAgent queued work for IDOR specialist
    - WORK_QUEUED_RCE: ThinkingAgent queued work for RCE specialist
    - WORK_QUEUED_SSRF: ThinkingAgent queued work for SSRF specialist
    - WORK_QUEUED_XXE: ThinkingAgent queued work for XXE specialist
    - WORK_QUEUED_JWT: ThinkingAgent queued work for JWT specialist
    - WORK_QUEUED_OPENREDIRECT: ThinkingAgent queued work for OpenRedirect specialist
    - WORK_QUEUED_PROTOTYPE_POLLUTION: ThinkingAgent queued work for PrototypePollution specialist

    Exploitation Phase:
    - VULNERABILITY_DETECTED: Specialist confirmed a vulnerability

    Validation Phase:
    - FINDING_VALIDATED: AgenticValidator confirmed finding
    - FINDING_REJECTED: AgenticValidator rejected finding

    Legacy (existing):
    - NEW_INPUT_DISCOVERED: ReconAgent found new input
    - WAF_DETECTED: ExploitAgent detected WAF
    - AGENT_STARTED: Agent started execution
    - AGENT_STOPPED: Agent stopped execution
    """
    # Discovery
    URL_ANALYZED = "url_analyzed"

    # Evaluation (work distribution)
    WORK_QUEUED_XSS = "work_queued_xss"
    WORK_QUEUED_SQLI = "work_queued_sqli"
    WORK_QUEUED_CSTI = "work_queued_csti"
    WORK_QUEUED_LFI = "work_queued_lfi"
    WORK_QUEUED_IDOR = "work_queued_idor"
    WORK_QUEUED_RCE = "work_queued_rce"
    WORK_QUEUED_SSRF = "work_queued_ssrf"
    WORK_QUEUED_XXE = "work_queued_xxe"
    WORK_QUEUED_JWT = "work_queued_jwt"
    WORK_QUEUED_OPENREDIRECT = "work_queued_openredirect"
    WORK_QUEUED_PROTOTYPE_POLLUTION = "work_queued_prototype_pollution"

    # Exploitation
    VULNERABILITY_DETECTED = "vulnerability_detected"

    # Validation
    FINDING_VALIDATED = "finding_validated"
    FINDING_REJECTED = "finding_rejected"

    # Legacy
    NEW_INPUT_DISCOVERED = "new_input_discovered"
    WAF_DETECTED = "waf_detected"
    PATTERN_DETECTED = "pattern_detected"
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    FINDING_VERIFIED = "finding_verified"  # Legacy alias for FINDING_VALIDATED


@dataclass
class EventRecord:
    """Record of an emitted event for replay."""
    event: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    scan_context: Optional[str] = None


class EventBus:
    """
    Event Bus central para comunicación inter-agente.
    
    Patrón: Pub/Sub asíncrono
    Thread-safe: Sí (asyncio.Lock)
    Singleton: Sí (instancia global al final del archivo)
    
    Eventos soportados:
    - new_input_discovered: ReconAgent → ExploitAgent
    - vulnerability_detected: ExploitAgent → SkepticalAgent
    - finding_verified: SkepticalAgent → Dashboard/Report
    - waf_detected: ExploitAgent → ReconAgent (feedback)
    - pattern_detected: ExploitAgent → ReconAgent (priorización)
    - agent_started: Cualquier agente → TeamOrchestrator
    - agent_stopped: Cualquier agente → TeamOrchestrator
    """
    
    def __init__(self):
        # Estructura: {event_name: [handler1, handler2, ...]}
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)

        # Lock para thread-safety en subscribe/unsubscribe
        self._lock = asyncio.Lock()

        # Estadísticas (debugging)
        self._stats = {
            "total_events_emitted": 0,
            "events_by_type": defaultdict(int),
            "total_subscribers": 0
        }

        # Pattern subscribers for wildcard matching
        self._pattern_subscribers: Dict[str, List[Callable]] = defaultdict(list)

        # Scan context ordering
        self._context_queues: Dict[str, asyncio.Queue] = {}
        self._context_processors: Dict[str, asyncio.Task] = {}
        self._context_lock = asyncio.Lock()

        # Event history for replay
        self._history: deque = deque(maxlen=1000)  # Last 1000 events
        self._replay_enabled: bool = False

        logger.info("Event Bus initialized (v2 with ordering and replay)")
    
    def subscribe(self, event: str, handler: Callable) -> None:
        """
        Suscribirse a un evento.

        Args:
            event: Nombre del evento (ej: "new_input_discovered")
            handler: Función async que maneja el evento
                     Firma: async def handler(data: Dict) -> None

        Example:
            event_bus.subscribe("new_input_discovered", self.handle_new_input)
        """
        if not asyncio.iscoroutinefunction(handler):
            raise ValueError(f"Handler must be async function, got {type(handler)}")

        # Append is atomic in Python due to GIL - no lock needed
        self._subscribers[event].append(handler)
        self._stats["total_subscribers"] += 1

        logger.debug(
            f"Subscriber added: {handler.__name__} → {event} "
            f"(total: {len(self._subscribers[event])})"
        )

    def subscribe_pattern(self, pattern: str, handler: Callable) -> None:
        """
        Subscribe to events matching a pattern.

        Pattern examples:
        - "work_queued_*" matches work_queued_xss, work_queued_sqli, etc.
        - "finding_*" matches finding_validated, finding_rejected

        Args:
            pattern: fnmatch-style pattern
            handler: Async handler function
        """
        if not asyncio.iscoroutinefunction(handler):
            raise ValueError(f"Handler must be async function")

        self._pattern_subscribers[pattern].append(handler)
        self._stats["total_subscribers"] += 1
        logger.debug(f"Pattern subscriber added: {handler.__name__} -> {pattern}")
    
    async def emit(self, event: str, data: Dict[str, Any]) -> None:
        """
        Emit event with optional scan context ordering.

        If data contains 'scan_context', events are guaranteed to be
        delivered in order for that context.

        Args:
            event: Event name (string or EventType)
            data: Event payload (must include 'scan_context' for ordering)

        Comportamiento:
            - Ejecuta handlers en paralelo (asyncio.create_task)
            - No bloquea al emisor
            - Errores en handlers se loggean pero no bloquean otros handlers

        Example:
            await event_bus.emit("new_input_discovered", {
                "url": "https://example.com/search",
                "input": {"name": "q", "type": "text"}
            })
        """
        # Convert EventType to string if needed
        if isinstance(event, EventType):
            event = event.value

        # Estadísticas
        self._stats["total_events_emitted"] += 1
        self._stats["events_by_type"][event] += 1

        # Record for replay if enabled
        if self._replay_enabled:
            record = EventRecord(
                event=event,
                data=data.copy(),
                scan_context=data.get("scan_context")
            )
            self._history.append(record)

        scan_context = data.get("scan_context")

        if scan_context:
            # Ordered delivery per scan context
            await self._emit_ordered(event, data, scan_context)
        else:
            # Immediate delivery (backward compatible)
            await self._emit_immediate(event, data)

    async def _emit_ordered(self, event: str, data: dict, scan_context: str) -> None:
        """Queue event for ordered delivery within scan context."""
        async with self._context_lock:
            if scan_context not in self._context_queues:
                self._context_queues[scan_context] = asyncio.Queue()
                # Start processor for this context
                processor = asyncio.create_task(
                    self._process_context_queue(scan_context)
                )
                self._context_processors[scan_context] = processor

        await self._context_queues[scan_context].put((event, data))

    async def _process_context_queue(self, scan_context: str) -> None:
        """Process events for a scan context in order."""
        queue = self._context_queues[scan_context]
        while True:
            try:
                event, data = await asyncio.wait_for(queue.get(), timeout=60.0)
                await self._emit_immediate(event, data)
                queue.task_done()
            except asyncio.TimeoutError:
                # Clean up idle contexts
                if queue.empty():
                    async with self._context_lock:
                        if scan_context in self._context_queues and self._context_queues[scan_context].empty():
                            del self._context_queues[scan_context]
                            del self._context_processors[scan_context]
                            logger.debug(f"Cleaned up idle context: {scan_context}")
                            return
            except Exception as e:
                logger.error(f"Context processor error: {e}")

    async def _emit_immediate(self, event: str, data: dict) -> None:
        """Emit event immediately to all matching subscribers."""
        # Get direct subscribers
        async with self._lock:
            handlers = self._subscribers.get(event, []).copy()

        # Get pattern subscribers
        for pattern, pattern_handlers in self._pattern_subscribers.items():
            if fnmatch.fnmatch(event, pattern):
                handlers.extend(pattern_handlers)

        if not handlers:
            logger.debug(f"Event '{event}' emitted but no subscribers")
            return

        logger.debug(f"Event '{event}' -> {len(handlers)} subscriber(s)")

        for handler in handlers:
            asyncio.create_task(self._safe_handler_call(handler, event, data))
    
    async def _safe_handler_call(
        self,
        handler: Callable,
        event: str,
        data: Dict[str, Any]
    ) -> None:
        """
        Wrapper para ejecutar handler con error handling.
        Evita que un handler crasheado bloquee otros.
        """
        try:
            await handler(data)
        except Exception as e:
            logger.error(
                f"Handler {handler.__name__} failed for event '{event}': {e}",
                exc_info=True
            )
    
    def unsubscribe(self, event: str, handler: Callable) -> bool:
        """
        Desuscribirse de un evento.

        Args:
            event: Nombre del evento
            handler: Handler a remover

        Returns:
            True si handler fue removido, False si no existía

        Use case:
            Cleanup cuando agent se detiene
        """
        try:
            self._subscribers[event].remove(handler)
            self._stats["total_subscribers"] -= 1
            logger.debug(f"Subscriber removed: {handler.__name__} from {event}")
            return True
        except ValueError:
            logger.warning(
                f"Handler {handler.__name__} not found in {event} subscribers"
            )
            return False

    def enable_replay(self, enabled: bool = True, max_history: int = 1000) -> None:
        """
        Enable/disable event replay recording.

        Args:
            enabled: Whether to record events
            max_history: Maximum events to keep
        """
        self._replay_enabled = enabled
        if enabled:
            self._history = deque(maxlen=max_history)
        logger.info(f"Event replay {'enabled' if enabled else 'disabled'} (max: {max_history})")

    def get_history(self, scan_context: str = None, event_type: str = None) -> List[EventRecord]:
        """
        Get event history for debugging.

        Args:
            scan_context: Filter by scan context (optional)
            event_type: Filter by event type (optional)

        Returns:
            List of EventRecord objects matching filters
        """
        records = list(self._history)

        if scan_context:
            records = [r for r in records if r.scan_context == scan_context]

        if event_type:
            records = [r for r in records if r.event == event_type]

        return records

    async def replay(self, scan_context: str = None, event_type: str = None) -> int:
        """
        Replay recorded events to subscribers.

        Args:
            scan_context: Filter by scan context (optional)
            event_type: Filter by event type (optional)

        Returns:
            Number of events replayed
        """
        records = self.get_history(scan_context, event_type)

        logger.info(f"Replaying {len(records)} events...")

        for record in records:
            await self._emit_immediate(record.event, record.data)

        return len(records)

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()
        logger.debug("Event history cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Obtener estadísticas del Event Bus.
        Útil para debugging y monitoring.
        """
        return {
            "total_events_emitted": self._stats["total_events_emitted"],
            "events_by_type": dict(self._stats["events_by_type"]),
            "total_subscribers": self._stats["total_subscribers"],
            "subscribers_by_event": {
                event: len(handlers)
                for event, handlers in self._subscribers.items()
            }
        }
    
    def reset_stats(self) -> None:
        """Reset estadísticas (útil para testing)"""
        self._stats["total_events_emitted"] = 0
        self._stats["events_by_type"].clear()


# Singleton global
event_bus = EventBus()
