"""
Event Bus - Sistema de publicación/suscripción asíncrono
Permite comunicación desacoplada entre agentes.

Author: BugtraceAI Team
Date: 2026-01-01
Version: 1.0.0
"""

import asyncio
from collections import defaultdict
from typing import Callable, Dict, List, Any
from bugtrace.utils.logger import get_logger

logger = get_logger("event_bus")


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
        
        logger.info("Event Bus initialized")
    
    async def subscribe(self, event: str, handler: Callable) -> None:
        """
        Suscribirse a un evento.

        Args:
            event: Nombre del evento (ej: "new_input_discovered")
            handler: Función async que maneja el evento
                     Firma: async def handler(data: Dict) -> None

        Example:
            await event_bus.subscribe("new_input_discovered", self.handle_new_input)
        """
        if not asyncio.iscoroutinefunction(handler):
            raise ValueError(f"Handler must be async function, got {type(handler)}")

        async with self._lock:
            self._subscribers[event].append(handler)
            self._stats["total_subscribers"] += 1

        logger.debug(
            f"Subscriber added: {handler.__name__} → {event} "
            f"(total: {len(self._subscribers[event])})"
        )
    
    async def emit(self, event: str, data: Dict[str, Any]) -> None:
        """
        Emitir evento a todos los suscritos.

        Args:
            event: Nombre del evento
            data: Payload del evento (dict)

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
        # Estadísticas
        self._stats["total_events_emitted"] += 1
        self._stats["events_by_type"][event] += 1

        # Copy handlers under lock to avoid iterator exhaustion if
        # subscribe/unsubscribe happens during iteration
        async with self._lock:
            handlers = self._subscribers.get(event, []).copy()

        if not handlers:
            logger.debug(f"Event '{event}' emitted but no subscribers")
            return

        logger.debug(
            f"Event '{event}' emitted to {len(handlers)} subscriber(s) "
            f"| Data keys: {list(data.keys())}"
        )

        # Ejecutar handlers en paralelo (fire-and-forget) outside the lock
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
    
    async def unsubscribe(self, event: str, handler: Callable) -> bool:
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
        async with self._lock:
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
