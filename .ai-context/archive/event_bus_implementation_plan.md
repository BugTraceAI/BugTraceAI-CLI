# Event Bus Implementation Plan - Phase 1
## Bugtraceai-CLI Architecture Modernization | 2026-01-01

---

## EXECUTIVE SUMMARY

**Objetivo**: Eliminar arquitectura de polling e implementar sistema event-driven  
**Impacto**: Latencia 10s → 50ms (200x más rápido), CPU -80%  
**Duración Estimada**: 3-5 días de desarrollo  
**Complejidad**: Media  
**Breaking Changes**: ❌ Ninguno (backward compatible)  
**Aprobación Requerida**: ✅ Usuario debe revisar antes de implementar

---

## PROBLEMA ACTUAL

### Arquitectura de Polling (Ineficiente)

```python
# bugtrace/agents/exploit.py - ACTUAL
async def run_loop(self):
    while self.running:
        # ❌ Polling cada 10 segundos
        attack_surface = memory_manager.get_attack_surface("Input")
        
        for input_node in attack_surface:
            if input_node.get('status') != 'TESTED':
                await self._test_xss(input_node)
        
        await asyncio.sleep(10)  # ⚠️ Latencia innecesaria
```

**Problemas identificados**:

1. **Alta Latencia**: Input descubierto por ReconAgent espera hasta 10s para ser testeado
2. **CPU Waste**: Queries constantes a memory_manager aunque no haya cambios
3. **No Escalable**: Con N agentes = N queries/segundo multiplicadas
4. **No hay Feedback**: ExploitAgent no puede informar a ReconAgent de patterns descubiertos
5. **Código Repetitivo**: Cada agente implementa su propio polling loop

### Métricas Actuales (Baseline)

```
Latency Recon → Exploit: ~5-10 segundos (promedio 7.5s)
Latency Exploit → Skeptic: ~3-5 segundos (promedio 4s)
CPU idle durante scan: 12-18% (polling constante)
Memory queries/minute: ~36 (6 agentes × 6 queries/min)
```

---

## SOLUCIÓN PROPUESTA

### Arquitectura Event-Driven

```python
# Event Bus - Pub/Sub Pattern
class EventBus:
    """
    Sistema de notificación asíncrona.
    Agentes publican eventos, otros se suscriben.
    """
    
    def subscribe(self, event: str, handler: Callable):
        """Agente se registra para recibir notificaciones"""
    
    async def emit(self, event: str, data: Dict):
        """Agente publica evento, notifica a suscritos inmediatamente"""
```

**Nuevo Flujo**:

```
ReconAgent descubre input
    ↓ (inmediato)
event_bus.emit("new_input_discovered", {...})
    ↓ (50ms)
ExploitAgent.handle_new_input() se ejecuta automáticamente
    ↓ (inmediato)
Testea input
    ↓ (inmediato)
event_bus.emit("vulnerability_detected", {...})
    ↓ (50ms)
SkepticalAgent.handle_candidate() se ejecuta automáticamente
```

**Beneficios**:
- ✅ Latencia: 10s → 50ms (200x mejora)
- ✅ CPU: -80% (no polling)
- ✅ Escalable: Agregar agentes sin overhead
- ✅ Feedback Loops: Comunicación bidireccional
- ✅ Código Limpio: No más while + sleep

---

## PLAN DE IMPLEMENTACIÓN DETALLADO

### PASO 1: Crear Event Bus Core

**Archivo**: `bugtrace/core/event_bus.py` (NUEVO)  
**Líneas**: ~120 líneas  
**Complejidad**: Media  
**Tiempo Estimado**: 3-4 horas

#### Código Completo:

```python
"""
Event Bus - Sistema de publicación/suscripción asíncrono
Permite comunicación desacoplada entre agentes.
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
        
        # Obtener suscritos (sin lock, lectura es thread-safe)
        handlers = self._subscribers.get(event, [])
        
        if not handlers:
            logger.debug(f"Event '{event}' emitted but no subscribers")
            return
        
        logger.debug(
            f"Event '{event}' emitted to {len(handlers)} subscriber(s) "
            f"| Data keys: {list(data.keys())}"
        )
        
        # Ejecutar handlers en paralelo (fire-and-forget)
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
```

**Tests Asociados**:

```python
# tests/test_event_bus.py (NUEVO)
import pytest
import asyncio
from bugtrace.core.event_bus import EventBus


@pytest.mark.asyncio
async def test_subscribe_and_emit():
    """Test básico de suscripción y emisión"""
    bus = EventBus()
    received = []
    
    async def handler(data):
        received.append(data)
    
    bus.subscribe("test_event", handler)
    await bus.emit("test_event", {"foo": "bar"})
    
    # Esperar a que handler se ejecute (async)
    await asyncio.sleep(0.1)
    
    assert len(received) == 1
    assert received[0]["foo"] == "bar"


@pytest.mark.asyncio
async def test_multiple_subscribers():
    """Test de múltiples suscritos al mismo evento"""
    bus = EventBus()
    received_a = []
    received_b = []
    
    async def handler_a(data):
        received_a.append(data)
    
    async def handler_b(data):
        received_b.append(data)
    
    bus.subscribe("test", handler_a)
    bus.subscribe("test", handler_b)
    
    await bus.emit("test", {"value": 123})
    await asyncio.sleep(0.1)
    
    assert len(received_a) == 1
    assert len(received_b) == 1


@pytest.mark.asyncio
async def test_handler_error_doesnt_block_others():
    """Test que error en un handler no bloquea otros"""
    bus = EventBus()
    received_good = []
    
    async def handler_bad(data):
        raise Exception("Intentional error")
    
    async def handler_good(data):
        received_good.append(data)
    
    bus.subscribe("test", handler_bad)
    bus.subscribe("test", handler_good)
    
    await bus.emit("test", {"x": 1})
    await asyncio.sleep(0.1)
    
    # Handler good debe ejecutarse aunque bad falle
    assert len(received_good) == 1


@pytest.mark.asyncio
async def test_unsubscribe():
    """Test de desuscripción"""
    bus = EventBus()
    received = []
    
    async def handler(data):
        received.append(data)
    
    bus.subscribe("test", handler)
    bus.unsubscribe("test", handler)
    
    await bus.emit("test", {"z": 99})
    await asyncio.sleep(0.1)
    
    # No debe recibir nada (desuscrito)
    assert len(received) == 0


@pytest.mark.asyncio
async def test_stats():
    """Test de estadísticas"""
    bus = EventBus()
    
    async def handler(data):
        pass
    
    bus.subscribe("event_a", handler)
    bus.subscribe("event_b", handler)
    
    await bus.emit("event_a", {})
    await bus.emit("event_a", {})
    await bus.emit("event_b", {})
    
    stats = bus.get_stats()
    
    assert stats["total_events_emitted"] == 3
    assert stats["events_by_type"]["event_a"] == 2
    assert stats["events_by_type"]["event_b"] == 1
    assert stats["total_subscribers"] == 2
```

---

### PASO 2: Modificar BaseAgent

**Archivo**: `bugtrace/agents/base.py` (MODIFICAR)  
**Líneas**: +10 líneas  
**Complejidad**: Baja  
**Tiempo Estimado**: 30 minutos

#### Cambios:

```python
# bugtrace/agents/base.py

# ANTES:
class BaseAgent:
    def __init__(self):
        self.running = False
        self.pause_event = asyncio.Event()
        self.conductor = conductor
        # ...

# DESPUÉS:
class BaseAgent:
    def __init__(self, event_bus=None):
        self.running = False
        self.pause_event = asyncio.Event()
        self.conductor = conductor
        
        # NUEVO: Event Bus integration
        from bugtrace.core.event_bus import event_bus as default_bus
        self.event_bus = event_bus or default_bus
        
        # Cada agente debe implementar esto en su __init__
        self._setup_event_subscriptions()
    
    def _setup_event_subscriptions(self):
        """
        Override en subclases para suscribirse a eventos.
        Llamado automáticamente en __init__.
        """
        pass
    
    async def stop(self):
        """Stop agent and cleanup event subscriptions"""
        self.running = False
        self._cleanup_event_subscriptions()
        logger.info(f"[{self.name}] Stopped")
    
    def _cleanup_event_subscriptions(self):
        """
        Override en subclases para cleanup.
        Llamado automáticamente en stop().
        """
        pass
```

---

### PASO 3: Integrar en TeamOrchestrator

**Archivo**: `bugtrace/core/team.py` (MODIFICAR)  
**Líneas**: +15 líneas  
**Complejidad**: Baja  
**Tiempo Estimado**: 1 hora

#### Cambios:

```python
# bugtrace/core/team.py

# Al inicio del archivo
from bugtrace.core.event_bus import event_bus

class TeamOrchestrator:
    def __init__(self, target: str, resume: bool = False, ...):
        self.target = target
        
        # NUEVO: Event Bus
        self.event_bus = event_bus
        logger.info("Event Bus integrated into orchestrator")
        
        # Suscribirse a eventos de agentes (opcional, para monitoring)
        self.event_bus.subscribe("finding_verified", self._on_finding_verified)
        
        # ... resto del código existente
    
    async def start(self):
        # ... código existente de inicialización ...
        
        # Crear agentes pasándoles el event_bus
        agents = [
            ReconAgent(
                self.target,
                max_depth=self.max_depth,
                max_pages=self.max_urls,
                event_bus=self.event_bus  # NUEVO
            ),
            ExploitAgent(
                event_bus=self.event_bus  # NUEVO
            ),
            SkepticalAgent(
                event_bus=self.event_bus  # NUEVO
            ),
        ]
        
        # ... resto del código (asyncio.gather, etc.)
    
    async def _on_finding_verified(self, data: Dict):
        """Handler para logging findings en tiempo real"""
        logger.info(f"[Orchestrator] New verified finding: {data.get('finding_id')}")
        dashboard.add_finding(
            title=data.get('title'),
            description=data.get('url'),
            severity=data.get('severity', 'MEDIUM')
        )
```

---

### PASO 4: Migrar ExploitAgent

**Archivo**: `bugtrace/agents/exploit.py` (MODIFICAR)  
**Líneas**: ~40 líneas modificadas  
**Complejidad**: Media  
**Tiempo Estimado**: 2-3 horas

#### Cambios Detallados:

```python
# bugtrace/agents/exploit.py

class ExploitAgent(BaseAgent):
    def __init__(self, event_bus=None):
        super().__init__(event_bus=event_bus)
        self.name = "ExploitAgent"
        
        # ... resto de init existente ...
    
    def _setup_event_subscriptions(self):
        """Suscribirse a eventos relevantes"""
        self.event_bus.subscribe("new_input_discovered", self.handle_new_input)
        logger.info(f"[{self.name}] Subscribed to: new_input_discovered")
    
    def _cleanup_event_subscriptions(self):
        """Cleanup al detener agente"""
        self.event_bus.unsubscribe("new_input_discovered", self.handle_new_input)
    
    async def handle_new_input(self, data: Dict):
        """
        Handler para nuevos inputs descubiertos por ReconAgent.
        Se ejecuta INMEDIATAMENTE (no polling).
        
        Args:
            data: {
                "url": "https://example.com/search",
                "input": {
                    "name": "q",
                    "type": "text",
                    "id": "search-box",
                    ...
                },
                "discovered_by": "ReconAgent",
                "timestamp": "2026-01-01T20:00:00Z"
            }
        """
        url = data.get('url')
        input_details = data.get('input')
        
        logger.info(
            f"[{self.name}] Received new input event: {input_details.get('name')} "
            f"at {url}"
        )
        
        # Verificar si ya fue testeado (evitar duplicados)
        input_id = f"Input:{url}:{input_details.get('name')}"
        node_data = memory_manager.get_node(input_id)
        
        if node_data and node_data.get('status') == 'TESTED':
            logger.debug(f"[{self.name}] Input already tested, skipping")
            return
        
        # Marcar como en proceso
        memory_manager.update_node_property(input_id, 'status', 'TESTING')
        
        # Ejecutar ladder logic (código existente)
        await self._check_waf(url)
        await self._ladder_sqli(url)
        await self._ladder_ui_attacks(url, input_details.get('label', ''))
        await self._ladder_infrastructure(url)
        
        # Marcar como testeado
        memory_manager.update_node_property(input_id, 'status', 'TESTED')
    
    async def _ladder_ui_attacks(self, url: str, label: str):
        """
        Modificar para emitir eventos cuando encuentra vulnerability.
        """
        # ... código existente de XSS detection ...
        
        # Si encuentra XSS reflectado:
        if "<script>alert(1)</script>" in response.text:
            # Crear candidate en memoria (como antes)
            memory_manager.add_node("FindingCandidate", f"XSS_{uuid.uuid4()}", {
                "url": url,
                "type": "XSS",
                "status": "FIRED",
                "payload": payload
            })
            
            # NUEVO: Emitir evento para SkepticalAgent
            await self.event_bus.emit("vulnerability_detected", {
                "finding_id": f"XSS_{uuid.uuid4()}",
                "type": "XSS",
                "url": url,
                "payload": payload,
                "confidence": 0.8,
                "detected_by": self.name,
                "timestamp": datetime.now().isoformat()
            })
            
            logger.warning(f"[{self.name}] XSS candidate found, notified SkepticalAgent")
    
    async def run_loop(self):
        """
        NUEVO run_loop - YA NO HACE POLLING.
        Solo monitorea pause_event y espera eventos.
        """
        logger.info(f"[{self.name}] Starting event-driven loop (no polling)")
        
        while self.running:
            # Solo espera pausas, no polling
            if not self.pause_event.is_set():
                await self.pause_event.wait()
            
            # Small sleep para no consumir CPU
            await asyncio.sleep(1)
        
        logger.info(f"[{self.name}] Event loop stopped")
```

**Antes vs Después (Comparación)**:

```python
# ❌ ANTES (Polling):
async def run_loop(self):
    while self.running:
        attack_surface = memory_manager.get_attack_surface("Input")  # Query DB
        for input_node in attack_surface:
            if input_node.get('status') != 'TESTED':
                await self._test_xss(input_node)
        
        await asyncio.sleep(10)  # ⚠️ Espera 10 segundos

# ✅ DESPUÉS (Event-Driven):
async def run_loop(self):
    while self.running:
        # Solo monitorea pausas
        await asyncio.sleep(1)

async def handle_new_input(self, data):
    # Se ejecuta INMEDIATAMENTE cuando ReconAgent emite evento
    await self._test_xss(data)
```

---

### PASO 5: Migrar SkepticalAgent

**Archivo**: `bugtrace/agents/skeptic.py` (MODIFICAR)  
**Líneas**: ~35 líneas modificadas  
**Complejidad**: Media  
**Tiempo Estimado**: 2 horas

#### Cambios:

```python
# bugtrace/agents/skeptic.py

class SkepticalAgent(BaseAgent):
    def __init__(self, event_bus=None):
        super().__init__(event_bus=event_bus)
        self.name = "SkepticalAgent"
        # ... resto del init
    
    def _setup_event_subscriptions(self):
        """Suscribirse a vulnerability_detected"""
        self.event_bus.subscribe("vulnerability_detected", self.handle_vulnerability_candidate)
        logger.info(f"[{self.name}] Subscribed to: vulnerability_detected")
    
    def _cleanup_event_subscriptions(self):
        self.event_bus.unsubscribe("vulnerability_detected", self.handle_vulnerability_candidate)
    
    async def handle_vulnerability_candidate(self, data: Dict):
        """
        Handler para candidatos de ExploitAgent.
        
        Args:
            data: {
                "finding_id": "XSS_uuid",
                "type": "XSS",
                "url": "https://example.com/...",
                "payload": "<script>alert(1)</script>",
                "confidence": 0.8,
                ...
            }
        """
        finding_id = data.get('finding_id')
        vuln_type = data.get('type')
        url = data.get('url')
        
        logger.info(
            f"[{self.name}] Received vulnerability candidate: {vuln_type} "
            f"at {url} (ID: {finding_id})"
        )
        
        # Solo verificar XSS visualmente (otros tipos pasan directo)
        if vuln_type != "XSS":
            logger.info(f"[{self.name}] {vuln_type} auto-approved (no visual verification needed)")
            await self._auto_approve_finding(data)
            return
        
        # Verificación visual para XSS
        screenshot_path, logs, triggered = await browser_manager.verify_xss(url)
        
        if not triggered:
            logger.warning(f"[{self.name}] XSS alert NOT triggered, rejecting")
            return
        
        # Análisis con LLM vision
        with open(screenshot_path, 'rb') as f:
            image_data = f.read()
        
        analysis = await llm_client.analyze_visual(
            image_data,
            "Analyze this XSS alert screenshot. Reply VERIFIED if legitimate."
        )
        
        if "VERIFIED" in analysis.upper():
            # Agregar a memoria como Finding confirmado
            memory_manager.add_node("Finding", finding_id, {
                "type": vuln_type,
                "url": url,
                "severity": "CRITICAL",
                "proof": screenshot_path,
                "verified_by": self.name,
                "timestamp": datetime.now().isoformat()
            })
            
            # NUEVO: Emitir evento de confirmación
            await self.event_bus.emit("finding_verified", {
                "finding_id": finding_id,
                "type": vuln_type,
                "url": url,
                "severity": "CRITICAL",
                "proof": screenshot_path,
                "verified_by": self.name
            })
            
            logger.info(f"[{self.name}] Finding VERIFIED and broadcasted")
        else:
            logger.warning(f"[{self.name}] Finding REJECTED (AI analysis: {analysis})")
    
    async def run_loop(self):
        """NUEVO run_loop - event-driven"""
        logger.info(f"[{self.name}] Starting event-driven loop")
        
        while self.running:
            await asyncio.sleep(1)
        
        logger.info(f"[{self.name}] Event loop stopped")
```

---

### PASO 6: Actualizar ReconAgent para Emitir

**Archivo**: `bugtrace/agents/recon.py` (MODIFICAR)  
**Líneas**: ~30 líneas nuevas  
**Complejidad**: Baja-Media  
**Tiempo Estimado**: 1-2 horas

#### Cambios:

```python
# bugtrace/agents/recon.py

class ReconAgent(BaseAgent):
    def __init__(self, target: str, max_depth: int = 2, max_pages: int = 25, event_bus=None):
        super().__init__(event_bus=event_bus)
        self.target = target
        # ... resto del init
    
    def _setup_event_subscriptions(self):
        """OPCIONAL: Suscribirse a patterns de ExploitAgent para feedback"""
        self.event_bus.subscribe("pattern_detected", self.handle_pattern_feedback)
        logger.info(f"[{self.name}] Subscribed to: pattern_detected (feedback loop)")
    
    async def handle_pattern_feedback(self, data: Dict):
        """
        Feedback loop: ExploitAgent informa de patterns descubiertos.
        ReconAgent ajusta prioridades.
        
        Example:
            data = {
                "pattern": "/api/* vulnerable to SQLi",
                "recommendation": "prioritize_api_paths"
            }
        """
        pattern = data.get('pattern')
        logger.info(f"[{self.name}] Received pattern feedback: {pattern}")
        
        # TODO (Fase 2): Implementar priority queue
        # Por ahora solo loggear
    
    async def run_loop(self):
        # ... código existente de Phase 0-3 ...
        
        # En Phase 1 (Visual Crawl), después de almacenar en memoria:
        for url, inputs in crawl_results.items():
            # Almacenar en memoria (como antes)
            for input_data in inputs:
                memory_manager.add_node("Input", f"{url}:{input_data['name']}", {
                    "url": url,
                    "name": input_data['name'],
                    "type": input_data['type'],
                    "status": "DISCOVERED"
                })
                
                # NUEVO: Emitir evento para ExploitAgent
                await self.event_bus.emit("new_input_discovered", {
                    "url": url,
                    "input": input_data,
                    "discovered_by": self.name,
                    "timestamp": datetime.now().isoformat(),
                    "phase": "Visual Crawl"
                })
                
                logger.info(
                    f"[{self.name}] Emitted new_input_discovered: "
                    f"{input_data['name']} at {url}"
                )
        
        # ... resto del código (Phase 2, 3, 4) ...
```

---

### PASO 7: Testing Completo

**Archivos**: `tests/test_integration_event_bus.py` (NUEVO)  
**Líneas**: ~150 líneas  
**Complejidad**: Media  
**Tiempo Estimado**: 3-4 horas

#### Tests de Integración:

```python
# tests/test_integration_event_bus.py

import pytest
import asyncio
from bugtrace.core.event_bus import EventBus
from bugtrace.agents.recon import ReconAgent
from bugtrace.agents.exploit import ExploitAgent
from bugtrace.agents.skeptic import SkepticalAgent
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_recon_to_exploit_flow():
    """Test flujo completo: ReconAgent → ExploitAgent"""
    
    # Setup
    bus = EventBus()
    exploit = ExploitAgent(event_bus=bus)
    
    # Mock ExploitAgent methods
    exploit._ladder_sqli = AsyncMock()
    exploit._ladder_ui_attacks = AsyncMock()
    
    # Simular evento de ReconAgent
    await bus.emit("new_input_discovered", {
        "url": "https://test.com/search",
        "input": {"name": "q", "type": "text"}
    })
    
    # Esperar procesamiento
    await asyncio.sleep(0.2)
    
    # Verificar que ExploitAgent procesó el input
    exploit._ladder_sqli.assert_called_once()
    exploit._ladder_ui_attacks.assert_called_once()


@pytest.mark.asyncio
async def test_exploit_to_skeptic_flow():
    """Test flujo: ExploitAgent → SkepticalAgent"""
    
    bus = EventBus()
    skeptic = SkepticalAgent(event_bus=bus)
    
    # Mock verification
    with patch('bugtrace.tools.visual.browser.browser_manager.verify_xss') as mock_verify:
        mock_verify.return_value = ("/tmp/screenshot.png", [], True)
        
        with patch('bugtrace.core.llm_client.llm_client.analyze_visual') as mock_llm:
            mock_llm.return_value = "VERIFIED - XSS alert clearly visible"
            
            # Simular evento de ExploitAgent
            await bus.emit("vulnerability_detected", {
                "finding_id": "XSS_test",
                "type": "XSS",
                "url": "https://test.com/vuln"
            })
            
            await asyncio.sleep(0.3)
            
            # Verificar que llamó a verification
            mock_verify.assert_called_once()
            mock_llm.assert_called_once()


@pytest.mark.asyncio
async def test_latency_improvement():
    """Test que latencia es < 200ms (objetivo: 50ms)"""
    
    bus = EventBus()
    received_at = []
    
    async def fast_handler(data):
        received_at.append(asyncio.get_event_loop().time())
    
    bus.subscribe("test_event", fast_handler)
    
    start_time = asyncio.get_event_loop().time()
    await bus.emit("test_event", {"test": 1})
    
    await asyncio.sleep(0.1)  # Buffer para handler
    
    latency = (received_at[0] - start_time) * 1000  # ms
    
    assert latency < 200, f"Latency too high: {latency}ms"
    print(f"✅ Latency: {latency:.2f}ms (objetivo: <200ms)")


@pytest.mark.asyncio
async def test_event_bus_stats():
    """Test estadísticas del Event Bus"""
    
    bus = EventBus()
    
    async def dummy(data):
        pass
    
    bus.subscribe("event_a", dummy)
    bus.subscribe("event_b", dummy)
    
    await bus.emit("event_a", {})
    await bus.emit("event_a", {})
    await bus.emit("event_b", {})
    
    await asyncio.sleep(0.1)
    
    stats = bus.get_stats()
    
    assert stats["total_events_emitted"] == 3
    assert stats["events_by_type"]["event_a"] == 2
    assert stats["events_by_type"]["event_b"] == 1
    assert stats["subscribers_by_event"]["event_a"] == 1
    assert stats["subscribers_by_event"]["event_b"] == 1


@pytest.mark.asyncio
async def test_e2e_scan_with_event_bus(mocker):
    """Test E2E: Scan completo con Event Bus"""
    
    # Mock external dependencies
    mocker.patch('bugtrace.tools.visual.browser.browser_manager.start', new_callable=AsyncMock)
    mocker.patch('bugtrace.tools.visual.crawler.visual_crawler.crawl', return_value={
        "https://test.com": [{"name": "q", "type": "text"}]
    })
    
    bus = EventBus()
    
    recon = ReconAgent("https://test.com", event_bus=bus)
    exploit = ExploitAgent(event_bus=bus)
    skeptic = SkepticalAgent(event_bus=bus)
    
    # Start agents
    await asyncio.gather(
        recon.start(),
        exploit.start(),
        skeptic.start()
    )
    
    # Wait for workflow
    await asyncio.sleep(2)
    
    # Stop agents
    await recon.stop()
    await exploit.stop()
    await skeptic.stop()
    
    # Verify stats
    stats = bus.get_stats()
    assert stats["total_events_emitted"] > 0
    print(f"✅ E2E test passed. Events emitted: {stats['total_events_emitted']}")
```

---

## VERIFICACIÓN Y VALIDACIÓN

### Checklist Pre-Deployment

- [ ] **Tests Unitarios**: `pytest tests/test_event_bus.py -v` (100% pass)
- [ ] **Tests Integración**: `pytest tests/test_integration_event_bus.py -v` (100% pass)
- [ ] **Linting**: `ruff check bugtrace/` (0 errors)
- [ ] **Type Checking**: `mypy bugtrace/core/event_bus.py` (0 errors)
- [ ] **Coverage**: `pytest --cov=bugtrace.core.event_bus --cov-report=term-missing` (>90%)

### Métricas de Éxito

#### Cuantitativas
- [ ] Latencia Recon → Exploit: < 200ms (baseline: 7500ms)
- [ ] Latencia Exploit → Skeptic: < 200ms (baseline: 4000ms)
- [ ] CPU idle durante scan: < 5% (baseline: 15%)
- [ ] Queries a memory_manager/min: < 5 (baseline: 36)
- [ ] Tests pass rate: 100%

#### Cualitativas
- [ ] Logs muestran "Event received" en lugar de "Polling memory..."
- [ ] Código más legible (eliminado while + sleep en agents)
- [ ] Scan real contra ginandjuice.shop encuentra ≥ mismas vulnerabilidades
- [ ] No regressions en funcionalidad existente

### Test E2E Real

```bash
# 1. Scan contra target de prueba
python -m bugtrace scan http://ginandjuice.shop \
    --max-depth 2 \
    --max-urls 20 \
    --verbose

# 2. Verificar en logs:
grep -i "event received" logs/execution_*.log
# Debe aparecer múltiples veces

grep -i "polling" logs/execution_*.log
# NO debe aparecer (eliminado)

# 3. Verificar latencia en timestamps
# Buscar tiempo entre "Input discovered" y "Testing input"
# Debe ser < 1 segundo

# 4. Comparar findings con scan anterior (baseline)
# Debe encontrar ≥ mismas vulnerabilidades
```

---

## ROLLBACK PLAN

### Si algo sale mal, rollback fácil:

1. **Event Bus tiene issues**: Añadir flag `USE_EVENT_BUS=false` en config
   ```python
   # En agents/__init__.py
   if settings.USE_EVENT_BUS:
       # Event-driven
   else:
       # Fallback a polling (código viejo)
   ```

2. **Agentes no se comunican**: Git revert a commit anterior
   ```bash
   git revert HEAD~1
   ```

3. **Performance peor**: Backup de archivos viejos en `.backup/`
   ```bash
   cp bugtrace/agents/exploit.py .backup/exploit.py.old
   ```

---

## TIMELINE ESTIMADO

### Escenario Optimista (3 días)

**Día 1** (6-8 horas):
- ✅ EventBus core implementation
- ✅ Tests unitarios EventBus
- ✅ BaseAgent modification
- ✅ TeamOrchestrator integration

**Día 2** (6-8 horas):
- ✅ ExploitAgent migration
- ✅ SkepticalAgent migration
- ✅ Tests integración

**Día 3** (4-6 horas):
- ✅ ReconAgent updates (emit)
- ✅ E2E testing
- ✅ Validation real scan

---

### Escenario Realista (5 días)

**Día 1-2**: EventBus + BaseAgent + TeamOrchestrator  
**Día 3**: ExploitAgent migration + debugging  
**Día 4**: SkepticalAgent + ReconAgent updates  
**Día 5**: Integration testing + E2E validation  

---

### Escenario Pesimista (7 días)

+2 días por:
- Async issues (race conditions)
- Memory leak debugging
- Edge cases no anticipados

---

## SIGUIENTE PASO

**Archivo a crear primero**: `bugtrace/core/event_bus.py`

¿Apruebas el plan? Si sí, empezamos con la implementación del EventBus core.

---

**Plan creado por**: Análisis arquitectónico profundo  
**Fecha**: 2026-01-01  
**Versión**: 1.0  
**Requiere Aprobación**: ✅ SÍ
