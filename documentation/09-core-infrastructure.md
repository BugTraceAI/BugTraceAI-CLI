# 09 - Infraestructura Core

## Resumen

Documentacion de los subsistemas transversales que soportan todo el pipeline: Event Bus, base de datos, worker pool, semaforos de fase, LLM client, conductor y sistema de memoria.

---

## 1. Event Bus (`core/event_bus.py`)

### Proposito

Sistema pub/sub asincrono que desacopla la comunicacion entre agentes. Todos los agentes se comunican via eventos, nunca con llamadas directas.

### Clase Principal

```python
class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = asyncio.Lock()

    async def emit(self, event: str, data: Dict[str, Any]):
        """Emit event to all subscribers."""
        handlers = self._subscribers.get(event, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def subscribe(self, event: str, handler: Callable):
        """Subscribe to an event."""
        if event not in self._subscribers:
            self._subscribers[event] = []
        self._subscribers[event].append(handler)

    def unsubscribe(self, event: str, handler: Callable):
        """Unsubscribe from an event."""
        if event in self._subscribers:
            self._subscribers[event].remove(handler)
```

### Singleton

```python
# core/event_bus.py
event_bus = EventBus()  # Global singleton

# Usage in agents:
from bugtrace.core.event_bus import event_bus
```

### Catalogo de Eventos

**Pipeline:**
| Evento | Emisor | Receptor | Data |
|--------|--------|----------|------|
| `pipeline_started` | TeamOrchestrator | ServiceEventBus, UI | `{scan_id, target}` |
| `pipeline_complete` | TeamOrchestrator | ServiceEventBus, UI | `{scan_id, findings_count}` |
| `pipeline_error` | TeamOrchestrator | ServiceEventBus, UI | `{scan_id, error}` |
| `pipeline_progress` | TeamOrchestrator | UI | `{phase, progress_pct}` |

**Discovery:**
| Evento | Emisor | Receptor |
|--------|--------|----------|
| `url_discovered` | GoSpiderAgent | DB, DASTySAST |
| `discovery_complete` | GoSpiderAgent | TeamOrchestrator |
| `phase_complete_reconnaissance` | TeamOrchestrator | ServiceEventBus |
| `phase_complete_discovery` | TeamOrchestrator | ServiceEventBus |

**Analysis:**
| Evento | Emisor | Receptor |
|--------|--------|----------|
| `url_analyzed` | DASTySASTAgent | ThinkingConsolidation |
| `discovery.consolidation.completed` | DASTySASTAgent | Metricas |
| `discovery.skeptical.started` | DASTySASTAgent | Metricas |

**Specialist Queues:**
| Evento | Emisor | Receptor |
|--------|--------|----------|
| `work_queued_xss` | ThinkingConsolidation | XSSAgent |
| `work_queued_sqli` | ThinkingConsolidation | SQLiAgent |
| `work_queued_{type}` | ThinkingConsolidation | Specialist |

**Findings:**
| Evento | Emisor | Receptor |
|--------|--------|----------|
| `finding_confirmed` | Specialists | DB, UI |
| `vulnerability_detected` | Specialists | ChainDiscovery |
| `finding_validated` | AgenticValidator | ReportingAgent |
| `finding_rejected` | AgenticValidator | Metricas |
| `validation_complete` | AgenticValidator | TeamOrchestrator |

**UI:**
| Evento | Emisor | Receptor |
|--------|--------|----------|
| `agent_update` | Agents | Dashboard |
| `metrics_update` | WorkerPool | Dashboard |
| `scan_log` | All | Dashboard |

---

## 2. Service Event Bus (`services/event_bus.py`)

### Proposito

Wrapper sobre el EventBus core que agrega:
- Historial de eventos por scan_id
- Streaming async para WebSocket
- Numeros de secuencia para reconexion

### Clase

```python
class ServiceEventBus:
    def __init__(self, core_bus: EventBus):
        self._core_bus = core_bus
        self._event_history: Dict[int, List[Dict]] = {}
        self._scan_queues: Dict[int, List[asyncio.Queue]] = {}
        self._seq_counters: Dict[int, int] = {}
        self._max_history_per_scan = 5000
```

### Streaming para WebSocket

```python
async def stream(self, scan_id: int) -> AsyncIterator:
    """Async generator for real-time event streaming."""
    queue = asyncio.Queue()
    if scan_id not in self._scan_queues:
        self._scan_queues[scan_id] = []
    self._scan_queues[scan_id].append(queue)

    try:
        while True:
            event = await queue.get()
            yield event
    finally:
        self._scan_queues[scan_id].remove(queue)
```

### Reconexion de Clientes

```python
# Client reconnects with last_seq
events = service_bus.get_history(scan_id, since_seq=last_seq)
# Returns only events after last_seq
```

### Mapeo de Eventos a WebSocket Types

```python
MAPPING = {
    "scan.created": "scan_created",
    "scan.completed": "scan_complete",
    "vulnerability_detected": "finding_discovered",
    "pipeline_progress": "progress",
    "error": "error",
}
```

---

## 3. Base de Datos (`core/database.py`)

### DatabaseManager

Gestiona conexiones SQLite via SQLAlchemy async:

```python
class DatabaseManager:
    def __init__(self):
        db_path = settings.BASE_DIR / "bugtrace.db"
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        self.SessionLocal = async_sessionmaker(self.engine)

    async def init_db(self):
        """Create all tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def session(self):
        """Context manager for database sessions."""
        async with self.SessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
```

### Singleton

```python
# Patron singleton via get_instance()
_db_instance = None

def get_instance() -> DatabaseManager:
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager()
    return _db_instance
```

**Nota importante:** `get_instance()` resuelve la ruta SQLite via `settings.BASE_DIR`, que es absoluta (derivada de la ubicacion de `config.py`). No depende del working directory.

### Operaciones Clave

| Metodo | Descripcion |
|--------|-------------|
| `create_scan(target_url, origin)` | Crea scan + target en DB |
| `update_scan_status(scan_id, status)` | Actualiza estado del scan |
| `add_finding(scan_id, finding_data)` | Inserta finding |
| `get_findings(scan_id, filters)` | Query findings con filtros |
| `get_scan(scan_id)` | Obtiene scan por ID |
| `list_scans(page, per_page)` | Lista paginada de scans |
| `delete_scan(scan_id)` | Elimina scan y findings |

### Bug Conocido y Fix

`database.py:385-398`: Se debe extraer `target.id` ANTES de abrir una nueva session para evitar `DetachedInstanceError`:

```python
# CORRECTO
target_id = target.id  # Extract before new session
async with self.session() as session:
    scan = ScanTable(target_id=target_id, ...)
```

---

## 4. Phase Semaphores (`core/phase_semaphores.py`)

### Proposito

Control de concurrencia granular por fase del pipeline.

```python
class ScanPhase(Enum):
    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    LLM_GLOBAL = "llm_global"

_semaphores = {
    ScanPhase.DISCOVERY: asyncio.Semaphore(settings.MAX_CONCURRENT_DISCOVERY),      # 1
    ScanPhase.ANALYSIS: asyncio.Semaphore(settings.MAX_CONCURRENT_ANALYSIS),        # 5
    ScanPhase.EXPLOITATION: asyncio.Semaphore(settings.MAX_CONCURRENT_SPECIALISTS), # 10
    ScanPhase.VALIDATION: asyncio.Semaphore(1),  # HARDCODED - CDP limitation
    ScanPhase.LLM_GLOBAL: asyncio.Semaphore(settings.MAX_CONCURRENT_LLM),          # 2
}
```

### Uso

```python
from bugtrace.core.phase_semaphores import get_semaphore, ScanPhase

async with get_semaphore(ScanPhase.ANALYSIS):
    await analyze_url(url)  # Max 5 concurrent
```

### Semaforo de Reporting

```python
# Separado del sistema de fases
_reporting_semaphore = asyncio.Semaphore(1)

async def get_reporting_semaphore():
    return _reporting_semaphore
```

---

## 5. Worker Pool (`core/worker_pool.py`)

### Proposito

Pool de workers asincrono para ejecutar tareas de especialistas en paralelo.

```python
class WorkerPool:
    def __init__(self, specialist_type: str, max_workers: int = 5):
        self.specialist_type = specialist_type
        self.max_workers = max_workers
        self.queue = asyncio.Queue()
        self.workers: List[asyncio.Task] = []
        self._running = False
```

### Ciclo de Vida

```python
async def start(self):
    """Start worker pool."""
    self._running = True
    for i in range(self.max_workers):
        task = asyncio.create_task(self._worker_loop(i))
        self.workers.append(task)

async def _worker_loop(self, worker_id: int):
    """Main loop for each worker."""
    while self._running:
        try:
            item = await asyncio.wait_for(
                self.queue.get(), timeout=1.0
            )
            await self._process_item(item)
            self.queue.task_done()
        except asyncio.TimeoutError:
            continue  # Check if still running

async def stop(self):
    """Graceful shutdown - drain queue first."""
    self._running = False
    await self.queue.join()  # Wait for remaining items
    for task in self.workers:
        task.cancel()
```

### Metricas del Pool

```python
{
    "queue_depth": self.queue.qsize(),
    "active_workers": len([w for w in self.workers if not w.done()]),
    "items_processed": self._processed_count,
    "throughput_per_sec": self._calculate_throughput(),
}
```

---

## 6. LLM Client (`core/llm_client.py`)

### Proposito

Cliente unificado para llamadas a LLM via OpenRouter.

```python
class LLMClient:
    async def generate(
        self,
        prompt: str,
        system_prompt: str = None,
        model_override: str = None,
        module_name: str = None,
        max_tokens: int = 4000,
    ) -> str:
        """
        Generate LLM response via OpenRouter API.

        Args:
            prompt: User prompt
            system_prompt: System prompt (persona)
            model_override: Override default model
            module_name: Caller identification for logging
            max_tokens: Max response tokens
        """
```

### Rate Limiting

Respeta el semaforo `ScanPhase.LLM_GLOBAL` (default: 2 llamadas concurrentes) para no exceder rate limits de OpenRouter.

### Singleton

```python
llm_client = LLMClient()  # Global singleton
```

---

## 7. Conductor (`core/conductor.py`)

### Proposito

Gestor de system prompts y contexto global para agentes.

```python
class Conductor:
    def get_full_system_prompt(self, agent_type: str = None) -> str:
        """Get system prompt, optionally for specific agent type."""

    def get_context(self, key: str) -> Any:
        """Get global context value (tech_stack, etc.)."""
```

### System Prompts

El Conductor carga prompts base que los agentes pueden extender:
- Prompt de pentest autorizado
- Contexto del target
- Tech stack detectado
- Reglas de seguridad

---

## 8. Memory Manager (`memory/manager.py`)

### Proposito

Sistema de memoria vectorial usando LanceDB para almacenar y recuperar contexto entre agentes.

```python
class MemoryManager:
    async def store(self, key: str, data: Dict, embedding: List[float]):
        """Store data with vector embedding."""

    async def search(self, query_embedding: List[float], top_k: int = 5):
        """Search similar memories by vector similarity."""
```

### Uso

Los agentes usan el memory manager para:
- Almacenar hallazgos previos como contexto
- Recuperar patrones similares para mejorar deteccion
- Compartir conocimiento entre ejecuciones

---

## 9. Safeguard (`utils/safeguard.py`)

### Proposito

Wrapper de seguridad para ejecucion de herramientas externas.

```python
async def run_tool_safely(
    tool_name: str,
    func: Callable,
    *args,
    timeout: float = 60.0,
    **kwargs
) -> Any:
    """
    Execute a tool function with timeout and error isolation.
    Prevents agent crashes due to tool failures.
    """
    try:
        result = await asyncio.wait_for(
            func(*args, **kwargs),
            timeout=timeout
        )
        return result
    except asyncio.TimeoutError:
        logger.error(f"Tool {tool_name} timed out after {timeout}s")
        return None
    except Exception as e:
        logger.error(f"Tool {tool_name} failed: {e}")
        return None
```

Cada agente usa `self.exec_tool()` (heredado de BaseAgent) para ejecutar herramientas de forma segura.
