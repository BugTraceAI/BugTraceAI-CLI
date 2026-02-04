# BugTraceAI - Claude Memory

## Current Issue: XSS Detection on ginandjuice.shop

### Problem Statement
The XSSAgent is NOT finding the XSS vulnerability on ginandjuice.shop. We accidentally "fixed" it by adding CSTI detection, but that's the wrong approach - CSTI should be handled by CSTIAgent, not XSSAgent.

### What We Know About ginandjuice.shop

**Reflection Points:**
1. Hidden input: `<input hidden type=text name="category" value="USER_INPUT">`
2. JS variable: `const selectedCategory = "USER_INPUT";`

**Server Behavior:**
- Single quote `'` alone → 500 Internal Server Error
- Double quote `"` → escaped to `\"`
- Backslash `\` → escaped to `\\`
- HTML chars `<>` → encoded to `&lt;&gt;` in HTML context

**Angular CSTI (NOT our target):**
- Has `ng-app` on body
- `{{7*7}}` evaluates to `49`
- `{{constructor.constructor("alert(1)")()}}` works
- This is CSTI, handled by CSTIAgent

### What We Need To Fix

The XSSAgent needs to find actual XSS, not rely on CSTI as a fallback.

**Possible XSS vectors to investigate:**
1. Does the server really escape ALL quotes? Or just in certain contexts?
2. Is there a way to break out of the JS string without quotes?
3. Are there other parameters or endpoints with XSS?
4. DOM XSS via other sources (hash, referrer, postMessage)?

### Changes Made

1. **Probe string changed:** `BT7331'"<>&` → `BT7331"<>&` (removed single quote)
   - This was correct - single quotes cause 500 errors

2. **CSTI removed from XSSAgent** ✅ (2026-02-04)
   - Reverted all Angular CSTI code from XSSAgent
   - XSSAgent now only detects XSS, not CSTI

3. **CSTIAgent enhanced** ✅ (2026-02-04)
   - Added double-quote Angular payloads for servers that error on single quotes
   - Added: `{{constructor.constructor("alert(1)")()}}` and variants

### Investigation Results (2026-02-04)

**Tested escaping behavior on ginandjuice.shop:**
| Input | HTML context | JS context |
|-------|-------------|-----------|
| `"` | `&quot;` | `\"` |
| `\` | `\\` | `\\` |
| `<>` | `&lt;&gt;` | passed through |
| `</script>` | `&lt;/script&gt;` | `<\/script>` |
| `\u0022` | - | `\\u0022` (escaped) |

**Conclusion for `category` parameter:** Does NOT have traditional XSS.
The escaping is robust - only Angular CSTI exists (CSTIAgent's territory).

### ACTUAL XSS FOUND: `searchTerm` parameter

**Different parameter, different escaping!**

```
var searchText = 'USER_INPUT';  ← single quotes, vulnerable to \'
```

**Backslash-quote breakout works:**
- Input: `\'`
- Server escapes `\` to `\\` but NOT the quote
- Result: `\\'` = escaped backslash + **unescaped quote breaks out!**

**Working payload:**
```
\';{const d=document.createElement(`div`);d.setAttribute(`style`,`position:fixed;top:0;width:100%;background:red;color:white;text-align:center;z-index:9999;padding:10px`);d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d)};//
```

**Why XSSAgent didn't find it:**
1. The scan URL was `?category=Juice` - searchTerm wasn't in the URL
2. **ROOT CAUSE #1:** `MAX_URLS = 1` in config causes form extraction to be SKIPPED!
   - Code at external.py:587 skips form params when `len(unique_urls) >= max_urls`
   - With MAX_URLS=1, this happens immediately
3. **ROOT CAUSE #2:** DASTySAST only probes params IN THE URL, not from HTML forms!
   - Code at analysis_agent.py:182-186 uses `parse_qs(parsed.query)` - only URL params
   - Even if HTML contains `<input name="searchTerm">`, it's never tested
4. XSSAgent HAS the right payloads (line 169 in xss_agent.py), just needs the parameter

**FIX #1:** ✅ FIXED (2026-02-04) - Form params now always extracted regardless of MAX_URLS
- Changed external.py:584-593 to always run form extraction
- Form param URLs added with high priority (at front of list)

**FIX #2:** ✅ FIXED (2026-02-04) - Backslash-quote breakouts added to ALL payload files
- `xss_agent.py` GOLDEN_PAYLOADS: moved to positions 0-3
- `tools/go-xss-fuzzer/payloads/xss_payloads.txt`: added at top
- `bugtrace/data/xss_curated_list.txt`: added visual versions

**FIX #3:** ✅ FIXED (2026-02-04) - DASTySAST now extracts params from HTML forms
- Added `_extract_html_params()` method to analysis_agent.py
- Modified `_run_reflection_probes()` to combine URL params + HTML form params
- Now when DASTySAST analyzes `?category=Juice`, it also probes `searchTerm` from the form
- Key change: DASTySAST probes ALL discoverable parameters, not just those in the URL

### Next Steps

1. ~~Remove CSTI detection from XSSAgent~~ ✅ DONE
2. ~~Pass double-quote knowledge to CSTIAgent~~ ✅ DONE
3. ~~Investigate if there's actual XSS on ginandjuice.shop~~ ✅ DONE - No traditional XSS exists
4. Test XSSAgent on a target with confirmed XSS (e.g., OWASP WebGoat, DVWA, or other intentionally vulnerable apps)

### Key Files

- `bugtrace/agents/xss_agent.py` - XSS detection agent
- `bugtrace/agents/csti_agent.py` - CSTI detection agent
- `bugtrace/agents/analysis_agent.py` - DASTySAST agent (FIX #3: now extracts HTML form params)
- `bugtrace/payloads/breakouts.json` - Breakout prefixes for payload generation
- `bugtrace/tools/external.py` - GoSpider/form extraction (FIX #1: always runs now)

### breakouts.json - Relevant Entries

```json
{"prefix": "\\'", "description": "Backslash-escaped single quote (JS string breakout)", "priority": 1, "success_count": 1},
{"prefix": "\\\"", "description": "Backslash-escaped double quote (JS string breakout)", "priority": 1},
{"prefix": "\\';", "description": "Backslash single quote + semicolon (ginandjuice killer)", "priority": 1, "success_count": 1},
{"prefix": "\\\";", "description": "Backslash double quote + semicolon", "priority": 1}
```

These breakouts are used when a server escapes `\` to `\\` but doesn't escape quotes.
- `\'` becomes `\\'` = escaped backslash + unescaped quote = **BREAKOUT**

---

## XSSAgent Internal Pipeline v2 (Optimizado)

### Filosofía: Bombardeo Primero, Análisis Después

El pipeline está optimizado para velocidad y eficiencia:
1. **Bombardear** con todos los payloads de una vez
2. **Analizar** las respuestas
3. **Amplificar** solo lo que mostró promesa
4. **Validar** solo si es necesario (skip si Interactsh confirmó)

### Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 0: WAF Detection (opcional, Q-Learning)                  │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: BOMBARDEO TOTAL (Go fuzzer)                           │
│                                                                 │
│  Dispara TODO de una vez:                                       │
│  • OMNIPROBE_PAYLOAD (para detectar contexto)                   │
│  • curated_list (payloads probados)                             │
│  • proven_payloads (memoria dinámica)                           │
│  • GOLDEN_PAYLOADS                                              │
│                                                                 │
│  NO PARAR - recolectar TODAS las respuestas                     │
│  → Guardar: phase1_bombardment.md                               │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: ANÁLISIS (Python)                                     │
│                                                                 │
│  • ¿Qué payloads reflejaron?                                    │
│  • ¿En qué contexto? (JS string, HTML attr, etc.)               │
│  • ¿Qué escaping aplicó el server?                              │
│  • ¿Interactsh callback recibido? → FINDING directo             │
│                                                                 │
│  → Guardar: phase2_analysis.md                                  │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
              ¿XSS confirmado (Interactsh/ejecución clara)?
                    │                    │
                   NO                   YES → Skip to PHASE 4
                    ↓
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: AMPLIFICACIÓN INTELIGENTE                             │
│                                                                 │
│  Step 3.1: LLM genera ~100 payloads visuales                    │
│    • Input: payloads que REFLEJARON + contexto detectado        │
│    • Output: variantes con "HACKED BY BUGTRACEAI"               │
│                                                                 │
│  Step 3.2: Multiplicar × breakouts.json                         │
│    • 100 payloads × 13 prefixes = ~1300 payloads                │
│                                                                 │
│  Step 3.3: Segundo bombardeo focalizado (Go fuzzer)             │
│                                                                 │
│  → Guardar: phase3_amplified.md                                 │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: VALIDATION (condicional)                              │
│                                                                 │
│  ¿Necesita Playwright?                                          │
│  • Interactsh confirmó → NO (skip, guardar finding)             │
│  • Contexto ejecutable sin encoding → NO (alta confianza)       │
│  • Reflexión dudosa → SÍ (validar visualmente)                  │
│                                                                 │
│  Si Playwright necesario:                                       │
│  • Seleccionar top min(N, 10) candidates                        │
│  • URL encode para navegador                                    │
│  • Screenshot si ve "HACKED BY BUGTRACEAI"                      │
│                                                                 │
│  → Guardar: phase4_results.md + screenshots/                    │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
                         FINDING o None
```

### Criterios para SKIP Playwright

| Condición | Confianza | Acción |
|-----------|-----------|--------|
| Interactsh callback recibido | 100% | Skip → FINDING directo |
| Payload en `<script>` sin encoding | 95% | Skip (opcional screenshot) |
| Payload en `onerror=` sin encoding | 90% | Skip (opcional screenshot) |
| Reflexión con encoding parcial | 60% | Usar Playwright |
| Contexto dudoso (hidden, comment) | 40% | Usar Playwright |

### Reports Structure

```
reports/target_YYYYMMDD_HHMMSS/
├── specialists/
│   └── xss/
│       ├── phase1_bombardment.md   ← Todos los payloads enviados
│       ├── phase2_analysis.md      ← Reflexiones + contextos
│       ├── phase3_amplified.md     ← Payloads LLM + breakouts
│       ├── phase4_results.md       ← Resultados finales
│       └── screenshots/            ← Evidencia visual
```

### Key Methods (xss_agent.py)

| Phase | Method | Tool | Output |
|-------|--------|------|--------|
| 0 | WAF detection | Q-Learning | waf_fingerprint |
| 1 | `_phase1_bombardment()` | Go fuzzer | phase1_bombardment.md |
| 2 | `_phase2_analysis()` | Python | phase2_analysis.md |
| 3.1 | `_phase3_llm_visual()` | LLM | 100 visual payloads |
| 3.2 | `_phase3_amplify()` | Python | 1300 amplified payloads |
| 3.3 | `_phase3_attack()` | Go fuzzer | reflections |
| 4 | `_phase4_validation()` | Playwright | screenshots + FINDING |

### Payload Priority (PayloadLearner)

```
1️⃣ curated_list (bugtrace/data/xss_curated_list.txt)   ← MÁXIMA
2️⃣ proven_payloads (xss_proven_payloads.json)          ← Memoria dinámica
3️⃣ GOLDEN_PAYLOADS (xss_agent.py)                      ← Defaults
```

### OMNIPROBE_PAYLOAD (incluido en Phase 1)

```
BT7331'"<>`\\'\\\"
```

| Char | Test |
|------|------|
| `BT7331` | Unique marker to find reflection |
| `'` | Single quote |
| `"` | Double quote |
| `<>` | HTML tags |
| `` ` `` | Backtick (template literal) |
| `\\'` | Backslash + single quote |
| `\\"` | Backslash + double quote |

**Purpose:** Detectar contexto y escaping. NO CSTI (CSTIAgent).

### XSS Payload Files

| File | Purpose | Usado en |
|------|---------|----------|
| `bugtrace/data/xss_curated_list.txt` | Payloads curados (prioridad 1) | Phase 1 |
| `bugtrace/data/xss_proven_payloads.json` | Memoria dinámica (prioridad 2) | Phase 1 |
| `bugtrace/agents/xss_agent.py` | GOLDEN_PAYLOADS (prioridad 3) | Phase 1 |
| `bugtrace/payloads/breakouts.json` | Prefijos para amplificación | Phase 3.2 |
| `tools/go-xss-fuzzer/payloads/xss_payloads.txt` | ⚠️ Solo uso manual del Go fuzzer | N/A |

---

## DASTySAST Parameter Discovery Flow (FIX #3)

### Problema Original

DASTySAST solo probaba parámetros que ya estaban en la URL:

```
URL: ?category=Juice
Params probados: category ← Solo este
Params ignorados: searchTerm (existía en el HTML form)
```

### Flujo Actual (Post-Fix)

```
┌─────────────────────────────────────────────────────────────────┐
│  1. FETCH HTML                                                  │
│     browser_manager.capture_state(url)                          │
│     → HTML completo de la página                                │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. EXTRACT URL PARAMS                                          │
│     parse_qs(urlparse(url).query)                               │
│     → {"category": ["Juice"]}                                   │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. EXTRACT HTML FORM PARAMS (NUEVO - FIX #3)                   │
│     _extract_html_params(html)                                  │
│     → Parsea <form> tags con BeautifulSoup                      │
│     → Extrae <input>, <textarea>, <select> con name=            │
│     → Excluye: submit, button, csrf tokens                      │
│     → ["searchTerm", "category"]                                │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  4. COMBINE PARAMS                                              │
│     all_params = URL_params ∪ HTML_params                       │
│     → {"category": ["Juice"], "searchTerm": [""]}               │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│  5. PROBE ALL PARAMS                                            │
│     Para cada param en all_params:                              │
│       → Inyectar OMNI_PROBE_MARKER                              │
│       → Analizar reflexión y contexto                           │
│       → Detectar: script_block, html_attr, html_text, etc.      │
└────────────────────────────┬────────────────────────────────────┘
                             ↓
                    reflection_probes[] → LLM Analysis
```

### Ejemplo Real (ginandjuice.shop)

**Input:** `https://ginandjuice.shop/catalog?category=Juice`

**HTML contiene:**
```html
<form action="/catalog" method=GET>
    <input type=text name="searchTerm">     ← NUEVO: Extraído del HTML
    <input hidden name="category" value="Juice">
</form>
```

**Log output:**
```
[DASTySASTAgent] Extracted 2 params from HTML forms: ['searchTerm', 'category']
[DASTySASTAgent] Probing 2 params: ['category', 'searchTerm']
[DASTySASTAgent] 🔍 category: script_block (chars survive: )
[DASTySASTAgent] 🔍 searchTerm: script_block (chars survive: )
```

**Resultado:** Ahora encuentra XSS en `searchTerm` aunque no estaba en la URL original.

### Código Clave (analysis_agent.py)

```python
# _run_reflection_probes() - Líneas 167-239
url_params = parse_qs(parsed.query)
html_params = self._extract_html_params(html_content)  # NUEVO

all_param_names = set(url_params.keys())
for html_param in html_params:
    if html_param not in all_param_names:
        all_param_names.add(html_param)
        url_params[html_param] = [""]  # Default vacío

# Ahora prueba TODOS los params
for param_name in all_param_names:
    # ... probe logic ...
```

### _extract_html_params() - Líneas 241-299

Extrae parámetros de formularios HTML:
- Parsea con BeautifulSoup
- Busca `<input>`, `<textarea>`, `<select>` con `name=`
- Excluye: `type=submit/button`, tokens CSRF
- Incluye `type=hidden` (pueden ser vulnerables)
