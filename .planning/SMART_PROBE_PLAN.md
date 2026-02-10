# Plan: Razonamiento Continuo — XSS, CSTI y LoneWolf

## Problema

BugTraceAI tarda 30 min para 2 URLs. Claude Code vanilla con WebFetch encuentra SQLi+XSS en 5 min haciendo: fetch → razonar → 1 probe inteligente → confirmar.

BugTraceAI usa "escalacion fija": L1→L2(882 payloads)→L3(100 LLM)→L4→L5→L6 para CADA parametro, aunque no refleje nada. El 70% del tiempo son llamadas LLM innecesarias (25+ round-trips a DeepSeek/Grok).

El DRY file ya tiene un campo `attack_strategy` con razonamiento LLM (ej: "GET param reflects inside unescaped JavaScript single-quoted string. Use backslash-quote breakout"). Pero se ignora y se bombardea igual.

## Objetivo

- Scan completo de 2 URLs: de 30 min a <10 min
- XSS confirma vuln en <5 requests inteligentes (no 882 brutos)
- CSTI confirma vuln en <3 requests
- LoneWolf activo y persistente en paralelo
- Reducir LLM calls de 25+ a ~5

## Contexto del Codebase

Lee primero estos archivos para entender la arquitectura:
- `.claude/CLAUDE.md` — arquitectura completa, pipeline, specialists
- `bugtrace/agents/xss_agent.py` — XSSAgentV4, escalacion L1-L6, `_xss_escalation_pipeline()`, `exploit_dry_list()`
- `bugtrace/agents/csti_agent.py` — CSTIAgent, escalacion L0-L6, `_csti_escalation_pipeline()`
- `bugtrace/core/lone_wolf.py` — agente autonomo paralelo, raw HTTP + LLM reasoning
- `bugtrace/core/config.py` — 100+ settings, modelos LLM, timeouts
- `bugtrace/agents/reporting.py` — generacion de reportes, CVSS enrichment
- `.claude/projects/-home-albert-Tools-BugTraceAI-BugTraceAI-CLI/memory/MEMORY.md` — memoria persistente, bugs resueltos, patterns

## Cambio 1: XSS — Smart Probing antes de bombardeo

**Archivo**: `bugtrace/agents/xss_agent.py`
**Donde**: En `_xss_escalation_pipeline()`, ANTES de L1

Nuevo nivel L0.5 "Smart Probe":

1. Leer el `attack_strategy` del finding DRY
2. Enviar 1 probe con el OMNI_PROBE_MARKER al parametro via `_send_payload()`
3. Analizar la respuesta:
   - Si NO refleja → SKIP este param entero (no L1, no L2, no L3, nada). Log: `"Smart probe: no reflection for '{param}', skipping"`
   - Si refleja → detectar contexto y chars que sobreviven
4. Si refleja, generar 3-5 payloads ESPECIFICOS basados en el contexto detectado:
   - JS single-quote string + backslash not escaped → `\';{payload}//`
   - JS double-quote string + backslash not escaped → `\";{payload}//`
   - HTML body + `<` sobrevive → `<svg onload={payload}>`
   - HTML attribute + `"` sobrevive → `" onmouseover={payload} x="`
   - Script tag + `</script>` sobrevive → `</script><script>{payload}</script>`
5. Enviar esos 3-5 payloads. Si uno confirma → FINDING → STOP. Log: `"Smart probe: CONFIRMED XSS on '{param}' with {payload}"`
6. SOLO si refleja pero ningun smart payload confirma → continuar a L2 (Go fuzzer 882)

**Referencia de codigo existente**:
- `_send_payload()` ya tiene branch GET/POST — reutilizar
- `_can_confirm_from_http_response()` ya valida XSS — reutilizar
- `_payload_reflects()` ya detecta reflexion — reutilizar
- La logica de "que caracteres sobreviven" ya existe en DASTySAST `_run_reflection_probes()` en `analysis_agent.py` — misma tecnica: enviar `BT7331"'<>\`` y buscar en response

**Payloads de smart probe** (NUNCA alert(1), siempre impacto real):
```python
SMART_PAYLOADS = {
    "js_single_quote_breakout": "\\';document.title=document.domain//",
    "js_double_quote_breakout": "\\\";document.title=document.domain//",
    "html_body_svg": "<svg onload=document.title=document.domain>",
    "html_body_img": "<img src=x onerror=document.title=document.domain>",
    "html_attr_breakout": "\" onmouseover=document.title=document.domain x=\"",
    "script_breakout": "</script><script>document.title=document.domain</script>",
}
```

## Cambio 2: XSS — Skip L3 si L2 tiene 0 reflexiones

**Archivo**: `bugtrace/agents/xss_agent.py`
**Donde**: En `_escalation_l2_static_bombing()`, despues de que Go fuzzer devuelve resultados

Si Go fuzzer devuelve 0 reflections:
- NO escalar a L3 (ahorra 1 LLM call de ~15s por param)
- NO escalar a L4 Manipulator
- Ir a L5 browser SOLO si contexto es DOM-related (`event_handler`, `form_input`, `anchor_href`)
- Si no es DOM-related → SKIP param completamente. Log: `"L2: 0 reflections, skipping L3+L4 for '{param}'"`

En ginandjuice.shop esto elimina ~9 LLM calls innecesarias (9 de 11 params no reflejan).

## Cambio 3: CSTI — Smart Probing

**Archivo**: `bugtrace/agents/csti_agent.py`
**Donde**: En `_csti_escalation_pipeline()`, ANTES de L0 (wet payload)

Smart Probe para CSTI:

1. Enviar polyglot `{{7*7}}${7*7}<%= 7*7 %>` al parametro
2. Analizar response:
   - Si "49" aparece Y "7*7" NO aparece → template engine evaluo → FINDING directo (o confirmar con 1-2 payloads mas especificos del engine)
   - Si la sintaxis template refleja pero NO evalua (ej: `{{7*7}}` aparece literal) → engine existe pero sandbox/escape activo → continuar escalacion normal
   - Si NADA de template syntax refleja → SKIP param. Log: `"CSTI Smart probe: no template reflection for '{param}', skipping"`
3. Si evaluo, detectar engine:
   - `{{7*7}}` evaluo → Angular/Jinja2/Twig → probar `{{constructor.constructor("document.title=document.domain")()}}` (Angular) o `{{config}}` (Jinja2)
   - `${7*7}` evaluo → Freemarker/Mako
   - `<%= 7*7 %>` evaluo → ERB/EJS

Para CSTI el smart probe es extremadamente efectivo porque la confirmacion es binaria: evaluo 7*7=49 si o no. 1-3 requests basta.

## Cambio 4: LoneWolf — Activar y persistir

**Archivos**: `bugtrace/core/config.py`, `bugtrace/core/lone_wolf.py`

### config.py
- Cambiar `LONEWOLF_ENABLED` default a `True`

### lone_wolf.py
El loop de razonamiento debe ser PERSISTENTE:
- Si encuentra una vuln → emitir finding via event_bus → SEGUIR buscando mas (no parar)
- Si no encuentra en un endpoint → probar otro endpoint/param
- Solo parar cuando: timeout alcanzado (`LONEWOLF_TIMEOUT`) O todos los endpoints/params probados
- Asegurar que findings se integran en el pipeline (emit via `event_bus.emit_finding()`)

LoneWolf ya hace razonamiento continuo (raw HTTP + LLM). Solo necesita:
1. No parar al primer finding
2. Cubrir todos los params descubiertos de las URLs
3. Emitir findings correctamente al pipeline

## Cambio 5: Batch CVSS en reporting

**Archivo**: `bugtrace/agents/reporting.py`
**Donde**: `_enrich_findings_with_cvss()`

En vez de 1 LLM call por finding (9 calls × ~20s = 3 min):
- Hacer 1 BATCH call con todos los findings juntos
- El LLM puede asignar CVSS a 9 findings en 1 sola llamada (~20s total)
- Agrupar findings en chunks de max 10 si hay muchos

Esto ahorra ~2.5 min y reduce coste de API.

## Archivos a tocar

| Archivo | Cambio |
|---------|--------|
| `bugtrace/agents/xss_agent.py` | Smart probe L0.5 + skip L3 si 0 reflections |
| `bugtrace/agents/csti_agent.py` | Smart probe antes de L0 |
| `bugtrace/core/lone_wolf.py` | Persistir hasta exito, no parar al primer finding |
| `bugtrace/core/config.py` | LONEWOLF_ENABLED = True |
| `bugtrace/agents/reporting.py` | Batch CVSS enrichment |
| Memory files | Actualizar tras cada cambio |

## Verificacion

### Paso 1: Tests unitarios
```bash
cd /home/albert/Tools/BugTraceAI/BugTraceAI-CLI
python3 -m pytest tests/ -x -q 2>&1 | tail -20
```

### Paso 2: Test con WET files existentes (SIN scan completo)

Los WET/DRY files de scans anteriores estan en:
- `reports/ginandjuice.shop_20260210_041035/specialists/wet/`
- `reports/ginandjuice.shop_20260210_041035/specialists/dry/`
- `reports/ginandjuice.shop_20260210_041035/dastysast/`

Escribir un test script `/tmp/test_smart_probe.py` que:
1. Lea el `xss_dry.json` y `csti_dry.json` existentes
2. Instancie XSSAgentV4 y CSTIAgent con los findings del DRY
3. Ejecute SOLO la fase de explotacion (`exploit_dry_list`) contra ginandjuice.shop en vivo
4. Mida el tiempo total
5. Verifique que:
   - XSS smart probe funciona (params sin reflexion se skipean)
   - XSS confirma `searchTerm` en <5 requests (no 882)
   - CSTI confirma `category` con `{{7*7}}` en <3 requests
   - Tiempo total de XSS + CSTI < 2 minutos (antes era 20+ min)

Referencia de test scripts anteriores:
- `/home/albert/Tools/BugTraceAI/BugTraceAI-CLI/test_gap_fixes.py`
- `tests/unit/test_discovery_methods.py`

### Paso 3: Scan completo (solo si paso 1 y 2 pasan)
```bash
./bugtraceai-cli full https://ginandjuice.shop/ -ul urls.txt 2>&1 | tee /tmp/scan_test.log
```

Monitorear que:
- XSS smart probe: `"Smart probe: X reflects, Y chars survive"`
- Params sin reflexion se skipean: `"Smart probe: no reflection, skipping"`
- L3 no se ejecuta cuando L2=0 reflections: `"L2: 0 reflections, skipping L3+L4"`
- CSTI smart probe: `"CSTI Smart probe: 49 detected, template engine evaluates"`
- LoneWolf activo: `"[LoneWolf] Started autonomous hunting"`
- **Scan total < 10 minutos**

## Reglas CRITICAS

1. **NUNCA usar `alert(1)` como payload XSS** — usar `document.domain`, `document.title=document.domain`, o payloads visuales ("HACKED BY BUGTRACEAI")
2. **NUNCA hacer SELECT en la DB desde CLI** — DB es write-only. Fuente de verdad = JSON files en disco
3. **Actualizar memoria** despues de cada cambio significativo: `.claude/projects/-home-albert-Tools-BugTraceAI-BugTraceAI-CLI/memory/MEMORY.md`
4. **No romper tests existentes**
5. **Martillo simple, no pneumatico** — preferir soluciones directas. No sobreingeniear.
6. **No crear archivos innecesarios** — editar los existentes
