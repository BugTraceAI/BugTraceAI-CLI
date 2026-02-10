# Plan: Fix Regressions del Smart Probe v3.5

## Contexto

Tras implementar Smart Probe v3.5, el scan paso de 30 min a 11 min (mejora). Pero hay regresiones:

- CSTI: 0 validated findings (antes encontraba Angular CSTI en `category`)
- XSS: 1 validated (antes 2 — falta `category` via Manipulator)
- Invalid JSON en WET files (csti.json, idor.json, xss.json)
- LoneWolf: 49 ciclos, 0 findings, quemando API (ya desactivado en .conf)

## Bug 1: CSTI auto-dispatch inyecta `_auto_dispatch` en vez de param real

**Archivo**: `bugtrace/core/team.py`
**Donde**: `_phase_3_strategy()`, seccion de auto-dispatch CSTI

**Problema**: El auto-dispatch inyecta un finding sintetico con `parameter: "_auto_dispatch"`. El CSTIAgent recibe este finding pero `_auto_dispatch` no es un parametro real de la pagina — no se puede inyectar `{{7*7}}` en el.

**Scan anterior (funcionaba)**: El auto-dispatch inyectaba con parametros reales que reflejaban.

**DRY actual** (roto):
```json
{"parameter": "_auto_dispatch", "url": "https://ginandjuice.shop/"}
```

**DRY esperado** (correcto):
```json
{"parameter": "category", "url": "https://ginandjuice.shop/catalog?category=Juice"}
```

**Fix**: En `_phase_3_strategy()`, cuando se hace auto-dispatch de CSTI:
1. Buscar en los findings de DAST cuales tienen parametros que reflejan (cualquier finding con `parameter` != None)
2. Usar esos parametros reales + sus URLs para el finding sintetico
3. Si no hay parametros disponibles, usar los de las URLs del scan (extraer query params)
4. El finding sintetico debe tener `url` del endpoint real donde esta el param, no solo el target base

**Buscar en team.py**: `auto_dispatch` o `synthetic` o `_auto_dispatched` para encontrar la seccion exacta.

**Test unitario** (NO necesita HTTP):
```python
# test_csti_autodispatch.py
"""Verify auto-dispatch injects real parameters, not _auto_dispatch."""

def test_csti_autodispatch_uses_real_params():
    """Auto-dispatch should use reflecting params from DAST findings."""
    # Simulate DAST findings with real params
    dast_findings = [
        {"url": "https://example.com/catalog?category=test", "parameter": "category", "vuln_type": "XSS"},
        {"url": "https://example.com/search?q=test", "parameter": "q", "vuln_type": "XSS"},
    ]
    tech_profile = {"frameworks": ["AngularJS"]}

    # Run strategy phase logic (extract the auto-dispatch function or simulate it)
    # The synthetic CSTI finding should have:
    # - parameter: "category" (or "q") — NOT "_auto_dispatch"
    # - url: "https://example.com/catalog?category=test" — NOT just "https://example.com/"

    # Assert synthetic finding has real param
    assert synthetic_finding["parameter"] != "_auto_dispatch"
    assert synthetic_finding["parameter"] in ["category", "q"]
    assert "?" in synthetic_finding["url"]  # URL has query params
```

## Bug 2: CSTI smart probe no se ejecuta o no logea

**Archivo**: `bugtrace/agents/csti_agent.py`
**Donde**: `_csti_escalation_pipeline()` o `_escalation_smart_probe_csti()`

**Problema**: En los logs del scan no aparece ningun mensaje de smart probe CSTI. Ni "Smart probe: no reflection" ni "Smart probe: CONFIRMED". Parece que el smart probe no se esta llamando.

**Verificar**:
1. Que `_escalation_smart_probe_csti()` se llama desde `_csti_escalation_pipeline()` ANTES de L0
2. Que el finding tiene los campos necesarios (url, parameter)
3. Que el probe `BT_CSTI_49{{7*7}}${7*7}` se envia correctamente
4. Que el log funciona

**Test unitario** (NO necesita HTTP, mockear _send_payload):
```python
# test_csti_smart_probe.py
"""Verify CSTI smart probe is called and handles responses correctly."""
from unittest.mock import AsyncMock, patch

async def test_csti_smart_probe_detects_evaluation():
    """Smart probe should detect {{7*7}}=49."""
    # Mock HTTP response containing "49" but not "7*7"
    mock_response = "BT_CSTI_49 result is 49 and more text"

    # The smart probe should:
    # 1. Send "BT_CSTI_49{{7*7}}${7*7}"
    # 2. See "49" in response
    # 3. See "7*7" NOT in response (template engine evaluated it)
    # 4. Return confirmed=True

    assert result.confirmed == True

async def test_csti_smart_probe_skips_no_reflection():
    """Smart probe should skip if probe doesn't reflect at all."""
    mock_response = "Page without any probe reflection"

    # BT_CSTI_49 not in response → skip
    assert should_continue == False

async def test_csti_smart_probe_continues_on_literal_reflection():
    """Smart probe should continue escalation if template reflects literally."""
    mock_response = "BT_CSTI_49{{7*7}}${7*7} reflected literally"

    # Template syntax reflects but didn't evaluate → continue to L0
    assert should_continue == True
```

## Bug 3: XSS smart probe — verificar que funciona para `searchTerm`

**Archivo**: `bugtrace/agents/xss_agent.py`
**Donde**: `_escalation_l05_smart_probe()`

**Problema**: XSS solo valido 1 finding (searchTerm via L2). El smart probe deberia haber encontrado `searchTerm` en 3-5 requests. Verificar que:
1. Smart probe se ejecuta
2. Detecta reflexion de `searchTerm` en JS string context
3. Envia payload correcto (backslash-quote breakout)
4. `category` no se perdio (aunque sea via Manipulator como antes)

**Test unitario** (NO necesita HTTP):
```python
# test_xss_smart_probe.py
"""Verify XSS smart probe generates correct context-specific payloads."""

def test_smart_probe_js_single_quote_context():
    """For JS single-quote string, smart probe should try backslash-quote breakout."""
    # Simulate: probe reflects in JS string context
    # var searchText = 'BT7331"\'<>\\`';
    # Chars surviving: " < > ` (single quote causes 500, backslash escaped)

    surviving_chars = '"<>`'
    context = "javascript"

    # Smart probe should generate payloads including:
    # - \\';document.title=document.domain//  (JS single-quote breakout)
    # Should NOT include:
    # - alert(1)

    payloads = generate_smart_payloads(surviving_chars, context)
    assert any("\\'" in p for p in payloads), "Should include backslash-quote breakout"
    assert not any("alert(1)" in p for p in payloads), "NEVER alert(1)"

def test_smart_probe_no_reflection_skips():
    """If probe doesn't reflect, skip all levels."""
    # Simulate: BT7331 marker NOT in response
    reflects = False

    # Should return: skip=True, no payloads generated
    assert skip == True
```

## Bug 4: Invalid JSON en WET files

**Archivos**: El scan genero WET files con JSON invalido:
```
WARNING | Invalid JSON in .../specialists/wet/csti.json
WARNING | Invalid JSON in .../specialists/wet/idor.json
WARNING | Invalid JSON in .../specialists/wet/xss.json
```

**Donde buscar**: La funcion que escribe WET files esta en `specialist_utils.py` (`write_wet_file` o similar) o en cada specialist's Phase A.

**Problema**: Posiblemente la sesion anterior rompio algo en el formato de escritura de WET files. O el queue file mode esta escribiendo JSON invalido.

**Verificar**:
```bash
python3 -c "
import json
for f in ['csti', 'idor', 'xss']:
    path = 'reports/ginandjuice.shop_20260210_090104/specialists/wet/{}.json'.format(f)
    try:
        json.load(open(path))
        print(f'{f}: OK')
    except Exception as e:
        print(f'{f}: INVALID - {e}')
        # Print first 200 chars to see what's wrong
        with open(path) as fh:
            print(fh.read()[:200])
"
```

**Fix**: Depende de lo que encuentres. Probablemente el queue file mode esta appendeando JSON objects sin wrapping en array, o hay caracteres extra.

## Bug 5: Reporting ejecuta 2 veces

En los logs, el ReportingAgent escribio `engagement_data.json` y `final_report.md` DOS veces. Posible duplicacion en el pipeline. Investigar pero es baja prioridad — no afecta findings.

## Orden de prioridad

1. **Bug 1** (CSTI auto-dispatch) — CRITICO, causa 0 CSTI findings
2. **Bug 2** (CSTI smart probe no logea) — ALTO, puede causar skips incorrectos
3. **Bug 4** (Invalid JSON WET) — MEDIO, puede afectar validator
4. **Bug 3** (XSS smart probe verificacion) — MEDIO, confirmar que funciona
5. **Bug 5** (Reporting duplicado) — BAJO

## Archivos a tocar

| Archivo | Bug | Cambio |
|---------|-----|--------|
| `bugtrace/core/team.py` | #1 | Auto-dispatch usa params reales |
| `bugtrace/agents/csti_agent.py` | #2 | Verificar smart probe se ejecuta |
| `bugtrace/agents/specialist_utils.py` | #4 | Fix JSON writing si es aqui |
| `bugtrace/agents/xss_agent.py` | #3 | Verificar smart probe (puede estar OK) |

## Verificacion final

Despues de arreglar todos los bugs, ejecutar el scan:
```bash
cd /home/albert/Tools/BugTraceAI/BugTraceAI-CLI
./bugtraceai-cli full https://ginandjuice.shop/ -ul urls.txt 2>&1 | tee /tmp/scan_post_fix.log
```

**Resultado esperado**:
- CSTI: al menos 1 validated finding (category param, Angular `{{7*7}}`=49)
- XSS: al menos 2 validated findings (searchTerm + category)
- Scan total < 12 minutos
- No warnings de "Invalid JSON" en WET files
- LoneWolf no arranca (ENABLED=False)

## Reglas

1. **NUNCA usar alert(1)** — usar document.domain o payloads visuales
2. **NUNCA hacer SELECT en DB** — CLI es write-only
3. **Actualizar memoria** despues de cada fix: `.claude/projects/-home-albert-Tools-BugTraceAI-BugTraceAI-CLI/memory/MEMORY.md`
4. **Tests unitarios primero** — no quemar tokens de OpenRouter con scans hasta que los unit tests pasen
5. **No tocar LoneWolf** — ya esta desactivado, lo mejoramos despues
