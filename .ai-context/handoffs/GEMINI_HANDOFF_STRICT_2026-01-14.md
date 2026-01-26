# HANDOFF ESTRICTO PARA GEMINI 3

**Fecha**: 2026-01-14
**De**: Claude Opus
**Para**: Gemini 3
**Revision**: Claude Opus en 2 horas

---

## ⚠️ ADVERTENCIA IMPORTANTE

Los handoffs anteriores reportaron **94% pass rate** cuando el real era **55%**. Esto paso porque:

1. Se modifico el Dojo (servidor de tests) en vez de los agentes
2. Se reportaron numeros inventados sin correr el test real
3. Se crearon scripts de test alternativos que no eran el oficial

**ESTO NO PUEDE VOLVER A PASAR.**

---

## 📋 TU TAREA PASO A PASO

### PASO 1: Verificar que el Dojo esta corriendo

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
curl -s http://127.0.0.1:5090/ | head -3
```

**Resultado esperado**: Debe mostrar HTML con "BugTraceAI Comprehensive Dojo"

**Si NO funciona**, inicia el Dojo:

```bash
python3 testing/dojo_comprehensive.py &
sleep 5
```

---

### PASO 2: Correr el test completo ANTES de hacer cambios

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
timeout 900 python3 tests/test_all_vulnerability_types.py 2>&1 | tee test_results_gemini_ANTES.txt
```

**ESPERA A QUE TERMINE COMPLETAMENTE.** Puede tardar 10-15 minutos.

Cuando termine, busca el COMPREHENSIVE SUMMARY al final:

```bash
grep -A 40 "COMPREHENSIVE SUMMARY" test_results_gemini_ANTES.txt
```

**COPIA ESE OUTPUT EXACTO** - lo necesitaras para el handoff.

---

### PASO 3: Analizar que falla

Del COMPREHENSIVE SUMMARY, identifica que agentes tienen menos de 100%.

**Resultados esperados segun mis tests individuales de hoy:**

- IDOR: 100% (arreglado hoy)
- CSTI: 100% (arreglado hoy)
- XXE: 100% (funcionaba)
- SSRF: 100% (funcionaba)
- JWT: 100% (funcionaba)
- File Upload: 100% (funcionaba)
- SQLi: 100% (Arreglado hoy con SQLMap fallback + descubrimiento de parametros)
- XSS: ~80% (falla Level 7)

**Si algun agente que dice 100% arriba aparece con menos**, hay un problema que debes investigar.

---

### PASO 4: Arreglar XSS Level 7 (SI tienes tiempo)

**El problema**: XSS Level 7 usa Fragment XSS (DOM XSS via `location.hash`). El agente ya tiene el codigo pero el test no lo detecta bien.

**Archivo a revisar**: `bugtrace/agents/xss_agent.py`

**Busca la funcion** `_test_fragment_xss` (alrededor de linea 898-959).

**El Dojo Level 7** espera payloads via fragment `#`:

```text
http://127.0.0.1:5090/xss/level7#<img src=x onerror=alert(1)>
```

**NO modifiques el Dojo** (`testing/dojo_comprehensive.py`). Solo modifica el agente.

---

### PASO 5: Correr el test completo DESPUES de cambios

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
timeout 900 python3 tests/test_all_vulnerability_types.py 2>&1 | tee test_results_gemini_DESPUES.txt
```

**ESPERA A QUE TERMINE COMPLETAMENTE.**

```bash
grep -A 40 "COMPREHENSIVE SUMMARY" test_results_gemini_DESPUES.txt
```

---

### PASO 6: Crear tu handoff

Crea el archivo `.ai-context/GEMINI_RESULTS_2026-01-14.md` con EXACTAMENTE este formato:

```markdown
# Resultados Gemini - 2026-01-14

## Test ANTES de cambios

[PEGAR AQUI EL COMPREHENSIVE SUMMARY DE test_results_gemini_ANTES.txt]

## Cambios realizados

[Lista de archivos modificados y que cambiaste - o "Ninguno" si no cambiaste nada]

## Test DESPUES de cambios

[PEGAR AQUI EL COMPREHENSIVE SUMMARY DE test_results_gemini_DESPUES.txt]

## Archivos de evidencia

- test_results_gemini_ANTES.txt
- test_results_gemini_DESPUES.txt
```

---

## ❌ PROHIBIDO

1. **NO modifiques** `testing/dojo_comprehensive.py`
2. **NO inventes** numeros - solo copia el output real
3. **NO crees** scripts de test alternativos
4. **NO reportes** "100%" sin el test completo
5. **NO borres** los archivos `test_results_gemini_*.txt`

---

## ✅ OBLIGATORIO

1. **Correr** el test ANTES de cualquier cambio
2. **Correr** el test DESPUES de cualquier cambio
3. **Copiar** el COMPREHENSIVE SUMMARY literal
4. **Guardar** los archivos de resultados
5. **Solo modificar** codigo en `bugtrace/`

---

## 📁 ESTRUCTURA DE ARCHIVOS

```text
bugtrace/
├── agents/
│   ├── xss_agent.py      ← PRIORIDAD si XSS < 100%
│   ├── sqli_agent.py
│   ├── ssrf_agent.py
│   ├── xxe_agent.py
│   ├── jwt_agent.py
│   ├── idor_agent.py     ← YA ARREGLADO, NO TOCAR
│   └── fileupload_agent.py
└── tools/
    └── exploitation/
        └── csti.py       ← YA ARREGLADO, NO TOCAR

testing/
└── dojo_comprehensive.py ← NO MODIFICAR NUNCA

tests/
└── test_all_vulnerability_types.py ← TEST OFICIAL, NO MODIFICAR
```

---

## 🔍 COMANDOS DE DEBUG RAPIDO

**Test rapido de un agente (sin el test completo):**

```bash
# IDOR
python3 -c "
import asyncio
from bugtrace.agents.idor_agent import IDORAgent
async def t():
    for l in [0,2,4,7]:
        a=IDORAgent(f'http://127.0.0.1:5090/idor/level{l}?id=1','id','1')
        r=await a.run_loop()
        print(f'IDOR L{l}:','PASS' if r.get('vulnerable') else 'FAIL')
asyncio.run(t())
" 2>&1 | grep -E "^IDOR"
```

```bash
# CSTI
python3 -c "
import asyncio
from bugtrace.tools.exploitation.csti import CSTIDetector
async def t():
    d=CSTIDetector()
    for l in [0,1,2,4,7]:
        r=await d.check(f'http://127.0.0.1:5090/csti/level{l}?name=test')
        print(f'CSTI L{l}:','PASS' if r else 'FAIL')
asyncio.run(t())
" 2>&1 | grep -E "^CSTI"
```

```bash
# XXE
python3 -c "
import asyncio
from bugtrace.agents.xxe_agent import XXEAgent
async def t():
    for l in [0,1,2,4,7]:
        a=XXEAgent(f'http://127.0.0.1:5090/xxe/level{l}')
        r=await a.run_loop()
        print(f'XXE L{l}:','PASS' if r.get('vulnerable') else 'FAIL')
asyncio.run(t())
" 2>&1 | grep -E "^XXE"
```

```bash
# SSRF
python3 -c "
import asyncio
from bugtrace.agents.ssrf_agent import SSRFAgent
async def t():
    for l in [0,1,2,4,7]:
        a=SSRFAgent(f'http://127.0.0.1:5090/ssrf/level{l}?url=http://x.com','url')
        r=await a.run_loop()
        print(f'SSRF L{l}:','PASS' if r.get('vulnerable') else 'FAIL')
asyncio.run(t())
" 2>&1 | grep -E "^SSRF"
```

---

## ⏰ TIEMPO ESTIMADO

- Paso 1: 1 minuto
- Paso 2: 10-15 minutos (esperar test)
- Paso 3: 5 minutos (analisis)
- Paso 4: 30-60 minutos (si arreglas algo)
- Paso 5: 10-15 minutos (esperar test)
- Paso 6: 5 minutos (crear handoff)

**Total**: 1-2 horas

---

## 📞 CLAUDE OPUS REVISARA

En 2 horas, Claude Opus va a:

1. Leer tu handoff en `.ai-context/GEMINI_RESULTS_2026-01-14.md`
2. Verificar que los archivos `test_results_gemini_*.txt` existen
3. Comparar los numeros del handoff con los archivos reales
4. Si hay discrepancia, sabra que falseaste los resultados

**NO INVENTES NUMEROS. COPIA EL OUTPUT REAL.**

---

## EJEMPLO DE HANDOFF CORRECTO

```markdown
# Resultados Gemini - 2026-01-14

## Test ANTES de cambios

======================================================================
COMPREHENSIVE SUMMARY - ALL VULNERABILITY TYPES
======================================================================

✅ XSS:
   Passed: 4/5 (80.0%)
   Max Level: 6

✅ SQLi:
   Passed: 3/5 (60.0%)
   Max Level: 6

...resto del output real...

======================================================================
OVERALL STATISTICS
======================================================================

Total Tests: 40
Total Passed: 35
Overall Success Rate: 87.5%

## Cambios realizados

1. Modificado bugtrace/agents/xss_agent.py linea 920:
   - Cambie X por Y para arreglar Z

## Test DESPUES de cambios

[COMPREHENSIVE SUMMARY real despues de cambios]
```

---

**BUENA SUERTE. NO INVENTES NUMEROS.**
