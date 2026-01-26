# HANDOFF PARA GEMINI - Conectar Agentes al Conductor

**Fecha**: 2026-01-14
**De**: Claude Opus (Tech Lead)
**Para**: Gemini 3
**Objetivo**: Implementar `_launch_agents()` para que el Conductor lance los agentes reales

---

## CONTEXTO

El Conductor ya tiene:
- `_fingerprint_target()` - Nuclei fingerprinting ✅
- `_crawl_target()` - GoSpider crawling ✅
- `run()` - Flujo principal ✅
- `_launch_agents()` - **STUB VACIO** ❌

Tu tarea: Implementar `_launch_agents()` para que lance los agentes de vulnerabilidad.

---

## REGLAS

1. **NO MODIFIQUES** los agentes existentes en `bugtrace/agents/`
2. **NO MODIFIQUES** `testing/` ni `tests/`
3. **SOLO MODIFICA** `bugtrace/core/conductor.py`
4. **DOCUMENTA** todo en el archivo de resultados

---

## PASO 1: Entender la estructura de agentes

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI

# Ver que agentes existen
ls bugtrace/agents/

# Ver la firma de cada agente (como se instancian)
grep -n "def __init__" bugtrace/agents/*_agent.py | head -20
```

**Resultado esperado**: Veras agentes como `xss_agent.py`, `sqli_agent.py`, etc.

---

## PASO 2: Entender como se llaman los agentes

Cada agente tiene un metodo `run_loop()` que devuelve un Dict con findings.

```bash
# Ver ejemplo de XSS Agent
grep -A 5 "async def run_loop" bugtrace/agents/xss_agent.py | head -10

# Ver ejemplo de SQLi Agent
grep -A 5 "async def run_loop" bugtrace/agents/sqli_agent.py | head -10
```

---

## PASO 3: Implementar _launch_agents()

**Archivo**: `bugtrace/core/conductor.py`

**Busca** el metodo stub (alrededor de linea 442):

```python
async def _launch_agents(self, endpoint: str):
    """Dispatches the specialist agents to a specific endpoint."""
    logger.info(f"[Conductor] Launching specialist agents on {endpoint}")
    # This will be integrated with TeamOrchestrator in the future
    pass
```

**Reemplaza con**:

```python
async def _launch_agents(self, endpoint: str):
    """Dispatches the specialist agents to a specific endpoint."""
    from urllib.parse import urlparse, parse_qs

    logger.info(f"[Conductor] Launching specialist agents on {endpoint}")

    # Extraer parametros de la URL
    parsed = urlparse(endpoint)
    params = parse_qs(parsed.query)

    # Si no hay parametros, no hay mucho que probar
    if not params:
        logger.info(f"[Conductor] No parameters in {endpoint}, skipping detailed scan")
        return

    # Obtener el primer parametro para los agentes que lo necesitan
    first_param = list(params.keys())[0] if params else None
    first_value = params[first_param][0] if first_param and params[first_param] else "1"

    all_findings = []

    # --- XSS Agent ---
    try:
        from bugtrace.agents.xss_agent import XSSAgent
        logger.info(f"[Conductor] Launching XSS Agent on {endpoint}")
        xss_agent = XSSAgent(url=endpoint, param=first_param)
        xss_result = await xss_agent.run_loop()
        if xss_result.get("vulnerable"):
            all_findings.extend(xss_result.get("findings", []))
            logger.info(f"[Conductor] XSS Agent found {len(xss_result.get('findings', []))} issues")
    except Exception as e:
        logger.error(f"[Conductor] XSS Agent failed: {e}")

    # --- SQLi Agent ---
    try:
        from bugtrace.agents.sqli_agent import SQLiAgent
        logger.info(f"[Conductor] Launching SQLi Agent on {endpoint}")
        sqli_agent = SQLiAgent(url=endpoint, param=first_param)
        sqli_result = await sqli_agent.run_loop()
        if sqli_result.get("vulnerable"):
            all_findings.extend(sqli_result.get("findings", []))
            logger.info(f"[Conductor] SQLi Agent found {len(sqli_result.get('findings', []))} issues")
    except Exception as e:
        logger.error(f"[Conductor] SQLi Agent failed: {e}")

    # --- SSRF Agent ---
    try:
        from bugtrace.agents.ssrf_agent import SSRFAgent
        logger.info(f"[Conductor] Launching SSRF Agent on {endpoint}")
        ssrf_agent = SSRFAgent(url=endpoint, param=first_param)
        ssrf_result = await ssrf_agent.run_loop()
        if ssrf_result.get("vulnerable"):
            all_findings.extend(ssrf_result.get("findings", []))
            logger.info(f"[Conductor] SSRF Agent found {len(ssrf_result.get('findings', []))} issues")
    except Exception as e:
        logger.error(f"[Conductor] SSRF Agent failed: {e}")

    # --- IDOR Agent ---
    try:
        from bugtrace.agents.idor_agent import IDORAgent
        # IDOR necesita el valor original del parametro
        if first_value.isdigit():
            logger.info(f"[Conductor] Launching IDOR Agent on {endpoint}")
            idor_agent = IDORAgent(url=endpoint, param=first_param, original_value=first_value)
            idor_result = await idor_agent.run_loop()
            if idor_result.get("vulnerable"):
                all_findings.extend(idor_result.get("findings", []))
                logger.info(f"[Conductor] IDOR Agent found {len(idor_result.get('findings', []))} issues")
    except Exception as e:
        logger.error(f"[Conductor] IDOR Agent failed: {e}")

    # Guardar findings en contexto compartido
    if all_findings:
        existing = self.get_shared_context("agent_findings") or []
        existing.extend(all_findings)
        self.share_context("agent_findings", existing)
        logger.info(f"[Conductor] Total findings so far: {len(existing)}")
```

---

## PASO 4: Verificar imports

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI

python3 -c "
from bugtrace.core.conductor import ConductorV2
print('Conductor import OK')

from bugtrace.agents.xss_agent import XSSAgent
from bugtrace.agents.sqli_agent import SQLiAgent
from bugtrace.agents.ssrf_agent import SSRFAgent
from bugtrace.agents.idor_agent import IDORAgent
print('All agent imports OK')
"
```

**Si hay errores de import**, revisalos y corrigelos. Algunos agentes pueden tener nombres diferentes.

---

## PASO 5: Test contra el Dojo

```bash
# Asegurar que el Dojo esta corriendo
curl -s http://127.0.0.1:5090/ | head -1 || (python3 testing/dojo_comprehensive.py & sleep 5)

# Test del conductor
python3 -c "
import asyncio
from bugtrace.core.conductor import ConductorV2

async def test():
    conductor = ConductorV2()
    await conductor.run('http://127.0.0.1:5090/')

    # Ver findings
    findings = conductor.get_shared_context('agent_findings') or []
    print(f'Total findings: {len(findings)}')

    for f in findings[:5]:
        print(f'  - {f.get(\"type\")}: {f.get(\"description\", \"\")[:50]}')

asyncio.run(test())
" 2>&1 | tee conductor_test_output.txt
```

---

## PASO 6: Agregar agentes faltantes (OPCIONAL)

Si tienes tiempo, agrega los agentes que faltan:

- `XXEAgent` - para XXE
- `JWTAgent` - para JWT
- `CSTIAgent` - para CSTI (si existe como agente separado)
- `FileUploadAgent` - para File Upload

**Usa el mismo patron**:

```python
try:
    from bugtrace.agents.xxx_agent import XXXAgent
    logger.info(f"[Conductor] Launching XXX Agent on {endpoint}")
    xxx_agent = XXXAgent(url=endpoint, param=first_param)
    xxx_result = await xxx_agent.run_loop()
    if xxx_result.get("vulnerable"):
        all_findings.extend(xxx_result.get("findings", []))
except Exception as e:
    logger.error(f"[Conductor] XXX Agent failed: {e}")
```

---

## ENTREGABLES

Crea `.ai-context/GEMINI_AGENTS_RESULTS_2026-01-14.md`:

```markdown
# Agent Integration Results - 2026-01-14

## Cambios

- Archivo modificado: `bugtrace/core/conductor.py`
- Metodo implementado: `_launch_agents()`
- Agentes integrados: [LISTA]

## Test de Imports

```
[PEGAR OUTPUT]
```

## Test del Conductor

```
[PEGAR OUTPUT de conductor_test_output.txt]
```

## Notas

[Cualquier problema encontrado o fix adicional]
```

---

## NOTAS TECNICAS

### Sobre los parametros de agentes

Cada agente espera parametros diferentes:

| Agente | Parametros |
|--------|-----------|
| XSSAgent | `url`, `param` |
| SQLiAgent | `url`, `param` |
| SSRFAgent | `url`, `param` |
| IDORAgent | `url`, `param`, `original_value` |
| XXEAgent | Verificar firma |
| JWTAgent | Verificar firma |

**Antes de agregar un agente**, verifica su `__init__`:

```bash
grep -A 10 "def __init__" bugtrace/agents/xxx_agent.py
```

### Sobre errores

Si un agente falla, el `try/except` lo captura y continua con los demas. Esto es intencional - no queremos que un agente roto detenga todo el scan.

---

## PROHIBIDO

- NO modifiques los agentes (`bugtrace/agents/*.py`)
- NO modifiques tests (`testing/`, `tests/`)
- NO borres codigo existente del conductor

---

## TIEMPO ESTIMADO

| Tarea | Tiempo |
|-------|--------|
| Entender estructura | 15 min |
| Implementar _launch_agents | 30 min |
| Verificar imports | 10 min |
| Test | 15 min |
| Agentes opcionales | 30 min |
| **Total** | ~1.5 horas |
