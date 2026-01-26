# [COMPLETADO] HANDOFF PARA GEMINI - Integracion SQLMap en SQLi Agent

**Fecha**: 2026-01-14
**De**: Claude Opus (Tech Lead)
**Para**: Gemini 3
**Objetivo**: Subir SQLi de 60% a 100% integrando SQLMap como fallback

---

## CONTEXTO

### Estado Actual

- **SQLi Agent**: 60% (3/5 tests pasan)
- **SQLMap**: Ya instalado via Docker (`googlesky/sqlmap:latest`)
- **Wrapper**: Ya existe en `bugtrace/tools/external.py`

### El Problema

El agente Python puro falla en:

- **Level 4**: Blind SQLi (time-based) - requiere medicion precisa de delays
- **Level 7**: WAF avanzado - requiere tamper scripts

SQLMap tiene 15 anos de refinamiento para estos casos.

---

## TU TAREA

### Paso 1: Verificar que SQLMap funciona

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI

# Test directo contra Dojo Level 4 (Blind)
docker run --rm googlesky/sqlmap -u "http://172.17.0.1:5090/sqli/level4?id=1" --batch --technique=T --level=2 2>&1 | tail -20
```

**Nota**: Usa `172.17.0.1` (Docker host) en lugar de `127.0.0.1` porque SQLMap corre dentro de Docker.

### Paso 2: Modificar el SQLi Agent

**Archivo**: `bugtrace/agents/sqli_agent.py`

**Estrategia**: Agente Python primero (rapido), SQLMap como fallback (preciso).

Busca el metodo `run_loop()` y modificalo asi:

```python
async def run_loop(self) -> Dict:
    logger.info(f"[{self.name}] Testing SQLi on {self.url}")

    findings = []

    # Fase 1: Deteccion Python (rapida, sin Docker)
    python_result = await self._python_detection()
    if python_result:
        findings.extend(python_result)
        return {"vulnerable": True, "findings": findings}

    # Fase 2: Si Python falla, usar SQLMap (lento pero preciso)
    logger.info(f"[{self.name}] Python detection failed, falling back to SQLMap...")

    from bugtrace.tools.external import external_tools

    # Extraer parametros de la URL
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(self.url)
    params = parse_qs(parsed.query)

    for param in params.keys():
        # Convertir localhost a IP accesible desde Docker
        docker_url = self.url.replace("127.0.0.1", "172.17.0.1").replace("localhost", "172.17.0.1")

        sqlmap_result = await external_tools.run_sqlmap(docker_url, target_param=param)

        if sqlmap_result and sqlmap_result.get("vulnerable"):
            findings.append({
                "type": "SQLi",
                "url": self.url,
                "parameter": sqlmap_result.get("parameter", param),
                "payload": "SQLMap confirmed",
                "description": f"SQLMap detected {sqlmap_result.get('type', 'SQL Injection')}",
                "severity": "CRITICAL",
                "validated": True,
                "tool": "sqlmap",
                "reproduction": sqlmap_result.get("reproduction_command", "")
            })
            break  # Found one, enough

    return {
        "vulnerable": len(findings) > 0,
        "findings": findings
    }
```

### Paso 3: Asegurar que `_python_detection` existe

Si no existe, crealo extrayendo la logica actual de deteccion:

```python
async def _python_detection(self) -> List[Dict]:
    """Deteccion rapida con payloads Python (sin Docker)."""
    findings = []

    # ... tu logica actual de payloads ...
    # Solo devuelve findings si encuentra algo

    return findings
```

### Paso 4: Verificar el cambio

```bash
# Test rapido solo SQLi
python3 -c "
import asyncio
from bugtrace.agents.sqli_agent import SQLiAgent

async def test():
    for level in [0, 2, 4, 6, 7]:
        url = f'http://127.0.0.1:5090/sqli/level{level}?id=1'
        agent = SQLiAgent(url=url, param='id')
        result = await agent.run_loop()
        status = 'PASS' if result.get('vulnerable') else 'FAIL'
        print(f'SQLi L{level}: {status}')

asyncio.run(test())
" 2>&1 | grep -E "^SQLi"
```

### Paso 5: Test completo

```bash
timeout 900 python3 tests/test_all_vulnerability_types.py 2>&1 | tee test_results_sqli_fix.txt
grep -A 40 "COMPREHENSIVE SUMMARY" test_results_sqli_fix.txt
```

---

## ARCHIVOS CLAVE

```markdown
bugtrace/agents/sqli_agent.py    <- MODIFICAR ESTE
bugtrace/tools/external.py       <- Ya tiene run_sqlmap(), NO TOCAR
testing/dojo_comprehensive.py    <- NO MODIFICAR
```

---

## NOTAS TECNICAS

### Por que 172.17.0.1?

SQLMap corre dentro de Docker. Desde dentro del container, `127.0.0.1` es el propio container, no tu maquina. `172.17.0.1` es el gateway de Docker que apunta al host.

### Timeout de SQLMap

SQLMap puede tardar 30-60 segundos por parametro. El timeout en `external.py` debe ser suficiente. Si ves timeouts, aumentalo.

### WAF Bypass (Level 7)

Si Level 7 sigue fallando, prueba agregar tamper scripts:

```python
cmd.extend(["--tamper=space2comment,between"])
```

Los tampers disponibles estan en: `/usr/share/sqlmap/tamper/`

---

## RESULTADO ESPERADO

**Antes**: SQLi 60% (3/5)
**Despues**: SQLi 100% (5/5)

**Overall**: 95.3% -> ~97-98%

---

## HANDOFF FORMAT

Crea `.ai-context/GEMINI_SQLI_RESULTS_2026-01-14.md`:

```markdown
# SQLi Integration Results

## Test ANTES
[COMPREHENSIVE SUMMARY]

## Cambios
1. Modificado sqli_agent.py: [descripcion]

## Test DESPUES
[COMPREHENSIVE SUMMARY]

## Evidencia
- test_results_sqli_fix.txt
```

---

## PROHIBIDO

- NO modifiques `testing/dojo_comprehensive.py`
- NO inventes numeros
- NO borres archivos de evidencia

---

**Tiempo estimado**: 1-2 horas
**Dificultad**: Media (integracion, no logica nueva)
