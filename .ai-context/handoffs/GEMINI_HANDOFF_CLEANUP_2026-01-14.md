# HANDOFF PARA GEMINI - Limpieza y Integracion de Herramientas

**Fecha**: 2026-01-14
**De**: Claude Opus (Tech Lead)
**Para**: Gemini 3
**Revision**: Claude Opus cuando termines

---

## REGLAS ABSOLUTAS

1. **NO INVENTES RESULTADOS** - Copia outputs literales
2. **NO MODIFIQUES** archivos de test (`testing/`, `tests/`)
3. **NO BORRES** archivos sin moverlos primero a `archive/`
4. **DOCUMENTA** cada cambio que hagas

---

## TAREA 1: Limpieza de Archivos (30 min)

### Paso 1.1: Crear directorio de archivo

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
mkdir -p archive/test_outputs_2026-01-14
```

### Paso 1.2: Mover archivos de test a archive

```bash
# Mover todos los test_results_*.txt
mv test_results_*.txt archive/test_outputs_2026-01-14/ 2>/dev/null || echo "No test_results files"

# Mover archivos de debug JWT
mv jwt_test_debug*.txt archive/test_outputs_2026-01-14/ 2>/dev/null || echo "No jwt_test_debug files"

# Mover otros archivos de output
mv output.txt archive/test_outputs_2026-01-14/ 2>/dev/null || echo "No output.txt"
mv status_out.txt archive/test_outputs_2026-01-14/ 2>/dev/null || echo "No status_out.txt"
mv scan_results.txt archive/test_outputs_2026-01-14/ 2>/dev/null || echo "No scan_results.txt"
```

### Paso 1.3: Verificar limpieza

```bash
# Lista de archivos en raiz - NO deberia haber .txt excepto requirements.txt
ls -la *.txt 2>/dev/null
```

**Resultado esperado**: Solo `requirements.txt` debe aparecer.

### Paso 1.4: Limpiar archivos PID huerfanos

```bash
rm -f scan.pid 2>/dev/null || echo "No scan.pid"
```

---

## TAREA 2: Integrar GoSpider en el Flujo Principal (1 hora)

### Contexto

GoSpider ya existe en `bugtrace/tools/external.py` (metodo `run_gospider`).
El problema: NO se usa en el flujo principal de scan.

### Paso 2.1: Leer el archivo del Conductor

```bash
cat bugtrace/core/conductor.py | head -100
```

Identifica donde se inicia el scan y donde se lanzan los agentes.

### Paso 2.2: Leer el metodo run_gospider existente

```bash
grep -A 50 "async def run_gospider" bugtrace/tools/external.py
```

### Paso 2.3: Modificar el Conductor

**Archivo**: `bugtrace/core/conductor.py`

Busca el metodo que inicia el scan (probablemente `run()` o `start_scan()`).

**Logica a agregar** (ANTES de lanzar agentes):

```python
# --- NUEVO: Crawling con GoSpider ---
from bugtrace.tools.external import external_tools

async def _crawl_target(self, target_url: str) -> List[str]:
    """Usa GoSpider para descubrir endpoints antes de atacar."""
    logger.info(f"[Conductor] Starting GoSpider crawl on {target_url}")

    urls = await external_tools.run_gospider(target_url, depth=2)

    # Filtrar URLs con parametros (las interesantes para SQLi/XSS)
    parameterized = [u for u in urls if '?' in u or '=' in u]

    logger.info(f"[Conductor] GoSpider found {len(urls)} URLs, {len(parameterized)} with parameters")

    return parameterized if parameterized else [target_url]
```

**Donde insertarlo**: Al inicio del scan, antes de lanzar agentes.

```python
async def run(self, target: str):
    # ... codigo existente de setup ...

    # NUEVO: Crawl primero
    endpoints = await self._crawl_target(target)

    # Luego lanzar agentes contra cada endpoint
    for endpoint in endpoints:
        await self._launch_agents(endpoint)
```

### Paso 2.4: Test de GoSpider

```bash
# Test directo de GoSpider contra el Dojo
python3 -c "
import asyncio
from bugtrace.tools.external import external_tools

async def test():
    urls = await external_tools.run_gospider('http://127.0.0.1:5090/', depth=2)
    print(f'Found {len(urls)} URLs')
    for u in urls[:10]:
        print(f'  - {u}')

asyncio.run(test())
"
```

**Nota**: Si el Dojo no esta corriendo, inicialo primero:

```bash
python3 testing/dojo_comprehensive.py &
sleep 5
```

---

## TAREA 3: Integrar Nuclei para Fingerprinting (1 hora)

### Contexto

Nuclei ya existe en `bugtrace/tools/external.py` (metodo `run_nuclei`).
Usarlo para fingerprinting ANTES de decidir que agentes lanzar.

### Paso 3.1: Leer el metodo run_nuclei existente

```bash
grep -A 40 "async def run_nuclei" bugtrace/tools/external.py
```

### Paso 3.2: Crear funcion de fingerprinting

**Archivo**: `bugtrace/core/conductor.py`

```python
async def _fingerprint_target(self, target_url: str) -> Dict[str, Any]:
    """Usa Nuclei para identificar tecnologias y vulns conocidas."""
    logger.info(f"[Conductor] Running Nuclei fingerprint on {target_url}")

    findings = await external_tools.run_nuclei(target_url)

    # Extraer info relevante
    technologies = []
    known_vulns = []

    for f in findings:
        template_id = f.get("template-id", "")
        severity = f.get("info", {}).get("severity", "")

        if "tech-detect" in template_id or "fingerprint" in template_id:
            technologies.append(template_id)
        elif severity in ["critical", "high"]:
            known_vulns.append(f)

    logger.info(f"[Conductor] Nuclei: {len(technologies)} techs, {len(known_vulns)} known vulns")

    return {
        "technologies": technologies,
        "known_vulns": known_vulns,
        "raw_findings": findings
    }
```

### Paso 3.3: Usar fingerprint para decidir agentes

**Logica sugerida**:

```python
async def run(self, target: str):
    # 1. Fingerprint
    fingerprint = await self._fingerprint_target(target)

    # 2. Si Nuclei ya encontro vulns criticas, reportarlas directamente
    if fingerprint["known_vulns"]:
        logger.info(f"[Conductor] Nuclei found {len(fingerprint['known_vulns'])} known vulnerabilities!")
        # Agregar a findings sin necesidad de agentes

    # 3. Crawl
    endpoints = await self._crawl_target(target)

    # 4. Lanzar agentes
    for endpoint in endpoints:
        await self._launch_agents(endpoint)
```

### Paso 3.4: Test de Nuclei

```bash
# Test directo - NOTA: Nuclei puede tardar 1-2 minutos
python3 -c "
import asyncio
from bugtrace.tools.external import external_tools

async def test():
    findings = await external_tools.run_nuclei('http://127.0.0.1:5090/')
    print(f'Found {len(findings)} issues')
    for f in findings[:5]:
        print(f'  - {f.get(\"template-id\", \"unknown\")}')

asyncio.run(test())
"
```

---

## TAREA 4: Actualizar CURRENT_STATE (15 min)

### Paso 4.1: Editar el archivo de estado

**Archivo**: `.ai-context/CURRENT_STATE_FOR_CLAUDE.md`

Actualiza la seccion de "Siguientes Pasos" para reflejar lo completado:

```markdown
## Siguientes Pasos Sugeridos

1. ~~**Orquestador (Conductor Agent)**~~: Parcialmente implementado - GoSpider y Nuclei integrados.
2. ~~**Mejora SQLi**~~: COMPLETADO - 100% pass rate con SQLMap fallback.
3. **Test en Target Real**: Probar contra ginandjuice.shop u otro target autorizado.
4. **Reporting**: Implementar generacion de reportes en formato bug bounty.
```

---

## ENTREGABLES

Cuando termines, crea el archivo `.ai-context/GEMINI_CLEANUP_RESULTS_2026-01-14.md`:

```markdown
# Cleanup & Integration Results - 2026-01-14

## Tarea 1: Limpieza
- Archivos movidos a archive/: [LISTA]
- Archivos en raiz despues de limpieza: [OUTPUT de ls *.txt]

## Tarea 2: GoSpider
- Archivo modificado: bugtrace/core/conductor.py
- Lineas agregadas: [RANGO]
- Test output:
```
[PEGAR OUTPUT DEL TEST DE GOSPIDER]
```

## Tarea 3: Nuclei
- Archivo modificado: bugtrace/core/conductor.py
- Lineas agregadas: [RANGO]
- Test output:
```
[PEGAR OUTPUT DEL TEST DE NUCLEI]
```

## Tarea 4: Estado Actualizado
- Archivo modificado: .ai-context/CURRENT_STATE_FOR_CLAUDE.md
```

---

## VERIFICACION FINAL

Antes de terminar, corre este comando para verificar que no rompiste nada:

```bash
# Test rapido de imports
python3 -c "
from bugtrace.core.conductor import Conductor
from bugtrace.tools.external import external_tools
print('Imports OK')
"
```

Si hay errores de import, **NO CONTINUES**. Revierte tus cambios y reporta el error.

---

## PROHIBIDO

- NO modifiques `testing/dojo_comprehensive.py`
- NO modifiques `tests/test_all_vulnerability_types.py`
- NO borres archivos de `.ai-context/` excepto para mover a archive
- NO inventes outputs - copia literalmente

---

## TIEMPO ESTIMADO

| Tarea | Tiempo |
|-------|--------|
| Limpieza | 30 min |
| GoSpider | 1 hora |
| Nuclei | 1 hora |
| Estado | 15 min |
| **Total** | ~3 horas |

---

## NOTAS

- Si Docker no funciona, salta las tareas 2 y 3 y reportalo
- Si el Dojo no esta corriendo: `python3 testing/dojo_comprehensive.py &`
- Cualquier error grave: PARA y documenta en el archivo de resultados
