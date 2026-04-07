# 04 - Fase 2: Analysis (DASTySAST Multi-Persona)

## Resumen

La fase de Analysis es el corazon inteligente del pipeline. Cada URL descubierta en Fase 1 es analizada por **6 enfoques LLM distintos** (5 personas de analisis + 1 agente skeptical) que votan sobre las vulnerabilidades encontradas. Concurrencia: **5** URLs en paralelo (configurable).

**Archivo principal:** `bugtrace/agents/analysis_agent.py` (~111KB, el mas complejo del sistema)

---

## DASTySASTAgent

### Clase

```python
class DASTySASTAgent(BaseAgent):
    def __init__(self, url: str, scan_id: int, tech_profile: dict = None):
        super().__init__(name=f"DASTySAST-{url_hash}", role="Security Analyst")
        self.url = url
        self.scan_id = scan_id
        self.tech_profile = tech_profile
```

### Los 6 Enfoques (Approaches)

Cada URL es analizada por 6 "personas" LLM diferentes. Cada persona tiene un system prompt especializado:

| # | Enfoque | Modelo Config | Perspectiva |
|---|---------|---------------|-------------|
| 1 | `sast_analyst` | `ANALYSIS_SAST_MODEL` | Analisis estatico de codigo fuente visible |
| 2 | `dast_analyst` | `ANALYSIS_DAST_MODEL` | Analisis dinamico de comportamiento HTTP |
| 3 | `fuzzer` | `ANALYSIS_FUZZER_MODEL` | Fuzzing inteligente de parametros |
| 4 | `red_team` | `ANALYSIS_RED_TEAM_MODEL` | Perspectiva ofensiva de atacante |
| 5 | `researcher` | `ANALYSIS_RESEARCHER_MODEL` | Investigacion profunda de patrones |
| 6 | `skeptical_agent` | `SKEPTICAL_MODEL` | Revision critica de hallazgos (post-voting) |

### Flujo de Ejecucion Detallado

```
URL entrada
    |
    v
[1. Fetch HTML + Headers]
    |
    v
[2. Build Context]
    |  - HTML source (truncado)
    |  - HTTP headers
    |  - Tech profile
    |  - Parametros descubiertos
    |
    v
[3. Run 5 Core Approaches in Parallel]
    |  - asyncio.gather(sast, dast, fuzzer, red_team, researcher)
    |  - Cada uno con su system prompt y modelo
    |
    v
[4. Consolidation (Voting)]
    |  - Merge por key (type:parameter)
    |  - Conteo de votos
    |  - Seleccion por mejor evidencia
    |
    v
[5. Run Skeptical Agent]
    |  - Revisa TODOS los hallazgos previos
    |  - Asigna skeptical_score (0-10)
    |  - Calcula fp_confidence
    |
    v
[6. Skeptical Review (Final Gate)]
    |  - Pre-filter: skeptical_score <= 3 AND fp_confidence < 0.5 → REJECTED
    |  - Deduplication
    |  - LLM review final
    |  - Probe-validated bypasses review
    |
    v
[7. Emit findings] --> ThinkingConsolidation (Fase 3)
```

---

## Paso 1-2: Fetch y Context Building

```python
async def _fetch_and_build_context(self) -> Dict:
    """Fetch HTML and build analysis context."""
    async with aiohttp.ClientSession() as session:
        response = await session.get(self.url, timeout=30)
        html = await response.text()
        headers = dict(response.headers)

    return {
        "url": self.url,
        "html": html[:50000],  # Truncado a 50KB
        "headers": headers,
        "tech_profile": self.tech_profile,
        "parameters": extract_param_metadata(html, self.url)
    }
```

---

## Paso 3: Ejecucion Paralela de Personas

Cada persona se ejecuta como una llamada LLM independiente:

```python
async def _run_approach(self, approach: str, context: Dict) -> Dict:
    system_prompt = self._get_approach_system_prompt(approach)
    user_prompt = self._build_analysis_prompt(context)

    model_override = self._get_model_for_approach(approach)

    response = await llm_client.generate(
        prompt=user_prompt,
        system_prompt=system_prompt,
        model_override=model_override,
        module_name=f"DASTySAST_{approach}",
        max_tokens=4000
    )

    return self._parse_analysis_response(response)
```

### System Prompts por Persona

**SAST Analyst:**
- Busca patrones vulnerables en HTML/JS visible
- Analiza uso inseguro de `innerHTML`, `eval()`, `document.write()`
- Detecta inyecciones en templates (Angular, Vue, React)
- Busca secrets expuestos en codigo cliente

**DAST Analyst:**
- Analiza headers HTTP de seguridad faltantes
- Busca patrones de error en respuestas
- Detecta redirects inseguros
- Analiza comportamiento de cookies

**Fuzzer:**
- Identifica puntos de inyeccion en parametros
- Sugiere payloads de fuzzing para cada parametro
- Prioriza parametros por probabilidad de vulnerabilidad

**Red Team:**
- Perspectiva de atacante real
- Busca cadenas de ataque (chained exploits)
- Evalua impacto de negocio
- Identifica rutas de escalacion

**Researcher:**
- Investigacion profunda de tecnologias detectadas
- Busca CVEs conocidos para versiones especificas
- Analiza patrones historicos de vulnerabilidad
- Correlaciona hallazgos con bases de datos de vulns

---

## Paso 4: Consolidation (Voting System)

El sistema de votacion fusiona hallazgos de las 5 personas:

```python
def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
    merged = {}

    for analysis in analyses:
        for vuln in analysis.get("vulnerabilities", []):
            key = f"{vuln['type']}:{vuln['parameter']}"

            if key not in merged:
                merged[key] = vuln.copy()
                merged[key]["votes"] = 1
            else:
                # TECHNICAL DEDUPLICATION: Keep better evidence
                new_evidence = _evidence_quality(vuln)
                existing_evidence = merged[key]["_evidence_score"]

                if new_evidence > existing_evidence:
                    # Replace with better evidence, keep votes
                    old_votes = merged[key]["votes"]
                    merged[key] = vuln.copy()
                    merged[key]["votes"] = old_votes + 1
                else:
                    merged[key]["votes"] += 1

    # Consensus filter: require minimum votes
    min_votes = settings.ANALYSIS_CONSENSUS_VOTES  # default: 4
    return [v for v in merged.values() if v["votes"] >= min_votes]
```

### Evidence Quality Scoring

```python
def _evidence_quality(vuln: Dict) -> int:
    score = 0
    if vuln.get("probe_validated"):    score += 5  # Highest priority
    if vuln.get("html_evidence"):      score += 3
    if vuln.get("xss_context"):        score += 2
    if vuln.get("chars_survive"):      score += 1
    return score
```

**Principio:** Se mantiene el hallazgo con MEJOR EVIDENCIA tecnica, no el que "explica mejor".

---

## Paso 5: Skeptical Agent

El agente skeptical revisa TODOS los hallazgos de las 5 personas y asigna un score de falso positivo.

### System Prompt Skeptical

```
SKEPTICAL MINDSET:
- Parameter names alone (id, user, file) are NOT evidence
- Generic patterns without concrete evidence are likely FPs
- Error messages must be SPECIFIC SQL/command errors
- XSS requires UNESCAPED reflection, not just reflection
- WAF-blocked requests indicate the app HAS protections

SCORING (0-10):
- 0-3: LIKELY FALSE POSITIVE
- 4-5: UNCERTAIN
- 6-7: PLAUSIBLE
- 8-10: LIKELY TRUE POSITIVE
```

### Calculo de FP Confidence

```python
def _calculate_fp_confidence(self, finding: Dict) -> float:
    # Weights (sum = 1.0)
    skeptical_weight = 0.4
    votes_weight = 0.3
    evidence_weight = 0.3

    # Components
    skeptical_component = (skeptical_score / 10.0) * skeptical_weight
    votes_component = (votes / max_votes) * votes_weight
    evidence_component = evidence_quality * evidence_weight

    return skeptical_component + votes_component + evidence_component
```

**Evidence Quality Assessment:**

| Indicador | Score |
|-----------|-------|
| SQL error patterns en reasoning | +0.3 |
| Reflected/unescaped XSS | +0.3 |
| Stack traces en respuesta | +0.3 |
| OOB callback recibido | +0.3 |
| Payload especifico (>10 chars) | +0.15 |
| Confidence >= 7 | +0.15 |
| >= 3 votos | +0.15 |
| "Parameter name only" reasoning | -0.2 |
| "Could be" / "potentially" | -0.2 |
| Payload < 5 chars | -0.2 |

---

## Paso 6: Skeptical Review (Final Gate)

```python
async def _skeptical_review(self, vulnerabilities: List[Dict]) -> List[Dict]:
    # 1. Separate probe-validated (bypass LLM review)
    probe_validated = [v for v in vulnerabilities if v.get("probe_validated")]
    llm_findings = [v for v in vulnerabilities if not v.get("probe_validated")]

    # 2. Pre-filter: reject low confidence
    threshold = settings.THINKING_FP_THRESHOLD  # default: 0.5
    pre_filtered = []
    for v in llm_findings:
        if v["skeptical_score"] <= 3 and v["fp_confidence"] < threshold:
            # REJECTED
            continue
        pre_filtered.append(v)

    # 3. Deduplicate
    deduped = self._review_deduplicate(pre_filtered)

    # 4. LLM Review (second skeptical pass)
    response = await llm_client.generate(
        prompt=review_prompt,
        system_prompt="You are a skeptical security expert.",
        model_override=settings.SKEPTICAL_MODEL,
    )

    approved = self._review_parse_approval(response, deduped)

    # 5. Combine: probe_validated + LLM-approved
    return probe_validated + approved
```

### Bypasses del Skeptical Review

1. **`probe_validated = True`**: Hallazgos confirmados por probing activo bypasean completamente la revision LLM
2. **SQLi**: SQLMap es autoritativo - si SQLMap confirma, es SQLi

---

## Formato de Respuesta LLM

Cada persona retorna XML:

```xml
<analysis>
  <vulnerability>
    <type>XSS</type>
    <parameter>search</parameter>
    <confidence_score>8</confidence_score>
    <reasoning>Unescaped reflection in HTML context...</reasoning>
    <exploitation_strategy><script>document.domain</script></exploitation_strategy>
    <html_evidence><div>USER_INPUT_HERE</div></html_evidence>
    <xss_context>html_tag</xss_context>
  </vulnerability>
</analysis>
```

Parseado con `XmlParser` customizado que extrae tags individuales.

---

## Skills System

Los agentes cargan "skills" especializadas desde archivos Markdown:

```python
# En agents/skills/loader.py
def get_scoring_guide(vuln_type: str) -> str:
    """Returns scoring guide for specific vuln type."""

def get_false_positives(vuln_type: str) -> str:
    """Returns FP indicators for specific vuln type."""
```

Archivos en `agents/skills/`:
- `xss_scoring.md` - Guia de scoring XSS
- `sqli_scoring.md` - Guia de scoring SQLi
- `false_positives_xss.md` - Indicadores de FP para XSS
- etc.

Estas skills se inyectan en el system prompt del agente para mejorar precision.

---

## Semaforo de Fase

```python
ScanPhase.ANALYSIS → Semaphore(5)     # 5 URLs DAST en paralelo
ScanPhase.LLM_GLOBAL → Semaphore(2)   # Rate limiting OpenRouter
```

**Nota:** Dentro de cada URL, las 5 personas se ejecutan en paralelo con `asyncio.gather()`. El semaforo de fase controla cuantas URLs se procesan simultaneamente.

---

## Eventos Emitidos

| Evento | Data | Receptor |
|--------|------|----------|
| `url_analyzed` | `{url, findings, votes, scan_id}` | ThinkingConsolidation |
| `discovery.consolidation.completed` | `{url, raw, dedup, passing}` | Metricas |
| `discovery.skeptical.started` | `{url, findings_to_review}` | Metricas |
