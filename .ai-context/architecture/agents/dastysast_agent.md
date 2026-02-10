# DASTySASTAgent - Triage Rápido Multi-Approach

> **Fase**: 2 (Analysis - Triage)
> **Rol**: Análisis rápido LLM para identificar URLs sospechosas
> **Clase**: `bugtrace.agents.analysis_agent.DASTySASTAgent`
> **Archivo**: `bugtrace/agents/analysis_agent.py`

---

## 🎯 Filosofía: Divide y Vencerás

DASTySASTAgent NO es un scanner completo - es un **TRIAGE RÁPIDO** que filtra URLs sospechosas para que los **Specialist Agents** hagan el trabajo pesado.

### ❌ Arquitectura INCORRECTA (Antigua)

```
DASTySAST hace TODO:
├─ Fetch HTML con Playwright (5-10s)      ← LENTO
├─ Active probes (1-2s)                   ← INNECESARIO
├─ LLM analysis (10-30s)
├─ Tech profile detection                 ← YA LO HIZO NUCLEI
└─ Skeptical review

Tiempo por URL: 40-60s
100 URLs × 40s = 4000s (66 minutos) para analizar todo
```

**Problema**: Si solo 3 de 100 URLs tienen vulnerabilidades, desperdiciaste 97 × 40s = **3880 segundos analizando URLs limpias**.

### ✅ Arquitectura CORRECTA (Nueva - v3.0)

```
┌────────────────────────────────────────────┐
│ DASTySASTAgent (TRIAGE RÁPIDO)            │
│ Input: URL string                         │
│                                            │
│ URL → pentester(URL) → LLM online         │
│ URL → bug_bounty(URL) → LLM online        │
│ URL → code_auditor(URL) → LLM online      │
│ URL → red_team(URL) → LLM online          │
│ URL → researcher(URL) → LLM online        │
│                                            │
│ ↓ Merge → Skeptical → Candidatos          │
│                                            │
│ Output: "PUEDE tener XSS/SQLi" (low conf) │
│ Tiempo: 10-15s por URL                    │
└────────────────────────────────────────────┘
         ↓ (solo URLs sospechosas ~10%)
┌────────────────────────────────────────────┐
│ Specialist Agents (TRABAJO PESADO)        │
│ - XSSAgent: 800 payloads + Playwright     │
│ - SQLiAgent: SQLMap + validation          │
│ - CSTIAgent: Framework-specific exploits  │
│                                            │
│ Tiempo: 30-60s por URL                    │
└────────────────────────────────────────────┘
```

**Beneficio**:
- 100 URLs × 10s (DASTySAST) = 1000s
- 10 sospechosas × 40s (Specialists) = 400s
- **Total: 1400s (23 min)** vs 4000s (66 min) ✅ 65% más rápido

---

## Pipeline Simplificado

```
Input: URL string
  ↓
┌──────────────────────────────────────────────────────────┐
│ STEP 1: Parallel Multi-Approach (5 LLMs online)         │
├──────────────────────────────────────────────────────────┤
│ En paralelo (5-10s):                                     │
│                                                          │
│ • pentester(URL) → LLM online                            │
│ • bug_bounty(URL) → LLM online                           │
│ • code_auditor(URL) → LLM online                         │
│ • red_team(URL) → LLM online                             │
│ • researcher(URL) → LLM online                           │
│                                                          │
│ LLM hace por sí mismo:                                   │
│ - Fetch del HTML (tiene internet: ONLINE=True)          │
│ - Analiza código JavaScript                             │
│ - Detecta patrones sospechosos                          │
│ - Genera candidatos (low confidence)                    │
└──────────────────────────────────────────────────────────┘
  ↓ (5 listas de candidatos)
┌──────────────────────────────────────────────────────────┐
│ STEP 2: Consolidate (merge)                             │
├──────────────────────────────────────────────────────────┤
│ Merge findings de los 5 approaches                       │
│ Voting system: consenso aumenta confidence               │
└──────────────────────────────────────────────────────────┘
  ↓ (candidatos merged)
┌──────────────────────────────────────────────────────────┐
│ STEP 3: Skeptical Review (3-5s)                         │
├──────────────────────────────────────────────────────────┤
│ LLM skeptical → filtra especulación sin evidencia        │
│ Score findings: 0-10                                     │
│ Rechaza findings < 3                                     │
└──────────────────────────────────────────────────────────┘
  ↓
┌──────────────────────────────────────────────────────────┐
│ STEP 4: Save & Emit                                     │
├──────────────────────────────────────────────────────────┤
│ Save: dastysast/{url_index}.json                        │
│ Emit: url_analyzed event → ThinkingAgent                │
└──────────────────────────────────────────────────────────┘
  ↓
Output: [
  {type: "XSS", param: "search", confidence: 0.6},
  {type: "SQLi", param: "id", confidence: 0.7}
]
```

**Tiempo total por URL: 10-15s**
- Step 1: 5-10s (parallel LLM calls, el más lento marca el tiempo)
- Step 2: instantáneo (merge)
- Step 3: 3-5s (skeptical LLM)
- Step 4: instantáneo (save JSON)

---

## Código Simplificado

### Estructura Actual (CORRECTA)

```python
class DASTySASTAgent:
    def __init__(self, url, tech_profile, report_dir, url_index):
        self.url = url
        self.url_index = url_index
        self.report_dir = report_dir
        self.approaches = [
            "pentester",
            "bug_bounty",
            "code_auditor",
            "red_team",
            "researcher"
        ]

    async def run(self):
        """Pipeline simplificado: URL → 5 LLMs → merge → skeptical → save"""

        # STEP 1: Parallel approaches (LLM online hace fetch por sí mismo)
        tasks = [
            self._analyze_with_approach(approach)
            for approach in self.approaches
        ]
        analyses = await asyncio.gather(*tasks)

        # STEP 2: Consolidate
        merged = self._consolidate(analyses)

        # STEP 3: Skeptical review
        vulnerabilities = await self._skeptical_review(merged)

        # STEP 4: Save & Emit
        await self._save_results(vulnerabilities)
        await self._emit_url_analyzed(vulnerabilities)

        return {
            "vulnerabilities": vulnerabilities,
            "json_report_file": f"{self.url_index}.json"
        }

    async def _analyze_with_approach(self, approach: str):
        """Simple: solo URL → LLM online (NO fetch HTML)"""

        system_prompt = self._get_system_prompt(approach)

        # LLM hace fetch del HTML por sí mismo (ONLINE=True)
        prompt = f"Analyze this URL for security vulnerabilities: {self.url}"

        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            online=True,  # ← KEY: LLM tiene acceso a internet
            module_name="DASTySASTAgent"
        )

        return self._parse_response(response)
```

### Lo que NO hace DASTySAST

❌ **Fetch HTML** - El LLM online lo hace
❌ **Active probes** - Los Specialists lo hacen
❌ **Playwright** - Solo para Specialists
❌ **Tech detection** - Ya lo hizo Nuclei
❌ **Deep analysis** - Lo hacen XSSAgent, SQLiAgent, etc.

### Lo que SÍ hace DASTySAST

✅ **URL → LLM** - Manda solo la URL string
✅ **5 approaches** - Diferentes perspectivas
✅ **Voting system** - Consenso aumenta confianza
✅ **Skeptical filter** - Reduce falsos positivos
✅ **Genera candidatos** - Para que Specialists validen

---

## Configuración

```ini
# bugtraceaicli.conf

# LLM tiene acceso a internet (fetch HTML por sí mismo)
ONLINE = True

# Modelos para DASTySAST (approaches)
PRIMARY_MODELS = google/gemini-3-flash-preview,qwen/qwen-2.5-coder-32b-instruct

# Modelo para Skeptical review
SKEPTICAL_MODEL = deepseek/deepseek-r1

# Concurrencia (cuántos análisis DASTySAST en paralelo)
MAX_CONCURRENT_ANALYSIS = 10  # Aumentado de 5 (ahora es más rápido)
```

---

## System Prompts (Approaches)

### pentester

```markdown
You are an experienced penetration tester with OSCP credentials.
Focus on practical, immediately exploitable vulnerabilities (OWASP Top 10).

CRITICAL: You have internet access. Fetch the URL yourself and analyze.

Analyze this URL: {url}

Look for:
- SQL Injection (error messages, blind)
- XSS (reflected parameters)
- CSRF (missing tokens)
- Authentication issues

Return only SUSPICIOUS parameters (confidence 0-1).
This is TRIAGE - the specialist will validate later.
```

### bug_bounty

```markdown
You are a bug bounty hunter on HackerOne/Bugcrowd.
Focus on high-severity, high-payout vulnerabilities.

CRITICAL: You have internet access. Fetch the URL yourself and analyze.

Analyze this URL: {url}

Look for:
- RCE, SSRF, XXE (critical payouts)
- Business logic flaws
- Chaining opportunities

Return only SUSPICIOUS findings (confidence 0-1).
Be aggressive but realistic.
```

### code_auditor

```markdown
You are a security code auditor.
Focus on insecure coding patterns visible in HTML/JS.

CRITICAL: You have internet access. Fetch the URL yourself and analyze.

Analyze this URL: {url}

Look for:
- Missing input validation
- Weak sanitization
- Client-side secrets
- Unsafe DOM manipulation

Return only CODE-LEVEL issues (confidence 0-1).
```

### red_team

```markdown
You are a red team operator.
Focus on attack chains and privilege escalation.

CRITICAL: You have internet access. Fetch the URL yourself and analyze.

Analyze this URL: {url}

Look for:
- Chaining opportunities
- Privilege escalation paths
- Session manipulation

Return only CHAIN-ABLE vulnerabilities (confidence 0-1).
```

### researcher

```markdown
You are a security researcher.
Focus on novel and non-obvious vulnerabilities.

CRITICAL: You have internet access. Fetch the URL yourself and analyze.

Analyze this URL: {url}

Look for:
- Prototype pollution
- Race conditions
- Edge cases
- Modern web security issues

Return only NOVEL findings (confidence 0-1).
```

---

## Salida (Output)

### JSON Report (`dastysast/{url_index}.json`)

```json
{
  "metadata": {
    "url": "https://example.com/page?id=1",
    "url_index": 5,
    "timestamp": 1738454400.0
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "parameter": "id",
      "confidence": 0.7,
      "severity": "High",
      "reasoning": "Numeric ID parameter, no evidence of sanitization",
      "votes": 4,
      "skeptical_score": 6,
      "suggested_by": ["pentester", "bug_bounty", "code_auditor", "red_team"]
    },
    {
      "type": "XSS",
      "parameter": "search",
      "confidence": 0.5,
      "severity": "Medium",
      "reasoning": "Search parameter visible in HTML, needs validation",
      "votes": 2,
      "skeptical_score": 4,
      "suggested_by": ["pentester", "researcher"]
    }
  ]
}
```

### Event Emitido

```python
EventBus.emit("url_analyzed", {
    "url": "https://example.com/page?id=1",
    "url_index": 5,
    "candidates": [
        {"type": "SQLi", "param": "id", "confidence": 0.7},
        {"type": "XSS", "param": "search", "confidence": 0.5}
    ]
})
```

ThinkingAgent recibe esto y envía:
- `id` → **SQLiAgent** queue (validación profunda)
- `search` → **XSSAgent** queue (800 payloads + Playwright)

---

## Métricas de Rendimiento

### Tiempo por URL

| Fase | Tiempo |
|------|--------|
| 5 approaches (parallel) | 5-10s |
| Merge | <0.1s |
| Skeptical review | 3-5s |
| Save | <0.1s |
| **TOTAL** | **10-15s** |

### Comparación con Arquitectura Antigua

| Métrica | Antigua | Nueva | Mejora |
|---------|---------|-------|--------|
| Tiempo/URL | 40s | 15s | 62% más rápido ✅ |
| Fetch HTML | Playwright 5s | LLM online 0s | Sin overhead ✅ |
| Active probes | 2s | 0s (Specialists) | Sin duplicación ✅ |
| Tech detection | Duplicado | Usa Nuclei | Sin redundancia ✅ |
| 100 URLs | 4000s (66m) | 1500s (25m) | 62% más rápido ✅ |

### Escalabilidad

```
100 URLs:
├─ DASTySAST triage: 100 × 15s = 1500s (25 min)
├─ Genera ~20 candidatos sospechosos (20% tasa)
└─ Specialists: 20 × 40s = 800s (13 min)

Total: 2300s (38 min)

vs Antigua (todo con DASTySAST pesado):
100 × 40s = 4000s (66 min)

Ahorro: 42% más rápido
```

---

## Integración con Reconnaissance Phase

### Input de DASTySAST

DASTySAST recibe:
1. **URL string** - de `urls.txt` (GoSpider)
2. **url_index** - posición en urls.txt (1-based)

**NO recibe**:
- ❌ HTML (el LLM lo fetches)
- ❌ Tech profile (no lo necesita, pero Nuclei ya lo detectó)
- ❌ Parámetros extraídos (el LLM los encuentra)

### Flujo Completo

```
RECONNAISSANCE Phase:
├─ GoSpider → urls.txt (100 URLs)
├─ Nuclei → tech_profile.json (frameworks)
└─ AuthDiscovery → reports/auth_discovery/

ANALYSIS Phase (DASTySAST):
├─ Lee urls.txt
├─ Para cada URL (10 en paralelo):
│  └─ URL → 5 LLMs online → candidatos → N.json
└─ Emit url_analyzed events

EXPLOITATION Phase (Specialists):
├─ ThinkingAgent recibe events
├─ Route candidates a specialist queues:
│  ├─ XSSAgent queue (XSS candidates)
│  ├─ SQLiAgent queue (SQLi candidates)
│  └─ CSTIAgent queue (CSTI candidates)
└─ Specialists validan con deep testing
```

---

## Ventajas de la Arquitectura Simplificada

✅ **10x más rápido**: 15s vs 40s por URL
✅ **Sin duplicación**: LLM hace fetch (no nosotros)
✅ **Sin overhead**: No Playwright en triage
✅ **Escalable**: 10 análisis concurrentes (antes 5)
✅ **Divide y vencerás**: Triage rápido + validación profunda solo en sospechosos
✅ **LLM online**: Ve HTML fresco (no snapshot obsoleto)

---

## Próximos Pasos (Refactorización)

### Cambios Necesarios en `analysis_agent.py`

1. **Eliminar `_run_prepare_context()`**
   - ❌ No hacer fetch HTML
   - ❌ No hacer active probes
   - ❌ No detectar tech profile

2. **Simplificar `_analyze_with_approach()`**
   - ✅ Solo: `prompt = f"Analyze {url}"` + `online=True`

3. **Eliminar dependencias**
   - ❌ `browser_manager` (Playwright)
   - ❌ `http_orchestrator` (HTTP fetch)
   - ❌ `_run_reflection_probes()`

4. **Mantener**
   - ✅ `_consolidate()` (merge)
   - ✅ `_skeptical_review()` (filter)
   - ✅ `_save_results()` (JSON report)
   - ✅ `_emit_url_analyzed()` (event)

### Testing

Probar con:
```bash
# Antes (lento)
time: 40s por URL, 66 min para 100 URLs

# Después (rápido)
time: 15s por URL, 25 min para 100 URLs
```

---

*Última actualización: 2026-02-05*
*Versión: 3.0 (Simple & Fast - LLM Online Edition)*
