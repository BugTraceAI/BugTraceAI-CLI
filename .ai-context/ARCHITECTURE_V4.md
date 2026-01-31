# BugTraceAI Architecture V4 - Pipeline de 5 Fases

**Fecha**: 2026-01-30
**Versión**: 4.0 (Reactor V5 + Phase Semaphores)

---

## Overview

BugTraceAI es un escáner de vulnerabilidades web impulsado por IA que combina análisis estático/dinámico con agentes especializados y validación visual. Esta versión introduce **control de concurrencia granular por fase** y mejoras en el filtrado de falsos positivos.

---

## Pipeline de 5 Fases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BUGTRACE SCAN PIPELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PHASE 1: DISCOVERY                    Concurrency: 1 (GoSpider)            │
│  ┌──────────────────┐                                                        │
│  │    GoSpider      │ → URLs discovered → stored in DB                      │
│  │  (URL Crawling)  │                                                        │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  PHASE 2: ANALYSIS                     Concurrency: 5 (configurable)        │
│  ┌──────────────────┐                                                        │
│  │   DASTySAST      │ → 5 LLM approaches → Consensus (4/5 votes)            │
│  │ (analysis_agent) │ → Skeptical Review (Claude Haiku)                     │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  PHASE 3: THINKING CONSOLIDATION       (Event-driven, no semaphore)         │
│  ┌──────────────────┐                                                        │
│  │ ThinkingConsol.  │ → Deduplication → FP Filter → Priority Queue          │
│  │     Agent        │ → SQLi BYPASSES FP filter (SQLMap decides)            │
│  └────────┬─────────┘ → probe_validated BYPASSES FP filter                  │
│           │                                                                  │
│           ▼                                                                  │
│  PHASE 4: EXPLOITATION                 Concurrency: 10 (configurable)       │
│  ┌──────────────────┐                                                        │
│  │   Specialists    │ → XSSAgent (Playwright)                               │
│  │  (SQLi, XSS,     │ → SQLiAgent (SQLMap)                                  │
│  │   CSTI, etc.)    │ → CSTIAgent, SSRFAgent, XXEAgent...                   │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  PHASE 5: VALIDATION                   Concurrency: 1 (CDP HARDCODED)       │
│  ┌──────────────────┐                                                        │
│  │ AgenticValidator │ → CDP (Chrome DevTools Protocol)                      │
│  │  (Final Audit)   │ → Vision AI verification                              │
│  └────────┬─────────┘ → SINGLE-THREADED (CDP limitation)                    │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐                                                        │
│  │  Final Report    │ → JSON, Markdown, HTML                                │
│  └──────────────────┘                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase Semaphores (Concurrencia Granular)

### Archivo: `bugtrace/core/phase_semaphores.py`

Cada fase tiene su propio semáforo independiente:

```python
ScanPhase.DISCOVERY    → Semaphore(1)   # GoSpider ya es rápido
ScanPhase.ANALYSIS     → Semaphore(5)   # 5 URLs DAST en paralelo
ScanPhase.EXPLOITATION → Semaphore(10)  # 10 specialists en paralelo
ScanPhase.VALIDATION   → Semaphore(1)   # CDP HARDCODED - NO CAMBIAR
ScanPhase.LLM_GLOBAL   → Semaphore(2)   # Rate limit OpenRouter
```

### Configuración (`bugtraceaicli.conf`)

```ini
[SCAN]
MAX_CONCURRENT_DISCOVERY = 1      # No configurable (GoSpider design)
MAX_CONCURRENT_ANALYSIS = 5       # Configurable: 1-20
MAX_CONCURRENT_SPECIALISTS = 10   # Configurable: 1-30
# MAX_CONCURRENT_VALIDATION = 1   # NO CONFIGURABLE - CDP limitation
MAX_CONCURRENT_REQUESTS = 2       # LLM rate limiting
```

### Por qué Validation = 1 (HARDCODED)

**CDP (Chrome DevTools Protocol) NO soporta múltiples conexiones simultáneas:**

1. Una sesión por proceso Chrome (puerto 9222)
2. `alert()` popups bloquean CDP indefinidamente
3. Múltiples conexiones = corrupción de estado o crash

**CDP vs Playwright:**

| Aspecto | CDP | Playwright |
|---------|-----|------------|
| Concurrencia | 1 (single-threaded) | N (multi-context) |
| Precisión XSS | Alta (detecta sin popup) | Media |
| `alert()` handling | Bloquea (timeout 45s) | Puede cerrar |
| Uso | AgenticValidator | Specialists |

**Estrategia:** Filtrar agresivamente ANTES de CDP para minimizar findings que llegan a validación.

---

## ThinkingConsolidationAgent

### Archivo: `bugtrace/agents/thinking_consolidation_agent.py`

Cerebro del pipeline que recibe findings de DASTySAST y decide qué pasa a los specialists.

### Flujo de Procesamiento

```
Finding recibido
       │
       ▼
┌──────────────────┐
│ 1. Classify      │ → Determina specialist (xss, sqli, csti, etc.)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 2. FP Filter     │ → fp_confidence < 0.5 → FILTERED
└────────┬─────────┘   EXCEPTO: SQLi y probe_validated BYPASSES
         │
         ▼
┌──────────────────┐
│ 3. Deduplication │ → key = (type:param:path)
└────────┬─────────┘   Duplicado → FILTERED
         │
         ▼
┌──────────────────┐
│ 4. Priority Queue│ → Score basado en confidence + evidence
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 5. Emit Event    │ → work_queued_{specialist}
└──────────────────┘
```

### SQLi Bypass del Filtro FP

```python
# thinking_consolidation_agent.py línea 577
if not is_sqli and not is_probe_validated and fp_confidence < threshold:
    # FILTERED - no pasa a specialists
    return

if is_sqli and fp_confidence < threshold:
    logger.info("SQLi bypass: forwarded to SQLMap for validation")
    # PASA - SQLMap es el juez final, no el LLM
```

**Razón:** SQLMap es determinístico y authoritative. Un LLM puede equivocarse con SQL injection, pero SQLMap confirma con payloads reales.

### probe_validated Bypass

Findings con `probe_validated=True` bypasean el filtro FP porque ya fueron confirmados por una herramienta (ej: XSSAgent con Playwright).

---

## Specialist Agents

### XSSAgent (`bugtrace/agents/xss_v4.py`)

- Usa **Playwright** (multi-threaded OK)
- Genera payloads context-aware
- Confirma con ejecución real en browser
- Findings confirmados → `probe_validated=True`

### SQLiAgent (`bugtrace/agents/sqli_agent_v3.py`)

- Usa **SQLMap** (herramienta externa)
- Bypasea filtro FP de ThinkingConsolidation
- SQLMap es authoritative → si confirma, es SQLi real
- Soporta WAF bypass strategies

### CSTIAgent (`bugtrace/agents/csti_agent.py`)

- Client-Side Template Injection
- Detecta AngularJS, Vue, React vulnerabilities
- Genera payloads específicos por framework

---

## AgenticValidator (CDP)

### Archivo: `bugtrace/agents/agentic_validator.py`

Última línea de defensa. Valida findings con estado `PENDING_VALIDATION`.

### Características

- **Single-threaded** (CDP limitation)
- **Timeout 45s** por finding (evita hang en `alert()`)
- **Vision AI** para verificación visual
- Solo procesa findings de alta confianza

### Por qué es crítico minimizar findings aquí

```
21 findings × 45s timeout = 15+ minutos de validación
5 findings × 45s timeout = 3-4 minutos de validación
```

El objetivo es que lleguen <10 findings a validación.

---

## Event System

El pipeline usa eventos para comunicación entre agentes:

```python
# Eventos principales
url_discovered      # GoSpider → DB
url_analyzed        # DASTySAST → ThinkingConsolidation
work_queued_{type}  # ThinkingConsolidation → Specialists
finding_confirmed   # Specialists → DB
validation_complete # AgenticValidator → Report
```

---

## Configuración Crítica

### `bugtraceaicli.conf`

```ini
[SCAN]
MAX_URLS = 100                      # Límite de URLs a escanear
MAX_CONCURRENT_ANALYSIS = 5         # DAST paralelo
MAX_CONCURRENT_SPECIALISTS = 10     # Specialists paralelo
# VALIDATION = 1 (HARDCODED)        # CDP - NO TOCAR

[THINKING]
THINKING_FP_THRESHOLD = 0.5         # Umbral FP filter
THINKING_DEDUP_ENABLED = True       # Deduplicación activa

[SCANNING]
MANDATORY_SQLMAP_VALIDATION = True  # SQLi requiere SQLMap
STOP_ON_CRITICAL = False            # Parar en SQLi/RCE

[VALIDATION]
CDP_ENABLED = True                  # Usar CDP
CDP_TIMEOUT = 5.0                   # Timeout base
VISION_ENABLED = True               # Vision AI
```

---

## Métricas y Debugging

### Parallelization Metrics (`bugtrace/core/parallelization_metrics.py`)

```python
{
    "by_phase": {
        "discovery": {"current": 0, "peak": 1},
        "analysis": {"current": 3, "peak": 5},
        "exploitation": {"current": 7, "peak": 10},
        "validation": {"current": 1, "peak": 1}  # Siempre max 1
    }
}
```

### Dedup Metrics (`bugtrace/core/dedup_metrics.py`)

```python
{
    "received": 50,
    "duplicates_eliminated": 20,
    "fp_filtered": 10,
    "passed_to_specialists": 20
}
```

---

## Archivos Clave

| Archivo | Responsabilidad |
|---------|-----------------|
| `core/team.py` | Orquestador principal |
| `core/phase_semaphores.py` | Control de concurrencia |
| `agents/analysis_agent.py` | DASTySAST (Fase 2) |
| `agents/thinking_consolidation_agent.py` | Filtrado y routing (Fase 3) |
| `agents/xss_v4.py` | XSS specialist |
| `agents/sqli_agent_v3.py` | SQLi specialist |
| `agents/agentic_validator.py` | Validación CDP (Fase 5) |
| `core/cdp_client.py` | Cliente Chrome DevTools |

---

## Changelog desde V3

### Nuevas Features

1. **Phase Semaphores** - Concurrencia granular por fase
2. **SQLi FP Bypass** - SQLMap decide, no el LLM
3. **probe_validated** - Findings confirmados bypasean filtro
4. **Dedup Metrics** - Tracking de duplicados eliminados
5. **CDP Hardcoded=1** - Documentado y enforced

### Breaking Changes

- `MAX_CONCURRENT_VALIDATION` ya no es configurable
- `MAX_CONCURRENT_URL_AGENTS` es alias de `MAX_CONCURRENT_SPECIALISTS`

---

*Última actualización: 2026-01-30*
