# Auditoría de Inconsistencias: Documentación vs Código

**Fecha:** 2026-02-05
**Estado:** EN REVISIÓN

---

## Resumen

Se detectaron **18+ inconsistencias graves** entre la documentación de arquitectura y el código real del proyecto.

---

## Inconsistencias por Documento

### 1. architecture_now.md

| # | Inconsistencia | Lo que dice la doc | Realidad | Estado |
|---|----------------|-------------------|----------|--------|
| 1.1 | Archivo central inexistente | `bugtrace/core/reactor.py` es el "sistema nervioso central" | **NO EXISTE** - El orquestador real es `bugtrace/core/team.py` (clase `TeamOrchestrator`) | ❌ CRÍTICO |
| 1.2 | Directorio inexistente | `bugtrace/agents/exploitation/` contiene 11+ agentes especialistas | **NO EXISTE** - Los agentes están en `bugtrace/agents/` directamente (sin subdirectorio) | ❌ CRÍTICO |
| 1.3 | Archivo inexistente | `bugtrace/core/phase_controller.py` controla concurrencia | **NO EXISTE** - Es `bugtrace/core/phase_semaphores.py` + lógica en `team.py` | ❌ CRÍTICO |
| 1.4 | Directorio vacío | `bugtrace/validators/http_validator.py` para validación HTTP | **NO EXISTE** - Directorio `validators/` está vacío | ❌ CRÍTICO |
| 1.5 | Archivo inexistente | `bugtrace/validators/vision_analyzer.py` para análisis visual | **NO EXISTE** - La lógica está integrada en `bugtrace/agents/agentic_validator.py` | ❌ CRÍTICO |
| 1.6 | Nombre de clase incorrecto | Clase `Conductor` | Es `ConductorV2` (línea 25 de `conductor.py`) | ⚠️ MENOR |
| 1.7 | Líneas de código incorrectas | `config.py` líneas 750-755 contienen MAX_CONCURRENT_* | Líneas 750-755 contienen método `restore_snapshot()` | ⚠️ MENOR |
| 1.8 | Funcionalidad removida | Conductor hace "Validation, anti-hallucination" | Conductor líneas 217-219: `# NOTE: Validation methods REMOVED (2026-02-04)` - Specialists ahora self-validan | ❌ CRÍTICO |

### 2. PIPELINE_FLOW_AND_FILES.md

| # | Inconsistencia | Lo que dice la doc | Realidad | Estado |
|---|----------------|-------------------|----------|--------|
| 2.1 | Línea de código inexistente | `pipeline.py:1735` contiene `_phase_2_batch_dast()` | **pipeline.py tiene solo 1115 líneas** - El código está en `team.py` | ❌ CRÍTICO |
| 2.2 | Estructura de directorios incorrecta | `reports/scan_<id>/queues/sqli/` (subdirectorios por tipo) | Es `reports/.../specialists/wet/sqli.json` (archivos JSON, no subdirectorios) | ❌ CRÍTICO |
| 2.3 | Archivos de cola incorrectos | Múltiples archivos: `cookie_tracking_id_1.json`, `cookie_tracking_id_2.json` | Es un solo archivo consolidado por tipo: `sqli.json`, `xss.json`, etc. | ❌ CRÍTICO |
| 2.4 | Número de fases incorrecto | 22 fases: "Phase 2-18: DAST", "Phase 19-20: Specialists", "Phase 21: Validation", "Phase 22: Reporting" | **Son 6 fases**: RECONNAISSANCE, DISCOVERY, STRATEGY, EXPLOITATION, VALIDATION, REPORTING | ❌ CRÍTICO |
| 2.5 | Archivos de recon incorrectos | Phase 1 genera: `discovered_urls.txt`, `tech_profile.json`, `parameters.json`, `cookies.json` en root | Estos archivos están en subdirectorios, no en root de scan | ⚠️ MENOR |

### 3. ARCHITECTURE.md (.planning/codebase/)

| # | Inconsistencia | Lo que dice la doc | Realidad | Estado |
|---|----------------|-------------------|----------|--------|
| 3.1 | Directorio inexistente | `bugtrace/agents/exploitation/` | **NO EXISTE** - Agentes en `bugtrace/agents/` | ❌ CRÍTICO |
| 3.2 | Path incorrecto | `bugtrace/agents/strategy/thinking_consolidation_agent.py` | Es `bugtrace/agents/thinking_consolidation_agent.py` (sin subdirectorio `strategy/`) | ❌ CRÍTICO |
| 3.3 | Path incorrecto | `bugtrace/agents/validation/agentic_validator.py` | Es `bugtrace/agents/agentic_validator.py` (sin subdirectorio `validation/`) | ❌ CRÍTICO |
| 3.4 | Archivo inexistente | `bugtrace/validators/http_validator.py` | **NO EXISTE** | ❌ CRÍTICO |
| 3.5 | Conductor desactualizado | Conductor hace "Validation, prompt management, anti-hallucination" | Conductor ya NO hace validation (removido 2026-02-04) | ❌ CRÍTICO |

---

## Contradicciones Entre Documentos

| Tema | architecture_now.md | PIPELINE_FLOW.md | ARCHITECTURE.md | Realidad |
|------|---------------------|------------------|-----------------|----------|
| Número de fases | 6 fases | 22 fases | 6 fases | **6 fases** |
| Directorio de colas | `queues/` | `queues/` | `specialists/wet/` | **specialists/wet/** |
| Nombre del orquestador | `reactor.py` | - | `team.py` | **team.py** |
| Estructura de agentes | `agents/exploitation/` | - | `agents/exploitation/`, `agents/strategy/`, `agents/validation/` | **agents/** (plano) |

---

## Estructura Real del Código

### Archivos Core (bugtrace/core/)

```
bugtrace/core/
├── __init__.py
├── batch_metrics.py
├── boot.py
├── cdp_client.py
├── conductor.py          ← ConductorV2 (solo routing, NO validation)
├── config.py
├── conversation_thread.py
├── database.py
├── dedup_metrics.py
├── diagnostics.py
├── embeddings.py
├── event_bus.py          ← EventBus (pub/sub)
├── executor.py
├── guardrails.py
├── http_manager.py
├── http_orchestrator.py
├── instance_lock.py
├── job_manager.py
├── llm_client.py
├── parallelization_metrics.py
├── payload_format.py
├── phase_semaphores.py   ← Semáforos por fase
├── pipeline.py           ← PipelinePhase enum, state machine
├── queue.py
├── specialist_dispatcher.py
├── state.py
├── state_manager.py
├── summary.py
├── team.py               ← TeamOrchestrator (ORQUESTADOR PRINCIPAL)
├── ui_legacy.py
├── url_prioritizer.py
├── validation_metrics.py
└── validator_engine.py
```

### Agentes (bugtrace/agents/) - ESTRUCTURA PLANA

```
bugtrace/agents/
├── __init__.py
├── agentic_validator.py      ← AgenticValidator (CDP validation)
├── analysis_agent.py         ← DASTySASTAgent
├── analysis.py
├── api_security_agent.py
├── asset_discovery_agent.py
├── auth_discovery_agent.py
├── base.py                   ← BaseAgent (clase abstracta)
├── chain_discovery_agent.py
├── csti_agent.py             ← CSTIAgent
├── exploit.py
├── fileupload_agent.py
├── gospider_agent.py         ← GoSpiderAgent
├── header_injection_agent.py ← HeaderInjectionAgent
├── idor_agent.py             ← IDORAgent
├── jwt_agent.py              ← JWTAgent
├── lfi_agent.py              ← LFIAgent
├── nuclei_agent.py
├── openredirect_agent.py     ← OpenRedirectAgent
├── openredirect_payloads.py
├── payload_batches.py
├── prototype_pollution_agent.py ← PrototypePollutionAgent
├── prototype_pollution_payloads.py
├── rce_agent.py              ← RCEAgent
├── recon.py
├── report_validator.py
├── reporting.py              ← ReportingAgent
├── skeptic.py                ← SkepticAgent
├── specialist_utils.py
├── sqli_agent.py             ← SQLiAgent
├── sqlmap_agent.py
├── ssrf_agent.py             ← SSRFAgent
├── thinking_consolidation_agent.py ← ThinkingConsolidationAgent
├── url_master.py
├── worker_pool.py
├── xss_agent.py              ← XSSAgent
└── xxe_agent.py              ← XXEAgent
```

### Pipeline de 6 Fases (CORRECTO)

```
Phase 1: RECONNAISSANCE
    └─ GoSpiderAgent, tech detection, URL discovery

Phase 2: DISCOVERY
    └─ DASTySASTAgent (análisis DAST por URL)

Phase 3: STRATEGY
    └─ ThinkingConsolidationAgent (dedup, filtro FP, routing a specialists)

Phase 4: EXPLOITATION
    └─ XSSAgent, SQLiAgent, CSTIAgent, LFIAgent, IDORAgent, RCEAgent,
       SSRFAgent, XXEAgent, JWTAgent, HeaderInjectionAgent,
       OpenRedirectAgent, PrototypePollutionAgent

Phase 5: VALIDATION
    └─ AgenticValidator (CDP, Vision AI - solo XSS/CSTI)

Phase 6: REPORTING
    └─ ReportingAgent (generación de reportes)
```

### Estructura de Reportes (CORRECTA)

```
reports/{domain}_{timestamp}/
├── recon/                    ← Phase 1 output
├── dastysast/                ← Phase 2 output (archivos numerados: 1.json, 2.json...)
├── specialists/
│   └── wet/                  ← Phase 3 output (colas por tipo)
│       ├── xss.json
│       ├── sqli.json
│       ├── csti.json
│       └── ...
├── validation/               ← Phase 5 output
│   └── screenshots/
├── raw_findings.json         ← Phase 6 output
├── validated_findings.json
├── engagement_data.json
└── final_report.md
```

---

## Plan de Corrección

### Prioridad 1: Eliminar documentos obsoletos

- [x] **COMPLETADO** - Archivar `architecture_now.md` → movido a `.ai-context/trash/`
- [x] **COMPLETADO** - Archivar `PIPELINE_FLOW_AND_FILES.md` → movido a `.ai-context/trash/`
- [x] **COMPLETADO** - Archivar `ARCHITECTURE.md` (.planning/codebase/) → movido a `.ai-context/trash/`

### Prioridad 2: Crear documentación correcta

- [x] **COMPLETADO** - Crear `ARCHITECTURE_V7.md` con estructura real del código
  - Ubicación: `.ai-context/architecture/ARCHITECTURE_V7.md`
  - Contenido verificado: TeamOrchestrator, 6 fases, agentes planos, specialists/wet/
- [x] **COMPLETADO** - Documentar las 6 fases correctamente
- [x] **COMPLETADO** - Documentar estructura de agentes (plana, sin subdirectorios)
- [ ] Documentar rol actual del Conductor (routing, NO validation)

### Prioridad 3: Limpiar referencias

- [ ] Buscar y corregir todas las referencias a `reactor.py`
- [ ] Buscar y corregir referencias a `agents/exploitation/`
- [ ] Buscar y corregir referencias a `validators/`
- [ ] Actualizar líneas de código específicas o eliminarlas

### Prioridad 4: Marcar docs obsoletos

- [ ] Añadir header "OBSOLETO" a docs que no se eliminen
- [ ] Crear README en `.ai-context/architecture/` indicando cuál es el doc activo

---

## Notas

- El Conductor fue refactorizado el 2026-02-04 para remover validación
- Los specialists ahora self-validan via `BaseAgent.emit_finding()`
- No existen subdirectorios en `agents/` (exploitation, strategy, validation)
- El orquestador principal es `TeamOrchestrator` en `team.py`, NO reactor.py
