# Plan de Mejoras - BugtraceAI-CLI v1.4

**Fecha**: 2026-01-04
**Versión**: v1.4 (Próxima)
**Estado**: PLANIFICADO

---

## 📋 RESUMEN

Este documento define las mejoras pendientes para el framework BugtraceAI-CLI, enfocadas en **bug bounty** y descartando features innecesarios.

---

## ✅ YA IMPLEMENTADO (v1.3.1)

| Feature | Descripción | Estado |
|---------|-------------|--------|
| URLMasterAgent | Agente vertical con 15 skills | ✅ |
| GoSpider Recon | Descubrimiento rápido de URLs | ✅ |
| HITL | Ctrl+C para pausar/ver findings | ✅ |
| Output Guardrails | Bloquea payloads destructivos | ✅ |
| Input Guardrails | Detecta prompt injection | ✅ |
| Scope Validation | Bloquea URLs fuera de scope | ✅ |
| Exhaustive Mode | Auto-test SQLi/XSS/LFI | ✅ |
| Conductor V2 | Validación anti-alucinación | ✅ |
| AI Reports | Technical + Executive + HTML | ✅ |

---

## 🔵 PENDIENTE - PRIORIDAD ALTA

### 1. SQLite Persistencia
**Estado**: Código existe en `bugtrace/core/database.py`, no integrado  
**Beneficio**: Guardar findings entre sesiones, historial de scans

**Tareas**:
- [ ] Integrar `DatabaseManager` en `TeamOrchestrator`
- [ ] Guardar findings al completar scan
- [ ] Cargar findings previos al iniciar
- [ ] Evitar re-escanear URLs ya probadas

```python
# Uso propuesto
db = DatabaseManager()
db.save_finding(target, finding)
previous = db.get_findings_for_target(target)
```

---

### 2. MemoryManager Activo
**Estado**: Existe en `bugtrace/memory/manager.py`, no usado activamente  
**Beneficio**: Búsqueda semántica de findings similares

**Tareas**:
- [ ] Activar MemoryManager en URLMasterAgent
- [ ] Almacenar embeddings de cada finding
- [ ] Buscar findings similares antes de reportar (deduplicación)
- [ ] Correlacionar vulns entre URLs

```python
# Uso propuesto
memory = MemoryManager()
memory.add_finding(finding)
similar = memory.search_similar(new_finding)
if similar:
    # Es duplicado o relacionado
```

---

## 🟡 PENDIENTE - PRIORIDAD MEDIA

### 3. OpenTelemetry Tracing (Nice-to-have)
**Estado**: No implementado  
**Beneficio**: Debugging avanzado, métricas de performance

**Tareas**:
- [ ] Integrar opentelemetry-sdk
- [ ] Traces para llamadas LLM
- [ ] Traces para ejecución de skills
- [ ] Dashboard opcional (Phoenix/Jaeger)

```python
# Uso propuesto
from opentelemetry import trace
tracer = trace.get_tracer("bugtrace")

@tracer.start_as_current_span("llm_call")
async def call_llm(prompt):
    ...
```

---

## ❌ DESCARTADO (No necesario para Bug Bounty)

| Feature | Razón de descarte |
|---------|-------------------|
| Handoffs | URLMasterAgent con skills ya cubre esto |
| Patterns (Swarm/Hierarchical) | Overkill para bug bounty |
| ReACT formal | El LLM ya razona bien con el prompt actual |
| Agent-as-Tool | No aporta valor significativo |

---

## 🗓️ ROADMAP

### Fase 1: Persistencia (v1.4.0)
- [ ] Integrar SQLite para findings
- [ ] Historial de scans
- [ ] ETA: 1-2 días

### Fase 2: Memoria Semántica (v1.4.1)
- [ ] Activar MemoryManager
- [ ] Deduplicación de findings
- [ ] ETA: 1 día

### Fase 3: Observabilidad (v1.5.0) - Opcional
- [ ] OpenTelemetry básico
- [ ] Dashboard de métricas
- [ ] ETA: 2-3 días

---

## 📁 ARCHIVOS RELEVANTES

| Archivo | Descripción |
|---------|-------------|
| `bugtrace/core/database.py` | SQLite + LanceDB manager |
| `bugtrace/memory/manager.py` | MemoryManager con embeddings |
| `bugtrace/schemas/db_models.py` | Modelos de base de datos |

---

**Próximo paso**: Implementar integración de SQLite en TeamOrchestrator
