# Plan de Mejoras v1.5 - BugtraceAI-CLI

**Fecha**: 2026-01-04
**Versión**: v1.5
**Estado**: ✅ IMPLEMENTACIÓN COMPLETA

---

## 📋 RESUMEN DE IMPLEMENTACIÓN

| Fase | Estado | Descripción |
|------|--------|-------------|
| **Phase 1** | ✅ | XSS Deduplication (vuln-type mapping) |
| **Phase 2** | ✅ | MemoryManager Activated |
| **Phase 3** | ✅ | Conductor Context Sharing |
| **Phase 4** | ⏳ | Tests pendientes |

---

### Problemas Detectados ⚠️
| Problema | Severidad | Impacto |
|----------|-----------|---------|
| LLM repite XSS sin parar | 🔴 Alta | Test no termina |
| MemoryManager inactivo | 🟡 Media | No deduplica findings |
| Conductor: solo valida, no comparte contexto | 🟡 Media | Agentes no comparten información |
| SQLite: código no probado | 🟡 Media | Persistencia no verificada |

---

## 🎯 FILOSOFÍA: MEJORAR SIN ROMPER

> No refactorizar lo que funciona. Añadir, no reemplazar.

---

## 📐 ARQUITECTURA PROPUESTA

### Roles Claros:

```
┌─────────────────────────────────────────────────────────┐
│                    TeamOrchestrator                      │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │Conductor │  │  Guardrails  │  │   URLMasterAgent │  │
│  │(Context) │  │  (Security)  │  │   (per URL)      │  │
│  └────┬─────┘  └──────┬───────┘  └────────┬─────────┘  │
│       │               │                    │            │
│       │  ┌────────────┴────────────┐      │            │
│       │  │                         │      │            │
│       ▼  ▼                         ▼      ▼            │
│  ┌──────────────┐            ┌──────────────────┐     │
│  │ Validation   │◀───────────│    Findings      │     │
│  │ (Conductor)  │            │                  │     │
│  └──────────────┘            └──────────────────┘     │
│                                      │                 │
│                                      ▼                 │
│                              ┌──────────────┐         │
│                              │MemoryManager │         │
│                              │(Deduplication)│         │
│                              └──────────────┘         │
└─────────────────────────────────────────────────────────┘
```

### Responsabilidades:

| Componente | Responsabilidad | Cambio |
|------------|-----------------|--------|
| **Conductor** | 1. Validar findings 2. **NUEVO: Compartir contexto entre agentes** | Extender |
| **Guardrails** | Bloquear payloads peligrosos | Sin cambios |
| **MemoryManager** | **ACTIVAR: Deduplicar findings** | Activar |
| **URLMasterAgent** | **FIX: No repetir pruebas** | Arreglar |

---

## 🔧 CAMBIOS PROPUESTOS

### 1. FIX: Deduplicación XSS (URGENTE)
**Archivo**: `url_master.py`
**Problema**: LLM ejecuta XSS infinitamente
**Solución**: Trackear qué param+skill ya fue probado

```python
# En URLMasterAgent.__init__
self.tested_combinations = set()  # (param, skill_name)

# En _execute_skill
combo = (param, skill_name)
if combo in self.tested_combinations:
    logger.info(f"Skipping duplicate: {combo}")
    return {"skipped": True}
self.tested_combinations.add(combo)
```

### 2. ACTIVAR: MemoryManager
**Archivo**: `url_master.py`
**Problema**: No busca findings similares
**Solución**: Antes de añadir finding, buscar duplicados

```python
from bugtrace.memory.manager import memory_manager

# Antes de añadir finding
similar = memory_manager.search_similar(finding)
if similar:
    logger.info(f"Finding similar to existing: {similar}")
    return  # Skip duplicate
```

### 3. EXTENDER: Conductor con Context Sharing
**Archivo**: `conductor.py`
**Problema**: No comparte contexto entre agentes
**Solución**: Añadir métodos para contexto compartido

```python
class ConductorV2:
    def __init__(self):
        # ... existing code ...
        self.shared_context = {}  # Shared between agents
    
    def share_context(self, key: str, value: Any):
        """Share context between agents."""
        self.shared_context[key] = value
    
    def get_context(self, key: str) -> Any:
        """Get shared context."""
        return self.shared_context.get(key)
    
    def get_all_context(self) -> Dict:
        """Get all shared context for agent prompts."""
        return self.shared_context.copy()
```

### 4. VERIFICAR: SQLite Persistence
**Archivo**: `team.py`
**Estado**: Código añadido pero no probado
**Acción**: Test de integración

---

## 🗓️ ORDEN DE EJECUCIÓN

| # | Tarea | Tiempo | Riesgo |
|---|-------|--------|--------|
| 1 | FIX deduplicación XSS | 10 min | Bajo |
| 2 | Activar MemoryManager | 15 min | Bajo |
| 3 | Extender Conductor | 20 min | Bajo |
| 4 | Test SQLite | 10 min | Bajo |
| 5 | Test completo E2E | 15 min | - |

---

## ✅ CRITERIOS DE ÉXITO

1. Test no repite XSS infinitamente
2. Findings duplicados son detectados
3. Conductor puede compartir contexto
4. Database guarda findings

---

## ❌ LO QUE NO HAREMOS

- Renombrar Conductor
- Mover validación a otro componente
- Refactorizar SkepticalAgent
- Cambiar arquitectura base

---

**Siguiente paso**: Revisar y aprobar plan
