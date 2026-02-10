# Registro de Resolución de Inconsistencias de Arquitectura
**Fecha:** 2026-02-05
**Estado:** En Progreso

Este documento rastrea las decisiones tomadas para resolver las discrepancias entre la documentación y el código base encontradas en la auditoría del 05/02/2026.

## Resoluciones Acordadas

### 1. Orquestador Central: Reactor vs Team
- **Inconsistencia:** La documentación menciona `bugtrace/core/reactor.py` como el núcleo. El código usa `bugtrace/core/team.py`.
- **Análisis:** `reactor.py` no existe. `team.py` contiene la lógica real (`TeamOrchestrator`).
- **Acción:** Actualizar toda la documentación para referenciar `team.py` y `TeamOrchestrator`. Eliminar referencias a `reactor.py`.

### 2. Estructura de Directorios de Agentes
- **Inconsistencia:** La documentación describe subdirectorios organizados (`agents/exploitation/`, `agents/strategy/`, etc.).
- **Realidad:** El código usa una estructura plana en `bugtrace/agents/`.
- **Acción:** Actualizar la documentación para reflejar la estructura plana actual. No mover archivos de código para evitar romper imports.

### 3. Módulos de Validación Inexistentes
- **Inconsistencia:** La documentación menciona `bugtrace/validators/` con archivos como `vision_analyzer.py` y `http_validator.py`.
- **Realidad:** Estos archivos no existen. La lógica de validación (Visual/CDP) reside **únicamente** en `bugtrace/agents/agentic_validator.py` y en la auto-validación de los propios agentes.
- **Acción:** Actualizar la documentación para eliminar referencias a validadores externos y aclarar que la responsabilidad recae exclusivamente en `AgenticValidator` y los agentes.

### 4. Definición de Fases del Pipeline
- **Inconsistencia:** Algunos documentos detallan hasta 22 fases lineales.
- **Realidad:** El sistema opera sobre **6 Fases Principales** (Macro-fases). Dentro de cada fase (y agente) existen sub-fases o estados internos.
- **Acción:** Estandarizar la documentación para reflejar el modelo de "6 Macro-Fases". Las "22 fases" deben reformularse como sub-procesos internos o eliminarse si causan confusión.

### 5. Estructura de Directorios de Reportes
- **Inconsistencia:** La documentación menciona carpetas como `queues/` en la raíz del scan.
- **Realidad:** El código genera una estructura específica: `reports/{id}/specialists/wet/` para las colas, más `recon/`, `dastysast/`, etc.
- **Acción:** Actualizar la documentación para documentar la estructura de carpetas REAL que genera el código.

---
## Pendientes de Decisión
