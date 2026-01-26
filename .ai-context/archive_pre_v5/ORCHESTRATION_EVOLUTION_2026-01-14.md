# Evolución Arquitectónica: Orquestación Quirúrgica (V4)

## Contexto

Históricamente, BugTraceAI utilizaba un enfoque de "Enjambre Incondicional" (Unconditional Swarm). Por cada URL descubierta, se lanzaban todos los agentes de ataque (XSS, SQLi, etc.) para probar todos los parámetros. Esto resultaba en:

- **Alta Latencia:** Miles de peticiones innecesarias.
- **Coste Elevado:** Uso excesivo de tokens de LLM para análisis repetitivos.
- **Ruido:** Generación de logs masivos difíciles de auditar.

## Objetivos del Cambio

Implementar una **Orquestación Quirúrgica** basada en el nuevo agente híbrido **DASTySAST**.

### 1. Cambio de Paradigma: De Enjambre a Precisión

- **Anterior:** `URL -> [XSSAgent + SQLiAgent + SSRFAgent...]` (Todos en cada URL).
- **Nuevo:** `URL -> DASTySASTAgent -> [Especialista Específico]` (Solo si hay evidencia).

### 2. Identidad Híbrida (DASTySAST)

El agente de análisis ya no se limita a mirar parámetros dinámicos. Realiza un análisis estático proyectivo (SAST) sobre la lógica probable del servidor basándose en los nombres de parámetros, cabeceras y respuestas tecnológicas, antes de decidir el vector de ataque.

## Implementación Técnica

### Archivos Modificados

- **`bugtrace/agents/analysis_agent.py`:**
  - Renombrado de `DASTAgent` a `DASTySASTAgent`.
  - Actualización de prompts para incluir razonamiento de código (SAST).
- **`bugtrace/core/reactor.py`:**
  - Integración total con el flujo reactivo.
  - Eliminación de heurísticas por reglas (hardcoded).
  - Creación dinámica de jobs basada únicamente en el output de la IA.
- **`bugtrace/core/team.py`:**
  - Desactivación del "Unconditional Swarm".
  - Implementación del despachador inteligente para la ejecución secuencial.
- **`bugtrace/agents/gospider_agent.py`:**
  - Añadido `_crawl_with_playwright` para descubrimiento avanzado de URLs en SPAs (JS-heavy).

## Medición del Éxito (KPIs)

Para confirmar que estos cambios son efectivos, mediremos los siguientes indicadores contra el **Comprehensive Dojo**:

| KPI | Métrica de Éxito | Método de Medición |
| :--- | :--- | :--- |
| **Eficiencia de Peticiones** | Reducción del >60% en peticiones totales. | Comparar logs de `access.log` vs versiones anteriores. |
| **Precisión de Jobs** | Ratio de Jobs de Ataque / Vulnerabilidades Reales > 0.8. | Verificar que no se crean jobs de SQLi en páginas sin SQLi. |
| **Reducción de Falsos Positivos** | Eliminación de los 19 IDOR FPs conocidos. | Reporte final contra el Dojo Level 0-10. |
| **Cobertura de Descubrimiento** | Detección de `/catalog?category=Juice`. | Verificar que la URL aparece en la fase de RECON. |
| **Tiempo por URL** | Reducción del tiempo medio de análisis en un 40%. | Logs de `execution.log` (Phase 2 duration). |

## Pasos para Validación

1. **Ejecutar Scan Quirúrgico:** `python3 tests/test_reactor.py` targeting Dojo puerto 5090.
2. **Auditar Decisiones:** Revisar `reports/jobs/job_X/vulnerabilities_...md` para ver por qué la IA decidió (o no) atacar un parámetro.
3. **Verificación de Cobertura:** Comprobar que el XSS de `/catalog` es detectado gracias al crawling dinámico.

---
**Fecha:** 2026-01-14
**Estado:** Implementación Completada / Pendiente de Validación Final.
