# BugTraceAI - Sesión de Evolución Arquitectónica (2026-01-14)

Este documento detalla los cambios realizados, la justificación técnica detrás de ellos y el impacto esperado en el framework.

## 1. El "POR QUÉ": La Necesidad de Evolución

**Motivo:** Eficiencia y Precisión.
BugTraceAI V3 funcionaba bajo el modelo de "Enjambre Incondicional". Si se descubrían 50 parámetros, se lanzaban 50 ataques de cada tipo (XSS, SQLi, etc.), sumando miles de peticiones. Esto causaba:

- **Ruido excesivo:** Difícil diferenciar vulnerabilidades reales de escaneos genéricos.
- **Falsos positivos:** Especialmente en IDOR y SSRF donde el contexto es rey.
- **Latencia:** El scan tardaba horas en objetivos medianos.

**Objetivo:** Pasar a una **Orquestación Quirúrgica** donde la IA actúa como un analista senior que decide *qué* atacar basándose en evidencia.

## 2. El "CUÁNDO": Línea de Tiempo de la Sesión

- **20:00 - 20:30:** Identificación de cuellos de botella y rediseño de la lógica de `team.py`.
- **20:30 - 21:00:** Evolución de `DASTAgent` a `DASTySASTAgent` (integración de análisis proyectivo).
- **21:00 - 21:20:** Implementación del soporte de Playwright en `GoSpiderAgent` para crawling dinámico.
- **21:20 - 21:40:** Creación de entornos de prueba controlados (`Mixed Dojo` y `Front App`) y solución del bug de persistencia en el `Reactor`.

## 3. El "QUÉ": Cambios Implementados

### A. Orquestación Quirúrgica (Core Evolution)

- **Archivo:** `bugtrace/core/team.py` y `bugtrace/core/reactor.py`.
- **Cambio:** Se eliminó el modo "Swarm" automático. Ahora, el `Reactor` espera el reporte del `DASTySASTAgent`. Solo si este agente detecta un vector con confianza > 0.3, se crea un job de ataque específico.

### B. El Agente DASTySAST (Intelligence Layer)

- **Archivo:** `bugtrace/agents/analysis_agent.py`.
- **Cambio:** No solo analiza parámetros `GET/POST`. Ahora realiza un **SAST Proyectivo** analizando la arquitectura probable del servidor (ej. si ve un puerto 5000, asume Flask y busca vulnerabilidades comunes de Werkzeug).

### C. Descubrimiento Dinámico (Modern Crawling)

- **Archivo:** `bugtrace/agents/gospider_agent.py`.
- **Cambio:** Integración de **Playwright**. Ahora el crawler puede renderizar JavaScript para descubrir endpoints en SPAs (React/Vue/Angular) que GoSpider por sí solo no veía.

### D. Persistencia de Hallazgos (Success Loop)

- **Archivo:** `bugtrace/core/reactor.py`.
- **Cambio:** Se añadió lógica para persistir los hallazgos confirmados por especialistas (XSS, SQLi, etc.) directamente en la base de datos de estados (`state/jobs.db`) y reportes JSON. Antes, solo el análisis inicial se guardaba.

## 4. El "CÓMO": Arquitectura Técnica

### Flujo de Datos V4

1. **RECON (GoSpider + Playwright):** Descubre URLs "vivas" y dinámicas.
2. **ANALYSIS (DASTySAST):** Ejecuta 5 enfoques paralelos de IA para calificar la URL.
3. **DISPATCH (Orchestrator):** Crea Jobs de ataque (`ATTACK_XSS`, `ATTACK_SQLI`) solo para los parámetros sospechosos.
4. **VALIDATION (Specialists):** Los especialistas técnicos confirman la vulnerabilidad con payloads reales.
5. **PERSISTENCE (State Manager):** El Hallazgo Confirmado se guarda con su captura de pantalla y evidencia técnica.

## 5. Entornos de Validación Creados

Para asegurar que el framework no alucine y mantenga el contexto, se crearon:

1. **`testing/vuln_front_app.py`:** Una app con vulnerabilidades reales mezcladas con "señuelos" (login seguro vs catálogo inseguro).
2. **`testing/mixed_orchestration_dojo.py`:** Un dojo de 10 niveles específicos (L0 a L5) para probar la precisión quirúrgica.

---
**Estado Final de la Sesión:** La arquitectura V4 es ahora funcional y está siendo validada contra el Comprehensive Dojo en tiempo real.
