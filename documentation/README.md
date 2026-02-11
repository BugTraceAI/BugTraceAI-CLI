# BugTraceAI-CLI Pipeline Documentation

Documentacion detallada del pipeline de seguridad de BugTraceAI-CLI, cubriendo cada fase, componente y subsistema a nivel de implementacion.

---

## Indice de Documentos

| # | Documento | Descripcion |
|---|-----------|-------------|
| 01 | [Arquitectura General](01-architecture-overview.md) | Vision global del sistema, flujo de datos, componentes principales |
| 02 | [Configuracion](02-configuration.md) | Sistema de configuracion: `.env`, `bugtraceaicli.conf`, clase `Settings` |
| 03 | [Fase 1: Discovery](03-phase1-discovery.md) | GoSpider, Nuclei, recon, crawling de URLs |
| 04 | [Fase 2: Analysis](04-phase2-analysis.md) | DASTySAST multi-persona, consenso, SkepticalAgent |
| 05 | [Fase 3: Thinking Consolidation](05-phase3-thinking-consolidation.md) | Deduplicacion, filtrado FP, routing a especialistas |
| 06 | [Fase 4: Exploitation](06-phase4-exploitation.md) | 13 agentes especialistas (XSS, SQLi, CSTI, etc.) |
| 07 | [Fase 5: Validation](07-phase5-validation.md) | AgenticValidator, CDP, Vision AI |
| 08 | [Fase 6: Reporting](08-phase6-reporting.md) | ReportingAgent, generacion HTML/MD/JSON |
| 09 | [Infraestructura Core](09-core-infrastructure.md) | Event Bus, base de datos, worker pool, semaforos |
| 10 | [API REST](10-api-layer.md) | FastAPI endpoints, servicios, schemas |
| 11 | [Interfaz de Usuario](11-ui-system.md) | TUI Textual, dashboard legacy Rich |

---

## Diagrama del Pipeline

```
Usuario
  |
  v
[__main__.py] --> [TeamOrchestrator (team.py)]
                        |
        +---------------+---------------+
        |               |               |
        v               v               v
  [Fase 1]        [Fase 2]        [Fase 3]
  Discovery       Analysis        Thinking
  GoSpider        DASTySAST       Consolidation
  Nuclei          5 Personas      Dedup + FP Filter
                  Skeptical       Queue Routing
                        |               |
                        v               v
                  [Fase 4]        [Fase 5]
                  Exploitation    Validation
                  13 Specialists  AgenticValidator
                  XSS, SQLi...   CDP + Vision AI
                        |               |
                        +-------+-------+
                                |
                                v
                          [Fase 6]
                          Reporting
                          HTML/MD/JSON
                                |
                                v
                          [SQLite DB]
                          [Report Files]
```

---

## Stack Tecnologico

| Componente | Tecnologia |
|------------|------------|
| Core | Python 3.10+, asyncio |
| Web Framework | FastAPI (API REST, port 8000) |
| ORM | SQLAlchemy + SQLModel |
| Base de Datos | SQLite (source of truth) |
| Vector Store | LanceDB |
| AI/LLM | OpenRouter (Gemini, Claude, GPT-4, DeepSeek) |
| Browser Automation | Playwright (multi-context) |
| CDP | Chrome DevTools Protocol |
| Herramientas Externas | SQLMap, GoSpider, Nuclei |
| TUI | Textual (nuevo), Rich (legacy) |
| Configuracion | ConfigParser + Pydantic Settings |

---

## Convenciones

- **Rutas relativas** al directorio `BugTraceAI-CLI/`
- **Lineas de codigo** referenciadas como `archivo.py:linea`
- **Eventos** en formato `nombre_evento` (snake_case)
- **Modelos de DB** en `bugtrace/schemas/db_models.py`
- **Modelos de dominio** en `bugtrace/schemas/models.py`
