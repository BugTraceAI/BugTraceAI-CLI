# 📚 Índice Completo de Funciones de Archivos - BugTraceAI (Reactor V6)

> **Generado**: 2026-02-02  
> **Última Actualización**: 2026-02-02  
> **Propósito**: Índice completo y exhaustivo de responsabilidades por archivo/módulo del proyecto BugTraceAI-CLI.

---

## 📂 Raíz del Proyecto

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **bugtraceai-cli** | Script ejecutable principal (entry point CLI). |
| **README.md** | Documentación principal del proyecto, instalación y uso. |
| **requirements.txt** | Dependencias Python necesarias para el proyecto. |
| **pyproject.toml** | Configuración de proyecto Python (Poetry/setuptools). |
| **.env / .env.example** | Variables de entorno (API keys, configuración). |
| **Dockerfile** | Imagen Docker para deployment del proyecto. |
| **docker-compose.yml** | Orquestación de servicios Docker. |
| **alembic.ini** | Configuración de migraciones de base de datos (Alembic). |
| **bugtrace.db** | Base de datos SQLite principal del sistema. |
| **bugtraceaicli.conf** | Archivo de configuración del sistema. |
| **check_db.py** | Script de utilidad para verificación de integridad de DB. |
| **scan_final.log** | Log de última ejecución de escaneo. |

---

## 📂 bugtrace/core/ (El Núcleo del Reactor)

### Componentes Principales

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **pipeline.py** | ⚡ **Orquestador del Pipeline de 6 Fases**: Controla transiciones, pausas y sincronización entre fases. |
| **team.py** | 🧠 **Sistema de Equipos de Agentes**: Orquestación de equipos especializados, asignación de tareas y coordinación. |
| **conductor.py** | 🎯 **Director del Flujo**: Coordina la ejecución de alto nivel de todo el pipeline. |
| **boot.py** | 🚀 **Inicialización del Sistema**: Bootstrap del framework, carga de configuraciones iniciales. |

### Gestión de Estado y Datos

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **database.py** | 💾 **Gestión de Base de Datos**: Conexión y gestión de sesiones SQLite (SQLAlchemy + Async). |
| **state.py** | 📊 **Estado Global**: Representación del estado general del sistema. |
| **state_manager.py** | 🔄 **Gestor de Estados**: Persistencia y recuperación de estados de escaneo. |
| **instance_lock.py** | 🔒 **Control de Instancias**: Sistema de locks para evitar ejecuciones concurrentes. |

### Comunicación y Eventos

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **event_bus.py** | 📡 **Bus de Eventos Pub/Sub**: Sistema de mensajería asíncrono para comunicación entre agentes. |
| **conversation_thread.py** | 💬 **Hilos de Conversación**: Gestión de conversaciones entre agentes AI. |

### Gestión de Recursos

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **queue.py** | 📋 **Sistema de Colas**: Gestión de colas de trabajo priorizadas para agentes especialistas. |
| **job_manager.py** | ⚙️ **Gestor de Jobs**: Administración de trabajos y tareas asíncronas. |
| **executor.py** | ⚡ **Ejecutor de Tareas**: Ejecución controlada de tareas con manejo de errores. |

### Integraciones Externas

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **llm_client.py** | 🤖 **Cliente LLM Unificado**: Cliente para OpenRouter/Gemini/Claude con rate limiting y fallback. |
| **http_orchestrator.py** | 🌐 **Orquestador HTTP**: Gestión centralizada de peticiones HTTP para evitar bloqueos y rate limits. |
| **http_manager.py** | 🔌 **Manager HTTP**: Gestión de conexiones HTTP reutilizables y pooling. |
| **cdp_client.py** | 🔍 **Chrome DevTools Protocol**: Cliente de bajo nivel para control granular del navegador. |

### Control de Concurrencia

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **phase_semaphores.py** | 🚦 **Semáforos por Fase**: Control de concurrencia granular por fase del pipeline. |
| **guardrails.py** | 🛡️ **Guardrails del Sistema**: Protecciones contra comportamientos peligrosos o no deseados. |

### Métricas y Monitoreo

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **batch_metrics.py** | 📈 **Métricas de Batch**: Seguimiento de rendimiento de procesamiento por lotes. |
| **dedup_metrics.py** | 🔀 **Métricas de Deduplicación**: Estadísticas sobre eliminación de duplicados. |
| **parallelization_metrics.py** | ⚡ **Métricas de Paralelización**: Seguimiento de eficiencia de procesamiento paralelo. |
| **validation_metrics.py** | ✅ **Métricas de Validación**: Estadísticas sobre validaciones exitosas/fallidas. |
| **diagnostics.py** | 🔧 **Diagnósticos del Sistema**: Herramientas de diagnóstico y troubleshooting. |
| **summary.py** | 📊 **Generador de Resúmenes**: Creación de resúmenes ejecutivos de escaneos. |

### Interfaz de Usuario

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **ui.py** | 🖥️ **Interfaz CLI**: Dashboard en tiempo real usando Rich (tablas, progreso, alertas). |

### Configuración y Utilidades

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **config.py** | ⚙️ **Configuración Global**: Carga de variables de entorno (.env) y configuración global (Pydantic). |
| **embeddings.py** | 🧬 **Sistema de Embeddings**: Generación de vectores para similitud semántica. |
| **url_prioritizer.py** | 🎯 **Priorizador de URLs**: Sistema de scoring para priorizar URLs más prometedoras. |
| **validation_status.py** | ✔️ **Estados de Validación**: Definición de estados del proceso de validación. |
| **validator_engine.py** | 🔬 **Motor de Validación**: Engine principal para validación de vulnerabilidades. |

---

## 📂 bugtrace/agents/ (El Enjambre de Especialistas)

### Agentes Base y de Coordinación

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **base.py** | 🧩 **Clase Base de Agentes**: Clase abstracta `BaseAgent` con utilidades comunes (logging, eventos, comunicación). |
| **thinking_consolidation_agent.py** | 🧠 **(Fase 3) Cerebro Central**: Deduplica, prioriza y consolida findings de múltiples agentes. |
| **analysis_agent.py** | 🔍 **(Fase 2) Análisis Inteligente**: Analiza respuestas HTTP con AI para detectar anomalías y patrones. |
| **analysis.py** | 📊 **Análisis Auxiliar**: Funciones de análisis complementarias. |
| **url_master.py** | 🗺️ **Maestro de URLs**: Gestión centralizada del inventario de URLs descubiertas. |
| **worker_pool.py** | 👷 **Pool de Workers**: Gestión de pool de workers para procesamiento paralelo. |

### Agentes de Reconocimiento (Fase 1)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **recon.py** | 🔭 **(Fase 1) Reconocimiento Pasivo**: Gathering de información inicial (DNS, subdominios, tech stack). |
| **gospider_agent.py** | 🕷️ **(Fase 1) Web Crawler**: Wrapper para GoSpider - crawling y descubrimiento de endpoints. |
| **nuclei_agent.py** | ⚡ **(Fase 1) Scanner de Plantillas**: Wrapper para Nuclei - detección de tecnologías y vulnerabilidades conocidas. |
| **asset_discovery_agent.py** | 🗺️ **(Fase 1) Descubrimiento de Assets**: Identificación de assets, subdominios y endpoints. |
| **chain_discovery_agent.py** | 🔗 **(Fase 1) Descubrimiento de Cadenas**: Identificación de cadenas de ataque complejas. |

### Agentes de Explotación Especializada (Fase 4)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **xss_agent.py** | 💉 **Especialista XSS**: Cross-Site Scripting (Reflected, Stored, DOM) - Payloads contextuales y evasión. |
| **sqli_agent.py** | 🗄️ **Especialista SQLi**: SQL Injection (Error-based, Boolean, Time-based, UNION) - Detección multi-DBMS. |
| **sqlmap_agent.py** | 💪 **SQLMap Orchestrator**: Wrapper inteligente para sqlmap con fine-tuning automático. |
| **rce_agent.py** | ⚠️ **Especialista RCE**: Remote Code Execution (Command Injection, Deserialization, Template Injection). |
| **lfi_agent.py** | 📁 **Especialista LFI**: Local File Inclusion y Path Traversal con técnicas de bypass. |
| **ssrf_agent.py** | 🌐 **Especialista SSRF**: Server-Side Request Forgery con OOB callbacks y bypass de blacklists. |
| **xxe_agent.py** | 📄 **Especialista XXE**: XML External Entity con payloads para diferentes parsers. |
| **idor_agent.py** | 🔓 **Especialista IDOR**: Insecure Direct Object Reference - fuzzing de IDs y control de acceso. |
| **csti_agent.py** | 🎭 **Especialista CSTI**: Client-Side Template Injection (Angular, Vue, React) con gadgets específicos. |
| **jwt_agent.py** | 🔑 **Especialista JWT**: Ataques a JSON Web Tokens (alg:none, weak secret, injection). |
| **api_security_agent.py** | 🔌 **Especialista API Security**: Vulnerabilidades específicas de APIs REST/GraphQL. |
| **fileupload_agent.py** | 📤 **Especialista File Upload**: Bypass de validaciones de upload y ejecución de archivos. |
| **header_injection_agent.py** | 📨 **Especialista Header Injection**: CRLF Injection, Host Header Poisoning. |
| **openredirect_agent.py** | 🔄 **Especialista Open Redirect**: Detección y explotación de redirecciones abiertas. |
| **prototype_pollution_agent.py** | 🧬 **Especialista Prototype Pollution**: Ataques a prototipos JavaScript. |

### Agentes de Validación (Fase 5)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **agentic_validator.py** | ✅ **(Fase 5) Validador Agéntico**: Validación con navegador real, CDP y visión AI multimodal. |
| **report_validator.py** | 📋 **(Fase 5) Validador de Reportes**: Valida la calidad y precisión de los reportes antes de generarlos. |
| **skeptic.py** | 🤔 **Agente Escéptico**: Desafía findings con análisis crítico para reducir falsos positivos. |

### Agentes de Reporting (Fase 6)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **reporting.py** | 📄 **(Fase 6) Generador de Reportes**: Creación de reportes finales en múltiples formatos (Markdown, HTML, JSON). |

### Utilidades de Agentes

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **exploit.py** | 💣 **Funciones de Explotación**: Utilidades compartidas para explotación. |
| **exploit_specialists.py** | 🎯 **Especialistas de Exploit**: Lógica especializada de explotación. |
| **payload_batches.py** | 📦 **Gestión de Batches de Payloads**: Organización de payloads en batches eficientes. |
| **openredirect_payloads.py** | 🔄 **Payloads Open Redirect**: Biblioteca de payloads para open redirect. |
| **prototype_pollution_payloads.py** | 🧬 **Payloads Prototype Pollution**: Biblioteca de payloads para prototype pollution. |

### System Prompts

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **system_prompts/** | 📝 **Prompts del Sistema**: Contiene 23 archivos con prompts especializados para cada agente AI. |

### Skills de Agentes

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **skills/** | 🛠️ **Habilidades de Agentes**: 13 módulos con skills reutilizables entre agentes. |

---

## 📂 bugtrace/tools/ (Herramientas y Recursos)

### Herramientas de Interacción

| Archivo/Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **interactsh.py** | 📡 **Cliente Interactsh**: Detecta interacciones OOB (DNS/HTTP callbacks) para SSRF, XXE, etc. |
| **external.py** | 🔧 **Wrappers de Herramientas Externas**: Ejecución de binarios externos (sqlmap, nuclei, etc.) via subprocess. |

### Manipulación y Mutación

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **manipulator/** | 🔀 **Engines de Mutación**: 7 módulos para mutación de payloads y evasión de WAFs. |

### Browser Automation

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **visual/** | 🌐 **Automatización Visual**: 5 módulos para gestión de navegadores Playwright y capturas. |
| **headless/** | 🤖 **Headless Browsers**: 2 módulos para operaciones headless browser. |

### Explotación

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **exploitation/** | 💣 **Framework de Explotación**: 6 módulos con técnicas de explotación avanzadas. |

### WAF y Bypass

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **waf/** | 🛡️ **WAF Detection & Bypass**: 4 módulos para detección de WAFs y generación de bypasses. |

### Reconocimiento

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **recon/** | 🔭 **Herramientas de Recon**: 1+ módulos para reconocimiento de infraestructura. |

---

## 📂 bugtrace/skills/ (Habilidades Reutilizables)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **injection.py** | 💉 **Skills de Inyección**: Funciones puras para inyecciones SQL, XSS, etc. (usadas por agentes). |
| **recon.py** | 🔍 **Skills de Reconocimiento**: Funciones de recon (DNS, subdominios, tecnologías). |
| **advanced.py** | 🎯 **Técnicas Avanzadas**: Skills de explotación avanzada. |
| **external_tools.py** | 🔧 **Skills de Herramientas Externas**: Integración con herramientas de terceros. |
| **infrastructure.py** | 🏗️ **Skills de Infraestructura**: Utilidades de infraestructura. |
| **utility.py** | 🛠️ **Skills de Utilidad**: Funciones de utilidad general compartidas. |
| **base.py** | 🧩 **Skills Base**: Clase base de skills. |

---

## 📂 bugtrace/memory/ (Sistema de Memoria)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **manager.py** | 🧠 **Gestor de Memoria**: Gestión de memoria a corto plazo (Redis/Dict) para contexto de agentes. |
| **payload_learner.py** | 📚 **Sistema de Aprendizaje**: Aprende de intentos fallidos, registra payloads bloqueados por WAF. |

---

## 📂 bugtrace/reporting/ (Sistema de Reportes)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **generator.py** | 📄 **Motor de Generación**: Orquestador principal de generación de reportes. |
| **markdown_generator.py** | 📝 **Generador Markdown**: Creación de reportes en formato Markdown enriquecido. |
| **ai_writer.py** | 🤖 **Escritor AI**: Usa LLMs para mejorar narrativas de reportes. |
| **collector.py** | 📊 **Recolector de Datos**: Recolecta y estructura datos de findings para reportes. |
| **url_reporter.py** | 🔗 **Reporteador de URLs**: Generación de reportes específicos por URL. |
| **models.py** | 📋 **Modelos de Reporte**: Estructuras de datos para reportes. |
| **standards.py** | 📏 **Estándares de Reporting**: Definición de estándares y formatos de reportes. |

### Templates

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **templates/** | 🎨 **Plantillas de Reportes**: 4 plantillas para diferentes formatos de reporte. |

---

## 📂 bugtrace/api/ (API REST y Web)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **server.py** | 🚀 **Servidor FastAPI**: Configuración del servidor (CORS, Middleware, lifespan). |
| **main.py** | 🌐 **Aplicación Principal**: Entry point de la aplicación FastAPI. |
| **deps.py** | 🔗 **Dependencias**: Injectable dependencies para FastAPI. |
| **schemas.py** | 📋 **Schemas Pydantic**: Modelos de validación para API. |
| **exceptions.py** | ⚠️ **Exception Handlers**: Manejadores de excepciones personalizados. |

### Routes

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **routes/** | 🛣️ **Endpoints REST**: 5 módulos con endpoints para scans, findings, health, etc. |

---

## 📂 bugtrace/services/ (Servicios de Negocio)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **scan_service.py** | 🔍 **Servicio de Escaneo**: Lógica de negocio para iniciar y gestionar escaneos. |
| **report_service.py** | 📊 **Servicio de Reportes**: Lógica de negocio para generación y consulta de reportes. |
| **scan_context.py** | 📦 **Contexto de Escaneo**: Gestión del contexto y estado de escaneos activos. |
| **event_bus.py** | 📡 **Bus de Eventos del Servicio**: Pub/sub a nivel de servicios. |

---

## 📂 bugtrace/schemas/ (Modelos de Datos)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **models.py** | 📋 **Modelos Pydantic**: Modelos de validación principales del sistema. |
| **db_models.py** | 🗄️ **Modelos de Base de Datos**: Modelos SQLAlchemy para persistencia. |
| **validation_feedback.py** | ✅ **Schemas de Feedback de Validación**: Estructuras para feedback de validaciones. |

---

## 📂 bugtrace/utils/ (Utilidades Compartidas)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **logger.py** | 📝 **Sistema de Logging**: Configuración centralizada de logging. |
| **logging_standards.py** | 📏 **Estándares de Logging**: Definición de formatos y niveles de log. |
| **http_client.py** | 🌐 **Cliente HTTP**: Cliente HTTP reutilizable con retry y timeout. |
| **parsers.py** | 🔍 **Parsers**: Utilidades de parsing (HTML, JSON, URLs). |
| **validation.py** | ✔️ **Validadores**: Funciones de validación de datos. |
| **prioritizer.py** | 🎯 **Priorizador**: Lógica de priorización de tareas. |
| **safeguard.py** | 🛡️ **Safeguards**: Protecciones y validaciones de seguridad. |
| **janitor.py** | 🧹 **Limpieza**: Utilidades de limpieza y mantenimiento. |
| **aiohttp_patch.py** | 🔧 **Patch de aiohttp**: Parches para aiohttp. |
| **token_scanner.py** | 🔑 **Scanner de Tokens**: Detección de tokens y secretos. |
| **refactoring_patterns.py** | ♻️ **Patrones de Refactoring**: Utilidades para refactoring. |

---

## 📂 bugtrace/mcp/ (Model Context Protocol)

| Archivo | Responsabilidad Principal |
|---------|---------------------------|
| **server.py** | 🖥️ **Servidor MCP**: Servidor del protocolo MCP para integración con Claude/AI. |
| **tools.py** | 🔧 **Herramientas MCP**: Definición de tools expuestas via MCP. |
| **resources.py** | 📚 **Recursos MCP**: Recursos expuestos via MCP. |
| **explain.py** | 💡 **Sistema de Explicaciones**: Genera explicaciones de vulnerabilidades para AI. |

---

## 📂 Directorios de Testing

### tests/

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **tests/** | 🧪 **Suite de Tests**: 56+ archivos de tests unitarios e integración (pytest). |

---

## 📂 Directorios de Configuración y Deployment

### alembic/

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **alembic/** | 🗄️ **Migrations**: Sistema de migraciones de base de datos (Alembic). |

### scripts/

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **scripts/** | 🔧 **Scripts de Utilidad**: Scripts de mantenimiento, deployment, etc. |

### bin/

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **bin/** | ⚙️ **Binarios**: 4 binarios/scripts ejecutables auxiliares. |

---

## 📂 Directorios de Datos y Output

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **logs/** | 📝 **Logs del Sistema**: Logs de ejecución, errores y auditoría. |
| **reports/** | 📊 **Reportes Generados**: Output de reportes de escaneos completados. |
| **uploads/** | 📤 **Archivos Subidos**: Archivos subidos via API. |
| **data/** | 📦 **Datos del Sistema**: Datos persistentes y cachés. |
| **state/** | 💾 **Estados de Escaneo**: Estados serializados de escaneos en progreso. |
| **backups/** | 💿 **Backups**: Backups de base de datos y configuraciones. |

---

## 📂 Directorios de Desarrollo

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **lab/** | 🧪 **Laboratorio**: 3 módulos experimentales y prototipos. |
| **testing/** | 🔬 **Testing Helpers**: Utilidades y fixtures para testing. |
| **archive/** | 📦 **Archivados**: Código legacy archivado. |
| **.planning/** | 📋 **Planificación**: Documentos de planificación y diseño. |
| **protocol/** | 📡 **Protocolos**: 9 módulos con definiciones de protocolos de comunicación. |

---

## 📂 Directorios de Documentación (.ai-context/)

| Directorio | Archivos | Responsabilidad Principal |
|---------|---------|---------------------------|
| **architecture/** | 24 archivos | 🏗️ **Documentación de Arquitectura**: Arquitectura actual, futura, fases, agentes. |
| **architecture/agents/** | 16 archivos | 🤖 **Docs de Agentes**: Documentación detallada de cada agente especialista. |
| **architecture/phases/** | 2 archivos | 📊 **Docs de Fases**: Documentación de las 6 fases del pipeline. |
| **guides/** | 4 archivos | 📖 **Guías de Uso**: Guías para desarrolladores y usuarios. |
| **specs/** | 2 archivos | 📋 **Especificaciones Técnicas**: Especificaciones detalladas de componentes. |
| **project/** | 2 archivos | 📂 **Documentación de Proyecto**: Información general del proyecto. |
| **planning/** | 2 archivos | 🗓️ **Planificación**: Roadmap y planificación futura. |
| **examples/** | Múltiples | 💡 **Ejemplos**: Ejemplos de uso y configuración. |
| **audits/** | 1 archivo | 🔍 **Auditorías**: Reportes de auditorías de calidad. |

---

## 📂 Directorios del Agent (Antigravity) (.agent/)

| Directorio | Responsabilidad Principal |
|---------|---------------------------|
| **.agent/workflows/** | 🔄 **Workflows**: Workflows automatizados (implement_feature, audit_report, etc.). |
| **.agent/skills/** | 🎯 **Skills del Agente**: 8 skills especializados para Antigravity. |

---

## 🔑 Archivos Clave por Fase del Pipeline

### Fase 1: Reconocimiento
- `bugtrace/agents/recon.py`
- `bugtrace/agents/gospider_agent.py`
- `bugtrace/agents/nuclei_agent.py`
- `bugtrace/agents/asset_discovery_agent.py`

### Fase 2: Análisis
- `bugtrace/agents/analysis_agent.py`
- `bugtrace/agents/url_master.py`

### Fase 3: Thinking & Consolidation
- `bugtrace/agents/thinking_consolidation_agent.py`

### Fase 4: Explotación
- Todos los agentes especialistas en `bugtrace/agents/*_agent.py`

### Fase 5: Validación
- `bugtrace/agents/agentic_validator.py`
- `bugtrace/agents/report_validator.py`
- `bugtrace/core/validator_engine.py`

### Fase 6: Reporting
- `bugtrace/agents/reporting.py`
- `bugtrace/reporting/*`

---

## 📊 Estadísticas del Proyecto

- **Total de Agentes Especialistas**: 20+
- **Total de Skills Reutilizables**: 8
- **Total de Herramientas (tools/)**: 28+ módulos
- **Total de Tests**: 56+ archivos
- **Total de Documentación**: 50+ archivos markdown
- **Fases del Pipeline**: 6
- **System Prompts**: 23

---

> **Nota**: Este índice representa la estructura completa del proyecto BugTraceAI-CLI Reactor V6.  
> Para detalles específicos de implementación, consulta los archivos individuales o la documentación en `.ai-context/`.
