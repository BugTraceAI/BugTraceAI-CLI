# 01 - Arquitectura General de BugTraceAI-CLI

## Entry Point

El CLI se inicia desde `bugtrace/__main__.py`:

```
python -m bugtrace [target_url] [opciones]
```

### Flujo de Arranque

1. **`__main__.py`** parsea argumentos CLI (target URL, flags)
2. Carga configuracion via `Settings` singleton (`core/config.py`)
3. Inicializa el dashboard TUI (Textual o Rich legacy)
4. Crea el **TeamOrchestrator** (`core/team.py`)
5. Ejecuta `orchestrator.start()` que lanza el pipeline secuencial

### Modos de Ejecucion

| Modo | Descripcion | Flag |
|------|-------------|------|
| `full` | Pipeline completo (6 fases) | default |
| `hunter` | Solo Discovery + Analysis | `--hunter` |
| `manager` | Solo Exploitation + Validation | `--manager` |
| `focused` | Agentes especificos | `--focus xss,sqli` |
| `lone_wolf` | Exploracion autonoma LLM | `--lone-wolf` |
| `vertical` | Pipeline vertical con especialistas | `--vertical` (default True) |

---

## TeamOrchestrator (`core/team.py`)

El orquestador central que coordina todo el ciclo de vida de un scan.

### Responsabilidades

- Inicializar las fases del pipeline secuencialmente
- Gestionar el ciclo de vida de agentes (arranque, health checks, shutdown)
- Manejar shutdown graceful (Ctrl+C, errores)
- Monitorizar progreso del scan y transiciones de fase
- Crear y gestionar el directorio unificado de reportes

### Atributos Clave

```python
class TeamOrchestrator:
    target: str              # URL objetivo
    scan_id: int             # ID del scan en SQLite
    report_dir: Path         # Directorio unificado de reportes
    tech_profile: dict       # Perfil tecnologico del target
    _stop_event: asyncio.Event  # Senal de shutdown
```

### Metodos Principales

| Metodo | Descripcion |
|--------|-------------|
| `start()` | Ejecuta el pipeline completo en orden |
| `_run_discovery()` | Lanza Fase 1 (GoSpider + Nuclei) |
| `_run_analysis(urls)` | Lanza Fase 2 (DASTySAST por cada URL) |
| `_run_exploitation(findings)` | Lanza Fase 4 (Especialistas en paralelo) |
| `_run_validation(findings)` | Lanza Fase 5 (AgenticValidator) |
| `_generate_vertical_report()` | Lanza Fase 6 (ReportingAgent) |
| `_authenticate()` | Autenticacion pre-scan si el target lo requiere |

### Directorio de Reportes Unificado

```python
# Creado en __init__ del TeamOrchestrator
report_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
# Ejemplo: reports/www.example.com_20260210_143521/
```

Todos los agentes escriben en el mismo directorio. Estructura:

```
reports/www.example.com_20260210_143521/
  recon/
    urls.txt
    technologies.json
  specialists/
    results/
      xss_results.json
      sqli_results.json
      ...
  logs/
    finding_details.findings
  REPORT.html
  engagement_data.js
  TECHNICAL_REPORT.md
```

---

## Flujo de Datos del Pipeline

```
[GoSpider] --urls--> [SQLite DB] --urls--> [DASTySAST]
                                                |
                                          findings (JSON)
                                                |
                                                v
                                    [ThinkingConsolidation]
                                          |         |
                                    dedup + FP    route to
                                    filter        specialist queues
                                          |         |
                                          v         v
                                    [Specialist Agents]
                                          |
                                    confirmed findings
                                          |
                                          v
                                    [AgenticValidator]
                                          |
                                    validated/rejected
                                          |
                                          v
                                    [ReportingAgent]
                                          |
                                    HTML + MD + JSON
                                          |
                                          v
                                    [SQLite DB] + [Files]
```

---

## Modelo de Datos (SQLite)

### Tablas Principales

**`target`** - URLs objetivo

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `url` | TEXT (indexed) | URL del target |
| `created_at` | DATETIME | Fecha de creacion |

**`scan`** - Scans ejecutados

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `target_id` | FK → target.id | Target escaneado |
| `timestamp` | DATETIME | Inicio del scan |
| `status` | ENUM | PENDING, INITIALIZING, RUNNING, PAUSED, COMPLETED, STOPPED, FAILED |
| `progress_percent` | INTEGER | 0-100 |
| `origin` | TEXT | "cli", "web", o "unknown" |

**`finding`** - Vulnerabilidades encontradas

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `scan_id` | FK → scan.id | Scan padre |
| `type` | ENUM VulnType | XSS, SQLI, RCE, XXE, CSTI, etc. |
| `severity` | TEXT | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `details` | TEXT | Descripcion de la vulnerabilidad |
| `payload_used` | TEXT | Payload que confirmo la vuln |
| `reflection_context` | ENUM | NONE, HTML_TAG, ATTRIBUTE, JS_BLOCK |
| `confidence_score` | FLOAT | 0.0 - 1.0 |
| `visual_validated` | BOOLEAN | Validado por Vision AI |
| `status` | ENUM FindingStatus | PENDING_VALIDATION, VALIDATED_CONFIRMED, VALIDATED_FALSE_POSITIVE, etc. |
| `validator_notes` | TEXT | Notas del validador |
| `proof_screenshot_path` | TEXT | Ruta al screenshot de evidencia |
| `attack_url` | TEXT | URL atacada |
| `vuln_parameter` | TEXT | Parametro vulnerable |
| `reproduction_command` | TEXT | Comando para reproducir (e.g. sqlmap) |

Indice compuesto: `(scan_id, status)` para queries eficientes.

**`scan_state`** - Estado persistido del scan

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `scan_id` | FK → scan.id (unique) | Scan asociado |
| `state_json` | TEXT | JSON blob con estado completo |
| `updated_at` | DATETIME | Ultima actualizacion |

### Enums

**VulnType**: XSS, SQLI, RCE, XXE, CSTI, PROTOTYPE_POLLUTION, OPEN_REDIRECT, HEADER_INJECTION, SENSITIVE_DATA_EXPOSURE, IDOR, LFI, SSRF, SECURITY_MISCONFIGURATION

**ScanStatus**: PENDING, INITIALIZING, RUNNING, PAUSED, COMPLETED, STOPPED, FAILED

**FindingStatus**: PENDING_VALIDATION, VALIDATED_CONFIRMED, VALIDATED_FALSE_POSITIVE, MANUAL_REVIEW_RECOMMENDED, SKIPPED, ERROR

---

## Principio de Diseno: "Don't Lie About Origin"

El campo `origin` en la tabla `scan` marca donde se lanzo el scan:
- `"cli"` - Lanzado desde la terminal CLI
- `"web"` - Lanzado desde la interfaz web
- `"unknown"` - **Default** - No asumimos si no podemos verificar

> "It's OK to not know. It's bad to lie."
