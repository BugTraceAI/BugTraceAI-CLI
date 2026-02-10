# 🔍 BugTraceAI REST API - Audit Completo

**Fecha de Auditoría:** 2026-02-06  
**Versión API:** 2.0.0  
**Framework:** FastAPI + Uvicorn  
**Auditor:** Antigravity AI Assistant

---

## 📋 Resumen Ejecutivo

| Categoría | Estado | Hallazgos |
|-----------|--------|-----------|
| **Arquitectura** | ✅ Sólida | Bien estructurada, modular, extensible |
| **Seguridad** | ⚠️ Media | Sin autenticación, CORS permisivo en dev |
| **Documentación** | ✅ Buena | OpenAPI/Swagger completo |
| **Real-time** | ✅ Excelente | WebSockets + EventBus robusto |
| **Error Handling** | ✅ Muy Bueno | Manejo centralizado, respuestas estandarizadas |
| **Rate Limiting** | ❌ Ausente | No implementado |
| **Tests** | ⚠️ Incompleto | No hay tests específicos para API |

---

## 🏗️ Arquitectura de la API

### Componentes Principales

```
bugtrace/api/
├── __init__.py          # Package exports
├── main.py              # FastAPI app, CORS, middleware, routers
├── server.py            # Uvicorn wrapper para CLI
├── deps.py              # Dependency Injection (DI)
├── schemas.py           # Pydantic request/response models  
├── exceptions.py        # Global exception handlers
├── websocket.py         # WebSocket ConnectionManager
└── routes/
    ├── scans.py         # Endpoints de escaneo (7 endpoints)
    ├── reports.py       # Endpoints de reportes (2 endpoints)
    ├── config.py        # Endpoints de configuración (2 endpoints)
    ├── metrics.py       # Endpoints de métricas (6 endpoints)
    └── websocket.py     # WebSocket routes (2 endpoints)
```

### Cómo Iniciar el Servidor

```bash
# Desde CLI
bugtrace serve --host 127.0.0.1 --port 8000

# Con auto-reload para desarrollo
bugtrace serve --reload

# Directamente con uvicorn
uvicorn bugtrace.api.main:app --reload
```

---

## 📡 Catálogo de Endpoints

### 🎯 Endpoints de Escaneo (`/api/scans`)

| Método | Endpoint | Descripción | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/scans` | Crear y lanzar nuevo escaneo | ❌ |
| `GET` | `/api/scans` | Listar historial de escaneos (paginado) | ❌ |
| `GET` | `/api/scans/{scan_id}/status` | Obtener estado de un escaneo | ❌ |
| `GET` | `/api/scans/{scan_id}/findings` | Obtener hallazgos (filtrable, paginado) | ❌ |
| `GET` | `/api/scans/{scan_id}/detailed-metrics` | Métricas detalladas en tiempo real | ❌ |
| `POST` | `/api/scans/{scan_id}/stop` | Detener escaneo en ejecución | ❌ |
| `DELETE` | `/api/scans/{scan_id}` | Eliminar escaneo y hallazgos | ❌ |

#### Ejemplo: Crear Escaneo

```json
POST /api/scans
{
  "target_url": "https://example.com",
  "scan_type": "full",
  "safe_mode": true,
  "max_depth": 2,
  "max_urls": 20,
  "resume": false,
  "use_vertical": true,
  "focused_agents": [],
  "param": null
}

// Respuesta 201 Created
{
  "scan_id": 42,
  "target": "https://example.com",
  "status": "RUNNING",
  "progress": 0,
  "findings_count": 0,
  "active_agent": null,
  "phase": "INIT",
  "origin": "web"
}
```

### 📊 Endpoints de Reportes (`/api/scans/{scan_id}`)

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/scans/{scan_id}/report/{format}` | Descargar reporte (html, json, markdown) |
| `GET` | `/api/scans/{scan_id}/files/{filename}` | Servir archivo individual del reporte |

#### Ejemplo: Descargar Reporte

```bash
# HTML
curl http://localhost:8000/api/scans/42/report/html -o report.html

# JSON
curl http://localhost:8000/api/scans/42/report/json -o report.json

# Markdown
curl http://localhost:8000/api/scans/42/report/markdown -o report.md
```

### ⚙️ Endpoints de Configuración (`/api/config`)

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/config` | Ver configuración actual (secretos enmascarados) |
| `PATCH` | `/api/config` | Actualizar configuración en runtime |

#### Campos Actualizables via PATCH

- `SAFE_MODE`: boolean
- `MAX_DEPTH`: integer (1+)
- `MAX_URLS`: integer (1+)
- `MAX_CONCURRENT_URL_AGENTS`: integer (1+)
- `MAX_CONCURRENT_REQUESTS`: integer (1+)
- `DEFAULT_MODEL`: string (provider/model format)
- `CODE_MODEL`, `ANALYSIS_MODEL`, `MUTATION_MODEL`, `SKEPTICAL_MODEL`: string
- `HEADLESS_BROWSER`: boolean
- `EARLY_EXIT_ON_FINDING`: boolean
- `STOP_ON_CRITICAL`: boolean
- `REPORT_ONLY_VALIDATED`: boolean

### 📈 Endpoints de Métricas (`/api/metrics`)

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/metrics` | Todas las métricas combinadas |
| `GET` | `/api/metrics/queues` | Métricas de colas por especialista |
| `GET` | `/api/metrics/cdp` | Métricas de reducción CDP |
| `GET` | `/api/metrics/parallelization` | Métricas de paralelización |
| `GET` | `/api/metrics/deduplication` | Métricas de deduplicación |
| `POST` | `/api/metrics/reset` | Resetear todas las métricas |

### 🔌 WebSocket Endpoints

| Protocolo | Endpoint | Descripción |
|-----------|----------|-------------|
| `WS` | `/ws/scans/{scan_id}` | Stream eventos de escaneo específico |
| `WS` | `/api/ws/scans/{scan_id}` | Stream eventos (router secundario) |
| `WS` | `/api/ws/global` | Stream eventos de TODOS los escaneos |

#### Tipos de Eventos WebSocket

```javascript
// Eventos que recibirás:
{
  "type": "progress_update",
  "scan_id": 42,
  "timestamp": 1707215469.123,
  "data": {
    "urls_discovered": 50,
    "urls_analyzed": 30,
    "urls_total": 100,
    "dedup_effectiveness": 0.85,
    "queue_stats": {...}
  }
}

{
  "type": "phase_update",
  "data": { "phase": "HUNTER", "agent": "XSSAgent" }
}

{
  "type": "finding_discovered",
  "data": { "type": "XSS", "severity": "HIGH", ... }
}

{
  "type": "log",
  "data": { "level": "INFO", "message": "..." }
}
```

#### Soporte de Reconexión

```javascript
// Reconectar y recibir solo eventos perdidos
const ws = new WebSocket('ws://localhost:8000/ws/scans/42?last_seq=150');
```

### 🏥 Endpoints de Salud

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/` | Info del API (versión, docs) |
| `GET` | `/health` | Liveness probe (Docker, K8s) |
| `GET` | `/ready` | Readiness probe (DB connectivity) |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc UI |

---

## 🛡️ Análisis de Seguridad

### 🔴 Hallazgos Críticos

#### 1. **Sin Autenticación/Autorización**

```python
# PROBLEMA: Cualquiera puede lanzar escaneos
@router.post("/scans", status_code=status.HTTP_201_CREATED)
async def create_scan(request: CreateScanRequest, scan_service: ScanServiceDep):
    # Sin verificación de credenciales
    options = _build_scan_options(request)
    scan_id = await scan_service.create_scan(options, origin="web")
```

**Riesgo:** Alto  
**Impacto:** Uso malicioso del servidor para atacar terceros  
**Recomendación:** Implementar JWT o API Key authentication

#### 2. **PATCH /config sin Restricciones**

```python
# PROBLEMA: Cualquiera puede cambiar la configuración
@router.patch("/config", response_model=ConfigUpdateResponse)
async def update_config(request: ConfigUpdateRequest):
    # Sin verificación de permisos
    updates = _extract_updates(request)
```

**Riesgo:** Alto  
**Impacto:** Cambiar configuración de modelos AI, límites de concurrencia  
**Recomendación:** Restringir a usuarios admin autenticados

### 🟡 Hallazgos Medios

#### 3. **CORS Permisivo en Desarrollo**

```python
# En main.py
def _get_cors_origins() -> list[str]:
    if settings.DEBUG or settings.ENV == "development":
        default_origins = [
            "http://localhost:3000",
            "http://localhost:5173",
        ]
        return default_origins
```

**Estado:** Aceptable para desarrollo  
**Producción:** Requiere configuración explícita via `BUGTRACE_CORS_ORIGINS`

#### 4. **Sin Rate Limiting**

No existe middleware de rate limiting, lo que permite:
- DoS en endpoints costosos como `/api/scans`
- Spam de nuevos escaneos

**Recomendación:** Implementar `slowapi` o similar

### 🟢 Aspectos Positivos de Seguridad

#### ✅ Validación de Path Traversal

```python
# En routes/reports.py - BIEN HECHO
file_path = (report_dir / filename).resolve()
if not str(file_path).startswith(str(report_dir.resolve())):
    raise HTTPException(status_code=400, detail="Invalid filename")
```

#### ✅ Concurrency Limit

```python
# Limita escaneos concurrentes (default: 1)
if len(self._active_scans) >= self._max_concurrent:
    raise RuntimeError(f"Maximum concurrent scans ({self._max_concurrent}) reached")
```

#### ✅ Exception Handling Centralizado

```python
# exceptions.py - Estandariza respuestas de error
def _error_response(status_code, error_code, message, request, details=None):
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "path": str(request.url),
            }
        },
    )
```

#### ✅ Correlation ID Middleware

Cada request recibe un `X-Correlation-ID` para trazabilidad en logs.

---

## 📦 Calidad del Código

### Patrón de Dependency Injection

```python
# deps.py - Singleton pattern con DI
ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]
ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]
EventBusDep = Annotated[ServiceEventBus, Depends(get_event_bus)]
```

**Evaluación:** ✅ Excelente separación de concerns

### Modelos Pydantic Tipados

```python
# schemas.py - Type safety
class CreateScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    scan_type: str = Field(default="full")
    safe_mode: Optional[bool] = Field(default=None)
    # ... más campos
```

**Evaluación:** ✅ Bien documentado y tipado

### WebSocket Implementation

```python
# websocket.py - Connection management
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        self.global_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
```

**Evaluación:** ✅ Thread-safe, maneja reconexión

---

## 🧪 Cobertura de Tests

### Estado Actual

```bash
# No existen tests específicos para la API
find tests/ -name "*api*" -o -name "*route*"
# Sin resultados
```

### Tests Recomendados

```python
# tests/test_api_scans.py (pendiente de crear)
import pytest
from fastapi.testclient import TestClient
from bugtrace.api.main import app

client = TestClient(app)

def test_create_scan():
    response = client.post("/api/scans", json={"target_url": "https://example.com"})
    assert response.status_code == 201
    assert "scan_id" in response.json()

def test_get_scan_status_not_found():
    response = client.get("/api/scans/99999/status")
    assert response.status_code == 404

def test_list_scans_pagination():
    response = client.get("/api/scans?page=1&per_page=10")
    assert response.status_code == 200
    assert "scans" in response.json()
```

---

## 🚀 Recomendaciones de Mejora

### Prioridad Alta

1. **Implementar Autenticación**
   ```python
   from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
   
   security = HTTPBearer()
   
   async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
       if not validate_jwt(credentials.credentials):
           raise HTTPException(status_code=401, detail="Invalid token")
   ```

2. **Añadir Rate Limiting**
   ```python
   from slowapi import Limiter
   from slowapi.util import get_remote_address
   
   limiter = Limiter(key_func=get_remote_address)
   
   @app.post("/api/scans")
   @limiter.limit("3/minute")
   async def create_scan(...):
       ...
   ```

3. **Crear Tests de API**
   - Unit tests para cada endpoint
   - Integration tests con base de datos de prueba
   - WebSocket tests

### Prioridad Media

4. **Server-Sent Events (SSE) alternativo a WebSocket**
   - Más fácil de implementar en algunos clientes
   - Fallback cuando WebSocket falla

5. **Documentar en OpenAPI los códigos de error**
   ```python
   @router.post("/scans", responses={
       201: {"model": ScanStatusResponse},
       400: {"model": ErrorResponse, "description": "Invalid request"},
       429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
   })
   ```

6. **Métricas Prometheus**
   ```python
   from prometheus_fastapi_instrumentator import Instrumentator
   Instrumentator().instrument(app).expose(app)
   ```

### Prioridad Baja

7. **Versionado de API** (v1, v2)
8. **Webhooks para notificación de eventos**
9. **API Keys para integración de terceros**

---

## 📊 Diagrama de Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLIENTS                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Web UI     │  │  CLI        │  │  MCP/AI     │              │
│  │  (React)    │  │  (Typer)    │  │  Assistants │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
└─────────┼────────────────┴─────────────────┴─────────────────────┘
          │                                                      
          │ HTTP/WebSocket                                      
          ▼                                                      
┌──────────────────────────────────────────────────────────────────┐
│                    FASTAPI APPLICATION                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    MIDDLEWARE CHAIN                          ││
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐               ││
│  │  │   CORS    │─▶│ Corr. ID  │─▶│ Exception │               ││
│  │  │ Middleware│  │ Middleware│  │ Handlers  │               ││
│  │  └───────────┘  └───────────┘  └───────────┘               ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      ROUTERS                                 ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       ││
│  │  │  Scans   │ │ Reports  │ │  Config  │ │ Metrics  │       ││
│  │  │ (7 eps)  │ │ (2 eps)  │ │ (2 eps)  │ │ (6 eps)  │       ││
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       ││
│  └───────┼────────────┼────────────┼────────────┼──────────────┘│
│          │            │            │            │                │
│  ┌───────▼────────────▼────────────▼────────────▼──────────────┐│
│  │                 DEPENDENCY INJECTION                         ││
│  │  ┌──────────────┐ ┌────────────────┐ ┌────────────────┐     ││
│  │  │ ScanServiceDep│ │ReportServiceDep│ │  EventBusDep   │     ││
│  │  └──────┬───────┘ └───────┬────────┘ └───────┬────────┘     ││
│  └─────────┼─────────────────┼──────────────────┼───────────────┘│
└────────────┼─────────────────┼──────────────────┼────────────────┘
             │                 │                  │
┌────────────▼─────────────────▼──────────────────▼────────────────┐
│                       SERVICES LAYER                              │
│  ┌──────────────┐ ┌────────────────┐ ┌──────────────────────┐   │
│  │ ScanService  │ │ ReportService  │ │ ServiceEventBus      │   │
│  │              │ │                │ │ (WebSocket Manager)  │   │
│  └──────┬───────┘ └───────┬────────┘ └──────────┬───────────┘   │
└─────────┼─────────────────┼─────────────────────┼────────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
┌──────────────────────────────────────────────────────────────────┐
│                        CORE LAYER                                 │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │TeamOrchestrat│ │ Reporting    │ │   EventBus   │             │
│  │     or       │ │  Generator   │ │    (Core)    │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    DATABASE (SQLite)                      │   │
│  │  ScanTable | TargetTable | FindingTable | CheckpointTable│   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📝 Ejemplo de Uso Completo

### 1. Iniciar un Escaneo

```bash
# Lanzar escaneo
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://ginandjuice.shop", "scan_type": "full", "safe_mode": true}'

# Respuesta
{"scan_id": 1, "status": "RUNNING", "progress": 0, ...}
```

### 2. Monitorear Progreso en Tiempo Real

```javascript
// JavaScript WebSocket client
const ws = new WebSocket('ws://localhost:8000/ws/scans/1');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(`${data.type}: `, data.data);
    
    if (data.type === 'progress_update') {
        updateProgressBar(data.data.progress);
    } else if (data.type === 'finding_discovered') {
        addFinding(data.data);
    }
};

ws.onclose = () => console.log('Scan completed or connection lost');
```

### 3. Obtener Hallazgos

```bash
# Todos los hallazgos
curl http://localhost:8000/api/scans/1/findings

# Filtrar por severidad
curl "http://localhost:8000/api/scans/1/findings?severity=CRITICAL&page=1&per_page=10"
```

### 4. Descargar Reporte

```bash
# Reporte HTML
curl http://localhost:8000/api/scans/1/report/html -o report.html

# Reporte JSON para integración
curl http://localhost:8000/api/scans/1/report/json -o report.json
```

### 5. Verificar Métricas

```bash
curl http://localhost:8000/api/metrics | jq

# Respuesta
{
  "cdp": {"reduction_percent": 99.2, "target_met": true},
  "parallelization": {"current_concurrent": 3, "peak_concurrent": 8},
  "deduplication": {"total_received": 150, "total_deduplicated": 45},
  "queues": {...}
}
```

---

## ✅ Conclusiones

### Fortalezas

1. **Arquitectura bien diseñada** - Separación clara de concerns, DI, modular
2. **WebSocket robusto** - Reconexión, history replay, múltiples canales
3. **Documentación OpenAPI completa** - Swagger UI funcional
4. **Error handling centralizado** - Respuestas consistentes
5. **Métricas extensivas** - Excelente observabilidad

### Debilidades

1. **Sin autenticación** - Riesgo de abuso
2. **Sin rate limiting** - Vulnerable a DoS
3. **Sin tests de API** - Riesgo de regresiones
4. **CORS en desarrollo permisivo** - OK pero documentar para producción

### Puntuación General

| Aspecto | Puntuación |
|---------|------------|
| Funcionalidad | ⭐⭐⭐⭐⭐ 5/5 |
| Seguridad | ⭐⭐⭐ 3/5 |
| Documentación | ⭐⭐⭐⭐ 4/5 |
| Código | ⭐⭐⭐⭐⭐ 5/5 |
| Tests | ⭐⭐ 2/5 |
| **Total** | **19/25 (76%)** |

---

*Auditoría completada el 2026-02-06 por Antigravity AI Assistant*
