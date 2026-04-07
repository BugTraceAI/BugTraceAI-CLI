# 10 - API REST (FastAPI)

## Resumen

BugTraceAI-CLI expone una API REST via FastAPI en el puerto 8000. Esta API permite a BugTraceAI-WEB (y cualquier cliente HTTP) iniciar scans, consultar estado, obtener findings y descargar reportes.

**Archivos:**
- `bugtrace/api/main.py` - App FastAPI, middleware, CORS
- `bugtrace/api/routes/scans.py` - Endpoints de scans
- `bugtrace/api/routes/reports.py` - Endpoints de reportes
- `bugtrace/api/routes/config.py` - Endpoints de configuracion
- `bugtrace/api/routes/metrics.py` - Endpoints de metricas
- `bugtrace/api/deps.py` - Dependency Injection
- `bugtrace/api/schemas.py` - Modelos Pydantic request/response
- `bugtrace/api/exceptions.py` - Exception handlers

---

## App Setup (`api/main.py`)

```python
app = FastAPI(
    title="BugTraceAI CLI API",
    version=settings.VERSION,
)

# CORS for WEB frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Localhost deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(scans_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(config_router, prefix="/api")
app.include_router(metrics_router, prefix="/api")

# Register exception handlers
register_exception_handlers(app)

# Startup event
@app.on_event("startup")
async def startup():
    await db.init_db()
    await scan_service.cleanup_orphaned_scans()
```

### Iniciar el API

```bash
cd BugTraceAI-CLI
python3 -m uvicorn bugtrace.api.main:app --host 0.0.0.0 --port 8000

# Dev mode with auto-reload:
python3 -m uvicorn bugtrace.api.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Endpoints de Scans (`api/routes/scans.py`)

### POST `/api/scans` - Crear Scan

**Request:**
```json
{
    "target_url": "https://example.com",
    "scan_type": "full",
    "scan_depth": "standard",
    "safe_mode": true,
    "max_depth": 2,
    "max_urls": 20,
    "resume": false,
    "use_vertical": true,
    "focused_agents": [],
    "param": null
}
```

**Response:** `201 Created`
```json
{
    "scan_id": 42,
    "target": "https://example.com",
    "status": "PENDING",
    "progress": 0,
    "origin": "web"
}
```

**Logica:**
1. Valida `target_url`
2. Chequea limite de scans concurrentes (429 si lleno)
3. Crea registro en SQLite
4. Lanza background task via `asyncio.create_task()`
5. Retorna inmediatamente con `scan_id`

---

### GET `/api/scans/{scan_id}/status` - Estado del Scan

**Response:**
```json
{
    "scan_id": 42,
    "target": "https://example.com",
    "status": "RUNNING",
    "progress": 65,
    "uptime_seconds": 127.5,
    "findings_count": 8,
    "active_agent": "XSSAgent",
    "phase": "exploitation",
    "origin": "web"
}
```

**Logica:**
- Si scan activo: retorna desde `ScanContext` en memoria
- Si scan completado: retorna desde SQLite

---

### GET `/api/scans/{scan_id}/findings` - Findings del Scan

**Query params:**
- `severity`: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `vuln_type`: XSS, SQLI, etc.
- `page`: Pagina (default 1)
- `per_page`: Items por pagina (max 100)

**Response:**
```json
{
    "findings": [
        {
            "finding_id": 1,
            "type": "XSS",
            "severity": "HIGH",
            "details": "Reflected XSS in search parameter",
            "payload": "<script>document.domain</script>",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "validated": true,
            "status": "VALIDATED_CONFIRMED",
            "confidence": 0.95
        }
    ],
    "total": 12,
    "page": 1,
    "per_page": 20,
    "scan_id": 42
}
```

---

### GET `/api/scans` - Listar Scans

**Query params:**
- `page`, `per_page`, `status_filter`

**Response:**
```json
{
    "scans": [
        {
            "scan_id": 42,
            "target": "https://example.com",
            "status": "COMPLETED",
            "progress": 100,
            "timestamp": "2026-02-10T14:35:21Z",
            "origin": "web",
            "has_report": true
        }
    ],
    "total": 15,
    "page": 1,
    "per_page": 20
}
```

---

### POST `/api/scans/{scan_id}/stop` - Parar Scan

**Response:**
```json
{
    "scan_id": 42,
    "status": "STOPPED",
    "message": "Scan stopped gracefully"
}
```

Usa `ctx.stop_event.set()` para shutdown graceful.

---

### POST `/api/scans/{scan_id}/pause` - Pausar Scan
### POST `/api/scans/{scan_id}/resume` - Reanudar Scan
### DELETE `/api/scans/{scan_id}` - Eliminar Scan

No se puede eliminar un scan en ejecucion (409 Conflict).

---

### GET `/api/scans/{scan_id}/detailed-metrics` - Metricas Detalladas

Retorna metricas ricas: URLs procesadas, efectividad de dedup, profundidad de colas.

---

## Endpoints de Reports (`api/routes/reports.py`)

### GET `/api/scans/{scan_id}/report/{format}` - Descargar Reporte

**Formatos:** `html`, `json`, `markdown`

- Retorna bytes del reporte con Content-Type apropiado
- Auto-genera si no existe
- 404 si el scan no tiene datos suficientes

### GET `/api/scans/{scan_id}/files/{filename}` - Servir Archivo

Sirve archivos individuales del directorio de reportes:
- Proteccion contra path traversal
- Auto-detecta Content-Type
- Usado por el frontend WEB para cargar markdown, JSON, screenshots

---

## Endpoints de Config (`api/routes/config.py`)

### GET `/api/config` - Obtener Configuracion

Retorna config actual con secrets enmascarados.

### PATCH `/api/config` - Actualizar Config

**Campos seguros (runtime):**
- `SAFE_MODE`, `MAX_DEPTH`, `MAX_URLS`
- `MAX_CONCURRENT_*`
- Nombres de modelos (format `provider/model`)

**Validaciones:**
- Enteros positivos
- Formato de modelo valido
- No permite cambiar API keys via API

---

## Endpoints de Metrics (`api/routes/metrics.py`)

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| GET | `/api/metrics` | Todas las metricas |
| GET | `/api/metrics/queues` | Stats por cola (depth, throughput, latency) |
| GET | `/api/metrics/cdp` | Metricas de reduccion CDP |
| GET | `/api/metrics/parallelization` | Stats de workers concurrentes |
| GET | `/api/metrics/deduplication` | Efectividad de dedup |
| POST | `/api/metrics/reset` | Reset metricas |

---

## Dependency Injection (`api/deps.py`)

```python
# Singletons
_scan_service: ScanService | None = None
_report_service: ReportService | None = None

def get_scan_service() -> ScanService:
    global _scan_service
    if _scan_service is None:
        _scan_service = ScanService()
    return _scan_service

# FastAPI dependency types
ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]
ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]
EventBusDep = Annotated[ServiceEventBus, Depends(get_event_bus)]
```

---

## Exception Handlers (`api/exceptions.py`)

Formato estandarizado de errores:

```json
{
    "error": {
        "code": "SCAN_NOT_FOUND",
        "message": "Scan with ID 999 not found",
        "timestamp": "2026-02-10T14:35:21.789Z",
        "path": "/api/scans/999/status",
        "details": {}
    }
}
```

**Handlers registrados:**
- `HTTPException` → Status code HTTP correspondiente
- `RequestValidationError` → 422 con detalles de validacion
- `ValueError` → 400 Bad Request
- `Exception` (catch-all) → 500 Internal Error

---

## ScanService (`services/scan_service.py`)

### Patron Critico: asyncio, NO threading

```python
class ScanService:
    def __init__(self):
        self._active_scans: Dict[int, ScanContext] = {}
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(1)  # Max 1 concurrent scan
```

**Por que asyncio y no threading:**
- El TeamOrchestrator usa `asyncio` internamente
- Mezclar threads con asyncio causa conflictos de event loop
- asyncio.Semaphore es mas seguro que threading.Semaphore para este caso

### ScanContext (Frozen Settings)

```python
@dataclass
class ScanContext:
    scan_id: int
    target: str
    options: ScanOptions
    stop_event: asyncio.Event
    start_time: float
    # Frozen copy of settings - does NOT mutate global singleton
```

Cada scan tiene su propio contexto con settings congelados. Esto permite que cambios de config via API no afecten scans en ejecucion.
