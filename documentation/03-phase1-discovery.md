# 03 - Fase 1: Discovery (Reconocimiento)

## Resumen

La fase de Discovery es la primera del pipeline. Su objetivo es descubrir todas las URLs, endpoints y superficie de ataque del target. Concurrencia: **1** (GoSpider es single-threaded por diseno).

**Archivos clave:**
- `bugtrace/agents/gospider_agent.py` - Crawling de URLs
- `bugtrace/agents/nuclei_agent.py` - Escaneo de CVEs conocidos
- `bugtrace/agents/recon.py` - Orquestacion de reconocimiento
- `bugtrace/agents/asset_discovery_agent.py` - Descubrimiento de activos
- `bugtrace/agents/auth_discovery_agent.py` - Descubrimiento de autenticacion

---

## GoSpiderAgent (`agents/gospider_agent.py`)

### Proposito
Crawler de URLs que utiliza GoSpider (herramienta Go externa) para enumerar todos los endpoints del target.

### Clase

```python
class GoSpiderAgent(BaseAgent):
    def __init__(self, target: str, scan_id: int, event_bus=None):
        super().__init__(name="GoSpider", role="URL Crawler")
        self.target = target
        self.scan_id = scan_id
```

### Flujo de Ejecucion

1. **Lanzamiento**: `TeamOrchestrator._run_discovery()` crea e inicia GoSpiderAgent
2. **Crawling**: Ejecuta GoSpider como subproceso externo
3. **Parsing**: Parsea la salida de GoSpider linea por linea
4. **Almacenamiento**: Guarda URLs descubiertas en SQLite
5. **Eventos**: Emite `url_discovered` por cada URL nueva

### Configuracion de GoSpider

```python
# Parametros de ejecucion
gospider_cmd = [
    "gospider",
    "-s", target_url,         # URL semilla
    "-d", str(max_depth),     # Profundidad de crawling
    "-c", str(concurrent),    # Hilos concurrentes
    "-t", str(timeout),       # Timeout por request
    "--other-source",         # Fuentes adicionales (Wayback, etc.)
    "--include-subs",         # Incluir subdominios
    "-a",                     # Usar User-Agent aleatorio
]
```

### Salida

Las URLs descubiertas se guardan en:
- **SQLite**: Tabla `url` o similar via DB manager
- **Archivo**: `reports/{target}_{timestamp}/recon/urls.txt`

### Eventos Emitidos

| Evento | Data | Receptor |
|--------|------|----------|
| `url_discovered` | `{url, source, scan_id}` | DASTySAST (Fase 2) |
| `discovery_complete` | `{total_urls, scan_id}` | TeamOrchestrator |

---

## NucleiAgent (`agents/nuclei_agent.py`)

### Proposito
Ejecuta Nuclei (herramienta de ProjectDiscovery) para detectar CVEs conocidos usando templates predefinidos.

### Clase

```python
class NucleiAgent(BaseAgent):
    def __init__(self, target: str, scan_id: int, event_bus=None):
        super().__init__(name="Nuclei", role="CVE Scanner")
```

### Flujo de Ejecucion

1. Ejecuta Nuclei como subproceso con templates de severidad configurada
2. Parsea salida JSON de Nuclei
3. Cada hallazgo se convierte a un finding y se emite como evento

### Configuracion

```python
nuclei_cmd = [
    "nuclei",
    "-u", target_url,
    "-severity", severity_filter,  # critical,high,medium
    "-json",                       # Salida JSON
    "-rate-limit", str(rate_limit),
    "-templates", template_path,
]
```

### Templates de Nuclei

Nuclei usa templates YAML para detectar vulnerabilidades conocidas:
- CVEs especificos
- Misconfigurations
- Exposures (paneles admin, backups)
- Default credentials

---

## Recon Orchestration (`agents/recon.py`)

### Proposito
Coordina las herramientas de reconocimiento y agrega resultados.

### Flujo

```
TeamOrchestrator
    |
    v
ReconOrchestrator
    |
    +-- GoSpiderAgent (URL crawling)
    +-- NucleiAgent (CVE scanning)
    +-- AssetDiscoveryAgent (assets)
    +-- AuthDiscoveryAgent (auth endpoints)
    |
    v
URLs consolidadas --> Fase 2
```

---

## AssetDiscoveryAgent (`agents/asset_discovery_agent.py`)

### Proposito
Descubre activos adicionales del target: subdominios, tecnologias, certificados, DNS.

### Capacidades

- Deteccion de tecnologias (frameworks, CMS, lenguajes)
- Enumeracion de subdominios
- Analisis de headers HTTP (Server, X-Powered-By, etc.)
- Deteccion de WAF (Web Application Firewall)
- Fingerprinting de servidor

### Salida

```json
{
  "technologies": ["PHP 8.1", "Apache 2.4", "WordPress 6.x"],
  "waf_detected": "Cloudflare",
  "subdomains": ["api.example.com", "admin.example.com"],
  "headers": {
    "Server": "Apache/2.4",
    "X-Powered-By": "PHP/8.1"
  }
}
```

Este perfil tecnologico (`tech_profile`) se pasa a los agentes posteriores para generar payloads contextualizados.

---

## AuthDiscoveryAgent (`agents/auth_discovery_agent.py`)

### Proposito
Descubre endpoints de autenticacion y flujos de login del target.

### Capacidades

- Deteccion de formularios de login
- Identificacion de endpoints OAuth/OIDC
- Deteccion de endpoints JWT
- Analisis de cookies de sesion
- Deteccion de mecanismos de proteccion CSRF

### Flujo

1. Analiza HTML de paginas descubiertas
2. Busca formularios con campos `password`, `login`, `auth`
3. Detecta redirects a proveedores OAuth
4. Analiza headers `Set-Cookie` para cookies de sesion
5. Reporta flujos de autenticacion al TeamOrchestrator

### Integracion con Pre-Scan Authentication

Si el TeamOrchestrator detecta que el target requiere autenticacion, usa la informacion de AuthDiscoveryAgent para:

```python
async def _authenticate(self):
    """Pre-scan authentication if target requires it."""
    browser_manager = BrowserManager()
    auth_result = await browser_manager.authenticate(
        self.target, self.auth_config
    )
```

---

## Semaforo de Fase

```python
ScanPhase.DISCOVERY → Semaphore(1)  # GoSpider single-threaded
```

GoSpider no soporta ejecucion concurrente segura. El semaforo garantiza que solo hay una instancia de discovery activa.

---

## Artefactos Generados

```
reports/{target}_{timestamp}/
  recon/
    urls.txt              # Lista de URLs descubiertas
    technologies.json     # Perfil tecnologico
    nuclei_results.json   # CVEs detectados
```
