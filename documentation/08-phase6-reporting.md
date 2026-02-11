# 08 - Fase 6: Reporting

## Resumen

La fase de Reporting agrega todos los hallazgos verificados y genera reportes profesionales en multiples formatos. Concurrencia: **1** (secuencial).

**Archivos:**
- `bugtrace/agents/reporting.py` - ReportingAgent principal
- `bugtrace/agents/report_validator.py` - Validacion de calidad del reporte
- `bugtrace/services/report_service.py` - Servicio de reportes (API)
- `bugtrace/reporting/html_generator.py` - Generador HTML
- `bugtrace/reporting/templates/report_viewer.html` - Template HTML

---

## ReportingAgent (`agents/reporting.py`)

### Clase

```python
class ReportingAgent:
    def __init__(self, scan_id: int, target_url: str,
                 output_dir: Path, tech_profile: dict = None):
        self.scan_id = scan_id
        self.target_url = target_url
        self.output_dir = output_dir
        self.tech_profile = tech_profile
```

### Metodo Principal

```python
async def generate_all_deliverables(self) -> List[str]:
    """
    Generate all report deliverables.
    Returns list of generated file paths.
    """
    # 1. Pull findings from SQLite DB
    findings = await self._get_findings_from_db()

    # 2. Collect specialist results from disk
    specialist_results = self._collect_specialist_results()

    # 3. Build report context
    context = self._build_report_context(findings, specialist_results)

    # 4. Generate deliverables
    paths = []
    paths.append(await self._generate_html_report(context))
    paths.append(await self._generate_json_report(context))
    paths.append(await self._generate_technical_report(context))
    paths.append(await self._generate_executive_summary(context))

    return [p for p in paths if p]
```

---

## Flujo de Generacion

```
[SQLite DB] + [Specialist Result Files]
        |
        v
[1. Recopilar hallazgos]
   - DB: FindingTable con status VALIDATED_CONFIRMED
   - Disco: specialists/results/*_results.json
        |
        v
[2. Build ReportContext]
   - engagement_info (target, fecha, scope)
   - findings (tipo, severidad, evidencia)
   - metadata (tech_profile, scan_duration)
   - screenshots references
        |
        v
[3. Generar HTML]
   - engagement_data.js (JSON embebido)
   - report_viewer.html (template SPA)
        |
        v
[4. Generar Technical Report (MD)]
   - AI-written (LLM)
   - Formato pentest profesional
        |
        v
[5. Generar Executive Summary]
   - AI-written (LLM)
   - Resumen para management
        |
        v
[6. Generar JSON]
   - engagement_data.json
   - Datos crudos para integracion
```

---

## Formato HTML: Static Viewer

El reporte HTML es una SPA (Single Page Application) autocontenida:

### HTMLGenerator (`reporting/html_generator.py`)

```python
class HTMLGenerator:
    def generate(self, context_or_json, output_path: str) -> str:
        # 1. Write engagement_data.js
        self._write_engagement_data(output_dir, json_src_path, context)

        # 2. Copy static viewer template
        self._copy_viewer_template(output_path)

        return output_path
```

### Estructura del Reporte HTML

```
report_dir/
  REPORT.html            # Template SPA viewer
  engagement_data.js     # Datos JSON como variable JS
```

El archivo `engagement_data.js` contiene:

```javascript
window.BUGTRACE_REPORT_DATA = {
    "engagement_info": {
        "target": "https://example.com",
        "scan_date": "2026-02-10T14:35:21Z",
        "scope": "Full scan",
        "version": "3.5"
    },
    "findings": [
        {
            "type": "XSS",
            "severity": "HIGH",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "payload": "<script>document.domain</script>",
            "evidence": "Unescaped reflection in HTML body",
            "screenshot": "screenshots/xss_search_001.png",
            "status": "VALIDATED_CONFIRMED",
            "confidence": 0.95
        }
    ],
    "statistics": {
        "total_urls": 47,
        "total_findings": 12,
        "critical": 2,
        "high": 4,
        "medium": 5,
        "low": 1
    }
};
```

---

## Technical Report (AI-Generated Markdown)

### Prompt al LLM

```python
tech_prompt = """
You are a Senior Penetration Tester writing a Professional
Technical Assessment Report.

TARGET: {target}
SCAN DATE: {scan_date}
URLS ANALYZED: {urls_scanned}
FINDINGS: {findings_summary}
ATTACK SURFACE: {meta_summary}
SCREENSHOTS: {screenshots}

Write a comprehensive Technical Vulnerability Report in Markdown.

STRUCTURE:
# Technical Assessment Report
## 1. Engagement Overview
## 2. Executive Summary
## 3. Vulnerability Details
   ### [Vuln Type] - [Severity]
   - URL, Parameter, Evidence, Impact, Remediation
   - Screenshot reference
   - Reproduction command (if available)
## 4. Attack Surface Analysis
## 5. Recommendations

TONE: Technical, precise, professional.
Include CVSS scores where applicable.
"""
```

### Salida

```
report_dir/
  TECHNICAL_REPORT.md    # Reporte tecnico completo
```

---

## Executive Summary (AI-Generated)

Resumen de alto nivel para stakeholders no tecnicos:
- Risk score general
- Top findings por impacto de negocio
- Recomendaciones priorizadas
- Timeline sugerido de remediacion

---

## Finding Details Format

Los hallazgos se escriben en disco con formato XML + Base64 para preservar integridad de payloads:

```python
def _write_finding_details(self, target_folder: Path, finding: dict):
    """Write finding using XML format with Base64 for payload integrity."""
    finding_json = json.dumps(finding, default=str, ensure_ascii=False)
    finding_b64 = base64.b64encode(finding_json.encode('utf-8')).decode('ascii')

    entry = (
        f"<FINDING>\n"
        f"  <TIMESTAMP>{time.time()}</TIMESTAMP>\n"
        f"  <TYPE>{finding.get('type', 'Unknown')}</TYPE>\n"
        f"  <DATA_B64>{finding_b64}</DATA_B64>\n"
        f"</FINDING>\n"
    )

    with open(target_folder / "finding_details.findings", "a") as fd:
        fd.write(entry)
```

**Razon del Base64:** Los payloads XSS contienen caracteres que rompen JSON/XML directo (`<script>`, comillas, etc.). Base64 preserva la integridad.

---

## Screenshots y Artefactos

```python
def _organize_artifacts(self, findings, url_folders, report_dir):
    """Organize screenshots into URL-specific folders."""
    for finding in findings:
        if finding.get("screenshot"):
            # Move screenshot to target URL folder
            self._move_screenshot(finding, target_folder, linked)
        # Write finding details
        self._write_finding_details(target_folder, finding)

def _cleanup_unlinked_screenshots(self, linked_screenshots):
    """Delete unreferenced screenshots from LOG_DIR."""
    for file in settings.LOG_DIR.glob("*.png"):
        if file.name not in linked_screenshots:
            file.unlink()
```

---

## Report Service (API Layer)

### `services/report_service.py`

Proporciona reportes via la API REST:

```python
class ReportService:
    async def generate_report(scan_id: int, format: str) -> str:
        """Generate report in format (html, markdown, json)."""

    def get_report(scan_id: int, format: str) -> Optional[bytes]:
        """Get report bytes (auto-generates if missing)."""

    def get_report_path(scan_id: int, format: str) -> Optional[str]:
        """Find existing report file path."""
```

### Endpoints API

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| GET | `/api/scans/{id}/report/{format}` | Descargar reporte |
| GET | `/api/scans/{id}/files/{filename}` | Servir archivo de reporte |

### Path Traversal Protection

```python
async def get_report_file(scan_id: int, filename: str):
    """Serve individual files with path traversal protection."""
    report_dir = _find_report_dir(scan_id)
    file_path = report_dir / filename

    # Validate file is within report directory
    if not file_path.resolve().is_relative_to(report_dir.resolve()):
        raise HTTPException(403, "Path traversal detected")
```

---

## Estructura Final de Reportes

```
reports/{domain}_{timestamp}/
  REPORT.html                 # SPA viewer
  engagement_data.js          # Datos JSON embebidos
  TECHNICAL_REPORT.md         # Reporte tecnico (AI)
  engagement_data.json        # Datos JSON crudo
  recon/
    urls.txt                  # URLs descubiertas
    technologies.json         # Tech profile
  specialists/
    results/
      xss_results.json        # Resultados XSS
      sqli_results.json       # Resultados SQLi
      ...
  {url_safe_name}/
    finding_details.findings  # Hallazgos por URL
    screenshot_001.png        # Screenshots
  logs/
    finding_details.findings  # Hallazgos sin URL match
```
