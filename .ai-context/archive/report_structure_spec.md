# Report Structure - Domain-Based Organization
## BugTrace-AI CLI - Current Implementation (2026-01-02)

---

## 📁 Directory Structure (ACTUALIZADO)

```
reports/
└── {domain}_{YYYYMMDD}_{HHMMSS}_{milliseconds}/
    ├── consolidated_report.json      # Análisis de 5 approaches
    ├── metadata.json                 # Metadata del análisis
    ├── validated_findings.json       # Vulnerabilidades validadas
    └── screenshots/                  # Evidencia visual
        ├── xss_test_20260102_164530.png
        └── sqli_evidence_20260102_164545.png
```

### Ejemplo Real:
```
reports/testphp.vulnweb.com_20260102_164114_456/
```

---

## 📄 Archivos y Contenido

### 1. `consolidated_report.json`
**Generado por**: `AnalysisAgent`  
**Contiene**: Resultados de 5 approaches (pentester, bug_bounty, code_auditor, red_team, researcher)

```json
{
  "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
  "framework_detected": "PHP",
  "tech_stack": ["PHP"],
  "consensus_vulns": [
    {
      "type": "SQL Injection",
      "confidence": 0.80,
      "votes": 3,
      "locations": ["parameter 'cat'"],
      "reasoning": [...],
      "models": [...]
    }
  ],
  "attack_priority": ["SQLi", "XSS"],
  "skip_tests": ["Prototype Pollution", ...]
}
```

### 2. `metadata.json`
**Generado por**: `AnalysisAgent`  
**Contiene**: Metadata del proceso de análisis

```json
{
  "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
  "domain": "testphp.vulnweb.com",
  "report_dir": "testphp.vulnweb.com_20260102_164114_456",
  "timestamp": "2026-01-02T16:41:14.456789",
  "approaches_count": 5,
  "approaches_used": ["pentester", "bug_bounty", "code_auditor", "red_team", "researcher"],
  "model": "google/gemini-2.5-flash",
  "total_vulnerabilities": 8,
  "consensus_count": 3,
  "attack_priority_count": 3
}
```

### 3. `validated_findings.json`
**Generado por**: `ExploitAgent`  
**Contiene**: Vulnerabilidades validadas con evidencia

```json
{
  "findings": [
    {
      "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
      "type": "XSS",
      "confidence": 0.95,
      "screenshot": "reports/testphp.vulnweb.com_20260102_164114_456/screenshots/xss_test_20260102_164530.png",
      "validated": true,
      "timestamp": "2026-01-02T16:45:30.123456",
      "validation_method": "vision_model"
    }
  ],
  "summary": {
    "total": 1,
    "validated": 1
  }
}
```

### 4. `screenshots/`
**Generado por**: `ExploitAgent`  
**Contiene**: Capturas de pantalla de evidencia

- Formato: PNG
- Nombre: `{tipo}_test_{YYYYMMDD}_{HHMMSS}.png`
- Referenciados en `validated_findings.json`

---

## 🔄 Flujo de Trabajo

```
1. ReconAgent descubre URL
   ↓
2. AnalysisAgent analiza con 5 approaches
   ↓
3. Crea directorio: {domain}_{timestamp}
   ↓
4. Guarda consolidated_report.json + metadata.json
   ↓
5. Emite evento: url_analyzed
   ↓
6. ExploitAgent recibe evento
   ↓
7. Busca directorio por dominio (más reciente)
   ↓
8. Valida XSS → captura screenshot
   ↓
9. Vision Model confirma alert()
   ↓
10. Guarda validated_findings.json + screenshot
```

---

## 🔧 Implementación

### AnalysisAgent (`analysis.py`)
```python
# Genera nombre de directorio
parsed = urlparse(url)
domain = parsed.netloc.replace(':', '_').replace('/', '_')
timestamp = datetime.now()
timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S')
milliseconds = timestamp.microsecond // 1000
report_dirname = f"{domain}_{timestamp_str}_{milliseconds:03d}"

# Crea y guarda
report_dir = Path("reports") / report_dirname
report_dir.mkdir(parents=True, exist_ok=True)
```

### ExploitAgent (`exploit.py`)
```python
def _find_report_dir(self, url: str):
    """Encuentra el directorio más reciente para una URL."""
    parsed = urlparse(url)
    domain = parsed.netloc.replace(':', '_').replace('/', '_')
    
    # Busca directorios que empiecen con el dominio
    matching_dirs = [d for d in Path("reports").iterdir() 
                    if d.is_dir() and d.name.startswith(domain + "_")]
    
    # Retorna el más reciente (ordenado por timestamp en nombre)
    return sorted(matching_dirs, reverse=True)[0] if matching_dirs else None
```

---

## ✅ Ventajas de esta Estructura

1. **Legibilidad**: Nombre de carpeta indica qué target y cuándo
2. **Organización**: Fácil encontrar reports por dominio
3. **Trazabilidad**: Timestamp con milisegundos evita colisiones
4. **Evidencia**: Screenshots y hallazgos en mismo directorio
5. **Auditable**: Metadata completa de cada análisis

---

## 📊 Ejemplo Completo

```
reports/
├── testphp.vulnweb.com_20260102_164114_456/
│   ├── consolidated_report.json (7.8KB)
│   ├── metadata.json (402B)
│   ├── validated_findings.json (1.2KB)
│   └── screenshots/
│       └── xss_test_20260102_164530.png (45KB)
└── example.com_20260102_165230_789/
    ├── consolidated_report.json
    ├── metadata.json
    └── screenshots/
        └── sqli_evidence_20260102_165245.png
```

---

**Última Actualización**: 2026-01-02 16:44  
**Estado**: Implementado y funcional
