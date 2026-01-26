# 🔧 HANDOFF: Mejoras del Framework - Reportes de SQL Injection

**Fecha:** 2026-01-24  
**Autor:** Albert (revisión de calidad de reportes)  
**Prioridad:** HIGH  
**Tipo:** Mejora de Framework  
**Componentes afectados:** `SQLiAgent`, `ReportGenerator`, `AgenticValidator`, `Finding` schema

---

## 📋 Resumen Ejecutivo

Los reportes de vulnerabilidades SQLi generados por BugTraceAI carecen de información crítica que permita a un triager humano **reproducir y verificar** la vulnerabilidad de forma autónoma. Esta mejora propone enriquecer el pipeline de detección y reporte de SQLi para generar documentación **"Triager-Ready"**.

---

## ❌ Problema Actual

El schema actual de findings para SQLi almacena información incompleta:

```python
# Estado actual del finding SQLi
{
    "type": "SQLI",
    "payload": "boolean-based blind, UNION query",  # ❌ TIPO, no payload
    "description": "SQL Injection confirmed via SQLMap...",
    "screenshot_path": null,                         # ❌ Sin evidencia visual
    "reproduction": null                             # ❌ Sin pasos de reproducción
}
```

### Problemas específicos:

1. **El campo `payload`** contiene el TIPO de inyección, no el payload funcional
2. **Sin URL de explotación** completa lista para copiar/pegar
3. **Sin datos extraídos** como prueba de compromiso
4. **Sin screenshot** de evidencia de explotación
5. **Sin número de columnas** detectado (crítico para UNION-based)
6. **Sin pasos de reproducción** detallados

---

## ✅ Mejora Propuesta

### 1. Extender el Schema de Finding para SQLi

```python
# bugtrace/models/finding.py

class SQLiFinding(BaseFinding):
    # Campos existentes
    type: str = "SQLI"
    url: str
    parameter: str
    severity: str
    
    # NUEVOS CAMPOS REQUERIDOS
    injection_type: str                    # "UNION-based", "boolean-blind", "time-blind", "error-based"
    working_payload: str                   # El payload EXACTO que funcionó
    payload_encoded: str                   # URL-encoded para copy/paste
    exploit_url: str                       # URL completa con payload (raw)
    exploit_url_encoded: str               # URL completa URL-encoded
    
    # Para UNION-based
    columns_detected: Optional[int]        # Número de columnas (ej: 20)
    column_detection_payload: Optional[str] # Payload usado para detectar columnas
    
    # Evidencia de explotación
    extracted_databases: List[str]         # DBs encontradas
    extracted_tables: List[str]            # Tablas encontradas (sample)
    sample_data: Optional[Dict]            # Datos de ejemplo extraídos
    
    # Metadata de SQLMap
    sqlmap_command: str                    # Comando exacto que se ejecutó
    sqlmap_output_summary: str             # Resumen del output
    dbms_detected: str                     # "PostgreSQL", "MySQL", etc.
    
    # Reproducción
    reproduction_steps: List[str]          # Pasos numerados
    curl_command: str                      # Comando curl para reproducir
    sqlmap_reproduce_command: str          # Comando sqlmap para re-explotar
```

### 2. Modificar SQLiAgent para capturar datos completos

```python
# bugtrace/agents/sqli_agent.py

class SQLiAgent:
    async def analyze(self, target_url: str, parameter: str) -> SQLiFinding:
        # Ejecutar SQLMap con output detallado
        sqlmap_result = await self.run_sqlmap(
            url=target_url,
            parameter=parameter,
            options=[
                "--batch",
                "--dbs",              # Enumerar DBs
                "--tables",           # Enumerar tablas
                "--dump-format=JSON", # Output estructurado
                "--output-dir=/tmp/sqlmap_scan",
                "-v 3"                # Verbosidad para capturar payloads
            ]
        )
        
        # Parsear output de SQLMap
        parsed = self.parse_sqlmap_output(sqlmap_result)
        
        # Construir finding completo
        return SQLiFinding(
            url=target_url,
            parameter=parameter,
            injection_type=parsed.injection_type,
            working_payload=parsed.payload,           # ← CRÍTICO: payload real
            columns_detected=parsed.columns,
            extracted_databases=parsed.databases,
            extracted_tables=parsed.tables[:10],      # Primeras 10 tablas
            sample_data=parsed.sample_rows,
            exploit_url=self.build_exploit_url(target_url, parameter, parsed.payload),
            exploit_url_encoded=urllib.parse.quote(exploit_url),
            sqlmap_command=parsed.command_used,
            dbms_detected=parsed.dbms,
            reproduction_steps=self.generate_repro_steps(target_url, parameter, parsed),
            curl_command=self.generate_curl_command(target_url, parameter, parsed.payload)
        )
    
    def parse_sqlmap_output(self, output: str) -> SQLMapResult:
        """
        Parsear output de SQLMap para extraer:
        - Payload exacto que funcionó
        - Número de columnas (para UNION)
        - DBs y tablas encontradas
        - Datos de ejemplo
        """
        # Buscar líneas como:
        # "Parameter: category (GET)"
        # "Type: UNION query"
        # "Payload: -1' UNION SELECT NULL,NULL,..."
        pass
    
    def generate_repro_steps(self, url, param, parsed) -> List[str]:
        return [
            f"1. Navigate to: {url}",
            f"2. Intercept the request and modify parameter `{param}`",
            f"3. Inject payload: `{parsed.payload}`",
            f"4. Observe database data in response",
            f"",
            f"Alternative - Use SQLMap:",
            f"```bash",
            f"sqlmap -u \"{url}\" -p {param} --batch --dbs",
            f"```"
        ]
```

### 3. Modificar SQLMapWrapper para parseo estructurado

```python
# bugtrace/tools/sqlmap_wrapper.py

class SQLMapWrapper:
    def parse_injection_details(self, output: str) -> Dict:
        """
        Extraer información detallada del output de SQLMap
        """
        result = {
            "injection_types": [],
            "working_payloads": [],
            "columns": None,
            "databases": [],
            "tables": {},
            "dbms": None
        }
        
        # Regex patterns para extraer info
        patterns = {
            "payload": r"Payload: (.+)",
            "columns": r"ORDER BY (\d+)",
            "dbms": r"back-end DBMS: (.+)",
            "database": r"available databases \[\d+\]:\n(.+)",
        }
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, output)
            if matches:
                result[name] = matches
        
        return result
```

### 4. Modificar ReportGenerator para mostrar info completa

```python
# bugtrace/reporting/report_generator.py

def render_sqli_finding(finding: SQLiFinding) -> str:
    return f"""
    <div class="finding sqli">
        <header>
            <span class="badge critical">CRITICAL</span>
            <span class="badge">{finding.injection_type}</span>
            <h3>SQL Injection - {finding.parameter}</h3>
        </header>
        
        <section class="exploit-details">
            <h4>Working Payload</h4>
            <pre class="payload">{finding.working_payload}</pre>
            
            <h4>One-Click Exploit URL</h4>
            <a href="{finding.exploit_url_encoded}" target="_blank" class="exploit-link">
                🔗 Open Exploit
            </a>
            <button onclick="copyToClipboard('{finding.exploit_url_encoded}')">📋 Copy URL</button>
        </section>
        
        <section class="evidence">
            <h4>Extracted Data (Proof of Exploitation)</h4>
            <table>
                <tr><th>Databases</th><td>{', '.join(finding.extracted_databases)}</td></tr>
                <tr><th>Tables</th><td>{', '.join(finding.extracted_tables)}</td></tr>
                <tr><th>DBMS</th><td>{finding.dbms_detected}</td></tr>
                {f'<tr><th>Columns</th><td>{finding.columns_detected}</td></tr>' if finding.columns_detected else ''}
            </table>
            
            {render_sample_data(finding.sample_data) if finding.sample_data else ''}
        </section>
        
        <section class="reproduction">
            <h4>Steps to Reproduce</h4>
            <ol>
                {''.join(f'<li>{step}</li>' for step in finding.reproduction_steps)}
            </ol>
            
            <h4>Reproduce with cURL</h4>
            <pre>{finding.curl_command}</pre>
            
            <h4>Reproduce with SQLMap</h4>
            <pre>{finding.sqlmap_reproduce_command}</pre>
        </section>
    </div>
    """
```

---

## 📁 Archivos a Modificar

| Archivo | Cambio |
|---------|--------|
| `bugtrace/models/finding.py` | Agregar campos SQLi-specific al schema |
| `bugtrace/agents/sqli_agent.py` | Capturar payload real, columnas, datos extraídos |
| `bugtrace/tools/sqlmap_wrapper.py` | Parsear output completo de SQLMap |
| `bugtrace/validators/agentic_validator.py` | Tomar screenshot de explotación real |
| `bugtrace/reporting/report_generator.py` | Renderizar sección SQLi completa |
| `bugtrace/reporting/templates/report.html` | Template para datos extraídos |

---

## 🎯 Criterios de Aceptación (Para CUALQUIER escaneo)

- [ ] Todo finding SQLi incluye el **payload exacto** que funcionó
- [ ] Todo finding SQLi incluye **URL de explotación** lista para usar
- [ ] Para UNION-based: se reporta **número de columnas**
- [ ] Se muestran **datos extraídos** como prueba (DBs, tablas)
- [ ] Se incluye **comando cURL** para reproducir
- [ ] Se incluye **comando SQLMap** para re-explotar
- [ ] Se toma **screenshot** de respuesta con datos inyectados
- [ ] Un triager puede **reproducir en < 2 minutos** con info del reporte

---

## 📊 Template de Reporte Mejorado

```
┌─────────────────────────────────────────────────────────────────┐
│ SQL INJECTION                                    CRITICAL 9.8   │
│ Type: [UNION-based | boolean-blind | time-blind | error-based]  │
├─────────────────────────────────────────────────────────────────┤
│ Target: [URL]                                                   │
│ Parameter: [param_name]                                         │
│ DBMS: [PostgreSQL | MySQL | MSSQL | Oracle | SQLite]            │
├─────────────────────────────────────────────────────────────────┤
│ WORKING PAYLOAD:                                                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ [actual_payload_here]                                       │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ [🔗 Open Exploit URL]  [📋 Copy]                                │
├─────────────────────────────────────────────────────────────────┤
│ PROOF OF EXPLOITATION:                                          │
│ ┌────────────────────┬──────────────────────────────────────┐  │
│ │ Databases          │ db1, db2, db3                        │  │
│ │ Tables (sample)    │ users, products, orders              │  │
│ │ Columns detected   │ 20 (for UNION-based)                 │  │
│ └────────────────────┴──────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│ REPRODUCE WITH CURL:                                            │
│ curl "[exploit_url]"                                            │
│                                                                 │
│ REPRODUCE WITH SQLMAP:                                          │
│ sqlmap -u "[url]" -p [param] --batch --dbs                      │
├─────────────────────────────────────────────────────────────────┤
│ [📷 Screenshot: Response showing extracted data]                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Caso de Descubrimiento

Esta mejora fue identificada durante la revisión del reporte del escaneo `ginandjuice.shop` (24/01/2026), donde se observó que:
- El campo `payload` contenía "boolean-based blind, UNION query" en lugar del payload real
- No se incluían los datos extraídos visibles en el output de SQLMap
- Un triager no podía reproducir la vulnerabilidad sin acceso a los logs

---

**Status:** 🟡 PENDIENTE DE IMPLEMENTACIÓN
