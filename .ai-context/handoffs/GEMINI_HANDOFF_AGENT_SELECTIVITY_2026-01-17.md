# Handoff: Agent Selectivity, Tiered Validation & Parallel Execution

**Date**: 2026-01-17
**From**: Claude (Opus 4.5)
**To**: Gemini
**Priority**: CRITICAL
**Status**: READY FOR IMPLEMENTATION

---

## 1. Executive Summary

### El Problema Real

Dos problemas relacionados:

**PROBLEMA 1 - Demasiados Findings Falsos**:
Los agentes especializados (XSS, SQLi, LFI, SSRF, RCE) generan **demasiados findings** y marcan casi todos como `VALIDATED_CONFIRMED`. Esto causa:
1. **Reportes inflados** con falsos positivos
2. **AgenticValidator nunca recibe findings** porque ya están "confirmados"
3. **Pérdida de credibilidad**

**PROBLEMA 2 - Ejecución Secuencial Lenta**:
Los agentes se ejecutan **uno tras otro** cuando podrían ejecutarse en paralelo. El semaphore existe (`MAX_CONCURRENT_URL_AGENTS = 10`) pero **no se usa**.

### La Solución Integral

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HUNTER PHASE (MULTI-HILO)                           │
│                                                                             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│   │ XSSAgent │  │SQLiAgent │  │ LFIAgent │  │SSRFAgent │  │IDORAgent │    │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│        │             │             │             │             │           │
│        └─────────────┴─────────────┴─────────────┴─────────────┘           │
│                                    │                                        │
│                          PARALELO (5-10 concurrent)                        │
│                          Rápido, sin CDP, selectivos                       │
│                                    │                                        │
│                    Solo crean findings MUY SELECTIVOS                       │
│                    TIER 1 → CONFIRMED | TIER 2 → PENDING | TIER 3 → SKIP   │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │   DATABASE   │
                              │  (Conveyor)  │
                              └──────┬───────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AUDITOR PHASE (SECUENCIAL - CDP)                       │
│                                                                             │
│                         ┌─────────────────────┐                            │
│                         │  AgenticValidator   │                            │
│                         │    (CDP + Vision)   │                            │
│                         └─────────────────────┘                            │
│                                                                             │
│                    Solo recibe PENDING_VALIDATION (muy pocos)              │
│                    Secuencial pero rápido porque son pocos                 │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      REPORTER PHASE (DESACOPLADO)                           │
│                         Puede tardar, no importa                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Parte 1: Agentes Selectivos

Los agentes deben ser **MUY SELECTIVOS** en qué reportan:

```
┌─────────────────────────────────────────────────────────────────────┐
│  TIER 1: PRUEBA DEFINITIVA → VALIDATED_CONFIRMED                    │
│  • OOB callback (Interactsh)                                        │
│  • SQLMap confirmó                                                  │
│  • Contenido de archivo sensible visible (/etc/passwd)              │
│  • Screenshot con banner visual "HACKED BY BUGTRACEAI"              │
├─────────────────────────────────────────────────────────────────────┤
│  TIER 2: EVIDENCIA FUERTE PERO NECESITA VALIDACIÓN → PENDING        │
│  • Reflexión en HTML sin ejecución confirmada                       │
│  • Error SQL genérico sin data dump                                 │
│  • IDOR con diferencia de contenido (80-98% similarity)             │
│  • Time-based detection sin output visible                          │
├─────────────────────────────────────────────────────────────────────┤
│  TIER 3: SOSPECHOSO PERO DÉBIL → NO CREAR FINDING                   │
│  • Solo reflexión en contexto no-ejecutable (texto plano)           │
│  • Error HTTP 500 genérico sin signature SQL/LFI                    │
│  • Respuesta diferente pero sin datos sensibles                     │
│  • Delay < 4 segundos (ruido de red)                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Análisis del Estado Actual

### 2.1 XSSAgent (BUENO - Modelo a seguir)

**Archivo**: `bugtrace/agents/xss_agent.py`
**Líneas**: 156-190

El XSSAgent YA tiene la lógica correcta:

```python
def _determine_validation_status(self, finding_data: Dict) -> str:
    evidence = finding_data.get("evidence", {})
    has_screenshot = finding_data.get("screenshot_path") is not None
    has_interactsh_hit = evidence.get("interactsh_hit", False)
    vision_confirmed = evidence.get("vision_confirmed", False)

    # TIER 1: Interactsh = DEFINITIVO
    if has_interactsh_hit:
        return "VALIDATED_CONFIRMED"

    # TIER 1: Vision + Screenshot = DEFINITIVO
    if vision_confirmed and has_screenshot:
        return "VALIDATED_CONFIRMED"

    # TIER 1: Fragment XSS con screenshot = DEFINITIVO
    if finding_data.get("context") == "dom_xss_fragment" and has_screenshot:
        return "VALIDATED_CONFIRMED"

    # TIER 2: Todo lo demás va al Auditor
    return "PENDING_VALIDATION"
```

**PROBLEMA DEL XSSAgent**: El problema NO es la lógica de validación, es que **crea findings por mera reflexión**. El XSSAgent debería NO CREAR FINDING si solo detecta reflexión sin contexto peligroso.

### 2.2 SQLiAgent (MALO - Necesita refactor)

**Archivo**: `bugtrace/agents/sqli_agent.py`
**Líneas**: 21-38

Estado actual (PROBLEMÁTICO):

```python
def _determine_validation_status(self, finding_type: str, evidence_type: str) -> str:
    # SIEMPRE devuelve VALIDATED_CONFIRMED
    if finding_type == "sqlmap" or evidence_type == "error_based":
        return "VALIDATED_CONFIRMED"
    if evidence_type == "time_based":
        return "VALIDATED_CONFIRMED"  # ← DEBERÍA SER PENDING_VALIDATION
    return "VALIDATED_CONFIRMED"  # ← NUNCA HAY PENDING
```

**PROBLEMA**: Time-based SQLi es muy propenso a falsos positivos (latencia de red). Debería ir a `PENDING_VALIDATION`.

### 2.3 LFIAgent (MALO - Necesita refactor)

**Archivo**: `bugtrace/agents/lfi_agent.py`
**Líneas**: 25-37

Estado actual (PROBLEMÁTICO):

```python
def _determine_validation_status(self, evidence: str) -> str:
    if "Sensitive file content detected" in evidence:
        return "VALIDATED_CONFIRMED"
    # DEFAULT: SIEMPRE CONFIRMED
    return "VALIDATED_CONFIRMED"  # ← NUNCA HAY PENDING
```

**PROBLEMA**: El agent crea finding cuando detecta "Sensitive file content", pero el default es CONFIRMED. Si hay heurística que no es file content, debería ser PENDING.

### 2.4 SSRFAgent (MALO - Sin status field)

**Archivo**: `bugtrace/agents/ssrf_agent.py`
**Líneas**: 82-91

Estado actual (PROBLEMÁTICO):

```python
def _create_finding(self, payload: str) -> Dict:
    return {
        "type": "SSRF",
        ...
        "validated": True  # ← NO HAY "status" FIELD!
    }
```

**PROBLEMA**: No tiene `status` field. Todos los findings son implícitamente "confirmados".

### 2.5 IDORAgent (PARCIALMENTE BUENO)

**Archivo**: `bugtrace/agents/idor_agent.py`
**Líneas**: 107-118, 144

Estado actual (MIXTO):

```python
# Differential Analysis → PENDING_VALIDATION (CORRECTO)
findings.append({
    ...
    "status": "PENDING_VALIDATION"  # ✓ Bien
})

# Cookie Tampering → VALIDATED_CONFIRMED (CORRECTO)
findings.append({
    ...
    "status": "VALIDATED_CONFIRMED"  # ✓ Bien
})
```

**PROBLEMA**: La lógica es buena pero el `_determine_validation_status` (líneas 28-39) siempre devuelve CONFIRMED. Inconsistencia.

---

## 3. Cambios Requeridos

### 3.1 SQLiAgent - Refactor Completo

**Archivo**: `bugtrace/agents/sqli_agent.py`

#### Cambio 1: Actualizar `_determine_validation_status`

**Líneas a modificar**: 21-38

**Código nuevo**:

```python
def _determine_validation_status(self, finding_type: str, evidence_type: str, evidence_data: Dict = None) -> str:
    """
    Determine tiered validation status based on evidence strength.

    TIER 1 (VALIDATED_CONFIRMED):
        - SQLMap confirmed (gold standard)
        - Error-based with actual data leak (table names, column data)

    TIER 2 (PENDING_VALIDATION):
        - Time-based (prone to network latency false positives)
        - Boolean-based without data extraction
        - Error-based without clear data leak

    Returns:
        "VALIDATED_CONFIRMED" or "PENDING_VALIDATION"
    """
    evidence_data = evidence_data or {}

    # TIER 1: SQLMap is the gold standard - always trust it
    if finding_type == "sqlmap":
        logger.info(f"[{self.name}] SQLMap confirmed. VALIDATED_CONFIRMED")
        return "VALIDATED_CONFIRMED"

    # TIER 1: Error-based WITH data leak (table names, extracted values)
    if evidence_type == "error_based":
        # Check if we actually extracted data
        has_data_leak = evidence_data.get("extracted_data") or evidence_data.get("table_names")
        if has_data_leak:
            logger.info(f"[{self.name}] Error-based with data leak. VALIDATED_CONFIRMED")
            return "VALIDATED_CONFIRMED"
        # Error message alone is not enough - could be false positive
        logger.info(f"[{self.name}] Error-based without data leak. PENDING_VALIDATION")
        return "PENDING_VALIDATION"

    # TIER 2: Time-based is ALWAYS pending (network latency causes FPs)
    if evidence_type == "time_based":
        logger.info(f"[{self.name}] Time-based SQLi. PENDING_VALIDATION (needs CDP timing verification)")
        return "PENDING_VALIDATION"

    # TIER 2: Boolean-based without data extraction
    if evidence_type == "boolean_based":
        logger.info(f"[{self.name}] Boolean-based SQLi. PENDING_VALIDATION")
        return "PENDING_VALIDATION"

    # Default: If we're uncertain, let the Auditor decide
    logger.info(f"[{self.name}] Unknown evidence type. PENDING_VALIDATION")
    return "PENDING_VALIDATION"
```

#### Cambio 2: Actualizar llamadas a `_determine_validation_status`

**Línea 103** (SQLMap finding):
```python
"status": self._determine_validation_status("sqlmap", "error_based", {"extracted_data": True})
```

**Línea 134** (Python detector):
```python
# Need to pass evidence about what was actually detected
evidence_data = {
    "extracted_data": "data" in msg.lower() or "table" in msg.lower(),
    "error_message": msg
}
"status": self._determine_validation_status("internal", self._classify_evidence(msg), evidence_data)
```

#### Cambio 3: Añadir helper `_classify_evidence`

**Añadir después de línea 150**:

```python
def _classify_evidence(self, message: str) -> str:
    """Classify the type of SQLi evidence from detection message."""
    msg_lower = message.lower()

    if any(kw in msg_lower for kw in ["sleep", "benchmark", "pg_sleep", "waitfor delay"]):
        return "time_based"

    if any(kw in msg_lower for kw in ["error", "syntax", "warning", "mysql", "postgresql", "sqlite"]):
        return "error_based"

    if any(kw in msg_lower for kw in ["true", "false", "1=1", "1=0", "and", "or"]):
        return "boolean_based"

    return "unknown"
```

---

### 3.2 LFIAgent - Refactor

**Archivo**: `bugtrace/agents/lfi_agent.py`

#### Cambio 1: Actualizar `_determine_validation_status`

**Líneas a modificar**: 25-37

**Código nuevo**:

```python
def _determine_validation_status(self, response_text: str, payload: str) -> str:
    """
    Determine validation status based on what we actually found.

    TIER 1 (VALIDATED_CONFIRMED):
        - /etc/passwd content visible (root:x:0:0)
        - win.ini content visible ([extensions])
        - PHP source code visible (<?php or base64 decoded PHP)

    TIER 2 (PENDING_VALIDATION):
        - Path traversal success but no sensitive file content
        - PHP wrapper returned something but unclear if source code
    """
    # TIER 1: Clear sensitive file signatures
    tier1_signatures = [
        "root:x:0:0",           # /etc/passwd Linux
        "root:*:0:0",           # /etc/passwd BSD
        "[extensions]",         # win.ini
        "[fonts]",              # win.ini
        "127.0.0.1 localhost",  # /etc/hosts
        "<?php",                # PHP source code (direct)
    ]

    for sig in tier1_signatures:
        if sig in response_text:
            logger.info(f"[{self.name}] Found '{sig}' in response. VALIDATED_CONFIRMED")
            return "VALIDATED_CONFIRMED"

    # TIER 1: Base64 decoded PHP (from php://filter)
    if "PD9waH" in response_text:  # Base64 for <?php
        logger.info(f"[{self.name}] Found base64 PHP source. VALIDATED_CONFIRMED")
        return "VALIDATED_CONFIRMED"

    # TIER 2: Path traversal worked but didn't get sensitive content
    # This could be a directory listing or error page
    logger.info(f"[{self.name}] LFI response unclear. PENDING_VALIDATION")
    return "PENDING_VALIDATION"
```

#### Cambio 2: Actualizar la creación del finding

**Líneas 80-91**, cambiar a:

```python
if await self._test_payload(session, p):
    # Get the actual response to classify
    response_text = await self._get_response_text(session, p)

    findings.append({
        "type": "LFI / Path Traversal",
        "url": self.url,
        "parameter": self.param,
        "payload": p,
        "description": "Local File Inclusion / Path Traversal vulnerability detected.",
        "severity": "CRITICAL",
        "validated": True,
        "evidence": f"Sensitive file content detected after injecting {p}",
        "status": self._determine_validation_status(response_text, p)
    })
    return {"vulnerable": True, "findings": findings}
```

#### Cambio 3: Añadir helper `_get_response_text`

```python
async def _get_response_text(self, session, payload) -> str:
    """Get the response text for classification."""
    target_url = self._inject_payload(self.url, self.param, payload)
    try:
        async with session.get(target_url, timeout=5) as resp:
            return await resp.text()
    except:
        return ""
```

---

### 3.3 SSRFAgent - Añadir Status Field

**Archivo**: `bugtrace/agents/ssrf_agent.py`

#### Cambio 1: Actualizar `_create_finding`

**Líneas 82-91**, cambiar a:

```python
def _create_finding(self, payload: str, response_text: str = "") -> Dict:
    """Create a finding with proper validation status."""

    # Determine status based on what we found
    status = self._determine_validation_status(payload, response_text)

    return {
        "type": "SSRF",
        "url": self.url,
        "parameter": self.param,
        "payload": payload,
        "description": "Server-Side Request Forgery detected.",
        "severity": "CRITICAL" if "passwd" in payload or "169.254" in payload else "HIGH",
        "validated": status == "VALIDATED_CONFIRMED",
        "status": status
    }

def _determine_validation_status(self, payload: str, response_text: str) -> str:
    """
    TIER 1 (VALIDATED_CONFIRMED):
        - Cloud metadata accessed (ami-id, instance-id)
        - /etc/passwd content via file://
        - Internal service accessed with clear response

    TIER 2 (PENDING_VALIDATION):
        - Internal IP responded but unclear content
        - Redirect detected but not followed
    """
    # TIER 1: Cloud metadata
    if any(kw in response_text for kw in ["ami-id", "instance-id", "iam/security-credentials"]):
        logger.info(f"[{self.name}] Cloud metadata accessed. VALIDATED_CONFIRMED")
        return "VALIDATED_CONFIRMED"

    # TIER 1: Local file read via file://
    if "file://" in payload and "root:x:0:0" in response_text:
        logger.info(f"[{self.name}] Local file read via SSRF. VALIDATED_CONFIRMED")
        return "VALIDATED_CONFIRMED"

    # TIER 1: Clear internal service response
    internal_signatures = [
        "BugTraceAI",           # Our dojo
        "Protocol Access Granted",
        "internal server",
        "admin panel"
    ]
    if any(sig.lower() in response_text.lower() for sig in internal_signatures):
        logger.info(f"[{self.name}] Internal service accessed. VALIDATED_CONFIRMED")
        return "VALIDATED_CONFIRMED"

    # TIER 2: Got a response but unclear
    logger.info(f"[{self.name}] SSRF response unclear. PENDING_VALIDATION")
    return "PENDING_VALIDATION"
```

#### Cambio 2: Actualizar llamadas a `_create_finding`

**Línea 61-62**:
```python
resp_text = await self._get_response_text(session, p)
findings.append(self._create_finding(p, resp_text))
```

**Línea 73-75**:
```python
resp_text = await self._get_response_text(session, payload)
findings.append(self._create_finding(payload, resp_text))
```

#### Cambio 3: Añadir helper

```python
async def _get_response_text(self, session, payload) -> str:
    """Get response text for a payload."""
    target_url = self._inject_payload(self.url, self.param, payload)
    try:
        async with session.get(target_url, timeout=5) as resp:
            return await resp.text()
    except:
        return ""
```

---

### 3.4 IDORAgent - Limpiar Inconsistencia

**Archivo**: `bugtrace/agents/idor_agent.py`

#### Cambio 1: Simplificar `_determine_validation_status`

**Líneas 28-39**, cambiar a:

```python
def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
    """
    TIER 1 (VALIDATED_CONFIRMED):
        - Cookie tampering success (horizontal privilege escalation)
        - HIGH confidence differential with sensitive data markers

    TIER 2 (PENDING_VALIDATION):
        - MEDIUM/LOW confidence differential analysis
        - Needs human/CDP verification
    """
    if evidence_type == "cookie_tampering":
        return "VALIDATED_CONFIRMED"

    if evidence_type == "differential" and confidence == "HIGH":
        return "VALIDATED_CONFIRMED"

    return "PENDING_VALIDATION"
```

#### Cambio 2: Actualizar creación de findings

**Líneas 107-118** (differential finding):
```python
findings.append({
    "type": "IDOR",
    "url": self.url,
    "parameter": self.param,
    "payload": tid,
    "description": f"Potential IDOR on ID {tid}. Similarity: {similarity:.2f}",
    "severity": "CRITICAL" if confidence == "HIGH" else "MEDIUM",
    "validated": confidence == "HIGH",
    "evidence": f"Status {status}. Diff ratio: {similarity:.2f}. Marker found: {has_success}",
    "status": self._determine_validation_status("differential", confidence)
})
```

**Líneas 136-145** (cookie tampering):
```python
findings.append({
    "type": "IDOR",
    "url": self.url,
    "parameter": self.param,
    "payload": tid,
    "description": f"IDOR via Cookie Tampering ({cookie_name}={tid})",
    "severity": "CRITICAL",
    "validated": True,
    "status": self._determine_validation_status("cookie_tampering", "HIGH")
})
```

---

### 3.5 XSSAgent - Añadir Filtro Pre-Finding

**Archivo**: `bugtrace/agents/xss_agent.py`

El XSSAgent ya tiene buena lógica de status, pero crea demasiados findings. Necesita un filtro **ANTES** de crear el finding.

#### Cambio: Añadir `_should_create_finding` method

**Añadir después de línea 190**:

```python
def _should_create_finding(self, test_result: Dict) -> bool:
    """
    Decide if we should create a finding based on evidence strength.
    This PREVENTS creating findings for weak evidence (TIER 3).

    Returns:
        True if evidence is strong enough to warrant a finding
        False if evidence is too weak (just log internally)
    """
    evidence = test_result.get("evidence", {})

    # ALWAYS create finding if we have OOB confirmation
    if evidence.get("interactsh_hit"):
        return True

    # ALWAYS create finding if Vision AI confirmed execution
    if evidence.get("vision_confirmed"):
        return True

    # ALWAYS create finding if we have a screenshot showing the banner
    if test_result.get("screenshot_path") and evidence.get("banner_visible"):
        return True

    # CHECK: Is this just reflection without execution?
    reflection_context = test_result.get("reflection_context", "")

    # REJECT: Reflection in non-executable context (plain text, comments)
    non_executable_contexts = ["html_comment", "text_node", "attribute_value_quoted"]
    if reflection_context in non_executable_contexts:
        logger.debug(f"[{self.name}] Skipping finding - reflection in non-executable context: {reflection_context}")
        return False

    # REJECT: No execution evidence at all
    if not evidence.get("dom_mutation") and not evidence.get("console_output"):
        logger.debug(f"[{self.name}] Skipping finding - no execution evidence")
        return False

    # ACCEPT: Has some execution evidence, create finding for Auditor
    return True
```

#### Cambio: Usar el filtro en `_test_parameter`

Buscar donde se crea el finding y añadir:

```python
# Before creating finding, check if evidence is strong enough
if not self._should_create_finding(test_result):
    logger.info(f"[{self.name}] Evidence too weak for '{param}', skipping finding creation")
    continue  # or return None

# Proceed with finding creation
finding = XSSFinding(...)
```

---

## 4. Resumen de Cambios por Archivo

| Archivo | Cambios | Prioridad |
|---------|---------|-----------|
| `bugtrace/agents/sqli_agent.py` | Refactor `_determine_validation_status`, añadir `_classify_evidence` | ALTA |
| `bugtrace/agents/lfi_agent.py` | Refactor `_determine_validation_status`, añadir `_get_response_text` | ALTA |
| `bugtrace/agents/ssrf_agent.py` | Añadir `status` field, crear `_determine_validation_status` | ALTA |
| `bugtrace/agents/idor_agent.py` | Simplificar `_determine_validation_status`, limpiar inconsistencias | MEDIA |
| `bugtrace/agents/xss_agent.py` | Añadir `_should_create_finding` filtro pre-finding | MEDIA |

---

## 5. Criterios de Validación

### Test 1: Ejecutar contra Dojo

```bash
./bugtraceai-cli http://127.0.0.1:5050
```

**Resultado esperado**:
- Findings con mix de `VALIDATED_CONFIRMED` y `PENDING_VALIDATION`
- AgenticValidator recibe los `PENDING_VALIDATION`
- Reporte final solo incluye los realmente confirmados

### Test 2: Verificar Status en DB

```sql
SELECT type, status, COUNT(*) FROM findings GROUP BY type, status;
```

**Resultado esperado**:
```
XSS  | VALIDATED_CONFIRMED    | 2
XSS  | PENDING_VALIDATION     | 3
SQLi | VALIDATED_CONFIRMED    | 1
SQLi | PENDING_VALIDATION     | 2
IDOR | PENDING_VALIDATION     | 4
...
```

### Test 3: Verificar Reporte

El `final_report.md` debe tener:
- Sección "Confirmed Vulnerabilities" (solo VALIDATED_CONFIRMED)
- Sección "Needs Manual Review" (MANUAL_REVIEW_RECOMMENDED)
- NO debe incluir PENDING_VALIDATION sin validar

---

## 6. Notas Importantes

### NO Romper lo que Funciona

- XSSAgent ya tiene la lógica correcta, solo añadir el filtro pre-finding
- IDORAgent ya usa PENDING_VALIDATION en algunos casos, solo limpiar
- SQLiAgent con SQLMap siempre debe ser VALIDATED_CONFIRMED

### Principio Guía

> "Es mejor NO reportar una vulnerabilidad dudosa que reportar 50 falsos positivos. La credibilidad del scanner depende de la precisión."

### Orden de Implementación

1. **SQLiAgent** (más impactante - SQLi crítico con muchos FPs actualmente)
2. **SSRFAgent** (no tiene status field - bug obvio)
3. **LFIAgent** (similar a SQLi)
4. **IDORAgent** (limpieza)
5. **XSSAgent** (filtro adicional)

---

## 7. Rollback Plan

Si algo falla:

```bash
git checkout HEAD -- bugtrace/agents/sqli_agent.py
git checkout HEAD -- bugtrace/agents/lfi_agent.py
git checkout HEAD -- bugtrace/agents/ssrf_agent.py
git checkout HEAD -- bugtrace/agents/idor_agent.py
git checkout HEAD -- bugtrace/agents/xss_agent.py
```

---

## 8. PARTE 2: Ejecución Paralela de Agentes (Hunter Phase)

### El Problema

En `bugtrace/core/team.py`, los agentes se ejecutan **secuencialmente**:

```python
# Líneas 970-1005 (ACTUAL - LENTO)
if "XSS_AGENT" in specialist_dispatches:
    xss_agent = XSSAgent(url, params=p_list, report_dir=url_dir)
    res = await xss_agent.run_loop()  # ← ESPERA
    process_result(res)

if "SQL_AGENT" in specialist_dispatches:
    sql_agent = SQLMapAgent(url, p_list, url_dir)
    res = await sql_agent.run_loop()  # ← ESPERA (después del anterior)
    process_result(res)

# ... etc, uno tras otro
```

El semaphore existe (`self.url_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_URL_AGENTS)`) pero **NO SE USA**.

### La Solución

Ejecutar los agentes en **paralelo con límite**:

**Archivo**: `bugtrace/core/team.py`

#### Cambio 1: Crear función helper para ejecución paralela

**Añadir cerca de línea 60** (después de imports):

```python
async def run_agent_with_semaphore(semaphore: asyncio.Semaphore, agent, process_result_fn):
    """
    Execute an agent with semaphore-controlled concurrency.
    This allows multiple agents to run in parallel while respecting resource limits.
    """
    async with semaphore:
        try:
            result = await agent.run_loop()
            process_result_fn(result)
            return result
        except Exception as e:
            logger.error(f"Agent {agent.name} failed: {e}")
            return {"error": str(e), "findings": []}
```

#### Cambio 2: Refactorizar el dispatch de agentes

**Líneas 970-1005**, cambiar de secuencial a paralelo:

```python
# Execute Batched Agents IN PARALLEL
agent_tasks = []

if "XSS_AGENT" in specialist_dispatches:
    p_list = list(params_map.get("XSS_AGENT", [])) or None
    xss_agent = XSSAgent(url, params=p_list, report_dir=url_dir)
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, xss_agent, process_result))

if "SQL_AGENT" in specialist_dispatches:
    p_list = list(params_map.get("SQL_AGENT", [])) or None
    sql_agent = SQLMapAgent(url, p_list, url_dir)
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, sql_agent, process_result))

if "XXE_AGENT" in specialist_dispatches:
    from bugtrace.agents.exploit_specialists import XXEAgent
    p_list = list(params_map.get("XXE_AGENT", [])) or None
    xxe_agent = XXEAgent(url, p_list, url_dir)
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, xxe_agent, process_result))

if "PROTO_AGENT" in specialist_dispatches:
    from bugtrace.agents.exploit_specialists import ProtoAgent
    p_list = list(params_map.get("PROTO_AGENT", [])) or None
    proto_agent = ProtoAgent(url, p_list, url_dir)
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, proto_agent, process_result))

if "FILE_UPLOAD_AGENT" in specialist_dispatches:
    from bugtrace.agents.fileupload_agent import FileUploadAgent
    upload_agent = FileUploadAgent(url)
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, upload_agent, process_result))

if "JWT_AGENT" in specialist_dispatches:
    agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, self.jwt_agent, process_result))

# NEW: Execute all agents in parallel (respecting semaphore limit)
if agent_tasks:
    logger.info(f"[TeamOrchestrator] Executing {len(agent_tasks)} agents in parallel (max {settings.MAX_CONCURRENT_URL_AGENTS} concurrent)")
    await asyncio.gather(*agent_tasks, return_exceptions=True)
```

#### Cambio 3: Añadir agentes de parámetros individuales al paralelo

Para LFI, SSRF, IDOR que se instancian por parámetro, también paralelizar:

```python
# Para SSRF, LFI, IDOR - crear tasks por parámetro
if "SSRF_AGENT" in specialist_dispatches:
    from bugtrace.agents.ssrf_agent import SSRFAgent
    for param in params_map.get("SSRF_AGENT", []):
        ssrf_agent = SSRFAgent(url, param)
        agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, ssrf_agent, process_result))

if "LFI_AGENT" in specialist_dispatches:
    from bugtrace.agents.lfi_agent import LFIAgent
    for param in params_map.get("LFI_AGENT", []):
        lfi_agent = LFIAgent(url, param)
        agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, lfi_agent, process_result))

if "IDOR_AGENT" in specialist_dispatches:
    from bugtrace.agents.idor_agent import IDORAgent
    for param, orig_val in params_map.get("IDOR_AGENT", {}).items():
        idor_agent = IDORAgent(url, param, orig_val)
        agent_tasks.append(run_agent_with_semaphore(self.url_semaphore, idor_agent, process_result))
```

### Configuración del Límite y Activación

**Archivo**: `bugtraceaicli.conf`

Añadir la siguiente opción en la sección `[SCAN]`:

```ini
[SCAN]
# ... existing config ...

# Enable parallel execution of specialist agents within each URL.
# When True: XSS, SQLi, LFI, etc. run in parallel (faster, more resources)
# When False: Agents run sequentially (slower, but safer and easier to debug)
# Recommended: True for production, False for debugging
PARALLEL_AGENTS = True

# Maximum concurrent agents in Hunter phase (only applies when PARALLEL_AGENTS = True)
# Higher = faster but more resource intensive
# Recommended: 5-10 for most systems
MAX_CONCURRENT_URL_AGENTS = 5
```

**Archivo**: `bugtrace/core/config.py`

Añadir o verificar que existe:
```python
# Parallel agent execution
PARALLEL_AGENTS: bool = True  # Default: enabled

# Maximum concurrent agents (used when PARALLEL_AGENTS = True)
MAX_CONCURRENT_URL_AGENTS: int = 10  # Default
```

**Archivo**: `bugtrace/core/team.py`

Modificar el dispatch para respetar la configuración:

```python
# Check if parallel execution is enabled
if settings.PARALLEL_AGENTS and agent_tasks:
    logger.info(f"[TeamOrchestrator] Executing {len(agent_tasks)} agents in PARALLEL (max {settings.MAX_CONCURRENT_URL_AGENTS} concurrent)")
    await asyncio.gather(*agent_tasks, return_exceptions=True)
else:
    # Sequential execution (for debugging or resource-limited environments)
    logger.info(f"[TeamOrchestrator] Executing {len(agent_tasks)} agents SEQUENTIALLY (PARALLEL_AGENTS=False)")
    for task in agent_tasks:
        await task
```

### Por Qué Esto Es Seguro

1. **Sin CDP en Hunter**: Los agentes usan Playwright en modo no-CDP, thread-safe
2. **DB Writes Aislados**: Cada finding se escribe individualmente (no batch)
3. **Semaphore controla**: Nunca más de N agentes simultáneos
4. **Errores aislados**: `return_exceptions=True` evita que un fallo mate a todos

### Resultados Esperados

| Métrica | Antes (Secuencial) | Después (Paralelo) |
|---------|-------------------|-------------------|
| 5 agentes, 1 URL | ~50 segundos | ~15 segundos |
| 5 agentes, 10 URLs | ~500 segundos | ~100 segundos |
| CPU Usage | 10-20% | 40-60% |

---

## 9. Resumen Final

### Orden de Implementación Completo

1. **Agentes Selectivos** (Parte 1)
   - SQLiAgent → time-based a PENDING
   - SSRFAgent → añadir status field
   - LFIAgent → sin firma a PENDING
   - IDORAgent → limpiar
   - XSSAgent → filtro pre-finding

2. **Paralelismo** (Parte 2)
   - Helper `run_agent_with_semaphore`
   - Refactorizar dispatch en team.py
   - Verificar config de semaphore

3. **Configuración** (Parte 3)
   - Añadir `PARALLEL_AGENTS = True` en `bugtraceaicli.conf` (sección `[SCAN]`)
   - Añadir `PARALLEL_AGENTS: bool = True` en `bugtrace/core/config.py`
   - Modificar team.py para respetar el flag de configuración

### El Flujo Final

```
                    ┌─────────────────────────────────────┐
                    │         HUNTER (PARALELO)           │
                    │   5-10 agentes simultáneos          │
                    │   Selectivos: TIER 1/2/3            │
                    └─────────────────┬───────────────────┘
                                      │
                    Pocos findings (solo TIER 1 y 2)
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │       DATABASE (Conveyor Belt)      │
                    │  VALIDATED_CONFIRMED + PENDING      │
                    └─────────────────┬───────────────────┘
                                      │
                    Solo PENDING_VALIDATION (muy pocos)
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │      AUDITOR (SECUENCIAL - CDP)     │
                    │   Rápido porque recibe pocos        │
                    └─────────────────┬───────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │     REPORTER (DESACOPLADO)          │
                    │   Puede tardar, no bloquea          │
                    └─────────────────────────────────────┘
```

---

## 10. Preguntas para Gemini

Antes de implementar, confirma:

1. ¿Hay tests unitarios que deba actualizar?
2. ¿Hay otros agentes que usen el mismo patrón (RCE, XXE)?
3. ¿El AgenticValidator maneja correctamente ambos status?
4. ¿El `process_result` es thread-safe? (debería serlo si solo hace DB writes)

---

**Firma**: Claude (Opus 4.5) - TechLead
**Fecha**: 2026-01-17
**Confianza**: 9/10
