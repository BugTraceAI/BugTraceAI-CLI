# 🔧 HANDOFF: Mejoras del Framework - Detección y Reporte de CSTI/SSTI

**Fecha:** 2026-01-24  
**Autor:** Albert (revisión de calidad de reportes)  
**Prioridad:** CRITICAL  
**Tipo:** Bug Fix + Mejora de Framework  
**Componentes afectados:** `CSTIAgent`, `AgenticValidator`, `ReportGenerator`

---

## 📋 Resumen Ejecutivo

Durante la revisión del reporte de `ginandjuice.shop` se detectó un **error grave** en el finding de CSTI: la vulnerabilidad reportada **no es reproducible** porque los datos del finding (URL, parámetro, payload) **no corresponden** con la ubicación real de la vulnerabilidad.

**Impacto:** Un triager que intente reproducir el CSTI con los datos del reporte **NUNCA** podrá confirmarlo, lo que genera:
- Pérdida de confianza en BugTraceAI
- Vulnerabilidad real ignorada (falso negativo percibido)
- Tiempo desperdiciado en debugging

---

## 🔍 Análisis de Root Cause

### El Finding Reportado:

```json
{
  "type": "CSTI",
  "url": "https://ginandjuice.shop/catalog?category=Juice",
  "parameter": "searchTerm",
  "payload": "<%= 7*7 %>",
  "description": "Template Injection vulnerability detected. Expression '<%= 7*7 %>' was evaluated by the server/client engine. Method: llm_smart_analysis."
}
```

### La Realidad Verificada:

| Campo | En Reporte | Realidad | Error |
|-------|------------|----------|-------|
| **URL** | `/catalog?category=Juice` | `/blog/?search={{7*7}}` | ❌ **Página incorrecta** |
| **Parámetro** | `searchTerm` | `search` | ❌ **Nombre incorrecto** |
| **Payload** | `<%= 7*7 %>` (EJS/ERB) | `{{7*7}}` (AngularJS) | ❌ **Tipo de template incorrecto** |
| **Motor** | "server/client engine" | AngularJS (solo cliente) | ❌ **Motor incorrecto** |

### Evidencia Visual:

1. **`/catalog?searchTerm=<%= 7*7 %>`** → Muestra `&lt;%= 7*7 %&gt;` (escapado, NO evalúa)
2. **`/catalog?searchTerm={{7*7}}`** → Muestra `{{7*7}}` (literal, NO evalúa)  
3. **`/blog/?search={{7*7}}`** → Muestra `49` en el input ✅ (SÍ evalúa)

---

## 🐛 Root Cause en el Código

### Problema 1: El agente prueba en una URL pero el LLM "alucina" otra

En `csti_agent.py` línea ~570-635, la función `_llm_smart_template_analysis()`:

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
    # ...
    user_prompt = f"""Analyze this page for Template Injection:
URL: {self.url}                    # ← Pasa la URL base
Parameter: {param}                  # ← Pasa el parámetro actual
Detected Engines: {detected_engines}
HTML (truncated):
{html[:6000]}                       # ← Pasa HTML truncado
```

**El problema:** El LLM ve HTML que menciona Angular y genera payloads EJS/ERB sin verificar que esos payloads específicos funcionan en la URL/parámetro dados.

### Problema 2: `_create_finding()` usa `self.url` sin modificar

En línea ~871-891:

```python
def _create_finding(self, param: str, payload: str, method: str) -> Dict:
    return {
        "type": "CSTI",
        "url": self.url,              # ← Siempre usa la URL base del agente
        "parameter": param,           # ← Usa el param que se le pasó
        "payload": payload,
        # ...
    }
```

**El problema:** Si el escaneo empezó en `/catalog` pero la vulnerabilidad real está en `/blog`, el finding reporta `/catalog`.

### Problema 3: No se verifica que el payload REALMENTE funciona en la respuesta

El método `_test_payload()` verifica si "49" está en la respuesta:

```python
if "49" in content:
    if "7*7" in payload:
        if payload not in content:
            return content              # ← Asume éxito
```

**El problema:** Si hay un "49" en cualquier parte de la página (ej: un price "$49.99"), esto puede dar falsos positivos. No hay verificación estricta de contexto.

### Problema 4: El `description` dice que el payload fue evaluado sin prueba

```python
"description": f"Template Injection vulnerability detected. Expression '{payload}' was evaluated by the server/client engine."
```

**El problema:** Esta descripción se genera aunque:
- El payload sea EJS (`<%= %>`) pero el motor sea Angular (`{{ }}`)
- El payload no se haya ejecutado realmente en esa URL

---

## ✅ Mejoras Propuestas

### 1. Verificación Estricta de Evaluación de Template

```python
# bugtrace/agents/csti_agent.py

async def _test_payload(self, session, param, payload) -> Optional[str]:
    """Verify template expression was ACTUALLY evaluated."""
    target_url = self._inject(param, payload)
    
    async with session.get(target_url, timeout=5) as resp:
        content = await resp.text()
        
        # STRICT CHECK: For arithmetic payloads
        if "7*7" in payload and "49" in content:
            # CRITICAL: Verify 49 is NOT in the original page
            baseline_content = await self._get_baseline_content(session)
            if "49" not in baseline_content:
                # "49" appeared ONLY after injection = confirmed
                return VerificationResult(
                    confirmed=True,
                    actual_url=target_url,  # Store the ACTUAL tested URL
                    evidence="49 appeared in response after injecting 7*7"
                )
            else:
                # "49" was already there, need different verification
                return None
```

### 2. El Finding debe incluir la URL EXACTA donde funciona

```python
def _create_finding(
    self, 
    param: str, 
    payload: str, 
    method: str,
    verified_url: str,           # NEW: La URL donde REALMENTE funcionó
    detected_engine: str          # NEW: El motor detectado
) -> Dict:
    return {
        "type": "CSTI",
        "url": verified_url,      # ← Usar URL verificada, no self.url
        "parameter": param,
        "payload": payload,
        "template_engine": detected_engine,  # NEW
        "description": self._generate_accurate_description(payload, detected_engine),
        # ...
    }

def _generate_accurate_description(self, payload: str, engine: str) -> str:
    """Generate description that matches the actual payload type."""
    if "{{" in payload:
        return f"AngularJS/Vue Client-Side Template Injection detected. Expression '{payload}' was evaluated by the AngularJS/Vue template engine."
    elif "<%" in payload:
        return f"ERB/EJS Server-Side Template Injection detected. Expression '{payload}' was evaluated by the server."
    elif "${" in payload:
        return f"FreeMarker/Mako Server-Side Template Injection detected."
    # etc.
```

### 3. Identificar motor ANTES de generar payloads

```python
# Nuevo flujo en run_loop():

async def run_loop(self):
    # 1. Fingerprint de motor PRIMERO
    engines = await self._detect_template_engines()
    
    # 2. Solo generar payloads para motores detectados
    if "angular" in engines:
        payloads = PAYLOAD_LIBRARY["angular"]
    elif "vue" in engines:
        payloads = PAYLOAD_LIBRARY["vue"]
    # etc.
    
    # 3. NO usar payloads de otros motores
    # NO mezclar <%= %> con {{ }} en el mismo finding
```

### 4. Verificación cruzada de URL/Parámetro

```python
async def _verify_injection_location(
    self, 
    session, 
    payload: str,
    suspected_url: str,
    suspected_param: str
) -> Optional[VerifiedLocation]:
    """
    Verify that the injection actually works at the claimed location.
    If not, search for where it DOES work.
    """
    # Test claimed location
    result = await self._test_at_location(session, suspected_url, suspected_param, payload)
    if result.success:
        return VerifiedLocation(url=suspected_url, param=suspected_param)
    
    # If claimed location fails, try to find real location
    # This prevents reporting wrong URL/param
    logger.warning(f"Payload {payload} failed at {suspected_url}?{suspected_param}")
    
    # Maybe the vulnerability is on a different page/param
    alternative_locations = await self._discover_alternative_injection_points(session, payload)
    if alternative_locations:
        return alternative_locations[0]
    
    # If we can't find where it works, DON'T report it
    return None
```

### 5. El reporte debe mostrar el motor de template correcto

```python
# bugtrace/reporting/report_generator.py

def render_csti_finding(finding: Dict) -> str:
    engine = finding.get("template_engine", "unknown")
    
    engine_info = {
        "angular": {
            "name": "AngularJS",
            "type": "Client-Side (CSTI)",
            "icon": "🅰️",
            "explanation": "Executes in the user's browser via AngularJS expression parser"
        },
        "erb": {
            "name": "ERB (Ruby)",
            "type": "Server-Side (SSTI)",
            "icon": "💎",
            "explanation": "Executes on the server - can lead to RCE"
        }
        # etc.
    }
    
    return f"""
    <div class="finding csti">
        <h3>{engine_info[engine]['icon']} Template Injection - {engine_info[engine]['name']}</h3>
        <p class="engine-type">{engine_info[engine]['type']}</p>
        <p class="explanation">{engine_info[engine]['explanation']}</p>
        
        <section class="payload-match">
            <h4>Payload & Engine Match</h4>
            <table>
                <tr><th>Engine Detected</th><td>{engine}</td></tr>
                <tr><th>Payload Syntax</th><td>{get_syntax_type(finding['payload'])}</td></tr>
                <tr><th>Match</th><td>{'✅ Yes' if engine_matches_payload(engine, finding['payload']) else '⚠️ Mismatch'}</td></tr>
            </table>
        </section>
    </div>
    """
```

### 6. Agregar campo `verified_url` al schema de Finding

```python
# bugtrace/models/finding.py

class CSTIFinding(BaseFinding):
    type: str = "CSTI"
    
    # URLs
    original_url: str         # URL donde empezó el scan
    verified_url: str         # URL donde SE CONFIRMÓ la vulnerabilidad
    
    # Template engine
    template_engine: str      # "angular", "vue", "jinja2", etc.
    engine_version: Optional[str]  # "1.7.7" si se detectó
    template_type: str        # "client-side" o "server-side"
    
    # Payload
    payload: str
    payload_syntax: str       # "angular_expression", "erb", "jinja2", etc.
    payload_engine_match: bool  # True si el payload coincide con el motor
    
    # Verification
    arithmetic_proof: bool    # True si 7*7=49 fue verificado
    baseline_had_49: bool     # True si 49 ya estaba antes de inyectar
    
    # Reproduction
    exploit_url: str          # URL completa con payload
    exploit_url_encoded: str  # URL-encoded
    curl_command: str
```

---

## 📁 Archivos a Modificar

| Archivo | Cambio | Prioridad |
|---------|--------|-----------|
| `bugtrace/agents/csti_agent.py` | Verificación estricta, matching payload-engine | CRITICAL |
| `bugtrace/models/finding.py` | Agregar campos CSTIFinding | HIGH |
| `bugtrace/validators/agentic_validator.py` | Verificar URL real antes de confirmar | HIGH |
| `bugtrace/reporting/report_generator.py` | Mostrar motor correcto, advertir mismatches | MEDIUM |

---

## 🎯 Criterios de Aceptación

### Verificación de Payload-Motor:
- [ ] El finding solo reporta payloads que COINCIDEN con el motor detectado
- [ ] Payloads EJS/ERB (`<%= %>`) NO se reportan si el motor es Angular/Vue
- [ ] Payloads Angular (`{{ }}`) NO se reportan si el motor es Jinja2/Twig

### Verificación de URL:
- [ ] El campo `url` del finding es la URL donde SE VERIFICÓ la inyección
- [ ] No se reporta una URL diferente a donde realmente funciona
- [ ] Se hace test de baseline para evitar falsos positivos de "49"

### Reproducibilidad:
- [ ] Un triager puede copiar la URL del reporte y ver "49" en la respuesta
- [ ] El motor reportado coincide con la tecnología real del sitio
- [ ] El payload tiene la sintaxis correcta para ese motor

---

## 📊 Flujo de Detección Mejorado

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. FINGERPRINT                                                  │
│    Detectar motor: ng-app="..." → Angular                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. SELECT PAYLOADS                                              │
│    Si Angular → Usar solo {{ }} payloads                        │
│    Si Jinja2 → Usar solo {{ }} y {% %} payloads                 │
│    Si ERB → Usar solo <%= %> payloads                           │
│    ❌ NO mezclar tipos                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. BASELINE CHECK                                               │
│    GET /page sin payload → ¿Tiene "49" ya?                      │
│    Si tiene 49 → Usar payload diferente (ej: {{8*8}}=64)        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. INJECTION TEST                                               │
│    GET /page?param={{7*7}} → ¿Tiene "49" ahora?                 │
│    Si apareció 49 → CONFIRMED                                   │
│    Si ya tenía 49 → INCONCLUSIVE                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. CREATE FINDING                                               │
│    url = URL donde se CONFIRMO (no self.url)                    │
│    template_engine = Motor DETECTADO                            │
│    payload_engine_match = True/False                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Errores Específicos a Corregir

### Error 1: URL incorrecta
**Causa:** `_create_finding()` usa `self.url` que es la URL inicial, no donde se verificó.
**Fix:** Pasar `verified_url` como parámetro a `_create_finding()`.

### Error 2: Parámetro incorrecto
**Causa:** El parámetro viene del scan inicial, no se verifica que sea el correcto.
**Fix:** Verificar que el parámetro existe en la URL donde funciona.

### Error 3: Payload incorrecto
**Causa:** LLM genera payloads basados en HTML pero inesperado para el motor.
**Fix:** Filtrar payloads por motor antes de probar.

### Error 4: Tipo de motor incorrecto
**Causa:** Descripción dice "server/client engine" sin especificar.
**Fix:** Detectar y reportar el motor específico (Angular, Jinja2, etc.).

---

## 🔗 Evidencia del Bug

- **Reporte original:** `reports/ginandjuice.shop_20260124_210845/validated_findings.json`
- **Finding ID:** 6
- **URL reportada:** `/catalog?searchTerm=<%= 7*7 %>`
- **URL real vulnerable:** `/blog/?search={{7*7}}`
- **Screenshots de verificación:** 
  - `csti_catalog_ejs_*.png` - Muestra payload escapado (NO funciona)
  - `csti_catalog_angular_*.png` - Muestra payload literal (NO funciona)
  - `csti_blog_angular_*.png` - Muestra "49" (SÍ funciona)

---

**Status:** 🔴 BUG CRÍTICO - Requiere fix antes de v2.1
