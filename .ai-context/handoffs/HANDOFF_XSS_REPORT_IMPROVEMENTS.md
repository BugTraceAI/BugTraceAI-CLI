# 🔧 HANDOFF: Mejoras del Framework - Reportes de XSS

**Fecha:** 2026-01-24  
**Autor:** Albert (revisión de calidad de reportes)  
**Prioridad:** HIGH  
**Tipo:** Mejora de Framework  
**Componentes afectados:** `XSSAgent`, `ReportGenerator`, `AgenticValidator`, `Finding` schema

---

## 📋 Resumen Ejecutivo

Los reportes de vulnerabilidades XSS generados por BugTraceAI no proporcionan suficiente contexto técnico para que un triager pueda **entender, verificar y reproducir** la vulnerabilidad. Esta mejora propone enriquecer el pipeline de XSS para incluir análisis de contexto de inyección, técnicas de bypass, y múltiples métodos de verificación.

---

## ❌ Problema Actual

### 1. Falta contexto de inyección

El reporte muestra el payload pero NO muestra dónde se inyecta:
```
Payload: \';alert(document.cookie);//
```

Sin saber que el contexto es:
```html
<script>var searchText = '[INJECTION]';</script>
```

El triager no puede entender POR QUÉ funciona el payload.

### 2. Falta explicación del bypass

El payload incluye un backslash inicial pero no explica que:
- El servidor escapa `'` → `\'`
- Pero NO escapa `\` → `\`
- Por lo tanto `\'` del usuario + `\'` del servidor = `\\'` (backslash literal + quote libre)

### 3. Dependencia de `alert()` para verificación

El framework usa `alert()` como prueba de ejecución, pero:
- Navegadores modernos bloquean popups automáticos
- Extensions de seguridad bloquean `alert()`
- CSP puede bloquear inline scripts

El triager prueba, no ve alert, y asume falso positivo.

### 4. Sin URL lista para usar

No hay URL clickeable con el payload ya URL-encoded.

---

## ✅ Mejora Propuesta

### 1. Extender el Schema de Finding para XSS

```python
# bugtrace/models/finding.py

class XSSFinding(BaseFinding):
    # Campos existentes
    type: str = "XSS"
    url: str
    parameter: str
    severity: str
    payload: str
    
    # NUEVOS CAMPOS REQUERIDOS
    xss_type: str                          # "reflected", "stored", "dom-based"
    
    # Contexto de inyección
    injection_context: str                 # "html_attribute", "javascript_string", "html_body", etc.
    vulnerable_code_snippet: str           # El código donde se inyecta
    reflection_point: str                  # Descripción de dónde aparece el input
    
    # Análisis de escaping
    server_escaping: Dict[str, bool]       # {"escapes_quotes": True, "escapes_backslashes": False}
    escape_bypass_technique: str           # "backslash_prefix", "unicode_encoding", etc.
    bypass_explanation: str                # Explicación humana del bypass
    
    # URLs de explotación
    exploit_url: str                       # URL con payload (raw)
    exploit_url_encoded: str               # URL con payload (URL-encoded)
    
    # Múltiples métodos de verificación
    verification_methods: List[Dict]       # Lista de métodos alternativos
    # Ejemplo:
    # [
    #   {"type": "console_log", "url": "...", "expected": "Check console for 'XSS'"},
    #   {"type": "dom_modification", "url": "...", "expected": "Page shows 'HACKED'"},
    #   {"type": "window_variable", "url": "...", "expected": "window.XSS === true"},
    #   {"type": "alert", "url": "...", "expected": "Alert popup (may be blocked)"}
    # ]
    
    # Reproducción
    reproduction_steps: List[str]
    curl_command: str
    
    # Warnings
    verification_warnings: List[str]       # ["alert() may be blocked by browser", ...]
```

### 2. Modificar XSSAgent para analizar contexto

```python
# bugtrace/agents/xss_agent.py

class XSSAgent:
    async def analyze(self, target_url: str, parameter: str, reflected_content: str) -> XSSFinding:
        # 1. Detectar contexto de inyección
        context = self.detect_injection_context(reflected_content)
        
        # 2. Analizar qué escapa el servidor
        escaping = await self.analyze_server_escaping(target_url, parameter)
        
        # 3. Determinar técnica de bypass
        bypass = self.determine_bypass_technique(context, escaping)
        
        # 4. Generar payload óptimo
        payload = self.generate_optimal_payload(context, escaping, bypass)
        
        # 5. Generar múltiples métodos de verificación
        verification_methods = self.generate_verification_methods(
            target_url, parameter, context, payload
        )
        
        return XSSFinding(
            url=target_url,
            parameter=parameter,
            payload=payload,
            xss_type=self.detect_xss_type(target_url, parameter),
            injection_context=context.type,
            vulnerable_code_snippet=context.code_snippet,
            server_escaping=escaping,
            escape_bypass_technique=bypass.technique,
            bypass_explanation=bypass.human_explanation,
            verification_methods=verification_methods,
            verification_warnings=self.get_verification_warnings(context),
            exploit_url=self.build_exploit_url(target_url, parameter, payload),
            exploit_url_encoded=urllib.parse.quote(exploit_url),
            reproduction_steps=self.generate_repro_steps(target_url, parameter, context, payload)
        )
    
    def detect_injection_context(self, html: str) -> InjectionContext:
        """
        Detectar dónde se refleja el input del usuario:
        - html_body: <div>USER_INPUT</div>
        - html_attribute: <input value="USER_INPUT">
        - javascript_string: var x = 'USER_INPUT';
        - javascript_template: `${USER_INPUT}`
        - html_comment: <!-- USER_INPUT -->
        - url_context: href="USER_INPUT"
        """
        contexts = [
            ("javascript_string", r"var\s+\w+\s*=\s*'[^']*USER_INPUT[^']*'"),
            ("javascript_string", r'var\s+\w+\s*=\s*"[^"]*USER_INPUT[^"]*"'),
            ("html_attribute", r'<\w+[^>]+\w+=["\'][^"\']*USER_INPUT'),
            ("html_body", r'>USER_INPUT<'),
            # ... más patrones
        ]
        
        for context_type, pattern in contexts:
            if re.search(pattern, html):
                return InjectionContext(type=context_type, ...)
    
    def analyze_server_escaping(self, url: str, param: str) -> Dict:
        """
        Enviar caracteres de prueba y ver qué escapa el servidor:
        - ' (single quote)
        - " (double quote)
        - \ (backslash)
        - < > (angle brackets)
        - / (forward slash)
        """
        test_chars = {
            "single_quote": "'",
            "double_quote": '"',
            "backslash": "\\",
            "lt": "<",
            "gt": ">",
        }
        
        escaping_results = {}
        for name, char in test_chars.items():
            response = await self.send_request(url, {param: f"TEST{char}TEST"})
            reflected = self.find_reflection(response, f"TEST{char}TEST")
            escaping_results[f"escapes_{name}"] = (char not in reflected)
        
        return escaping_results
    
    def generate_verification_methods(self, url, param, context, payload) -> List[Dict]:
        """
        Generar múltiples métodos de verificación para que el triager
        pueda confirmar aunque alert() esté bloqueado
        """
        methods = []
        
        # Método 1: Console.log (más confiable)
        console_payload = payload.replace("alert(1)", 'console.log("XSS-VERIFIED")')
        methods.append({
            "type": "console_log",
            "name": "Console Log (Recommended)",
            "payload": console_payload,
            "url": self.build_url(url, param, console_payload),
            "url_encoded": urllib.parse.quote(...),
            "instructions": "Open DevTools (F12) → Console tab → Look for 'XSS-VERIFIED'",
            "reliability": "high"
        })
        
        # Método 2: Modificación de DOM
        dom_payload = payload.replace("alert(1)", 'document.body.innerHTML="<h1>XSS-HACKED</h1>"')
        methods.append({
            "type": "dom_modification",
            "name": "DOM Modification",
            "payload": dom_payload,
            "url": self.build_url(url, param, dom_payload),
            "url_encoded": urllib.parse.quote(...),
            "instructions": "Page content will be replaced with 'XSS-HACKED'",
            "reliability": "high"
        })
        
        # Método 3: Variable global
        var_payload = payload.replace("alert(1)", 'window.XSS_CONFIRMED=true')
        methods.append({
            "type": "window_variable",
            "name": "Window Variable",
            "payload": var_payload,
            "url": self.build_url(url, param, var_payload),
            "url_encoded": urllib.parse.quote(...),
            "instructions": "In console, type: window.XSS_CONFIRMED (should return true)",
            "reliability": "high"
        })
        
        # Método 4: Alert (puede estar bloqueado)
        methods.append({
            "type": "alert",
            "name": "Alert Popup",
            "payload": payload,
            "url": self.build_url(url, param, payload),
            "url_encoded": urllib.parse.quote(...),
            "instructions": "Alert popup should appear",
            "reliability": "medium",
            "warning": "May be blocked by modern browsers or extensions"
        })
        
        return methods
```

### 3. Modificar AgenticValidator para verificación robusta

```python
# bugtrace/validators/agentic_validator.py

class XSSValidator:
    async def validate_xss(self, finding: XSSFinding) -> ValidationResult:
        """
        Verificar XSS usando múltiples métodos, no solo alert()
        """
        # Método primario: console.log (no se bloquea)
        for method in finding.verification_methods:
            if method["type"] == "console_log":
                result = await self.verify_via_console(method["url"])
                if result.confirmed:
                    return ValidationResult(
                        status="VALIDATED_CONFIRMED",
                        method_used="console_log",
                        evidence=result.console_output
                    )
        
        # Fallback: variable global
        for method in finding.verification_methods:
            if method["type"] == "window_variable":
                result = await self.verify_via_window_var(method["url"])
                if result.confirmed:
                    return ValidationResult(
                        status="VALIDATED_CONFIRMED",
                        method_used="window_variable",
                        evidence=f"window.XSS_CONFIRMED = {result.value}"
                    )
        
        # Último recurso: alert (puede fallar)
        # ...
    
    async def verify_via_console(self, url: str) -> ConsoleResult:
        """
        Navegar a URL y verificar si aparece el mensaje en console.log
        """
        await self.page.goto(url)
        logs = await self.page.get_console_logs()
        
        if "XSS-VERIFIED" in logs:
            # Tomar screenshot como evidencia
            screenshot_path = await self.capture_screenshot("xss_console_proof")
            return ConsoleResult(confirmed=True, console_output=logs, screenshot=screenshot_path)
        
        return ConsoleResult(confirmed=False)
```

### 4. Modificar ReportGenerator para mostrar contexto completo

```python
# bugtrace/reporting/report_generator.py

def render_xss_finding(finding: XSSFinding) -> str:
    return f"""
    <div class="finding xss">
        <header>
            <span class="badge critical">CRITICAL</span>
            <span class="badge">{finding.xss_type.upper()}</span>
            <h3>Cross-Site Scripting - {finding.parameter}</h3>
        </header>
        
        <section class="injection-context">
            <h4>Injection Context</h4>
            <p>User input is reflected in: <strong>{finding.injection_context}</strong></p>
            <pre class="code-snippet">{escape_html(finding.vulnerable_code_snippet)}</pre>
        </section>
        
        <section class="escaping-analysis">
            <h4>Server Escaping Analysis</h4>
            <table>
                <tr>
                    <th>Character</th>
                    <th>Escaped?</th>
                </tr>
                {render_escaping_table(finding.server_escaping)}
            </table>
            
            <div class="bypass-explanation">
                <h5>Bypass Technique: {finding.escape_bypass_technique}</h5>
                <p>{finding.bypass_explanation}</p>
            </div>
        </section>
        
        <section class="verification">
            <h4>Verification Methods</h4>
            
            {render_verification_warnings(finding.verification_warnings)}
            
            <div class="methods-grid">
                {render_verification_methods(finding.verification_methods)}
            </div>
        </section>
        
        <section class="payload">
            <h4>Working Payload</h4>
            <pre>{finding.payload}</pre>
            
            <div class="exploit-buttons">
                <a href="{finding.exploit_url_encoded}" target="_blank" class="btn">🔗 Open Exploit</a>
                <button onclick="copyToClipboard('{finding.exploit_url_encoded}')">📋 Copy URL</button>
            </div>
        </section>
        
        <section class="reproduction">
            <h4>Steps to Reproduce</h4>
            <ol>
                {''.join(f'<li>{step}</li>' for step in finding.reproduction_steps)}
            </ol>
        </section>
    </div>
    """

def render_verification_warnings(warnings: List[str]) -> str:
    if not warnings:
        return ""
    return f"""
    <div class="warnings">
        <strong>⚠️ Verification Notes:</strong>
        <ul>
            {''.join(f'<li>{w}</li>' for w in warnings)}
        </ul>
    </div>
    """

def render_verification_methods(methods: List[Dict]) -> str:
    html = ""
    for method in methods:
        reliability_class = f"reliability-{method['reliability']}"
        warning = f'<span class="warning">⚠️ {method["warning"]}</span>' if method.get("warning") else ""
        
        html += f"""
        <div class="verification-method {reliability_class}">
            <h5>{method['name']}</h5>
            <p>{method['instructions']}</p>
            <a href="{method['url_encoded']}" target="_blank" class="btn-small">🔗 Test</a>
            <button onclick="copyToClipboard('{method['url_encoded']}')" class="btn-small">📋 Copy</button>
            {warning}
        </div>
        """
    return html
```

---

## 📁 Archivos a Modificar

| Archivo | Cambio |
|---------|--------|
| `bugtrace/models/finding.py` | Agregar campos XSS-specific al schema |
| `bugtrace/agents/xss_agent.py` | Detectar contexto, analizar escaping, generar métodos de verificación |
| `bugtrace/validators/agentic_validator.py` | Usar console.log como método primario |
| `bugtrace/reporting/report_generator.py` | Renderizar contexto, escaping, y múltiples verificaciones |
| `bugtrace/reporting/templates/report.html` | Template para sección XSS expandida |

---

## 🎯 Criterios de Aceptación (Para CUALQUIER escaneo)

- [ ] Todo finding XSS identifica el **contexto de inyección** (JS string, HTML attr, etc.)
- [ ] Todo finding XSS analiza **qué caracteres escapa el servidor**
- [ ] Si hay bypass, se explica la **técnica de bypass** en lenguaje humano
- [ ] Se proporcionan **múltiples métodos de verificación** (no solo alert)
- [ ] Hay **advertencia** cuando alert() puede estar bloqueado
- [ ] Hay **URLs clickeables** listas para probar cada método
- [ ] El validador usa **console.log como método primario** (más confiable que alert)
- [ ] El screenshot muestra **evidencia de ejecución real** (no depender de alert)
- [ ] Un triager puede **verificar en < 1 minuto** usando cualquier método

---

## 📊 Template de Reporte Mejorado

```
┌─────────────────────────────────────────────────────────────────┐
│ CROSS-SITE SCRIPTING (XSS)                       CRITICAL 9.8   │
│ Type: [Reflected | Stored | DOM-based]                          │
├─────────────────────────────────────────────────────────────────┤
│ Target: [URL]                                                   │
│ Parameter: [param_name]                                         │
│ Injection Context: [javascript_string | html_attribute | ...]   │
├─────────────────────────────────────────────────────────────────┤
│ VULNERABLE CODE:                                                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ <script>                                                    │ │
│ │   var searchText = '[INJECTION_POINT]';  ◄── HERE           │ │
│ │ </script>                                                   │ │
│ └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ SERVER ESCAPING ANALYSIS:                                       │
│ ┌──────────────────────┬─────────┬────────────────────────────┐ │
│ │ Character            │ Escaped │ Implication                │ │
│ ├──────────────────────┼─────────┼────────────────────────────┤ │
│ │ Single quote (')     │ ✅ Yes  │ ' → \'                     │ │
│ │ Double quote (")     │ ✅ Yes  │ " → \"                     │ │
│ │ Backslash (\)        │ ❌ No   │ VULNERABLE!                │ │
│ │ Angle brackets (<>)  │ ✅ Yes  │ < → &lt;                   │ │
│ └──────────────────────┴─────────┴────────────────────────────┘ │
│                                                                 │
│ BYPASS TECHNIQUE: Backslash Prefix                              │
│ Input \' + Server escape \' = \\' (literal \ + free quote)      │
├─────────────────────────────────────────────────────────────────┤
│ VERIFICATION METHODS:                                           │
│ ⚠️ Note: alert() may be blocked by modern browsers              │
│                                                                 │
│ ┌─────────────────────┐ ┌─────────────────────┐                │
│ │ ✅ Console Log      │ │ ✅ DOM Modification │                │
│ │ (Recommended)       │ │                     │                │
│ │ [🔗 Test] [📋 Copy] │ │ [🔗 Test] [📋 Copy] │                │
│ └─────────────────────┘ └─────────────────────┘                │
│ ┌─────────────────────┐ ┌─────────────────────┐                │
│ │ ✅ Window Variable  │ │ ⚠️ Alert Popup      │                │
│ │                     │ │ (may be blocked)    │                │
│ │ [🔗 Test] [📋 Copy] │ │ [🔗 Test] [📋 Copy] │                │
│ └─────────────────────┘ └─────────────────────┘                │
├─────────────────────────────────────────────────────────────────┤
│ [📷 Screenshot: Console showing "XSS-VERIFIED" message]         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Caso de Descubrimiento

Esta mejora fue identificada durante la revisión del reporte de `ginandjuice.shop` (24/01/2026), donde:
- El triager probó el payload y no vio ningún alert
- Después de investigación profunda, se descubrió que el XSS SÍ funcionaba
- El problema era que `alert()` estaba bloqueado y no había métodos alternativos
- El reporte no explicaba la técnica de bypass necesaria para entender el payload

---

**Status:** 🟡 PENDIENTE DE IMPLEMENTACIÓN
