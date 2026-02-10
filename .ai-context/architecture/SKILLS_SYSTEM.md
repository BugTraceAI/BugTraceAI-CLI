# Skills System - Conocimiento Especializado por Vulnerabilidad

> **Versión**: 1.0.0
> **Fecha**: 2026-02-02
> **Componente**: `bugtrace.agents.skills`

---

## Overview

El **Skills System** es un módulo de conocimiento especializado que proporciona información técnica detallada sobre cada tipo de vulnerabilidad a los agentes de análisis. En lugar de tener todo el conocimiento en los prompts (lo cual consume muchos tokens), las skills se cargan **dinámicamente** solo cuando se detecta un tipo específico de vulnerabilidad.

### 🎯 Objetivo

**Enriquecer el análisis de LLMs** con conocimiento experto sin saturar el contexto:
- ✅ Cargar solo las skills relevantes (ej: XSS skill solo cuando hay sospecha de XSS)
- ✅ Proporcionar guías de scoring específicas por vulnerabilidad
- ✅ Documentar patrones de false positives conocidos
- ✅ Incluir payloads y técnicas de bypass
- ✅ Reducir el uso de tokens (solo 2-3 skills por request vs todo el conocimiento)

---

## Arquitectura

### Ubicación de Archivos

```
bugtrace/agents/skills/
├── loader.py                    # Lógica de carga dinámica
├── __init__.py
├── vulnerabilities/             # Skills por tipo de vulnerabilidad
│   ├── xss.md                   # Cross-Site Scripting
│   ├── sqli.md                  # SQL Injection
│   ├── ssrf.md                  # Server-Side Request Forgery
│   ├── xxe.md                   # XML External Entity
│   ├── rce.md                   # Remote Code Execution
│   ├── lfi.md                   # Local File Inclusion
│   ├── idor.md                  # Insecure Direct Object Reference
│   └── jwt.md                   # JWT vulnerabilities
├── frameworks.md                # Conocimiento de frameworks
├── jwt.md                       # JWT standalone
└── vulnerabilities.md           # Overview general
```

### Herramientas del Skills System

El Skills System utiliza herramientas especializadas para explotación:

**ManipulatorOrchestrator** ([bugtrace/tools/manipulator/orchestrator.py](../../bugtrace/tools/manipulator/orchestrator.py))
- **Usado por:** XSSSkill, CSTISkill
- **Propósito:** HTTP manipulation con context detection, LLM expansion, y auto-learning
- **Características:**
  - Context-aware payload testing (13 tipos de reflexión detectados)
  - LLM expansion con DeepSeek (100 base payloads → ~1,000 variaciones)
  - Intelligent breakout selection basado en contexto
  - Auto-learning de breakouts exitosos
- **Documentación:** [INTELLIGENT_BREAKOUTS.md](INTELLIGENT_BREAKOUTS.md)

**Otras herramientas por skill:**
- SQLiSkill → SQLMap (herramienta externa authoritative)
- SSRFSkill → Interactsh (OOB validation)
- RCE/LFI/XXE → Lógica específica integrada

---

## Estructura de una Skill

Cada skill es un archivo Markdown con secciones estructuradas usando **comentarios HTML** para facilitar la extracción programática:

```markdown
# SKILL: [VULNERABILITY NAME]

<!-- critical -->
Descripción breve del riesgo crítico
<!-- /critical -->

## 1. SCOPE - Dónde Buscar
<!-- scope -->
- Parámetros típicos
- Headers
- Paths
<!-- /scope -->

## 2. METHODOLOGY
<!-- methodology -->
1. IDENTIFY
2. CONTEXT
3. PAYLOAD
4. BYPASS
5. VALIDATION
<!-- /methodology -->

## 3. KNOWLEDGE BASE
<!-- knowledge -->
- Contextos de inyección
- Técnicas de bypass
- CSP bypass
<!-- /knowledge -->

## 4. SCORING GUIDE
<!-- scoring_guide -->
| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| 9-10 | CONFIRMED | Ejecución confirmada |
| 7-8 | HIGH | Reflexión sin escape |
| 5-6 | MEDIUM | Reflexión parcial |
| 3-4 | LOW | Reflexión escapada |
| 0-2 | REJECT | Falso positivo |
<!-- /scoring_guide -->

## 5. FALSE POSITIVES
<!-- false_positives -->
RECHAZAR INMEDIATAMENTE:
1. Condición FP #1
2. Condición FP #2
<!-- /false_positives -->

## 6. PAYLOADS
<!-- payloads -->
### HIGH VALUE
```html
<payload examples>
```
<!-- /payloads -->

## 7. PRO TIPS
<!-- pro_tips -->
1. Tip #1
2. Tip #2
<!-- /pro_tips -->
```

---

## API del Loader

### Funciones Principales

**Archivo**: `bugtrace/agents/skills/loader.py`

#### 1. `get_skill_content(vuln_type: str) -> Optional[str]`

Carga el contenido completo de una skill basándose en el tipo de vulnerabilidad.

```python
from bugtrace.agents.skills.loader import get_skill_content

# Cargar skill completa
xss_skill = get_skill_content("XSS")
sqli_skill = get_skill_content("SQL Injection")
ssrf_skill = get_skill_content("Server-Side Request Forgery")
```

**Mapeo de Keywords**:
```python
SKILL_MAP = {
    "ssrf": "ssrf.md",
    "server-side request": "ssrf.md",
    "sqli": "sqli.md",
    "sql injection": "sqli.md",
    "sql": "sqli.md",
    "xxe": "xxe.md",
    "xml external": "xxe.md",
    "xss": "xss.md",
    "cross-site scripting": "xss.md",
    "rce": "rce.md",
    "remote code": "rce.md",
    "command injection": "rce.md",
    "lfi": "lfi.md",
    "path traversal": "lfi.md",
    "local file": "lfi.md",
    "idor": "idor.md",
    "insecure direct": "idor.md",
    "jwt": "jwt.md",
    "token": "jwt.md",
}
```

#### 2. `get_skills_for_findings(findings: List[dict], max_skills: int = 3) -> str`

Carga skills relevantes para una lista de findings, **deduplicando** para evitar cargar la misma skill múltiples veces.

```python
from bugtrace.agents.skills.loader import get_skills_for_findings

findings = [
    {"type": "XSS", "parameter": "search"},
    {"type": "XSS (Reflected)", "parameter": "name"},
    {"type": "SQL Injection", "parameter": "id"},
]

# Carga máximo 3 skills (en este caso: XSS + SQLi)
skills_content = get_skills_for_findings(findings, max_skills=3)
```

**Características**:
- ✅ Deduplicación automática (no carga XSS dos veces)
- ✅ Límite configurable (default: 3 skills máximo)
- ✅ Salida concatenada con separadores `---`

#### 3. `get_scoring_guide(vuln_type: str) -> str`

Extrae **solo la sección de scoring guide** de una skill.

```python
from bugtrace.agents.skills.loader import get_scoring_guide

xss_scoring = get_scoring_guide("XSS")
# Retorna:
# | Score | Criterio | Ejemplo |
# | 9-10 | CONFIRMED | alert(1) ejecutado |
# | 7-8 | HIGH | Reflexión sin escape |
# ...
```

#### 4. `get_false_positives(vuln_type: str) -> str`

Extrae **solo la sección de false positives** de una skill.

```python
from bugtrace.agents.skills.loader import get_false_positives

xss_fps = get_false_positives("XSS")
# Retorna:
# RECHAZAR INMEDIATAMENTE:
# 1. El script se ve como texto literal (&lt;script&gt;)
# 2. Self-XSS sin impacto real
# ...
```

---

## Uso en DASTySASTAgent

### 1. Carga durante Analysis Approaches

**Archivo**: `bugtrace/agents/analysis_agent.py:956-983`

Cuando el DASTySASTAgent ejecuta cada approach (pentester, bug_bounty, etc.), carga skills basadas en **findings previos** (si existen):

```python
async def _analyze_with_approach(self, context: Dict, approach: str) -> Dict:
    """Analyze with a specific persona."""
    # Cargar skills relevantes
    skill_context = self._approach_get_skill_context()

    # Construir prompt con skills incluidas
    user_prompt = self._approach_build_prompt(context, skill_context)

    # Enviar a LLM
    response = await llm_client.generate(
        prompt=user_prompt,
        system_prompt=self._get_system_prompt(approach),
        module_name="DASTySASTAgent",
        max_tokens=8000
    )

    return self._approach_parse_response(response)

def _approach_get_skill_context(self) -> str:
    """Get skill context for enrichment."""
    from bugtrace.agents.skills.loader import get_skills_for_findings

    # Si hay findings previos, cargar sus skills
    if hasattr(self, "_prior_findings") and self._prior_findings:
        return get_skills_for_findings(self._prior_findings, max_skills=2)
    return ""
```

**Flujo**:
```
1. DASTySASTAgent ejecuta approach 1 (pentester)
   └─> Sin findings previos → skill_context = ""

2. Approach 1 detecta: XSS, SQLi
   └─> _prior_findings = [{"type": "XSS"}, {"type": "SQLi"}]

3. DASTySASTAgent ejecuta approach 2 (bug_bounty)
   └─> Con findings previos → Carga XSS.md + SQLi.md
   └─> skill_context = "# XSS SKILL\n...\n---\n# SQLI SKILL\n..."

4. Approach 2 recibe contexto enriquecido con conocimiento especializado
```

### 2. Inyección en el Prompt

**Archivo**: `bugtrace/agents/analysis_agent.py:1035`

Las skills se añaden al prompt del LLM en la sección `SPECIALIZED KNOWLEDGE`:

```python
def _approach_build_prompt(self, context: Dict, skill_context: str) -> str:
    """Build analysis prompt with context and skills."""

    return f"""Analyze this URL for security vulnerabilities.

URL: {self.url}
Technology Stack: {self.tech_profile.get('frameworks', [])}

=== ACTIVE RECONNAISSANCE RESULTS ===
{probe_section}

=== PAGE HTML SOURCE ===
{context.get('html_content', '')[:8000]}

{f"=== SPECIALIZED KNOWLEDGE ==={chr(10)}{skill_context}{chr(10)}" if skill_context else ""}

OUTPUT FORMAT (XML):
<vulnerabilities>
  <vulnerability>...</vulnerability>
</vulnerabilities>
"""
```

**Ejemplo de Prompt Resultante**:
```
=== SPECIALIZED KNOWLEDGE ===

# SKILL: CROSS-SITE SCRIPTING (XSS)

XSS permite inyectar scripts maliciosos en páginas web...

## SCORING GUIDE
| Score | Criterio | Ejemplo |
| 9-10 | CONFIRMED | alert(1) ejecutado |
...

---

# SKILL: SQL INJECTION

SQL Injection permite manipular queries SQL...
```

### 3. Uso en Skeptical Review

**Archivo**: `bugtrace/agents/analysis_agent.py:1580-1593`

Durante el **Skeptical Review**, se cargan secciones específicas de las skills para cada finding:

```python
def _review_build_prompt(self, vulnerabilities: List[Dict]) -> str:
    """Build skeptical review prompt with enriched context."""
    from bugtrace.agents.skills.loader import get_scoring_guide, get_false_positives

    vulns_summary_parts = []
    for i, v in enumerate(vulnerabilities):
        vuln_type = v.get('type', 'Unknown')

        # Cargar guías específicas
        scoring_guide = get_scoring_guide(vuln_type)
        fp_guide = get_false_positives(vuln_type)

        part = f"""{i+1}. {vuln_type} on '{v.get('parameter')}'
   DASTySAST Score: {v.get('confidence_score', 5)}/10
   Reasoning: {v.get('reasoning')}

   {scoring_guide[:500] if scoring_guide else ''}
   {fp_guide[:300] if fp_guide else ''}"""

        vulns_summary_parts.append(part)

    return f"""Review these findings with skepticism...

    === FINDINGS ===
    {chr(10).join(vulns_summary_parts)}
    """
```

**Ventaja**: El Skeptical Agent recibe **criterios de scoring y FP patterns** específicos para cada vulnerabilidad, mejorando la precisión del filtrado.

---

## Extracción de Secciones

### Implementación Técnica

**Archivo**: `bugtrace/agents/skills/loader.py:117-140`

La función `_extract_section()` soporta dos formatos de tags:

```python
def _extract_section(content: str, tag_name: str) -> str:
    """
    Core extraction logic for skill sections.
    Supports:
    1. <!-- tag --> ... <!-- /tag --> (MD033 compliant)
    2. <tag> ... </tag> (Legacy/XML-like)
    """
    if not content:
        return ""

    # Pattern 1: Markdown comments (preferred)
    comment_pattern = rf"<!--\s*{tag_name}\s*-->(.*?)<!--\s*/{tag_name}\s*-->"
    match = re.search(comment_pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Pattern 2: XML-like tags (legacy)
    xml_pattern = rf"<{tag_name}>(.*?)</{tag_name}>"
    match = re.search(xml_pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return ""
```

### Secciones Extraíbles

| Sección | Tag | Uso |
|---------|-----|-----|
| **Scoring Guide** | `<!-- scoring_guide -->` | Criterios de confidence scoring |
| **False Positives** | `<!-- false_positives -->` | Patrones de FP conocidos |
| **Scope** | `<!-- scope -->` | Dónde buscar la vulnerabilidad |
| **Methodology** | `<!-- methodology -->` | Proceso de detección paso a paso |
| **Knowledge** | `<!-- knowledge -->` | Conocimiento técnico avanzado |
| **Payloads** | `<!-- payloads -->` | Payloads y técnicas de bypass |
| **Pro Tips** | `<!-- pro_tips -->` | Consejos expertos |
| **Critical** | `<!-- critical -->` | Descripción del riesgo crítico |

---

## Ejemplo Completo: XSS Skill

**Archivo**: `bugtrace/agents/skills/vulnerabilities/xss.md`

```markdown
# SKILL: CROSS-SITE SCRIPTING (XSS)

<!-- critical -->
XSS permite inyectar scripts maliciosos en páginas web vistas por otros usuarios.
Puede llevar al robo de sesiones (cookies), phishing, redirecciones maliciosas o defacement.
<!-- /critical -->

## 1. SCOPE - Dónde Buscar

<!-- scope -->
- **Parámetros de URL**: q=, name=, id=, redirect_url=, msg=
- **Formularios**: Comentarios, perfiles, mensajes, registro.
- **Headers**: User-Agent, Referer (si se muestran en logs o dashboards).
- **Paths**: `/blog/<script>...`
- **Fragmentos (DOM)**: `index.html#name=...`
<!-- /scope -->

## 4. SCORING GUIDE

<!-- scoring_guide -->

| Score | Criterio | Ejemplo |
| :--- | :--- | :--- |
| **9-10** | **CONFIRMED** - Ejecución de JS confirmada | `alert`, `prompt` o callback OOB ejecutado |
| **7-8** | **HIGH** - Reflexión sin escape en contexto ejecutable | `<script>`, `onerror`, `javascript:` sin filtrar |
| **5-6** | **MEDIUM** - Reflexión parcial o bloqueada por WAF | Caracteres `< >` permitidos pero etiquetas bloqueadas |
| **3-4** | **LOW** - Reflexión escapada o fuera de contexto | `&lt;script&gt;` visible como texto |
| **0-2** | **REJECT** - Falso positivo claro | No se refleja o "EXPECTED: SAFE" |

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
```

---

## Beneficios del Sistema de Skills

### 1. Eficiencia de Tokens

**Sin Skills** (enfoque tradicional):
```
Prompt para análisis XSS: 15,000 tokens
├─ Todo el conocimiento de XSS embebido en el prompt
├─ Conocimiento de SQLi (innecesario para este caso)
├─ Conocimiento de SSRF (innecesario)
└─ Total: 15,000 tokens por análisis
```

**Con Skills** (enfoque dinámico):
```
Prompt base: 3,000 tokens
Skill XSS cargada dinámicamente: 2,000 tokens
Total: 5,000 tokens (66% de ahorro)
```

### 2. Mantenibilidad

✅ **Centralizado**: Actualizar el conocimiento de XSS solo requiere editar `xss.md`
✅ **Modular**: Agregar una nueva vulnerabilidad = crear un nuevo archivo `.md`
✅ **Versionable**: Las skills están en Git junto con el código

### 3. Escalabilidad

✅ **Crecimiento sin overhead**: Agregar 10 nuevas skills no aumenta el tamaño del prompt base
✅ **Selectivo**: Solo se cargan las skills relevantes (2-3 máximo por request)
✅ **Composable**: Se pueden combinar múltiples skills (XSS + SQLi + SSRF)

### 4. Precisión

✅ **Scoring específico**: Cada vulnerabilidad tiene su propia tabla de scoring
✅ **FP patterns**: Patrones de false positives conocidos por tipo
✅ **Context-aware**: El LLM recibe guías específicas del tipo de vulnerabilidad detectado

---

## Roadmap de Skills

### Skills Existentes (v1.0)

- ✅ XSS (Cross-Site Scripting)
- ✅ SQLi (SQL Injection)
- ✅ SSRF (Server-Side Request Forgery)
- ✅ XXE (XML External Entity)
- ✅ RCE (Remote Code Execution)
- ✅ LFI (Local File Inclusion)
- ✅ IDOR (Insecure Direct Object Reference)
- ✅ JWT (JSON Web Token vulnerabilities)

### Skills Planeadas (v2.0)

- ⏳ CSRF (Cross-Site Request Forgery)
- ⏳ SSTI (Server-Side Template Injection)
- ⏳ CSTI (Client-Side Template Injection)
- ⏳ Open Redirect
- ⏳ Prototype Pollution
- ⏳ Race Conditions
- ⏳ File Upload vulnerabilities
- ⏳ GraphQL vulnerabilities
- ⏳ NoSQL Injection

### Skills Avanzadas (v3.0)

- ⏳ OAuth/OIDC vulnerabilities
- ⏳ WebSocket security
- ⏳ CORS misconfigurations
- ⏳ Insecure Deserialization
- ⏳ Business Logic Flaws

---

## Agregar una Nueva Skill

### Paso 1: Crear el archivo Markdown

```bash
touch bugtrace/agents/skills/vulnerabilities/csrf.md
```

### Paso 2: Seguir la estructura estándar

```markdown
# SKILL: CROSS-SITE REQUEST FORGERY (CSRF)

<!-- critical -->
Descripción del riesgo
<!-- /critical -->

## 1. SCOPE
<!-- scope -->
...
<!-- /scope -->

## 2. METHODOLOGY
<!-- methodology -->
...
<!-- /methodology -->

## 4. SCORING GUIDE
<!-- scoring_guide -->
| Score | Criterio | Ejemplo |
<!-- /scoring_guide -->

## 5. FALSE POSITIVES
<!-- false_positives -->
...
<!-- /false_positives -->
```

### Paso 3: Agregar al mapeo

**Archivo**: `bugtrace/agents/skills/loader.py`

```python
SKILL_MAP = {
    # ... existing mappings ...
    "csrf": "csrf.md",
    "cross-site request": "csrf.md",
    "request forgery": "csrf.md",
}
```

### Paso 4: Probar la carga

```python
from bugtrace.agents.skills.loader import get_skill_content

csrf_skill = get_skill_content("CSRF")
print(csrf_skill)
```

---

## Mejores Prácticas

### 1. Escritura de Skills

✅ **Concisión**: Mantener las skills bajo 2,000 tokens
✅ **Estructura**: Usar siempre los comentarios HTML para las secciones
✅ **Ejemplos concretos**: Incluir payloads y casos reales
✅ **Auto-scoring keywords**: Agregar keywords para automatic scoring

### 2. Uso de Skills

✅ **Límite de skills**: No cargar más de 3 skills por request
✅ **Relevancia**: Solo cargar skills cuando hay sospecha del tipo de vulnerabilidad
✅ **Priorización**: Cargar primero las skills de los findings con mayor confidence

### 3. Mantenimiento

✅ **Versionado**: Incluir fecha de última actualización en cada skill
✅ **Testing**: Probar la extracción de secciones después de cambios
✅ **Documentación**: Actualizar este documento cuando se agreguen skills

---

## Referencias

- **Código fuente**: `bugtrace/agents/skills/`
- **Loader**: `bugtrace/agents/skills/loader.py`
- **Uso en DASTySAST**: `bugtrace/agents/analysis_agent.py:956-983, 1580-1593`
- **Skills existentes**: `bugtrace/agents/skills/vulnerabilities/*.md`

---

*Última actualización: 2026-02-02*
*Versión: 1.0.0 (Phoenix Edition)*
