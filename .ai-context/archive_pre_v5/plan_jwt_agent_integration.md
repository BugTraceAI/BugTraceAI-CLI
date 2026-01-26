# Plan de Integración: JWTAgent (Experto en Tokens & Sesiones)

**Autor**: BugTraceAI Team
**Fecha**: 2026-01-13
**Versión**: 1.0.0
**Contexto**: Evolución de la Arquitectura V4

---

## 🚀 1. Visión Estratégica

El sistema actual (V4) sobresale en vulnerabilidades de inyección (XSS, SQLi, CRLF), pero carece de un especialista dedicado a la **Lógica de Autenticación** y **Autorización**. El `JWTAgent` llenará este vacío, actuando como el experto forense que disecciona, manipula y rompe la identidad digital.

Su objetivo no es solo decodificar tokens, sino realizar ataques criptográficos y lógicos complejos que los escáneres DAST genéricos ignoran.

---

## 🧠 2. Arquitectura del Agente (`JWTAgent`)

El agente seguirá el patrón de diseño de **Specialist Agent V4** (heredando de `BaseAgent`), integrándose en el bus de eventos y siguiendo las directrices del Conductor.

### 2.1. Skills Modulares Requeridas

El agente cargará dinámicamente el conocimiento necesario (`skills/jwt.md`):

1. **JWT Anatomy**: Estructura, claims estándar (`iss`, `exp`, `sub`, `aud`).
2. **Weak Algorithms**: Ataques de degradación (`RS256` -> `HS256`, `None` algorithm).
3. **Key Confusion**: Ataques de confusión de claves públicas/privadas.
4. **Kid Manipulation**: Inyección de claves en la cabecera (JKU/JWK injection).

### 2.2. Herramientas Especializadas

El agente no usará `jwet` o herramientas externas binarias para evitar dependencias pesadas, sino una implementación Python robusta (`PyJWT` + lógica custom).

| Herramienta | Función |
| :--- | :--- |
| **TokenDecoder** | Análisis estático, extracción de claims y cabeceras sin verificar firma. |
| **TokenForger** | Reimpresión de tokens con nuevos claims y firma manipulada (None, clave débil). |
| **BruteForcer** | Ataque offline de fuerza bruta contra secretos débiles (usando wordlist pequeña de 10k). |
| **Injector** | Modificación de cabeceras (`kid`, `jku`) para RCE/SSRF via validación de claves. |

---

## ⚙️ 3. Flujo de Activación (Dispatcher Logic)

El `JWTAgent` no se activará para todos los targets. El **Dispatcher** (o `DASTAgent`) dará la señal solo bajo condiciones específicas.

### Trigger Conditions

1. **Header Detection**: Presencia de `Authorization: Bearer <JWT>`.
2. **Cookie Detection**: Cookies con formato JWT (`eyJ...`).
3. **LocalStorage**: Claves que contienen strings JWT.

---

## 🛠️ 4. Hoja de Ruta de Implementación

### Fase 1: Creador y Analista (Foundation)

* [ ] Crear `bugtrace/agents/jwt_agent.py`.
* [ ] Implementar lógica de detección y decodificación.
* [ ] Integrar reporte básico de "Información Divulgada" (e.g., emails o roles en el token).

### Fase 2: El Falsificador (Attack Logic)

* [ ] Implementar ataque `None` Algorithm.
* [ ] Implementar ataque de degradación `RS256` -> `HS256`.
* [ ] Implementar chequeo de secretos débiles (rockyou-top1000).

### Fase 3: Integración Sistémica (V4)

* [ ] Añadir `jwt.md` a `bugtrace/agents/skills/`.
* [ ] Actualizar `TeamOrchestrator` para reconocer al nuevo agente.
* [ ] Configurar reglas de **Rate Limit** globales en el Conductor para proteger estos ataques intensivos.

---

## 🛑 5. Consideraciones de Seguridad (Anti-Vibecoding)

Para evitar el problema de los Rate Limits mencionado por el usuario:

1. **Passive First**: El agente primero analizará el token **offline** (decodificación, fuerza bruta local). Cero impacto en el servidor.
2. **Surgical Active**: Solo enviará tokens manipulados si detecta debilidad teórica.
3. **Global Backoff**: Se integrará en el sistema de gestión de tráfico del Conductor para pausar si detecta 429/503.

---

## 6. Ejemplo de Thinking Process (Prompt)

```markdown
# MISSION
You have intercepted a JWT: `eyJ...`

# ANALYSIS
1. DECODE header and payload.
2. CHECK algorithm. Is it RS256? -> Plan HM256 swap. Is it None logic enabled?
3. SENSITIVE DATA: Does payload contain `role: user`? -> Plan privilege escalation to `role: admin`.

# EXECUTION
1. Create FORGED token with `alg: None`.
2. Replay request to endpoint `/api/admin`.
3. Analyze response (200 OK vs 401 Unauthorized).
```
