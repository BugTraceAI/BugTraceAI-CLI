# Infraestructura de Pruebas: BugTraceAI Dojos

Para validar la evolución de la Orquestación Quirúrgica (V4), BugTraceAI utiliza un ecosistema de Dojos locales. Estos entornos permiten medir la precisión, el descubrimiento y la capacidad de bypass de los agentes en un entorno controlado pero realista.

## 1. Comprehensive Dojo (Puerto 5090)

**Archivo:** `testing/dojo_comprehensive.py`

Es el entorno de referencia para medir el progreso técnico de los especialistas.

### Estructura de Niveles (0-10)

- **Nivel 0-2 (Básico):** Sin protecciones o filtros de caracteres simples (`<`, `>`).
- **Nivel 3-5 (Intermedio):** WAFs basados en keywords (`script`, `UNION`), filtros de eventos XSS, y validación de extensiones de archivo.
- **Nivel 6-8 (Avanzado):** Bypasses de firmas complejas, inyecciones en JSON, JWT con secretos débiles, y SSRF con listas negras de localhost.
- **Nivel 9-10 (Investigación):** CSP estricto, ataques de deserialización y vulnerabilidades de lógica multi-paso.

### Categorías Cubiertas

- **XSS:** Reflejado, DOM y Fragment XSS.
- **SQLi:** Error-based, Boolean-blind y Time-based.
- **SSRF:** Acceso a interfaces internas y metadatos.
- **XXE:** Exfiltración de archivos y OOB.
- **File Upload:** Bypasses de extensión, MIME-type y RCE.
- **JWT:** Algoritmo `none`, secretos débiles y manipulación de claims.
- **IDOR:** Acceso a recursos de otros usuarios mediante IDs incrementales.
- **CSTI:** Inyecciones de plantillas en el lado del cliente (Angular, Vue).

---

## 2. Mixed Orchestration Dojo (Puerto 5100)

**Archivo:** `testing/mixed_orchestration_dojo.py`

Creado específicamente para la sesión del 14 de enero de 2026. Su objetivo no es solo probar especialistas, sino **entrenar al Orquestador (Reactor V4)**.

### Características Clave

- **URL Mix:** Solo 10 URLs críticas que mezclan diferentes tipos de vulnerabilidades y niveles de dificultad (L0 a L5).
- **Señuelos (Decoys):** Incluye páginas como `/secure-login` que son 100% seguras (parameterized queries) pero que "parecen" vulnerables para probar si la IA alucina.
- **Contexto Cruzado:** Obliga al orquestador a decidir entre atacar un XSS o un SQLi en el mismo parámetro basándose en el análisis del `DASTySASTAgent`.

---

## 3. GinandJuice Mixed Front App (Puerto 5095)

**Archivo:** `testing/vuln_front_app.py`

Un frontend realista que simula una tienda online.

- **Propósito:** Validar el **Descubrimiento Dinámico** (Playwright) y el mantenimiento de sesión/contexto durante el ataque.
- **Flujo:** Login -> Catalog -> Checkout. El orquestador debe ser capaz de mantener el estado para encontrar vulnerabilidades en áreas protegidas.

---

## 4. Cómo Ejecutar las Pruebas

### Iniciar los Dojos (Background)

```bash
python3 testing/dojo_comprehensive.py &
python3 testing/mixed_orchestration_dojo.py &
python3 testing/vuln_front_app.py &
```

### Ejecutar el Reactor contra un Dojo

```bash
# Contra el Dojo de Entrenamiento
export PYTHONPATH=$PYTHONPATH:. && python3 test_training_center.py

# Contra el Comprehensive Dojo
export PYTHONPATH=$PYTHONPATH:. && python3 test_orchestration_local.py
```

## 5. Reportes de Hallazgos

Los resultados de los Dojos se guardan en:

- **Estado DB:** `state/jobs.db`
- **Reportes Markdown:** `reports/jobs/job_X/vulnerabilities_...md` (Incluyen el razonamiento de la IA).
- **JSON State:** `logs/state_[target_hash].json`

---
**Documentación actualizada al 14 de enero de 2026.**
