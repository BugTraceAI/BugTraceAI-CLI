# 📊 Auditoría Técnica: Nuevo Sistema de Calibración de Puntuación (DASTySAST V5)

**Fecha**: 2026-01-20
**Autor**: Antigravity AI
**Estado**: Implementado y Calibrado en Dojo

---

## 🚀 Resumen del Refactor

Se ha implementado un sistema de puntuación **0-10** (en lugar del anterior 0.1-1.0) para el agente de análisis `DASTySAST`, integrando una **Revisión Escéptica (Skeptical Review)** con umbrales configurables por tipo de vulnerabilidad. El objetivo es maximizar la captura de vulnerabilidades críticas (SQLi, RCE, SSRF) mientras se minimiza la saturación de los agentes especialistas con falsos positivos.

## 📁 Ficheros Modificados (Para Revisión del Guru)

1. **`bugtraceaicli.conf`**: Definición de la sección `[SKEPTICAL_THRESHOLDS]`.
2. **`bugtrace/core/config.py`**: Lógica de carga y helper `get_threshold_for_type`.
3. **`bugtrace/agents/analysis_agent.py`**: Evolución de la lógica de análisis y el prompt del Juez Escéptico.
4. **`bugtrace/core/team.py`**: Integración de nuevos agentes especialistas (SSRF, LFI, RCE) y lógica de despacho rápido.

---

## 🛠️ Detalles Arquitectónicos

### 1. Sistema de Puntuación "Human-Readable" (0-10)

Se ha pasado a una escala entera para facilitar el razonamiento de los LLMs.

- **0-3**: Rechazo (hallazgo ruidoso/alucinación).
- **4-5**: Riesgo bajo (sospecha técnica, requiere especialista).
- **6-8**: Riesgo medio/alto (evidencia técnica clara).
- **9-10**: Confirmado (vulnerabilidad obvia).

### 2. Umbrales Configurables (Thresholds)

Para evitar saturar los agentes especialistas (como `sqlmap` o `nuclei`), hemos definido umbrales mínimos en el `.conf`:

- **Críticos (Umbral 4)**: SQL, RCE. No queremos perderlos aunque la sospecha sea baja.
- **Altos (Umbral 5)**: XXE, SSRF, LFI, XSS.
- **Medios (Umbral 6)**: JWT, File Upload, IDOR.

### 3. El Juez Escéptico (Skeptical Review)

Se ha implementado una fase de post-procesamiento donde un modelo (Gemini Pro/Flash) evalúa los hallazgos de los 5 enfoques originales de DASTySAST bajo estas reglas:
- **Consenso de Votos**: Si una vulnerabilidad tiene 4/5 o 5/5 votos, el Juez está instruido para subir su nota final automáticamente.
- **Anti-Alucinación**: No se permite pasar un hallazgo basado solo en el nombre del parámetro (ej. `?id=`) a menos que haya un consenso unánime.

---

## 🧪 Validación en Dojo (DASTySAST Calibration Dojo)

Se han realizado pruebas de fuego contra el Dojo de calibración (puerto 5200) con estos resultados:

- **SQLi (L4)**: `❌ REJECTED (Score 3/10 < 4)`. Correcto: Evitó lanzar a los especialistas ante una sospecha muy débil.
- **SSRF (Decoy)**: `✅ APPROVED (Score 6/10 >= 5)`. Correcto: El sistema detectó un mensaje de error real del backend ("Domain not allowed") y decidió que valía la pena investigar un posible bypass.
- **XSS (L1)**: `✅ APPROVED (Score 7/10 >= 5)`. Correcto: Detección por consenso y evidencia de reflexión.

## 📝 Notas para el TechLead

- **Lazy Loading**: Los agentes especialistas solo se importan e instancian si la vulnerabilidad sobrepasa el umbral configurado.
- **Normalization**: Se ha mejorado la lógica de búsqueda de tipos (cambiando `SQLI` por `SQL`) para asegurar que el mapeo de umbrales sea robusto frente a variaciones en la nomenclatura del LLM.

---
**Este documento resume la calibración final del sistema antes de entrar en producción masiva.**
