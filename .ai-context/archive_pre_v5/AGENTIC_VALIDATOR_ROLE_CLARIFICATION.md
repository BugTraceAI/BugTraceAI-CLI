# AgenticValidator: Clarificación de Rol y Alcance

**Fecha**: 2026-01-14T18:45:00+01:00  
**Autor**: Usuario + Antigravity (Gemini 3)  

---

## 🎯 Propósito del AgenticValidator

El AgenticValidator actúa como **"Senior Pentester Review Layer"**, NO como descubridor.

### Analogía con Pentesting Real

```text
📋 Junior Pentester (Specialist Agents)
   ├─ Descubre vulnerabilidades
   ├─ Genera PoC
   ├─ A veces se equivoca
   └─ Crea primer reporte

          ↓

👨‍💼 Senior Pentester (AgenticValidator)
   ├─ Revisa el reporte
   ├─ Ejecuta los PoCs del junior
   ├─ Confirma o rechaza findings
   └─ Firma el reporte final para el cliente
```

---

## ✅ Lo Que DEBE Hacer

### 1. **Validar PoCs Existentes** (NO Descubrir)

**Input esperado**:

```python
finding = {
    "url": "https://example.com/search?q=test",
    "payload": "<script>alert(document.domain)</script>",
    "type": "XSS",
    "parameter": "q",
    "validated": False  # ← NO validado aún
}
```

**Proceso**:

1. ✅ Recibe URL + payload del agente
2. ✅ Navega con Chrome a `URL?param=payload`
3. ✅ Captura screenshot
4. ✅ Verifica ejecución (alert, cambios visuales, etc.)
5. ✅ Marca `validated=True` si confirma

**NO hace**:

- ❌ Descubrir parámetros
- ❌ Generar nuevos payloads
- ❌ Fuzzing
- ❌ Discovery

### 2. **Ser Rápido**

Dado que solo valida (no descubre):

- ⚡ 1 finding = 1-3 segundos (navegar + screenshot + análisis)
- ⚡ 20 findings = 20-60 segundos total
- ⚡ Mucho más rápido que un scan completo

### 3. **Proporcionar Extra Layer de Confianza**

**Importante**: Un finding NO validado **NO significa que sea falso**.

```text
┌─────────────────────────────────────────────────────┐
│  FINDING STATUS                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ✅ VALIDATED                                       │
│     - AgenticValidator confirmó con browser        │
│     - Screenshot + Vision AI                       │
│     - Confidence: VERY HIGH                        │
│     - Listo para entregar al cliente               │
│                                                     │
│  ⚠️  POTENTIAL (not validated)                     │
│     - Agent detectó pero no pudo confirmar         │
│     - Puede ser real, solo falta validación manual │
│     - Confidence: MEDIUM-HIGH                      │
│     - Revisar manualmente antes de entregar        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 4. **Especialmente Útil para XSS**

El AgenticValidator es **crítico** para XSS porque:

- ✅ **Visual confirmation**: Ve si el payload se renderiza o se escapa
- ✅ **WAF detection**: Diferencia entre block y ejecución
- ✅ **Alert detection**: Captura `alert()` con Chrome DevTools
- ✅ **DOM changes**: Vision AI ve cambios visuales

Para otros tipos:

- **SQLi**: Útil pero SQLMap ya valida bien
- **SSRF**: Útil si hay respuesta visual
- **IDOR**: Útil para confirmar acceso no autorizado
- **XXE**: Menos útil (validación OOB mejor)

---

## 🚫 Lo Que NO Debe Hacer

### 1. **NO Descubrir Parámetros o Endpoints**

**Correcto** (recibe PoC del agente):

```python
# XSSAgent ya descubrió y generó PoC
finding = {
    "url": "https://example.com/search?q=<script>alert(1)</script>",
    "payload": "<script>alert(1)</script>",
}

# AgenticValidator solo valida
validator.validate_finding(finding)
```

**Incorrecto** (si el validator descubriera):

```python
# ❌ Esto NO debería pasar
validator.discover_parameters("https://example.com")
validator.generate_payloads()
validator.fuzz_all_params()
```

### 2. **NO Reinventar el Trabajo del Agente**

Si el agente **ya validó** con evidencia sólida (screenshot, SQLMap output, OOB response):

- ✅ AgenticValidator **respeta** esa validación
- ✅ Solo valida findings **NO validados**

```python
# En validate_batch()
for finding in findings:
    if finding.get("validated"):  # Ya validado por agente
        validated_findings.append(finding)  # ← Skip, no re-validar
        continue
```

### 3. **NO Generar Ruido**

Solo se ejecuta **una vez** antes del reporte, no continuamente.

---

## 📋 Flujo Correcto

### Pipeline Completo

```text
Phase 1: Reconnaissance
  └─→ GoSpider descubre 10 URLs con parámetros

Phase 2: Analysis & Exploitation (para cada URL)
  ├─→ DAST Agent
  │   └─→ Analiza → 5 vulnerabilidades POTENCIALES (validated=False)
  │
  └─→ Swarm Agents
      ├─→ XSSAgent
      │   ├─ Descubre parámetro "q"
      │   ├─ Genera payload: <script>alert(1)</script>
      │   ├─ Inyecta y verifica
      │   └─→ Finding: { validated: True/False, payload: "..." }
      │
      ├─→ SQLiAgent
      │   ├─ Descubre parámetro "id"
      │   ├─ Detecta SQL error
      │   ├─ Ejecuta SQLMap
      │   └─→ Finding: { validated: True, evidence: "SQLMap confirmed" }
      │
      └─→ ... otros agentes

Phase 3: Global Review
  └─→ Análisis de chaining

Phase 3.5: AgenticValidator (NUEVO) 🔍
  ├─→ Recibe 25 findings
  ├─→ Separa: 8 ya validados, 17 potenciales
  ├─→ Para los 17 potenciales:
  │   ├─ Toma URL + payload existente
  │   ├─ Navega con Chrome
  │   ├─ Captura screenshot
  │   ├─ Vision AI analiza
  │   └─ Marca validated=True si confirma (6 confirmados)
  └─→ Retorna: 8 + 6 = 14 findings validados

Phase 4: Report Generation
  └─→ Reporte con 14 findings VALIDADOS + 11 POTENCIALES
      (si REPORT_ONLY_VALIDATED=True → Solo 14)
```

---

## 🎨 Visualización en el Reporte

### Ejemplo de Finding Validado

```markdown
## Cross-Site Scripting (XSS) - High Severity

**URL**: `https://example.com/search?q=test`  
**Parameter**: `q`  
**Payload**: `<script>alert(document.domain)</script>`  

**Status**: ✅ **VALIDATED**  
**Validation Method**: `AgenticValidator - Vision AI`  
**Evidence**: [Screenshot](captures/xss_confirmed_123.png)  

**Reproduction**:
1. Navigate to target URL
2. Inject payload into parameter 'q'
3. Observe alert popup with domain name

**CVSS Score**: 6.1 (Medium)
```

### Ejemplo de Finding NO Validado (Potential)

```markdown
## SQL Injection (Potential) - High Severity

**URL**: `https://example.com/product?id=1`  
**Parameter**: `id`  
**Payload**: `1' OR '1'='1`  

**Status**: ⚠️ **POTENTIAL** (Not Validated)  
**Detected By**: DAST Agent (AI Analysis)  
**Reasoning**: Parameter accepts numeric input, potential for SQL injection  

**Recommendation**: Manual verification recommended before reporting

**CVSS Score**: 9.8 (Critical if confirmed)
```

---

## 🧪 Testing Plan

### ¿Necesita un Dojo?

**Respuesta**: NO es crítico, pero podría ser útil para testing.

**Razones para NO crear Dojo específico**:

1. ✅ AgenticValidator valida PoCs, no descubre
2. ✅ Los agentes ya tienen Dojos (XSS, SQLi, etc.)
3. ✅ Podemos testearlo con findings reales

**Razones para crear Dojo (futuro)**:

1. 📊 Testear tasa de falsos positivos/negativos
2. 🎯 Medir accuracy de Vision AI
3. 🔍 Edge cases (WAF blocks, encoding, etc.)

**Recomendación**: Usar Dojo existente, validar findings de agentes:

```python
# test_agentic_validator.py
async def test_validator_xss():
    # 1. XSSAgent encuentra XSS en Dojo Level 1
    xss_agent = XSSAgent("http://127.0.0.1:5090/xss/level1?q=test", ["q"])
    result = await xss_agent.run_loop()
    
    # 2. Marcar como NO validado para testear validator
    for finding in result["findings"]:
        finding["validated"] = False
    
    # 3. AgenticValidator debería confirmar
    validator = AgenticValidator()
    validated = await validator.validate_batch(result["findings"])
    
    # 4. Verificar que validó correctamente
    assert validated[0]["validated"] == True
    assert "AgenticValidator" in validated[0]["validation_method"]
```

---

## 📊 Métricas de Éxito

### KPIs del AgenticValidator

| Métrica | Target | Cómo Medir |
|---------|--------|------------|
| **Velocidad** | <3 seg/finding | Tiempo de ejecución |
| **Accuracy** | >90% | TP/(TP+FP) en Dojo |
| **False Negatives** | <5% | Vulns reales no confirmadas |
| **False Positives** | <10% | No-vulns marcadas como validated |

### Logs Esperados

```text
[Phase 3.5] Running AgenticValidator on 25 findings...
  Already validated by agents: 8
  Needs senior review: 17

  Launching AgenticValidator (single-threaded, Chrome DevTools)...
  
  [1/17] XSS on /search?q=... ✅ CONFIRMED (alert detected)
  [2/17] SQLi on /product?id=... ❌ REJECTED (no SQL error)
  [3/17] SSRF on /api?url=... ⏭️ SKIPPED (can't validate visually)
  ...
  [17/17] XSS on /blog?comment=... ✅ CONFIRMED (Vision AI: payload visible)

  ✅ AgenticValidator confirmed 6/17 findings
  
✅ Validation complete: 6 confirmed, 11 rejected/pending
```

---

## 🔄 Mejoras Futuras

### 1. **Validación Inteligente por Tipo**

```python
# Priorizar validación según tipo
priority_types = ["XSS", "SQLi", "RCE"]  # Visual/critical
skip_types = ["Information Disclosure", "Header Injection"]  # Hard to validate visually
```

### 2. **Timeout Configurable**

```python
# Permitir configurar timeout por tipo
VALIDATION_TIMEOUTS = {
    "XSS": 5,      # Rápido
    "SQLi": 10,    # Medio (SQLMap)
    "SSRF": 15,    # Lento (esperar OOB)
}
```

### 3. **Modo Batch Eficiente**

Si hay 20 XSS en la misma página:

- ✅ Abrir browser UNA vez
- ✅ Testear todos los payloads en una sesión
- ✅ Cerrar browser

En vez de:

- ❌ Abrir/cerrar browser 20 veces

---

## 📝 Conclusión

**AgenticValidator**:

- ✅ Es un **revisor**, no un descubridor
- ✅ Debe ser **rápido** (solo valida PoCs existentes)
- ✅ Proporciona **confianza extra** (no elimina potenciales)
- ✅ Es **especialmente útil para XSS**
- ✅ Respeta la **auto-validación de agentes**

**NO necesita Dojo dedicado** (por ahora), pero se puede testear con Dojos existentes.

---

**Actualizado**: 2026-01-14T18:45:00+01:00  
**Relacionado**: `VALIDATOR_REINTEGRATION_2026-01-14.md`
