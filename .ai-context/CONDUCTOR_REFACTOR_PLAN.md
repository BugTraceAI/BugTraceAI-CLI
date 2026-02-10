# Plan de Refactorización: Conductor como Checkpoint Manager

**Fecha:** 2026-02-04
**Objetivo:** Simplificar Conductor para que sea solo un monitor/checkpoint manager, sin validación de findings

---

## 🎯 Objetivo

Convertir el Conductor de un "validador con reglas" a un "monitor de pipeline":

```
ANTES: Conductor = Orquestador + Validador (regex) + Health checks
DESPUÉS: Conductor = Orquestador + Health checks (SOLO)
```

---

## ✅ Lo que MANTIENE el Conductor

### 1. Integrity checks entre fases
```python
def verify_integrity(self, phase: str, expected: Dict, actual: Dict) -> bool:
    """Verifica coherencia entre fases del pipeline"""
    # Discovery: URLs in = Reports out + Errors
    # Strategy: Raw findings >= WET queue items
    # Exploitation: DRY findings <= WET items (anti-hallucination)
```

### 2. Shared context (comunicación entre agentes)
```python
def share_context(self, key: str, value: Any) -> None:
    """Compartir datos entre agentes"""

def get_shared_context(self, key: str = None) -> Any:
    """Obtener contexto compartido"""
```

### 3. Statistics y health metrics
```python
def get_statistics(self) -> Dict:
    """Métricas para la API (health checks)"""
    return {
        "integrity_passes": X,
        "integrity_failures": Y,
        "context_refreshes": Z
    }
```

### 4. Protocol files (opcional, poco usado)
```python
def get_context(self, key: str) -> str:
    """Cargar archivos de protocol/ (security-rules.md, etc.)"""
```

---

## ❌ Lo que ELIMINA del Conductor

### Métodos de validación (mover a specialists):
- `validate_finding()` → Cada specialist se auto-valida
- `_validate_xss_evidence()` → XSSAgent
- `_validate_sqli_evidence()` → SQLiAgent
- `_validate_csti_evidence()` → CSTIAgent
- `validate_payload()` → Cada specialist valida sus payloads
- `_validate_basic_payload_rules()` → Specialists
- `_validate_xss_payload()` → XSSAgent
- `_validate_sqli_payload()` → SQLiAgent
- `_validate_payload_format()` → **Este es el problemático, eliminarlo**
- `check_false_positive()` → Specialists o AgenticValidator
- `_check_waf_block()` → ReconAgent o specialists
- `_check_generic_error()` → Specialists
- `_check_captcha_or_rate_limit()` → ReconAgent
- `_check_auth_required()` → ReconAgent
- `audit_batch()` → No usado realmente

### Configuración relacionada (eliminar de config.py):
- `CONDUCTOR_DISABLE_VALIDATION`
- `CONDUCTOR_MIN_CONFIDENCE`
- `CONDUCTOR_ENABLE_FP_DETECTION`

---

## 📦 Dónde mover la lógica eliminada

### 1. Auto-validación en BaseAgent (nuevo método)

**Archivo:** `bugtrace/agents/base.py`

```python
class BaseAgent:
    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """
        Valida finding ANTES de emitir al pipeline.
        Override este método en subclases para validación específica.

        Returns:
            (is_valid, error_message)
        """
        # Validación básica (todos los agents)
        if not finding.get("type"):
            return False, "Missing vulnerability type"

        if not finding.get("url"):
            return False, "Missing target URL"

        # Validación de payload (si aplica)
        payload = finding.get("payload")
        if payload and self._is_conversational_payload(payload):
            return False, f"Conversational payload detected: {payload[:50]}"

        return True, ""

    def _is_conversational_payload(self, payload: str) -> bool:
        """Detecta payloads conversacionales (regex simple)"""
        import re
        conversational_patterns = [
            r"^(Try|Navigate|Inject|Use)\s",
            r"\(e\.g\.,",
            r"payload (could|should|must) be"
        ]
        return any(re.search(p, payload, re.IGNORECASE) for p in conversational_patterns)

    def emit_finding(self, finding: Dict):
        """Emite finding SOLO si pasa validación"""
        is_valid, error = self._validate_before_emit(finding)
        if not is_valid:
            logger.warning(f"[{self.name}] Finding rejected: {error}")
            return None

        # Emitir al pipeline
        event_bus.emit("finding_discovered", finding)
        return finding
```

### 2. Validación específica en cada Specialist

**XSSAgent:**
```python
class XSSAgent(BaseAgent):
    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        # Llamar validación base
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # Validación XSS específica
        if not finding.get("evidence", {}).get("screenshot"):
            return False, "XSS requires screenshot proof"

        payload = finding.get("payload", "")
        if not any(c in payload for c in '<>\'"();'):
            return False, "XSS payload missing attack chars"

        return True, ""
```

**SQLiAgent:**
```python
class SQLiAgent(BaseAgent):
    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # Validación SQLi específica
        evidence = finding.get("evidence", {})
        if not (evidence.get("error_message") or
                evidence.get("time_delay") or
                evidence.get("data_extracted")):
            return False, "SQLi requires error/time/data proof"

        return True, ""
```

### 3. Detección de False Positives

**Opción A:** Mover a AgenticValidator (validación inteligente con CDP)
**Opción B:** Cada specialist detecta sus propios FPs

**Recomendación:** Opción B (specialists)

```python
class SQLiAgent(BaseAgent):
    def _is_false_positive(self, response: Dict) -> Tuple[bool, str]:
        """Detecta FPs específicos de SQLi"""
        status = response.get("status_code")
        body = response.get("body", "").lower()

        # WAF block
        if status == 403 and any(kw in body for kw in ["waf", "blocked"]):
            return True, "WAF_BLOCK"

        # Generic 500 (no SQL error)
        if status == 500 and not any(kw in body for kw in ["sql", "syntax"]):
            return True, "GENERIC_500"

        return False, ""
```

---

## 🔧 Cambios en archivos

### 1. `bugtrace/core/conductor.py`

**ELIMINAR:**
- Todos los métodos `validate_*` y `_validate_*`
- Métodos `check_false_positive()` y `_check_*`
- Método `audit_batch()` (no usado)
- Atributos: `validation_enabled`, `min_confidence`, `fp_detection_enabled`

**MANTENER:**
- `verify_integrity()` ✅
- `share_context()`, `get_shared_context()` ✅
- `get_statistics()` ✅
- `get_context()` (archivos de protocol) ✅

**Nuevo ConductorV2 (simplificado):**
```python
class ConductorV2:
    """
    Pipeline health monitor and checkpoint manager.
    NO validation logic - specialists self-validate.
    """

    def __init__(self):
        self.shared_context = {}
        self.stats = {
            "integrity_passes": 0,
            "integrity_failures": 0,
            "context_refreshes": 0
        }

    def verify_integrity(self, phase, expected, actual):
        """Check phase completed correctly"""
        # Mantener lógica actual

    def share_context(self, key, value):
        """Cross-agent communication"""
        # Mantener lógica actual

    def get_statistics(self):
        """Health metrics for API"""
        return self.stats
```

### 2. `bugtrace/core/team.py`

**Línea 1387-1388: ELIMINAR**
```python
# ANTES:
if not self._validate_finding_format(f):
    continue

# DESPUÉS: (confiar en specialist)
# [eliminar estas líneas]
```

**Línea 1398-1403: ELIMINAR método completo**
```python
def _validate_finding_format(self, finding: dict) -> bool:
    # ELIMINAR TODO ESTE MÉTODO
```

### 3. `bugtrace/agents/base.py`

**AGREGAR:**
```python
def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
    """Validación base para todos los agents"""
    # Ver código completo arriba

def _is_conversational_payload(self, payload: str) -> bool:
    """Detecta payloads conversacionales"""
    # Ver código completo arriba

def emit_finding(self, finding: Dict):
    """Emite finding si pasa validación"""
    # Ver código completo arriba
```

### 4. Specialists (XSSAgent, SQLiAgent, etc.)

**ACTUALIZAR todos los specialists:**
```python
# Buscar todas las llamadas a:
event_bus.emit("finding_discovered", finding)

# Reemplazar con:
self.emit_finding(finding)  # Usa validación antes de emitir
```

**AGREGAR métodos `_validate_before_emit()` específicos:**
- XSSAgent: validar screenshot, payload XSS
- SQLiAgent: validar evidencia SQL, payload SQL
- CSTIAgent: validar template execution
- Etc.

### 5. Agentes que llaman al Conductor

**Archivos afectados:**
- `bugtrace/agents/exploit.py` (línea 657, 789, 795)
- `bugtrace/agents/skeptic.py` (línea 125)
- `bugtrace/agents/url_master.py` (línea 500)

**Buscar y reemplazar:**
```python
# ANTES:
is_valid, reason = conductor.validate_finding(finding_data)
if not is_valid:
    logger.warning(f"Blocked: {reason}")
    return

# DESPUÉS:
# [Ya no se valida aquí, el specialist ya validó antes de emitir]
# O usar self._validate_before_emit() si no se emitió aún
```

### 6. `bugtrace/core/config.py`

**ELIMINAR settings:**
```python
# ELIMINAR:
CONDUCTOR_DISABLE_VALIDATION: bool = False
CONDUCTOR_MIN_CONFIDENCE: float = 0.6
CONDUCTOR_ENABLE_FP_DETECTION: bool = True

# Y sus lecturas en _load_from_file()
```

### 7. Tests

**Actualizar:**
- `tests/test_conductor_v2.py` - Eliminar tests de validación, mantener solo integrity checks
- Agregar: `tests/test_base_agent_validation.py` - Tests de auto-validación

---

## 📋 Pasos de implementación

### Fase 1: Preparación (sin romper nada)
1. ✅ Crear métodos en BaseAgent (`_validate_before_emit`, `emit_finding`)
2. ✅ Implementar validación específica en 2-3 specialists (XSSAgent, SQLiAgent)
3. ✅ Tests unitarios de BaseAgent.emit_finding()

### Fase 2: Migración gradual
4. ✅ Actualizar XSSAgent para usar `self.emit_finding()` en lugar de `event_bus.emit()`
5. ✅ Actualizar SQLiAgent
6. ✅ Actualizar resto de specialists uno por uno
7. ✅ Tests de integración por cada specialist migrado

### Fase 3: Limpieza del Conductor
8. ✅ Verificar que ningún specialist llama a `conductor.validate_*()`
9. ✅ Eliminar métodos de validación del Conductor
10. ✅ Actualizar tests del Conductor (solo integrity checks)

### Fase 4: Limpieza de Team.py
11. ✅ Eliminar `_validate_finding_format()` de team.py
12. ✅ Eliminar llamada en línea 1387

### Fase 5: Config y docs
13. ✅ Eliminar settings de validación de config.py
14. ✅ Actualizar CLAUDE.md con nueva arquitectura
15. ✅ Tests E2E completos

---

## 🧪 Testing

### Tests críticos a verificar:

1. **BaseAgent.emit_finding() rechaza conversacionales:**
```python
def test_base_agent_rejects_conversational():
    agent = XSSAgent()
    finding = {"payload": "Navigate to: http://...", "type": "XSS"}
    result = agent.emit_finding(finding)
    assert result is None  # Rechazado
```

2. **Specialists auto-validan correctamente:**
```python
def test_xss_agent_requires_screenshot():
    agent = XSSAgent()
    finding = {"type": "XSS", "payload": "<script>", "evidence": {}}
    result = agent.emit_finding(finding)
    assert result is None  # Sin screenshot = rechazado
```

3. **Conductor solo hace integrity checks:**
```python
def test_conductor_no_validation():
    c = ConductorV2()
    # Verificar que NO tiene métodos validate_*
    assert not hasattr(c, 'validate_finding')
    assert not hasattr(c, '_validate_payload_format')
```

4. **Pipeline E2E funciona sin validación en Conductor:**
```python
def test_pipeline_with_self_validating_specialists():
    # Scan completo debe funcionar
    # Findings mal formados no deben llegar a DB
    # Solo findings válidos en final_report.md
```

---

## 📊 Impacto esperado

### Antes (con Conductor validador):
```
Specialist → Finding → Conductor.validate_finding_format() →
  ❌ Rechazado por regex → Se pierde
```

### Después (specialists auto-validan):
```
Specialist → self._validate_before_emit() →
  ✅ Válido → event_bus.emit() → Pipeline
  ❌ Inválido → No se emite (log warning)
```

### Beneficios:
1. ✅ Cada specialist controla su propia calidad
2. ✅ Conductor más simple (solo monitor)
3. ✅ No se pierden findings legítimos por regex tontas
4. ✅ Validación específica por tipo de vuln
5. ✅ AgenticValidator sigue siendo la validación visual inteligente

---

## ⚠️ Riesgos y mitigaciones

### Riesgo 1: Findings conversacionales pasan
**Mitigación:** Regex simple en BaseAgent detecta casos obvios

### Riesgo 2: Specialists olvidan validar
**Mitigación:** BaseAgent.emit_finding() es el único método para emitir (enforce by convention)

### Riesgo 3: Romper tests existentes
**Mitigación:** Fase 1-2 no rompen nada, tests pasan durante migración

---

## 🎯 Checklist final

Antes de dar por terminada la refactorización:

- [ ] Todos los specialists usan `self.emit_finding()`
- [ ] Ningún código llama a `conductor.validate_*()`
- [ ] Tests de Conductor solo verifican integrity checks
- [ ] Scan E2E completo funciona correctamente
- [ ] No hay findings conversacionales en reportes finales
- [ ] CLAUDE.md actualizado con nueva arquitectura
- [ ] Git commit con mensaje descriptivo

---

## 📝 Notas adicionales

- El AgenticValidator (CDP) sigue siendo la validación inteligente para XSS
- Los specialists pueden compartir utilidades de validación en `specialist_utils.py`
- Si un specialist NO implementa `_validate_before_emit()`, usa la validación base (suficiente para mayoría)
