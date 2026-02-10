# Errores Encontrados Durante Refactoring

Este archivo documenta errores pre-existentes encontrados durante el proceso de refactoring para arreglarlos después.

---

## Tests Fallidos (Pre-existentes)

### 1. test_eventbus_tui_bridge.py - 2 tests fallidos

**Archivo:** `tests/unit/test_eventbus_tui_bridge.py`

**Tests:**
- `TestEventBusTUIBridge::test_finding_bridges_to_conductor`
- `TestEventBusTUIBridge::test_finding_with_alternate_keys`

**Error:** Problemas con mocks asincrónicos
```
RuntimeWarning: coroutine 'AsyncMockMixin._execute_mock_call' was never awaited
```

**Causa probable:** El mock de EventBus no está configurado correctamente para operaciones async.

**Prioridad:** Media

---

### 2. Tests con errores de colección

**Archivos afectados:**
- `tests/test_all_vulnerability_types.py`
- `tests/test_e2e_vision.py` - `NameError: name 'Optional' is not defined`
- `tests/test_phase1_agents.py`
- `tests/test_reactor.py`
- `tests/test_smoke.py`

**Error:** Errores de import durante la colección de tests

**Causa probable:** Imports faltantes o mal configurados en archivos de test.

**Fix sugerido para test_e2e_vision.py:**
```python
from typing import Optional  # Añadir este import
```

**Prioridad:** Baja (tests de integración/E2E)

---

## Deprecation Warnings

### 1. datetime.utcnow() deprecado

**Archivos:** Múltiples (pydantic, etc.)
```
DeprecationWarning: datetime.datetime.utcnow() is deprecated
```

**Fix:** Usar `datetime.datetime.now(datetime.UTC)` en lugar de `datetime.utcnow()`

**Prioridad:** Baja

---

### 2. asyncio.get_event_loop() deprecado

**Archivo:** `bugtrace/tools/visual/browser.py:38`
```python
loop = asyncio.get_event_loop()  # Deprecated
```

**Fix:** Usar `asyncio.get_running_loop()` o `asyncio.new_event_loop()`

**Prioridad:** Baja

---

### 3. lancedb table_names() deprecado

**Archivo:** `bugtrace/core/database.py:263`
```
DeprecationWarning: table_names() is deprecated, use list_tables() instead
```

**Fix:** Cambiar `table_names()` por `list_tables()`

**Prioridad:** Baja

---

### 4. aiohttp unittest_run_loop deprecado

**Archivo:** `tests/test_prototype_pollution_agent.py`
```
DeprecationWarning: Decorator `@unittest_run_loop` is no longer needed in aiohttp 3.8+
```

**Fix:** Eliminar el decorador `@unittest_run_loop`

**Prioridad:** Baja

---

## Código Muerto Identificado

### 1. _extract_html_params() en DASTySAST

**Archivo:** `bugtrace/agents/analysis_agent.py`
**Estado:** Marcado como "NEVER CALLED" en CLAUDE.md
**Acción:** Eliminar o documentar por qué se mantiene

---

## Notas

- Los 2 tests fallidos de EventBus son pre-existentes (no causados por refactoring)
- Los 367 tests unitarios pasan correctamente
- Las deprecation warnings no afectan funcionalidad actual
