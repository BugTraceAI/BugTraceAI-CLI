# GEMINI HANDOFF: Remaining Bug Fixes

**Date:** 2026-01-20
**Priority:** MEDIUM
**Scope:** 3 bugs pendientes + 1 mejora de integración
**Estimated Effort:** 1-2 horas
**Author:** Claude (Code Review Session)

---

## ✅ BUGS YA CORREGIDOS (No tocar)

| Bug | Archivo | Estado |
|-----|---------|--------|
| Bug #2: NameError verifier.py | `_make_result()` definida en línea 185 | ✅ FIXED |
| Bug #3: NameError interactsh.py | `dashboard` importado en línea 17 | ✅ FIXED |
| Bug #5: Race condition payload_learner.py | `filelock` implementado líneas 84-95 | ✅ FIXED |
| Bug #6: Memory leak verifier.py | `finally` block líneas 430-439 | ✅ FIXED |
| Bug #7: OOB Polling corto | `poll_interactions()` líneas 248-267 | ✅ FIXED |

---

## 🐛 BUG #1: CÓDIGO DUPLICADO EN csti.py (MENOR)

### Ubicación
**Archivo:** `bugtrace/tools/exploitation/csti.py`
**Líneas:** 11-25

### Problema
No hay duplicados reales, pero el archivo `csti.py` es **LEGACY** ahora que existe `CSTIAgent`.

### Decisión Requerida

**OPCIÓN A (Recomendada): Eliminar archivo legacy**
```bash
# El CSTIAgent en bugtrace/agents/csti_agent.py reemplaza esta funcionalidad
rm bugtrace/tools/exploitation/csti.py
```

**OPCIÓN B: Mantener como fallback**
Si se quiere mantener, actualizar los imports en cualquier código que lo use para usar `CSTIAgent` en su lugar.

### Verificación
```bash
# Buscar usos de csti_detector
grep -r "csti_detector" bugtrace/
grep -r "from bugtrace.tools.exploitation.csti" bugtrace/
```

---

## 🐛 BUG #4: EncodingAgent usa strategies incorrectamente (IMPORTANTE)

### Ubicación
**Archivo:** `bugtrace/tools/manipulator/specialists/implementations.py`
**Líneas:** 119-135

### Problema
El `EncodingAgent` obtiene `selected_strategies` del `strategy_router` (lista de nombres de técnicas), pero luego llama a `encoding_techniques.encode_payload()` pasando el nombre del WAF, no las estrategias específicas.

El `encode_payload()` ignora las estrategias seleccionadas y usa su propia lógica basada en WAF.

### Código actual (INEFICIENTE)
```python
# Línea 99-100: Obtiene strategies del router
_, self.selected_strategies = await strategy_router.get_strategies_for_target(request.url)
# selected_strategies = ["unicode_encode", "html_entity_hex", "case_mixing", ...]

# Línea 122-126: Pero las ignora y usa WAF name
encoded_variants = encoding_techniques.encode_payload(
    payload=str(v),
    waf=self.detected_waf,      # ← Usa WAF name
    max_variants=len(self.selected_strategies)  # ← Solo usa el COUNT
)
```

### FIX REQUERIDO

**Opción A: Usar strategies directamente**

```python
async def generate_mutations(
    self,
    request: MutableRequest,
    strategies: List[MutationStrategy]
) -> AsyncIterator[MutableRequest]:
    """
    Generate encoded mutations using intelligent strategy selection.
    """
    if MutationStrategy.BYPASS_WAF not in strategies:
        return

    # Ensure we have strategies
    if not self.selected_strategies:
        await self.analyze(request)

    # Generate encoded variants for each parameter value
    for k, v in request.params.items():
        # Apply SPECIFIC strategies from router (not generic WAF-based)
        for i, strategy_name in enumerate(self.selected_strategies):
            try:
                # Get the specific encoding technique
                technique = encoding_techniques.get_technique_by_name(strategy_name)
                if technique:
                    encoded_value = technique.encoder(str(v))

                    if encoded_value != str(v):  # Only if encoding changed something
                        mutation = copy.deepcopy(request)
                        mutation.params[k] = encoded_value
                        mutation._encoding_strategy = strategy_name
                        yield mutation
            except Exception as e:
                logger.debug(f"Encoding with {strategy_name} failed: {e}")
```

**Opción B: Añadir método a EncodingTechniques**

En `bugtrace/tools/waf/encodings.py`, añadir:

```python
def get_technique_by_name(self, name: str) -> Optional[EncodingTechnique]:
    """Get a specific encoding technique by name."""
    for tech in self.techniques:
        if tech.name == name:
            return tech
    return None

def encode_with_strategies(
    self,
    payload: str,
    strategy_names: List[str]
) -> List[Tuple[str, str]]:
    """
    Encode payload using specific strategies.

    Returns:
        List of (encoded_payload, strategy_name) tuples
    """
    results = []
    for name in strategy_names:
        tech = self.get_technique_by_name(name)
        if tech:
            try:
                encoded = tech.encoder(payload)
                if encoded != payload:
                    results.append((encoded, name))
            except Exception:
                pass
    return results
```

### Verificación
```bash
# Test que EncodingAgent usa las strategies correctas
python3 -c "
from bugtrace.tools.waf.encodings import encoding_techniques
tech = encoding_techniques.get_technique_by_name('unicode_encode')
print(f'Technique: {tech.name if tech else None}')
print(f'Result: {tech.encoder(\"<script>\") if tech else None}')
"
```

---

## ⚡ MEJORA: Limpiar imports en XSSAgent

### Ubicación
**Archivo:** `bugtrace/agents/xss_agent.py`
**Líneas:** 400-402

### Problema
Variables `detected_waf` y `status_code` se usan sin estar definidas previamente en el scope.

### Código actual (WARNING)
```python
# Línea 400-402
probe_result = ProbeResult(
    ...
    waf_name=detected_waf if 'detected_waf' in locals() else None,  # ← detected_waf nunca definida
    ...
    status_code=status_code if 'status_code' in locals() else 200   # ← status_code nunca definida
)
```

### FIX REQUERIDO

```python
# Añadir estas líneas ANTES de crear ProbeResult (alrededor de línea 395):

# Get WAF info if available
detected_waf = None
status_code = 200

if waf_detected:
    # Try to fingerprint the specific WAF
    from bugtrace.tools.waf import waf_fingerprinter
    try:
        detected_waf, _ = await waf_fingerprinter.detect(self.url)
    except:
        pass

# Build probe result from analysis phase
probe_result = ProbeResult(
    reflected=context_data.get("reflected", False),
    surviving_chars=surviving_chars,
    waf_detected=waf_detected or context_data.get("is_blocked", False),
    waf_name=detected_waf,
    context=reflection_type,
    status_code=status_code
)
```

---

## ✅ CHECKLIST DE VERIFICACIÓN

```bash
# 1. Verificar sintaxis
python3 -m py_compile bugtrace/tools/manipulator/specialists/implementations.py
python3 -m py_compile bugtrace/tools/waf/encodings.py
python3 -m py_compile bugtrace/agents/xss_agent.py

# 2. Verificar imports
python3 -c "
from bugtrace.tools.manipulator.specialists.implementations import EncodingAgent
from bugtrace.tools.waf.encodings import encoding_techniques
from bugtrace.agents.xss_agent import XSSAgent
print('✅ All imports OK')
"

# 3. Test EncodingAgent con strategy_router
python3 -c "
import asyncio
from bugtrace.tools.waf import strategy_router, encoding_techniques

async def test():
    waf, strategies = await strategy_router.get_strategies_for_target('https://example.com')
    print(f'WAF: {waf}')
    print(f'Strategies: {strategies}')

    # Verify we can get technique by name
    for s in strategies[:3]:
        tech = encoding_techniques.get_technique_by_name(s)
        print(f'  {s}: {\"OK\" if tech else \"MISSING\"}')

asyncio.run(test())
"
```

---

## 📊 RESUMEN

| Bug/Mejora | Prioridad | Esfuerzo |
|------------|-----------|----------|
| Bug #1: csti.py legacy | BAJA | 5 min (decidir si eliminar) |
| Bug #4: EncodingAgent strategies | **ALTA** | 30 min |
| Mejora: XSSAgent variables | MEDIA | 15 min |

---

**Total estimado:** 1 hora

**Orden recomendado:**
1. Bug #4 (EncodingAgent) - Más impacto
2. Mejora XSSAgent - Evita warnings
3. Bug #1 - Decisión sobre legacy code

---

**Handoff creado por:** Claude (Opus 4.5)
**Fecha:** 2026-01-20
