# GEMINI HANDOFF: Specialist Agent Status Fix (CRITICAL)

**Date:** 2026-01-20  
**Priority:** CRITICAL  
**Status:** ✅ COMPLETED  
**Scope:** Fix all specialist agents to set proper `status` field

## ✅ FIXES APPLIED

| Agent | File | Status |
|-------|------|--------|
| SQLMapAgent | `sqlmap_agent.py` | ✅ DONE |
| XXEAgent | `exploit_specialists.py` | ✅ DONE |
| SSRFAgent | `ssrf_agent.py` | ✅ DONE |
| JWTAgent | `jwt_agent.py` | ✅ DONE (5 places) |
| LFIAgent | `lfi_agent.py` | ✅ DONE |
| RCEAgent | `rce_agent.py` | ✅ DONE (2 places) |

## 📊 VALIDATION RESULTS

| Metric | BEFORE | AFTER |
|--------|--------|-------|
| AgenticValidator calls | 214 | **1** |
| False positives | 205 | **0** |
| Validated findings | 18 (duplicates) | **3** (correct) |

---

## 🚨 PROBLEMA IDENTIFICADO

Los agentes especialistas (SQLMapAgent, XXEAgent, SSRFAgent, JWTAgent, LFIAgent, RCEAgent) **NO establecen el campo `status`** en sus findings. Esto causa que TODOS los findings vayan al AgenticValidator, incluso cuando el especialista ya validó con herramientas reales.

### Resultado actual

- DASTySAST genera ~400 findings
- Skeptical aprueba ~300
- Especialistas ejecutan pero NO marcan status
- **TODOS** van al AgenticValidator (que solo sabe validar XSS visualmente)
- AgenticValidator marca 205 como FALSE_POSITIVE (erróneamente)

---

## 🔧 FIX REQUERIDO

Cada agente especialista debe establecer `status` en sus findings:

```python
# Si la herramienta confirma la vulnerabilidad:
"status": "VALIDATED_CONFIRMED"

# Si la herramienta NO confirma:
# NO crear finding (simplemente no añadirlo a la lista)
```

---

## 📁 ARCHIVOS A MODIFICAR

### 1. `bugtrace/agents/sqlmap_agent.py` ✅ (YA HECHO)

- Línea ~64: Added `"status": "VALIDATED_CONFIRMED"`
- Línea ~129: Added `"status": "VALIDATED_CONFIRMED"`

### 2. `bugtrace/agents/exploit_specialists.py` (XXEAgent, ProtoAgent)

- **Línea ~108**: Cambiar:

  ```python
  # ANTES:
  "validated": True
  # DESPUÉS:
  "validated": True,
  "status": "VALIDATED_CONFIRMED"  # Specialist authority - skip AgenticValidator
  ```

### 3. `bugtrace/agents/ssrf_agent.py`

- **Línea ~180**: Añadir `"status": "VALIDATED_CONFIRMED"`

### 4. `bugtrace/agents/jwt_agent.py`

- **Líneas 357, 371, 425, 466, 561**: Añadir `"status": "VALIDATED_CONFIRMED"` a cada finding

### 5. `bugtrace/agents/lfi_agent.py`

- **Línea ~141**: Añadir `"status": "VALIDATED_CONFIRMED"`

### 6. `bugtrace/agents/rce_agent.py`

- **Líneas 67, 84**: Añadir `"status": "VALIDATED_CONFIRMED"`

### 7. `bugtrace/agents/idor_agent.py` (verificar)

- Revisar si ya tiene `status` correcto (parece que sí por `_determine_validation_status`)

---

## 📋 PATRÓN DE BÚSQUEDA

Para encontrar TODOS los lugares que necesitan el fix:

```bash
grep -n '"validated": True' bugtrace/agents/*.py
```

En cada resultado, añadir después de `"validated": True`:

```python
"status": "VALIDATED_CONFIRMED"  # Specialist authority
```

---

## ⚠️ EXCEPCIÓN: XSSAgent

**NO modificar XSSAgent** para casos donde no puede confirmar. XSS es el único tipo que necesita validación visual del AgenticValidator. XSSAgent ya tiene lógica correcta con `_determine_validation_status()`.

---

## ✅ VERIFICACIÓN

Después de aplicar el fix:

```bash
# Ejecutar scan corto
./bugtraceai-cli --clean http://127.0.0.1:5050

# Verificar que los findings de especialistas NO van al AgenticValidator
grep "AgenticValidator.*Auditing" logs/execution.log | wc -l
# Debería ser MUCHO menor (solo XSS)

# Verificar status en raw_findings
cat reports/*/raw_findings.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for f in d.get('findings', []):
    print(f'{f.get(\"type\"):10} | {f.get(\"status\", \"NO_STATUS\")}')" | sort | uniq -c
```

---

## 🎯 RESULTADO ESPERADO

| Tipo | Status después de especialista | Va a AgenticValidator? |
|------|-------------------------------|------------------------|
| SQLi | VALIDATED_CONFIRMED | ❌ NO |
| XXE | VALIDATED_CONFIRMED | ❌ NO |
| SSRF | VALIDATED_CONFIRMED | ❌ NO |
| JWT | VALIDATED_CONFIRMED | ❌ NO |
| LFI | VALIDATED_CONFIRMED | ❌ NO |
| RCE | VALIDATED_CONFIRMED | ❌ NO |
| IDOR | VALIDATED_CONFIRMED | ❌ NO |
| XSS (confirmed) | VALIDATED_CONFIRMED | ❌ NO |
| XSS (needs visual) | PENDING_VALIDATION | ✅ SÍ |
