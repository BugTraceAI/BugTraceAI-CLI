# Handoff: Testing Tiered Validation Implementation

**Date**: 2026-01-17
**From**: Claude Opus 4.5
**To**: Claude Sonnet (Testing)
**Priority**: HIGH
**Status**: READY FOR TESTING

---

## 1. Contexto

Gemini implementó cambios críticos en los agentes especializados para resolver el problema de **demasiados falsos positivos**. Los agentes ahora usan **Tiered Validation**:

- **TIER 1 (VALIDATED_CONFIRMED)**: Prueba definitiva (OOB, SQLMap, file content)
- **TIER 2 (PENDING_VALIDATION)**: Evidencia fuerte pero necesita CDP/Auditor
- **TIER 3 (SKIP)**: Evidencia débil, no crear finding

### Archivos Modificados

| Archivo | Cambio Principal |
|---------|------------------|
| `bugtrace/agents/sqli_agent.py` | Time-based → PENDING, SQLMap → CONFIRMED |
| `bugtrace/agents/lfi_agent.py` | Sin firma → PENDING, con /etc/passwd → CONFIRMED |
| `bugtrace/agents/ssrf_agent.py` | Añadido `status` field, respuesta unclear → PENDING |
| `bugtrace/agents/idor_agent.py` | Differential → PENDING, Cookie tampering → CONFIRMED |
| `bugtrace/agents/xss_agent.py` | Sin OOB/Vision → PENDING, con Interactsh → CONFIRMED |

---

## 2. Entorno de Testing

### 2.1 Dojo Local

El dojo está en `http://127.0.0.1:5050` (o `http://127.0.0.1:5150` según configuración).

Para verificar que está corriendo:

```bash
curl -s http://127.0.0.1:5050 | head -20
```

Si no está corriendo, levantarlo:

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
# Buscar el script de inicio del dojo
ls -la lab/ scripts/
# Normalmente: python lab/dojo.py o similar
```

### 2.2 Configuración Actual

Archivo: `bugtraceaicli.conf`

Configuración relevante:
```ini
[SCAN]
MAX_DEPTH = 1
MAX_URLS = 2
MAX_CONCURRENT_URL_AGENTS = 2

[SCANNING]
STOP_ON_CRITICAL = True
MANDATORY_SQLMAP_VALIDATION = True

[OPTIMIZATION]
EARLY_EXIT_ON_FINDING = False
```

---

## 3. Plan de Testing

### Test 1: Verificar Sintaxis (Imports)

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
python -c "from bugtrace.agents.sqli_agent import SQLiAgent; print('SQLi OK')"
python -c "from bugtrace.agents.lfi_agent import LFIAgent; print('LFI OK')"
python -c "from bugtrace.agents.ssrf_agent import SSRFAgent; print('SSRF OK')"
python -c "from bugtrace.agents.idor_agent import IDORAgent; print('IDOR OK')"
python -c "from bugtrace.agents.xss_agent import XSSAgent; print('XSS OK')"
```

**Resultado esperado**: Todos imprimen "OK" sin errores.

### Test 2: Unit Test de Tiered Validation

Crear y ejecutar un test rápido:

```python
# Test inline
python3 << 'EOF'
import asyncio
from bugtrace.agents.sqli_agent import SQLiAgent

agent = SQLiAgent(url="http://test.com?id=1", param="id")

# Test TIER 1: SQLMap
status = agent._determine_validation_status("sqlmap", "error_based", {"extracted_data": True})
assert status == "VALIDATED_CONFIRMED", f"SQLMap should be CONFIRMED, got {status}"

# Test TIER 2: Time-based
status = agent._determine_validation_status("internal", "time_based", {})
assert status == "PENDING_VALIDATION", f"Time-based should be PENDING, got {status}"

# Test TIER 2: Boolean-based
status = agent._determine_validation_status("internal", "boolean_based", {})
assert status == "PENDING_VALIDATION", f"Boolean should be PENDING, got {status}"

print("✅ SQLiAgent Tiered Validation: PASS")
EOF
```

```python
# LFI Test
python3 << 'EOF'
from bugtrace.agents.lfi_agent import LFIAgent

agent = LFIAgent(url="http://test.com?file=x", param="file")

# Test TIER 1: /etc/passwd content
status = agent._determine_validation_status("root:x:0:0:root:/root:/bin/bash", "/etc/passwd")
assert status == "VALIDATED_CONFIRMED", f"passwd should be CONFIRMED, got {status}"

# Test TIER 2: No signature
status = agent._determine_validation_status("Some random content", "/etc/passwd")
assert status == "PENDING_VALIDATION", f"No signature should be PENDING, got {status}"

print("✅ LFIAgent Tiered Validation: PASS")
EOF
```

```python
# SSRF Test
python3 << 'EOF'
from bugtrace.agents.ssrf_agent import SSRFAgent

agent = SSRFAgent(url="http://test.com?url=x", param="url")

# Test TIER 1: Cloud metadata
status = agent._determine_validation_status("http://169.254.169.254", "ami-id: ami-12345")
assert status == "VALIDATED_CONFIRMED", f"Cloud metadata should be CONFIRMED, got {status}"

# Test TIER 2: Unclear response
status = agent._determine_validation_status("http://127.0.0.1", "Some HTML page")
assert status == "PENDING_VALIDATION", f"Unclear should be PENDING, got {status}"

print("✅ SSRFAgent Tiered Validation: PASS")
EOF
```

```python
# IDOR Test
python3 << 'EOF'
from bugtrace.agents.idor_agent import IDORAgent

agent = IDORAgent(url="http://test.com?id=1", param="id", original_value="1")

# Test TIER 1: Cookie tampering
status = agent._determine_validation_status("cookie_tampering", "HIGH")
assert status == "VALIDATED_CONFIRMED", f"Cookie tampering should be CONFIRMED, got {status}"

# Test TIER 1: HIGH confidence differential
status = agent._determine_validation_status("differential", "HIGH")
assert status == "VALIDATED_CONFIRMED", f"HIGH diff should be CONFIRMED, got {status}"

# Test TIER 2: MEDIUM confidence
status = agent._determine_validation_status("differential", "MEDIUM")
assert status == "PENDING_VALIDATION", f"MEDIUM diff should be PENDING, got {status}"

print("✅ IDORAgent Tiered Validation: PASS")
EOF
```

### Test 3: Scan Real contra Dojo

```bash
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI

# Ejecutar scan contra dojo
./bugtraceai-cli http://127.0.0.1:5050

# O si el CLI no está configurado:
python -m bugtrace.cli http://127.0.0.1:5050
```

**Observar**:
1. ¿Los agentes se ejecutan sin errores?
2. ¿Los findings tienen campo `status`?
3. ¿Hay mix de `VALIDATED_CONFIRMED` y `PENDING_VALIDATION`?

### Test 4: Verificar Status en Findings

Después del scan, verificar la DB:

```bash
# Buscar la DB SQLite
find . -name "*.db" -o -name "*.sqlite" 2>/dev/null

# O revisar los logs/reports
ls -la reports/
cat reports/*/findings.json 2>/dev/null | head -50
```

**Resultado esperado**:
```json
{
  "type": "SQLi",
  "status": "VALIDATED_CONFIRMED",  // o PENDING_VALIDATION
  "validated": true
}
```

### Test 5: Verificar que AgenticValidator recibe PENDING

Buscar en logs:

```bash
grep -r "PENDING_VALIDATION" logs/ 2>/dev/null | head -20
grep -r "AgenticValidator" logs/ 2>/dev/null | head -20
```

---

## 4. Criterios de Éxito

| Test | Criterio | Prioridad |
|------|----------|-----------|
| Imports | Todos los agentes importan sin error | CRÍTICO |
| Unit Tests | `_determine_validation_status` devuelve valores correctos | CRÍTICO |
| Scan Dojo | Scan completa sin crashes | ALTO |
| Status Field | Findings tienen `status` field | ALTO |
| Mix Status | Hay tanto CONFIRMED como PENDING | MEDIO |
| AgenticValidator | Recibe findings PENDING | MEDIO |

---

## 5. Problemas Conocidos

### 5.1 XSSAgent tiene error de indentación

En `xss_agent.py` línea ~406, hay un bloque `if validated:` que parece tener indentación incorrecta. Si el test falla, verificar:

```python
# Líneas 398-436 aproximadamente
if reflected or is_oob_payload:
    validated, evidence = await self._validate(...)

    finding_data = {  # <-- Esta línea puede tener mala indentación
        ...
    }

    if not self._should_create_finding(finding_data):
        continue
```

### 5.2 Playwright puede colgar

Si el test se queda colgado, verificar procesos:

```bash
ps aux | grep -E "(playwright|chromium|chrome)" | grep -v grep
pkill -f playwright  # Si es necesario
```

---

## 6. Comandos Útiles

```bash
# Ver estado del proyecto
cd /home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI
git status
git diff --stat

# Ver logs recientes
tail -f logs/*.log 2>/dev/null

# Limpiar procesos zombie
pkill -f playwright
pkill -f chromium

# Verificar dojo
curl -s http://127.0.0.1:5050 | grep -i "dojo\|bugtraceai"
```

---

## 7. Siguiente Paso Después del Testing

Si todos los tests pasan:
1. Crear handoff de vuelta confirmando el éxito
2. Proceder con **PARTE 2** del handoff original: Paralelismo en `team.py`

Si hay errores:
1. Documentar el error específico
2. Crear handoff para Gemini con los fixes necesarios

---

## 8. Archivos de Referencia

- Handoff original: `.ai-context/handoffs/GEMINI_HANDOFF_AGENT_SELECTIVITY_2026-01-17.md`
- Config: `bugtraceaicli.conf`
- Agentes: `bugtrace/agents/*.py`

---

**Firma**: Claude Opus 4.5
**Fecha**: 2026-01-17
**Nota**: Usar Sonnet para testing es más económico. Opus solo si hay problemas complejos.
