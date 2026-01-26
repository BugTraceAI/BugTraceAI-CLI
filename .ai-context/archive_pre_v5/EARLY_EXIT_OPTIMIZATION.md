# Early Exit Optimization - XSS/SQLi Agents

**Fecha**: 2026-01-14T19:27:00+01:00  
**Usuario**: Identificó ineficiencia  
**Problema**: Agents prueban múltiples payloads innecesariamente después de encontrar vulnerabilidad

---

## 🐛 Problema Identificado

### Caso Actual

```python
# URL: http://example.com/search?q=test&page=1&sort=asc

# X SSAgent:
for param in ["q", "page", "sort"]:
    for payload in GOLDEN_PAYLOADS:  # 15 payloads
        if xss_found(param, payload):
            save_finding()
            break  # ← ROMPE del loop de payloads ✅
    # ← Pero NO rompe del loop de parámetros ❌
    # Sigue probando "page" y "sort" innecesariamente
```

**Resultado ineficiente**:

- Encuentra XSS en `q` con payload #3
- ✅ Para de probar payloads en `q` (correcto)
- ❌ Sigue probando `page` con 15 payloads (innecesario)
- ❌ Sigue probando `sort` con 15 payloads (innecesario)

**Total**: 3 + 15 + 15 = **33 requests** cuando solo necesitaba **3**

---

## 💡 Solución: Early Exit Strategies

### Opción 1: Stop on First Finding (Agresivo)

**Filosofía**: Si encontraste XSS en UN parámetro, la URL es vulnerable. No necesitas probar más.

```python
# bugtrace/agents/xss_agent.py

async def run_loop(self) -> Dict:
    ...
    for param in self.params:
        finding = await self._test_parameter(param, ...)
        if finding:
            self.findings.append(finding)
            dashboard.log(f"[{self.name}] 🎯 XSS CONFIRMED on '{param}'! Stopping test on this URL.", "SUCCESS")
            break  # ← EARLY EXIT ✅
    ...
```

**Ventajas**:

- ⚡ Mucho más rápido (10-30x en URLs con muchos params)
- 💰 Más barato (menos API calls)
- 🔇 Menos ruido en WAFs

**Desventajas**:

- ⚠️ Podrías perder findings en otros parámetros
  - Ejemplo: `q` tiene XSS, pero `comment` tiene un XSS más crítico (stored)

**Recomendación**: ✅ Usar esta para **scans automáticos completos**

---

### Opción 2: Stop Per Parameter (Moderado) ← **YA IMPLEMENTADO**

```python
for param in self.params:
    for payload in GOLDEN_PAYLOADS:
        if xss_found(param, payload):
            break  # ← Para de probar más payloads en ESTE param
    # Continúa con siguiente param
```

**Estado actual**: ✅ **YA IMPLEMENTADO** (línea 290: `return` sale del loop de payloads)

**Ventajas**:

- Testa todos los parámetros
- No desperdicia payloads en un param ya explotado

**Desventajas**:

- Sigue probando parámetros que probablemente tengan la misma vuln

---

### Opción 3: Intelligent Early Exit (Balanceado)

**Filosofía**: Para si encontraste N findings, o si el parámetro es "obvio" duplicate.

```python
MAX_FINDINGS_PER_URL = 3  # Config

async def run_loop(self) -> Dict:
    ...
    for param in self.params:
        if len(self.findings) >= MAX_FINDINGS_PER_URL:
            dashboard.log(f"[{self.name}] ✅ Reached max findings ({MAX_FINDINGS_PER_URL}). Stopping.", "INFO")
            break  # ← EARLY EXIT after N findings
            
        finding = await self._test_parameter(param, ...)
        if finding:
            self.findings.append(finding)
    ...
```

**Ventajas**:

- ⚡ Rápido (para después de N findings)
- 🎯 Detecta múltiples vectors diferentes
- 🔍 No pierde findings críticos

**Desventajas**:

- Configuración adicional (MAX_FINDINGS_PER_URL)

---

## 📊 Comparación de Performance

### Escenario de Test

**URL**: `http://example.com/search?q=1&page=1&sort=asc&filter=all&category=news`  
**Parámetros**: 5  
**Payloads por param**: 15 (GOLDEN_PAYLOADS)  
**XSS vulnerable**: `q` (payload #3 funciona)

| Estrategia | Requests | Tiempo | Costo | Findings |
|------------|----------|--------|-------|----------|
| **Sin optimización** | 75 (5×15) | ~3 min | $0.015 | 5 (todos iguales) |
| **Opción 1 (Stop on First)** | 3 | ~10 seg | $0.001 | 1 |
| **Opción 2 (Stop Per Param)** | 15 (3+15+15+...) | ~45 seg | $0.005 | 1 |
| **Opción 3 (Max N)** | 9 (3+3+3) | ~25 seg | $0.003 | 3 |

**Ganancia de Opción 1 vs Sin optimización**:

- ⚡ **18x más rápido**
- 💰 **15x más barato**

---

## 🛠️ Implementación Recomendada

### Para XSS Agent

```python
# bugtrace/agents/xss_agent.py (línea 172)

# ANTES
for param in self.params:
    finding = await self._test_parameter(param, interactsh_domain, screenshots_dir)
    if finding:
        self.findings.append(finding)
        dashboard.log(f"[{self.name}] 🎯 XSS CONFIRMED on '{param}'!", "SUCCESS")

# DESPUÉS (Opción 1: Early Exit)
for param in self.params:
    finding = await self._test_parameter(param, interactsh_domain, screenshots_dir)
    if finding:
        self.findings.append(finding)
        dashboard.log(f"[{self.name}] 🎯 XSS CONFIRMED on '{param}'!", "SUCCESS")
        dashboard.log(f"[{self.name}] ⚡ Early exit: XSS found, skipping remaining {len(self.params) - self.params.index(param) - 1} params", "INFO")
        break  # ← EARLY EXIT ✅
```

### Para SQLi Agent

Misma lógica:

```python
# bugtrace/agents/sqli_agent.py

for param in self.params:
    finding = await self._test_sql_injection(param)
    if finding:
        self.findings.append(finding)
        logger.info(f"SQLi found in {param}, stopping further tests on this URL")
        break  # ← EARLY EXIT ✅
```

---

## ⚙️ Configuración Flexible

**Añadir a `bugtraceaicli.conf`**:

```ini
[OPTIMIZATION]
# Early exit after first finding per URL
EARLY_EXIT_ON_FINDING = true

# Max findings per URL (0 = unlimited)
MAX_FINDINGS_PER_URL = 3

# Stop testing params after N consecutive fails
MAX_CONSECUTIVE_FAILS = 5
```

**Código**:

```python
from bugtrace.core.config import settings

# In run_loop()
for param in self.params:
    finding = await self._test_parameter(...)
    
    if finding:
        self.findings.append(finding)
        
        if settings.EARLY_EXIT_ON_FINDING:
            break  # ← Config-driven early exit
            
    if settings.MAX_FINDINGS_PER_URL > 0:
        if len(self.findings) >= settings.MAX_FINDINGS_PER_URL:
            break
```

---

## 🎯 Recomendación Final

**Para scans de producción**: Usar **Opción 1 (Stop on First)**

**Razones**:

1. ⚡ 10-30x más rápido
2. 💰 10-30x más barato
3. 🎯 Un XSS es suficiente para reportar la URL vulnerable
4. 🔄 Si el cliente quiere coverage completo, puede escanear específicamente ese URL con `EARLY_EXIT=false`

**Para testing/Dojo**: Usar config `EARLY_EXIT_ON_FINDING = false`

---

## 📝 Testing

```bash
# Test con Early Exit (rápido)
EARLY_EXIT_ON_FINDING=true ./bugtraceai-cli http://testphp.vulnweb.com

# Test sin Early Exit (completo, para benchmarking)
EARLY_EXIT_ON_FINDING=false ./bugtraceai-cli http://testphp.vulnweb.com
```

---

**Status**: 📋 Propuesta documentada  
**Next**: Implementar en XSSAgent y SQLiAgent  
**Expected Impact**: 10-30x speed improvement en URLs con múltiples params
