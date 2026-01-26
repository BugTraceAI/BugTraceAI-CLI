# GEMINI HANDOFF: Go IDOR Fuzzer

**Date:** 2026-01-20  
**Priority:** MEDIUM  
**Estimated Time:** 1-2 days  
**Scope:** Create a high-performance Go tool for IDOR/ID enumeration

---

## 🎯 OBJETIVO

Crear un fuzzer IDOR en **Go** para enumerar IDs en paralelo masivo:

- Numeric IDs (1, 2, 3... 10000)
- UUID brute-force (si hay patrón)
- Hash enumeration (MD5 de IDs conocidos)
- Sequential vs Random detection

---

## 📊 IMPACTO ESPERADO

| Métrica | Python Actual | Go Propuesto | Mejora |
|---------|---------------|--------------|--------|
| IDs probados | ~100 | ~10,000+ | 100x |
| Tiempo (1000 IDs) | ~30 seg | ~1 seg | 30x más rápido |
| Detección | Manual diff | Auto-diff | Smarter |

---

## 📋 ESPECIFICACIÓN

### CLI Interface

```bash
./go-idor-fuzzer \
    -u "https://target.com/api/user?id=FUZZ" \
    -range 1-10000 \            # Numeric range
    -c 200 \                    # Concurrencia alta
    -t 3 \                      # Timeout corto
    --baseline 1 \              # ID válido conocido para comparar
    --auth "Cookie: session=abc" \
    --json
```

### Output Format

```json
{
    "metadata": {
        "target": "https://target.com/api/user?id=",
        "range": "1-10000",
        "valid_ids_found": 47,
        "duration_ms": 2500,
        "requests_per_second": 4000
    },
    "baseline": {
        "id": "1",
        "status_code": 200,
        "response_length": 512,
        "response_hash": "a1b2c3d4"
    },
    "hits": [
        {
            "id": "2",
            "status_code": 200,
            "response_length": 518,
            "is_different": true,
            "diff_type": "length_change",
            "severity": "HIGH"
        },
        {
            "id": "1337",
            "status_code": 200,
            "response_length": 1024,
            "is_different": true,
            "diff_type": "new_content",
            "contains_sensitive": ["email", "password_hash"],
            "severity": "CRITICAL"
        }
    ],
    "errors": [
        {"id": "500", "status_code": 403, "reason": "forbidden"},
        {"id": "9999", "status_code": 404, "reason": "not_found"}
    ]
}
```

---

## 🔧 MODOS DE ENUMERACIÓN

### 1. Numeric Sequential

```bash
--range 1-10000
# Tests: 1, 2, 3, ... 10000
```

### 2. Numeric with Step

```bash
--range 1-10000 --step 100
# Tests: 1, 100, 200, ... 10000 (sampling)
```

### 3. UUID Brute (si detecta patrón)

```bash
--uuid-prefix "550e8400-e29b-41d4-a716-"
# Tests last 12 hex chars
```

### 4. Hash-based

```bash
--hash-type md5 --range 1-1000
# Tests: md5("1"), md5("2"), ... md5("1000")
```

---

## 🔗 INTEGRACIÓN CON PYTHON

```python
# bugtrace/tools/external.py
async def run_go_idor_fuzzer(url: str, param: str, id_range: str = "1-1000", 
                             baseline_id: str = "1", auth_header: str = None) -> Dict:
    binary_path = settings.TOOLS_DIR / "bin" / "go-idor-fuzzer"
    
    fuzz_url = url.replace(f"{param}=", f"{param}=FUZZ")
    
    cmd = [
        str(binary_path),
        "-u", fuzz_url,
        "-range", id_range,
        "-c", "200",
        "--baseline", baseline_id,
        "--json"
    ]
    
    if auth_header:
        cmd.extend(["--auth", auth_header])
    
    # ... execute and parse JSON
```

---

## ✅ DETECCIÓN DE ÉXITO

1. **Response diff:** Length > baseline ± 10%
2. **Status code change:** 200 vs 403/404
3. **Sensitive data keywords:** email, password, ssn, credit_card, token
4. **New fields in JSON:** Campos que no estaban en baseline

---

## ⚡ OPTIMIZACIONES ESPECÍFICAS

1. **Early termination:** Si encuentra 50+ hits, puede parar
2. **Smart sampling:** Si 1-100 tiene patrón, extrapolar
3. **Rate limiting detection:** Backoff automático si 429
4. **Async DNS:** Resolver una vez, cachear

---

## 📁 FILES

| File | Action |
|------|--------|
| `tools/go-idor-fuzzer/main.go` | Create |
| `tools/go-idor-fuzzer/fuzzer/idor.go` | Create |
| `tools/go-idor-fuzzer/diff/compare.go` | Create |
| `bugtrace/agents/idor_agent.py` | Modify (integrate) |
