# Expert Deduplication Template for All Specialist Agents

## Pattern to Apply

### 1. Add to `__init__`:
```python
# Expert deduplication: Track emitted findings by fingerprint
self._emitted_findings: set = set()  # Agent-specific fingerprint
```

### 2. Create fingerprint method (customize per agent):
```python
def _generate_<vuln_type>_fingerprint(self, <params>) -> tuple:
    """
    Generate fingerprint for expert deduplication.

    Rules:
    - URL params: URL-specific (include path)
    - Cookies/Headers: Global (ignore URL)
    - Endpoints: Endpoint-specific (normalize path, remove query)

    Returns:
        Tuple fingerprint for deduplication
    """
    from urllib.parse import urlparse

    # Custom logic per vulnerability type
    # Example for SSRF:
    parsed = urlparse(url)
    return ("SSRF", parsed.netloc, parsed.path.rstrip('/'), parameter.lower())
```

### 3. Add deduplication check in `_handle_queue_result`:
```python
# EXPERT DEDUPLICATION: Check if we already emitted this finding
fingerprint = self._generate_<vuln_type>_fingerprint(...)

if fingerprint in self._emitted_findings:
    logger.info(f"[{self.name}] Skipping duplicate finding: {url} (already reported)")
    return

# Mark as emitted
self._emitted_findings.add(fingerprint)

# Emit vulnerability_detected event...
```

---

## Agent-Specific Fingerprint Rules

### SSRF
```python
# URL-specific + parameter-specific
("SSRF", netloc, path, parameter, callback_domain)
```

### RCE
```python
# URL-specific + parameter-specific
("RCE", netloc, path, parameter)
```

### LFI
```python
# URL-specific + parameter-specific
("LFI", netloc, path, parameter)
```

### CSTI (Client/Server Template Injection)
```python
# URL-specific + parameter-specific + template_type
("CSTI", netloc, path, parameter, template_engine)
```

### Open Redirect
```python
# URL-specific + parameter-specific
("OPEN_REDIRECT", netloc, path, parameter)
```

### IDOR
```python
# Endpoint-specific (different endpoints = different bugs)
("IDOR", netloc, path, resource_type)
```

### JWT
```python
# Token-specific (different tokens = different bugs)
("JWT", netloc, vulnerability_type)  # e.g., "none_alg", "weak_secret"
```

### Prototype Pollution
```python
# Endpoint-specific
("PROTO_POLLUTION", netloc, path, parameter)
```

### Header Injection
```python
# Header-specific (global)
("HEADER_INJECTION", header_name.lower())
```

---

## Implementation Status

| Agent | Status | Fingerprint Logic |
|-------|--------|-------------------|
| **XXEAgent** | ✅ Done | Endpoint-specific (ignores query params) |
| **SQLiAgent** | ✅ Done | Cookie=global, URL param=URL-specific |
| **XSSAgent** | ✅ Done | URL+param+context specific |
| **SSRFAgent** | ⏳ Pending | URL+param+callback domain |
| **RCEAgent** | ⏳ Pending | URL+param specific |
| **LFIAgent** | ⏳ Pending | URL+param specific |
| **CSTIAgent** | ⏳ Pending | URL+param+template engine |
| **OpenRedirectAgent** | ⏳ Pending | URL+param specific |
| **IDORAgent** | ⏳ Pending | Endpoint+resource type |
| **JWTAgent** | ⏳ Pending | Token+vuln type |
| **PrototypePollutionAgent** | ⏳ Pending | Endpoint+param |
| **HeaderInjectionAgent** | ⏳ Pending | Header name (global) |

---

**Created:** 2026-02-02
**Purpose:** Standardize expert deduplication across all specialist agents
