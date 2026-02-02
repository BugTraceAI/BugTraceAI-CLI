# Expert Deduplication Implementation Status - 2026-02-02

## ✅ Fully Implemented (6 agents)

These agents have **complete expert deduplication** with fingerprint methods and checks:

| # | Agent | File | Status | Commits |
|---|-------|------|--------|---------|
| 1 | XXEAgent | xxe_agent.py | ✅ Complete | 7e7a69f |
| 2 | SQLiAgent | sqli_agent.py | ✅ Complete | 7e7a69f |
| 3 | XSSAgent | xss_agent.py | ✅ Complete | 7e7a69f |
| 4 | SSRFAgent | ssrf_agent.py | ✅ Complete | 7e7a69f |
| 5 | RCEAgent | rce_agent.py | ✅ Complete | 08a48a6 |
| 6 | LFIAgent | lfi_agent.py | ✅ Complete | 08a48a6 |

## 🔨 Partially Implemented (6 agents)

These agents have `_emitted_findings` set added but need fingerprint methods and dedup checks:

| # | Agent | File | Status | What's Missing |
|---|-------|------|--------|----------------|
| 7 | CSTIAgent | csti_agent.py | ⚠️ Partial | Fingerprint method + dedup check |
| 8 | OpenRedirectAgent | openredirect_agent.py | ⚠️ Partial | Fingerprint method + dedup check |
| 9 | IDORAgent | idor_agent.py | ⚠️ Partial | Fingerprint method + dedup check |
| 10 | JWTAgent | jwt_agent.py | ⚠️ Partial | Fingerprint method + dedup check |
| 11 | PrototypePollutionAgent | prototype_pollution_agent.py | ⚠️ Partial | Fingerprint method + dedup check |
| 12 | HeaderInjectionAgent | header_injection_agent.py | ⚠️ Partial | Fingerprint method + dedup check |

---

## Implementation Pattern

Each agent needs 3 changes:

### 1. Add `_emitted_findings` set in `__init__` ✅ DONE

```python
# Expert deduplication: Track emitted findings by fingerprint
self._emitted_findings: set = set()  # Agent-specific fingerprint
```

### 2. Create fingerprint method ⚠️ TODO

```python
def _generate_<vuln>_fingerprint(self, <params>) -> tuple:
    """Generate fingerprint for expert deduplication."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')

    # Agent-specific fingerprint logic
    fingerprint = ("<VULN_TYPE>", ...)

    return fingerprint
```

### 3. Add dedup check in `_handle_queue_result` ⚠️ TODO

```python
# EXPERT DEDUPLICATION: Check if we already emitted this finding
fingerprint = self._generate_<vuln>_fingerprint(...)

if fingerprint in self._emitted_findings:
    logger.info(f"[{self.name}] Skipping duplicate finding (already reported)")
    return

# Mark as emitted
self._emitted_findings.add(fingerprint)

# Emit VULNERABILITY_DETECTED event...
```

---

## Fingerprint Logic by Agent

### CSTIAgent
```python
def _generate_csti_fingerprint(self, url: str, parameter: str, template_engine: str) -> tuple:
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    return ("CSTI", parsed.netloc, normalized_path, parameter.lower(), template_engine)
```

**Insert before:** `async def _handle_queue_result`
**Dedup check location:** After status determination, before `self.event_bus.emit`

---

### OpenRedirectAgent
```python
def _generate_openredirect_fingerprint(self, url: str, parameter: str) -> tuple:
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    return ("OPEN_REDIRECT", parsed.netloc, normalized_path, parameter.lower())
```

**Insert before:** `async def _handle_queue_result`
**Dedup check location:** After status determination, before `self.event_bus.emit`

---

### IDORAgent
```python
def _generate_idor_fingerprint(self, url: str, resource_type: str) -> tuple:
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    return ("IDOR", parsed.netloc, normalized_path, resource_type)
```

**Insert before:** `async def _handle_queue_result`
**Dedup check location:** After status determination, before `self.event_bus.emit`

---

### JWTAgent
```python
def _generate_jwt_fingerprint(self, url: str, vuln_type: str) -> tuple:
    parsed = urlparse(url)
    # JWT vulnerabilities are token-specific, not URL-specific
    return ("JWT", parsed.netloc, vuln_type)
```

**Insert before:** `async def _handle_queue_result`
**Dedup check location:** After status determination, before `self.event_bus.emit`

---

### PrototypePollutionAgent
```python
def _generate_protopollution_fingerprint(self, url: str, parameter: str) -> tuple:
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    return ("PROTOTYPE_POLLUTION", parsed.netloc, normalized_path, parameter.lower())
```

**Insert before:** `async def _handle_queue_result`
**Dedup check location:** After status determination, before `self.event_bus.emit`

---

### HeaderInjectionAgent
```python
def _generate_headerinjection_fingerprint(self, header_name: str) -> tuple:
    # Header injection is global (same header = same vuln)
    return ("HEADER_INJECTION", header_name.lower())
```

**Insert before:** `async def _handle_queue_result`
**Dedup check location:** After status determination, before `self.event_bus.emit`

---

## Next Steps

1. ✅ **Step 1/3 Complete:** Added `_emitted_findings` to all 6 agents
2. ⚠️ **Step 2/3 Pending:** Add fingerprint methods (copy-paste from above)
3. ⚠️ **Step 3/3 Pending:** Add dedup checks before `VULNERABILITY_DETECTED` emit

**Estimated time:** 10-15 minutes to complete steps 2-3 for all 6 agents

---

**Last Updated:** 2026-02-02
**Status:** 6/12 complete, 6/12 in progress (50% done)
