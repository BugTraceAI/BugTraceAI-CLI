# STOP-ON-CRITICAL IMPLEMENTATION - PATCH FOR EXPLOIT AGENT
## Apply these changes to bugtrace/agents/exploit.py

---

## 1. Add to __init__ (after line 40: self.tested_vectors = set()):

```python
# Stop-on-finding-per-type tracking
self.validated_findings = {"SQLi": set(), "XSS": set(), "CSTI": set()}

# Load config
from bugtrace.core.config import settings  
self.mandatory_sqlmap = settings.MANDATORY_SQLMAP_VALIDATION
self.skip_validated_params = settings.SKIP_VALIDATED_PARAMS
```

---

## 2. Add helper method (before _ladder_sqli, around line 180):

```python
def _get_param_key(self, url: str) -> str:
    """Extract parameter key from URL for tracking."""
    try:
        if "?" not in url:
            return f"url_{url.split('/')[-1]}"
        query = url.split("?")[1]
        if "=" in query:
            param_name = query.split("=")[0].split("&")[0]
            return f"param_{param_name}"
        return f"query_{query[:20]}"
    except:
        return f"url_{url[:30]}"
```

---

## 3. Add skip check at START of _ladder_sqli (after line 181):

```python
# Check if already validated this param for SQLi
param_key = self._get_param_key(url)
if self.skip_validated_params and param_key in self.validated_findings["SQLi"]:
    logger.info(f"[{self.name}] ⏭️ Skipping SQLi on {param_key} - already validated")
    return
```

---

## 4. Add param tracking AFTER validation passes (after line 214, before event emit):

```python
# Mark param as validated for SQLi
self.validated_findings["SQLi"].add(param_key)
logger.critical(f"[{self.name}] 🎯 SQLi VALIDATED on {param_key} - won't test SQLi on this param again")
```

---

## 5. Same for XSS in _ladder_ui_attacks:

Add at start (after line 298):
```python
param_key = self._get_param_key(url)
if self.skip_validated_params and param_key in self.validated_findings["XSS"]:
    logger.info(f"[{self.name}] ⏭️ Skipping XSS on {param_key} - already validated")
    return
```

Add after validation passes (before event emit):
```python
self.validated_findings["XSS"].add(param_key)
logger.critical(f"[{self.name}] 🎯 XSS VALIDATED on {param_key}")
```

---

## RESULT:

✅ If cat=1 has SQLi → Skip future SQLi tests on cat=2, cat=3
✅ BUT still test XSS, CSRF, etc on cat params
✅ If search=x has XSS → Skip future XSS on search
✅ BUT still test SQLi, CSTI, etc on search

❌ NO scan stop - continues finding OTHER types
❌ NO 20 payloads on same vuln - 1 validated = done
