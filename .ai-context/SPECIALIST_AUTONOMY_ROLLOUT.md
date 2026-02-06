# Specialist Autonomy Rollout Plan

**Status:** 🚧 In Progress
**Completed:** XSSAgent ✅, SSRFAgent ✅
**Remaining:** 10 specialists

---

## Agents Requiring Autonomous Discovery

### ✅ COMPLETED

| Agent | Status | Date | Notes |
|-------|--------|------|-------|
| **XSSAgent** | ✅ Done | 2026-02-06 | Finds XSS in `searchTerm` (discovered from HTML form) |
| **SSRFAgent** | ✅ Done | 2026-02-06 | Discovers URL-like params (`url`, `callback`, `target`, etc.) from forms |

---

## 🔥 HIGH PRIORITY (Apply Next)

These agents frequently miss vulnerabilities because they only test URL parameters sent by DASTySAST.

### 1. SQLiAgent ⭐⭐⭐
**File:** `bugtrace/agents/sqli_agent.py`

**Why High Priority:**
- SQLi is CRITICAL severity
- Forms often have hidden parameters (e.g., `sort`, `filter`, `order_by`)
- Database queries can be triggered by ANY parameter

**Discovery Strategy:**
```python
async def _discover_sqli_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - URL query parameters
    # - HTML form inputs (<input>, <select>, <textarea>)
    # - Hidden inputs (type="hidden")
    # Skip:
    # - JS variables (not injectable for SQLi)
    # - CSRF tokens
```

**Impact:** Will find SQLi in form-only parameters like `sortBy`, `pageSize`, `itemsPerPage`

---

### 2. SSRFAgent ⭐⭐⭐
**File:** `bugtrace/agents/ssrf_agent.py`

**Why High Priority:**
- SSRF is HIGH severity
- Often in hidden/admin parameters
- Parameters like `url`, `callback`, `webhook` are rarely in URL

**Discovery Strategy:**
```python
async def _discover_ssrf_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - URL params with URL-like names: "url", "callback", "target", "redirect"
    # - Hidden inputs (type="hidden")
    # - Form inputs with URL patterns in default values
    # Priority:
    # - Params named: url, callback, target, redirect, proxy, fetch, webhook, api_url
```

**Impact:** Will find SSRF in admin callbacks, webhook URLs, API proxies

---

### 3. OpenRedirectAgent ⭐⭐
**File:** `bugtrace/agents/openredirect_agent.py`

**Why High Priority:**
- Often in `next`, `return_url`, `continue` params
- These are frequently in forms, not URL

**Discovery Strategy:**
```python
async def _discover_openredirect_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - URL params with redirect-like names
    # - Form inputs named: redirect, next, return_url, goto, continue, callback
    # - Meta refresh tags: <meta http-equiv="refresh" content="0;url=...">
    # Priority:
    # - Params named: redirect, next, return_to, return_url, goto, continue
```

**Impact:** Will find open redirects in login forms, logout flows

---

### 4. IDORAgent ⭐⭐
**File:** `bugtrace/agents/idor_agent.py`

**Why Medium-High Priority:**
- IDOR often in path segments, not query params
- IDs in forms (e.g., `user_id`, `order_id`) are common

**Discovery Strategy:**
```python
async def _discover_idor_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - URL query params
    # - Path segments: /users/123 → {"user_id": "123"}
    # - Form hidden inputs with numeric/UUID values
    # - Params ending in _id, Id, ID
    # Priority:
    # - Numeric params, UUIDs, base64 strings
```

**Impact:** Will find IDOR in RESTful paths, hidden form IDs

---

### 5. LFIAgent ⭐⭐
**File:** `bugtrace/agents/lfi_agent.py`

**Why Medium Priority:**
- LFI often in `file`, `path`, `template` params
- Forms with file selectors

**Discovery Strategy:**
```python
async def _discover_lfi_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - URL params named: file, path, template, document, page, include
    # - Form inputs with file-like defaults: "templates/header.php"
    # - Hidden inputs with path values
    # Priority:
    # - Params with file extensions in values (.php, .html, .txt)
```

**Impact:** Will find LFI in template selectors, document viewers

---

## 🟡 MEDIUM PRIORITY

### 6. RCEAgent ⭐
**File:** `bugtrace/agents/rce_agent.py`

**Why Medium Priority:**
- RCE is rare, but CRITICAL when found
- Command params often hidden

**Discovery Strategy:**
```python
async def _discover_rce_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - Params named: cmd, command, exec, run, shell, system
    # - Form inputs with command-like values
    # - Any param accepting executable patterns
```

---

### 7. CSTIAgent ⭐
**File:** `bugtrace/agents/csti_agent.py`

**Why Medium Priority:**
- Template injection in forms is common
- Email templates, notification systems

**Discovery Strategy:**
```python
async def _discover_csti_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - Form text inputs, textareas (template content)
    # - Params named: template, message, content, subject, body
    # - Check for framework detection (Angular, Vue, Jinja2)
```

---

### 8. HeaderInjectionAgent ⭐
**File:** `bugtrace/agents/header_injection_agent.py`

**Why Medium Priority:**
- Headers often set from hidden params
- Redirect headers, cache control

**Discovery Strategy:**
```python
async def _discover_header_params(self, url: str) -> Dict[str, str]:
    # Extract:
    # - Any parameter that might influence HTTP headers
    # - Params named: redirect, language, locale, encoding, charset
```

---

## 🟢 LOWER PRIORITY

### 9. PrototypePollutionAgent
**File:** `bugtrace/agents/prototype_pollution_agent.py`

**Why Lower Priority:**
- Specific to JavaScript frameworks
- Usually in JSON POST bodies, not forms

**Discovery Strategy:**
- Focus on JSON params in POST bodies
- Check for `__proto__`, `constructor` patterns

---

### 10. XXEAgent
**File:** `bugtrace/agents/xxe_agent.py`

**Why Lower Priority:**
- Requires XML upload or processing
- Less common in modern apps

**Discovery Strategy:**
- Look for `<input type="file" accept=".xml">`
- Check for XML content-type acceptance

---

### 11. FileUploadAgent
**File:** `bugtrace/agents/fileupload_agent.py`

**Why Lower Priority:**
- Already discovers from `<input type="file">`
- Less about params, more about upload endpoints

**Discovery Strategy:**
- Extract all file upload forms
- Check allowed extensions from `accept=` attribute

---

### 12. JWTAgent
**File:** `bugtrace/agents/jwt_agent.py`

**Why Lower Priority:**
- JWT is in headers/cookies, not parameters
- Discovery already handled by AuthDiscoveryAgent

**Discovery Strategy:**
- Check for JWT in cookies, Authorization header
- Look for refresh_token params in forms

---

## ❌ AGENTS THAT DON'T NEED AUTONOMY

These agents don't test parameters, so autonomous discovery doesn't apply:

| Agent | Reason |
|-------|--------|
| **DASTySASTAgent** | Coordinator, not exploiter |
| **ThinkingConsolidationAgent** | Router, not exploiter |
| **AuthDiscoveryAgent** | Discovery agent, not exploiter |
| **AssetDiscoveryAgent** | Discovery agent, not exploiter |
| **GoSpiderAgent** | Crawler, not exploiter |
| **NucleiAgent** | External tool wrapper |
| **SQLMapAgent** | External tool wrapper |
| **AgenticValidator** | Validator, not exploiter |
| **ChainDiscoveryAgent** | Meta-analysis, not exploiter |
| **APISecurityAgent** | API analyzer, not param tester |

---

## Implementation Order (Recommended)

### Phase 1: Critical Injection Attacks (Week 1)
1. ✅ **XSSAgent** - DONE
2. **SQLiAgent** - Most impactful
3. **SSRFAgent** - Often missed in hidden params
4. **RCEAgent** - Critical if found

### Phase 2: Access Control & Logic (Week 2)
5. **IDORAgent** - RESTful paths
6. **OpenRedirectAgent** - Login flows
7. **LFIAgent** - Template selectors

### Phase 3: Template & Header Attacks (Week 3)
8. **CSTIAgent** - Email templates
9. **HeaderInjectionAgent** - Hidden headers

### Phase 4: Specialized Attacks (Week 4)
10. **PrototypePollutionAgent** - JSON bodies
11. **XXEAgent** - XML uploads
12. **FileUploadAgent** - File forms

---

## Testing Requirements Per Agent

For each agent after implementing autonomy:

```bash
# 1. Find a vulnerable target with param NOT in URL
# Example: ginandjuice.shop has XSS in searchTerm (form only)

# 2. Run scan
./bugtraceai-cli https://target.com --clean

# 3. Check Phase A logs
grep "Discovered.*params" logs/execution.log
# Expected: "🔍 Discovered N params on https://target.com: ['param1', 'param2', ...]"

# 4. Check expansion
grep "Expanded.*hints.*testable" logs/execution.log
# Expected: "Expanded 1 hints → N testable params" (N > 1)

# 5. Check dedup
grep "WET → DRY" logs/execution.log
# Expected: "N WET → N DRY (0 duplicates removed)" or reasonable dedup

# 6. Verify finding
grep "Emitted.*finding" logs/execution.log
# Expected: Finding with the "hidden" parameter name

# 7. Check final report
cat reports/*/final_report.md
# Expected: Vulnerability listed with correct parameter
```

---

## Code Template for Each Agent

```python
async def _discover_<vuln>_params(self, url: str) -> Dict[str, str]:
    """
    <Vuln>-focused parameter discovery.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)
    3. [Vuln-specific sources]

    Returns:
        Dict mapping param names to default values
    """
    from bugtrace.tools.visual.browser import browser_manager
    from urllib.parse import urlparse, parse_qs
    from bs4 import BeautifulSoup

    all_params = {}

    # 1. URL query parameters
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    for param_name, values in url_params.items():
        all_params[param_name] = values[0] if values else ""

    # 2. HTML form parameters
    state = await browser_manager.capture_state(url)
    html = state.get("html", "")

    if html:
        soup = BeautifulSoup(html, "html.parser")

        # Extract from forms
        for tag in soup.find_all(["input", "textarea", "select"]):
            param_name = tag.get("name")
            if param_name and param_name not in all_params:
                # Skip non-testable types
                input_type = tag.get("type", "text").lower()
                if input_type not in ["submit", "button", "reset"]:
                    # Skip CSRF (unless testing header injection)
                    if "csrf" not in param_name.lower():
                        all_params[param_name] = tag.get("value", "")

        # 3. Vuln-specific discovery
        # [Add specialist logic here]

    logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
    return all_params
```

---

## Success Metrics

Track for each agent:

| Metric | Target | Notes |
|--------|--------|-------|
| **Discovery Rate** | >3 params per URL | HTML forms should yield multiple params |
| **Expansion Ratio** | >2x | Should expand 1 WET → 2+ DRY items |
| **Dedup Accuracy** | <30% false dedup | Keep truly different params |
| **Finding Rate** | +20% findings | Should find more vulns in "hidden" params |
| **False Positive Rate** | <5% | Autonomous discovery shouldn't increase FPs |

---

## Rollout Status

| Agent | Discovery Method | Phase A | LLM Dedup | Phase B | Tested | Status |
|-------|-----------------|---------|-----------|---------|--------|--------|
| XSSAgent | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ DONE** |
| SSRFAgent | ✅ | ✅ | ✅ | N/A | ⏳ | **✅ DONE** |
| SQLiAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| OpenRedirectAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| IDORAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| LFIAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| RCEAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| CSTIAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| HeaderInjectionAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| PrototypePollutionAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| XXEAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |
| FileUploadAgent | ❌ | ❌ | ❌ | ❌ | ❌ | 🔴 TODO |

---

**Next Action:** Implement SQLiAgent autonomous discovery (highest remaining priority)

**Reference:** See [SPECIALIST_AUTONOMY_PATTERN.md](SPECIALIST_AUTONOMY_PATTERN.md) for implementation guide

**Recent Updates:**
- 2026-02-06: SSRFAgent autonomous discovery implemented ✅

---

**Document Version:** 1.0
**Last Updated:** 2026-02-06
**Owner:** Albert + Claude
