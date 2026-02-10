# Specialist Autonomy Pattern - Parameter Discovery Architecture

**Status:** ✅ Implemented in XSSAgent (2026-02-06)
**Next:** Apply to SQLi, SSRF, OpenRedirect, IDOR, and all other specialists

---

## Executive Summary

**Problem:** Specialists were missing vulnerabilities because they only tested parameters sent by DASTySAST.

**Solution:** Make specialists AUTONOMOUS - they discover ALL testable parameters on a URL, not just what DASTySAST sends.

**Result:** XSSAgent now finds XSS in `searchTerm` parameter even though DASTySAST only sent `category`.

---

## Architecture Philosophy

### Before (BROKEN)
```
DASTySAST analyzes URL
    ↓
DASTySAST finds suspicious param: "category"
    ↓
DASTySAST sends to XSSAgent WET queue: {"parameter": "category"}
    ↓
XSSAgent ONLY tests "category"
    ↓
❌ MISS: XSS in "searchTerm" parameter (never tested)
```

### After (CORRECT)
```
DASTySAST analyzes URL
    ↓
DASTySAST finds suspicious param: "category"
    ↓
DASTySAST sends SIGNAL to XSSAgent: "this URL is interesting"
    ↓
XSSAgent receives signal → IGNORES specific parameter
    ↓
XSSAgent does autonomous discovery:
    1. Fetch HTML with browser
    2. Extract ALL params (URL + forms + JS variables)
    3. Test EVERY discovered parameter
    ↓
✅ SUCCESS: Finds XSS in "searchTerm", "category", "email", etc.
```

---

## Core Principle

> **A finding from DASTySAST is a SIGNAL, not a constraint.**
>
> When a specialist receives a finding, it means:
> - ✅ "This URL is interesting, investigate it"
> - ❌ NOT "Only test this specific parameter"

Specialists must be **AUTONOMOUS** and discover their own attack surface.

---

## Implementation Pattern

### Step 1: Create Parameter Discovery Method

Every specialist needs a `_discover_params(url)` method that extracts ALL testable parameters for that vulnerability type.

**Example from XSSAgent:**

```python
async def _discover_xss_params(self, url: str) -> Dict[str, str]:
    """
    XSS-focused parameter discovery for a given URL.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)
    3. JavaScript variables (var x = "USER_INPUT")

    Returns:
        Dict mapping param names to default values
        Example: {"category": "Juice", "searchTerm": "", "filter": ""}

    Architecture Note:
        Specialists must be AUTONOMOUS - they discover their own attack surface.
        The finding from DASTySAST is just a "signal" that the URL is interesting.
        We IGNORE the specific parameter and test ALL discoverable params.
    """
    from bugtrace.tools.visual.browser import browser_manager
    from urllib.parse import urlparse, parse_qs
    from bs4 import BeautifulSoup
    import re

    all_params = {}

    # 1. Extract URL query parameters
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

    # 2. Fetch HTML and extract form parameters
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if html:
            soup = BeautifulSoup(html, "html.parser")

            # Extract from <input>, <textarea>, <select>
            for tag in soup.find_all(["input", "textarea", "select"]):
                param_name = tag.get("name")
                if param_name and param_name not in all_params:
                    input_type = tag.get("type", "text").lower()

                    # Skip non-testable input types
                    if input_type not in ["submit", "button", "reset"]:
                        # Skip CSRF tokens (common pattern)
                        if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                            default_value = tag.get("value", "")
                            all_params[param_name] = default_value

            # 3. Extract JavaScript variables (optional, XSS-specific)
            # Pattern: var searchText = "value";
            js_var_pattern = r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']'
            for match in re.finditer(js_var_pattern, html):
                var_name, var_value = match.groups()
                if var_name not in all_params and len(var_name) > 2:
                    all_params[var_name] = var_value

    except Exception as e:
        logger.error(f"[{self.name}] HTML parsing failed: {e}")

    logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
    return all_params
```

**Adaptation Guide for Other Specialists:**

| Specialist | Discovery Focus | Extra Sources |
|------------|----------------|---------------|
| **SQLiAgent** | All params (URL + forms) | Skip JS vars, focus on form inputs |
| **SSRFAgent** | URL params + hidden inputs | Look for `url=`, `callback=`, `target=` params |
| **OpenRedirectAgent** | URL params + meta refresh | Check `<meta http-equiv="refresh">` |
| **IDORAgent** | Numeric params + path segments | Extract `/users/123` → param: `user_id=123` |
| **LFIAgent** | File/path params | Look for `file=`, `path=`, `template=` |
| **XXEAgent** | Form file uploads | Check `<input type="file">` |

---

### Step 2: Integrate into Phase A (WET → DRY)

Modify `analyze_and_dedup_queue()` to expand each WET finding into multiple testable params.

**Template:**

```python
async def analyze_and_dedup_queue(self) -> List[Dict]:
    """Phase A: WET → DRY with autonomous parameter discovery."""

    logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
    queue = queue_manager.get_queue(self.queue_name)
    wet_findings = []

    # Drain WET queue
    while not queue.empty():
        item = await queue.get()
        wet_findings.append(item)

    logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")

    if not wet_findings:
        return []

    # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
    logger.info(f"[{self.name}] Phase A: Expanding WET findings with autonomous discovery...")
    expanded_wet_findings = []
    seen_urls = set()

    for wet_item in wet_findings:
        url = wet_item["url"]

        # Only discover params once per unique URL (avoid redundant fetches)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        try:
            # Discover ALL params on this URL
            all_params = await self._discover_params(url)  # ← Specialist-specific method

            if not all_params:
                # Fallback: keep original param if discovery fails
                logger.warning(f"[{self.name}] No params discovered on {url}, keeping original")
                expanded_wet_findings.append(wet_item)
                continue

            # Create a WET item for EACH discovered parameter
            for param_name, param_value in all_params.items():
                expanded_wet_findings.append({
                    "url": url,
                    "parameter": param_name,
                    "context": wet_item.get("context", "unknown"),
                    "finding": wet_item.get("finding", {}),  # Copy original finding
                    "scan_context": wet_item.get("scan_context", self._scan_context),
                    "_discovered": True  # Mark as autonomously discovered
                })

            logger.info(f"[{self.name}] 🔍 Expanded {url}: {len(all_params)} params discovered")

        except Exception as e:
            logger.error(f"[{self.name}] Discovery failed for {url}: {e}")
            # Fallback: keep original finding
            expanded_wet_findings.append(wet_item)

    logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints → {len(expanded_wet_findings)} testable params")

    # ========== DEDUPLICATION ==========
    try:
        dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
    except:
        dry_list = self._fallback_fingerprint_dedup(expanded_wet_findings)

    self._dry_findings = dry_list
    logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET → {len(dry_list)} DRY ({len(expanded_wet_findings)-len(dry_list)} duplicates removed)")

    return dry_list
```

---

### Step 3: Fix LLM Deduplication

The LLM dedup must understand that items with `_discovered: true` are DIFFERENT parameters, even if they share the same `finding` object.

**Update `_llm_analyze_and_dedup()` system prompt:**

```python
system_prompt = f"""You are an expert security analyst for {self.vuln_type} vulnerabilities.

## WET LIST ({len(wet_findings)} potential findings):
{json.dumps(wet_findings, indent=2)}

## DEDUPLICATION RULES

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param → DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context → DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same URL + Same param + Same context → DUPLICATE (keep best)
   - Different endpoints → DIFFERENT (keep both)

3. **Prioritization:**
   - Rank by exploitability given the tech stack
   - Remove findings unlikely to succeed

## OUTPUT FORMAT (JSON only):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "context": "...",
      "rationale": "why this is unique and exploitable",
      "attack_priority": 1-5
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}"""
```

---

### Step 4: Simplify Phase B (Exploitation)

Phase B should just attack the prepared DRY list - no discovery needed.

```python
async def exploit_dry_list(self) -> List[Dict]:
    """Phase B: Exploit prepared DRY list."""

    logger.info(f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings =====")

    validated = []

    for idx, dry_item in enumerate(self._dry_findings, 1):
        try:
            url = dry_item["url"]
            param_name = dry_item["parameter"]

            # Phase A already discovered ALL params - DRY list is ready to attack
            logger.info(f"[{self.name}] [{idx}/{len(self._dry_findings)}] Testing '{param_name}' on {url}")

            result = await self._test_single_param(url, param_name, dry_item)

            if result and result.validated:
                validated.append(result)
                self._emit_finding(result)

        except Exception as e:
            logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: {e}")

    logger.info(f"[{self.name}] Phase B complete: {len(validated)} validated")
    return validated
```

---

## Files to Modify Per Specialist

For each specialist agent (e.g., `sqli_agent.py`, `ssrf_agent.py`):

1. **Add discovery method:**
   - `_discover_<vuln>_params(url)` - Extract all testable params

2. **Modify Phase A:**
   - `analyze_and_dedup_queue()` - Expand WET items with discovered params
   - Add `_discovered: True` flag to expanded items

3. **Update LLM dedup:**
   - `_llm_analyze_and_dedup()` - Add autonomous discovery rules to prompt

4. **Fix imports:**
   - Ensure `from bugtrace.tools.visual.browser import browser_manager` (NOT `bugtrace.tools.browser_manager`)

---

## Testing Checklist

For each specialist after implementing autonomy:

- [ ] Run scan on target with known vuln in param NOT sent by DASTySAST
- [ ] Verify Phase A logs show: `🔍 Discovered N params`
- [ ] Verify Phase A logs show: `Expanded X hints → Y testable params` (Y > X)
- [ ] Verify LLM dedup keeps all discovered params (check `WET → DRY` count)
- [ ] Verify Phase B tests ALL discovered params
- [ ] Verify finding is emitted with correct parameter name
- [ ] Check final report includes the "hidden" parameter

---

## Example: Expected Logs

**Phase A:**
```
INFO [XSSAgentV4] Phase A: Drained 1 WET findings
INFO [XSSAgentV4] Phase A: Expanding WET findings with XSS-focused discovery...
INFO [XSSAgentV4] 🔍 Discovered 4 params on https://example.com: ['category', 'searchTerm', 'email', 'searchText']
INFO [XSSAgentV4] 🔍 Expanded https://example.com: 4 params discovered
INFO [XSSAgentV4] Phase A: Expanded 1 hints → 4 testable params
INFO [XSSAgentV4] LLM deduplication: Keeping all 4 params - different parameters discovered autonomously
INFO [XSSAgentV4] Phase A: 4 WET → 4 DRY (0 duplicates removed)
```

**Phase B:**
```
INFO [XSSAgentV4] ===== PHASE B: Exploiting 4 DRY findings =====
INFO [XSSAgentV4] [1/4] Testing 'category' on https://example.com
INFO [XSSAgentV4] [2/4] Testing 'searchTerm' on https://example.com
INFO [XSSAgentV4] ✅ Emitted unique XSS: https://example.com?searchTerm (context: javascript)
INFO [XSSAgentV4] [3/4] Testing 'email' on https://example.com
INFO [XSSAgentV4] [4/4] Testing 'searchText' on https://example.com
INFO [XSSAgentV4] Phase B complete: 1 validated
```

---

## Common Pitfalls

### ❌ Pitfall 1: Wrong Import Path
```python
# WRONG:
from bugtrace.tools.browser_manager import browser_manager

# CORRECT:
from bugtrace.tools.visual.browser import browser_manager
```

**Error:** `ModuleNotFoundError: No module named 'bugtrace.tools.browser_manager'`

---

### ❌ Pitfall 2: LLM Dedup Removes Discovered Params
```
Phase A: 4 WET → 1 DRY (3 duplicates removed)  ← TOO AGGRESSIVE
```

**Cause:** LLM sees same `finding` object and thinks they're duplicates.

**Fix:** Add `_discovered: true` check to dedup rules (see Step 3).

---

### ❌ Pitfall 3: Discovery Runs in Phase B
```python
# WRONG: Discovery in Phase B
async def exploit_dry_list(self):
    for item in self._dry_findings:
        params = await self._discover_params(item["url"])  # ❌ TOO LATE!
        ...

# CORRECT: Discovery in Phase A
async def analyze_and_dedup_queue(self):
    for wet_item in wet_findings:
        params = await self._discover_params(url)  # ✅ PREPARE DRY LIST
        ...
```

**Why:** Phase A prepares findings, Phase B attacks them. Discovery must happen in Phase A.

---

### ❌ Pitfall 4: Discovery Runs on Every WET Item
```python
# WRONG: Redundant fetches
for wet_item in wet_findings:
    params = await self._discover_params(wet_item["url"])  # Fetches same URL 5 times!

# CORRECT: Deduplicate URLs first
seen_urls = set()
for wet_item in wet_findings:
    if url in seen_urls:
        continue
    seen_urls.add(url)
    params = await self._discover_params(url)  # Fetch once per URL
```

---

## Specialist-Specific Discovery Patterns

### SQLiAgent
```python
async def _discover_sqli_params(self, url: str) -> Dict[str, str]:
    # Focus: URL params + form inputs
    # Skip: JS variables (not injectable for SQLi)
    # Include: All <input>, <select>, <textarea> with name=
    ...
```

### SSRFAgent
```python
async def _discover_ssrf_params(self, url: str) -> Dict[str, str]:
    # Focus: URL params with URL-like names
    # Look for: "url", "callback", "target", "redirect", "proxy", "fetch"
    # Include: Hidden inputs (often contain URLs)
    ...
```

### OpenRedirectAgent
```python
async def _discover_openredirect_params(self, url: str) -> Dict[str, str]:
    # Focus: Redirect-related params
    # Look for: "redirect", "next", "return_url", "goto", "continue"
    # Check: <meta http-equiv="refresh"> tags
    ...
```

### IDORAgent
```python
async def _discover_idor_params(self, url: str) -> Dict[str, str]:
    # Focus: Numeric/ID params
    # Extract: /users/123 → {"user_id": "123"}
    # Look for: Params with values like UUIDs, integers, base64
    ...
```

---

## Performance Considerations

**Q: Won't fetching HTML for every URL be slow?**

A: Yes, but this is acceptable because:
1. Discovery happens **once per URL** (deduplicated)
2. Browser fetch is already used in DASTySAST
3. The performance cost is offset by **finding more vulnerabilities**
4. Can be optimized with caching if needed

**Optimization (future):**
- Cache HTML from DASTySAST phase
- Share HTML between specialists for same URL
- Use static analysis for simple cases (URL params only)

---

## Success Criteria

A specialist has proper autonomy when:

✅ It discovers params from URL query strings
✅ It discovers params from HTML forms
✅ It discovers params specific to its vuln type
✅ LLM dedup respects `_discovered: true` flag
✅ Phase A expands 1 hint → N testable params
✅ Phase B tests ALL discovered params
✅ Finds vulns in params NOT sent by DASTySAST

---

## Next Steps

**Priority Order:**

1. **SQLiAgent** - High impact, similar to XSS
2. **SSRFAgent** - Often in hidden params
3. **OpenRedirectAgent** - URL params + meta refresh
4. **IDORAgent** - Path segments + numeric params
5. **LFIAgent** - File upload forms
6. **RCEAgent** - Command injection params
7. **XXEAgent** - XML upload forms
8. **PrototypePollutionAgent** - JSON params

---

## References

- Original Issue: XSS in `searchTerm` missed because DASTySAST only sent `category`
- Implementation: [bugtrace/agents/xss_agent.py](../bugtrace/agents/xss_agent.py#L3403-3469) (lines 3403-3469)
- Fix #1: Import path ([xss_agent.py:3421](../bugtrace/agents/xss_agent.py#L3421))
- Fix #2: LLM dedup rules ([xss_agent.py:3353-3358](../bugtrace/agents/xss_agent.py#L3353-3358))
- Test Results: [reports/ginandjuice.shop_20260206_074503/specialists/results/xss_results.json](../reports/ginandjuice.shop_20260206_074503/specialists/results/xss_results.json)

---

**Document Version:** 1.0
**Last Updated:** 2026-02-06
**Author:** Claude (with Albert)
**Status:** ✅ Production-ready pattern
