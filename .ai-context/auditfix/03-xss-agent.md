# XSS Agent - Audit Fix Tasks

## Feature Overview
The XSS Agent detects Cross-Site Scripting vulnerabilities using:
- **Browser Automation**: Playwright/CDP for JavaScript execution
- **Vision AI Validation**: Screenshot analysis to verify visual proof
- **Reflection Detection**: DOM-based and reflected XSS
- **Context-Aware Payloads**: HTML, attribute, script context detection

---

## 🔴 CRITICAL Tasks (2)

### TASK-49: Fix Browser/CDP Resource Leak
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/agents/xss_agent.py:84-153`
**Issue**: Browser pages not guaranteed to close on exception
**Impact**: System exhaustion after 100+ scans, ports/memory leak

**Current Code**:
```python
# Lines 84-153
page = await browser_manager.get_page()
try:
    await page.goto(url)
    # ... operations
except Exception as e:
    logger.error(f"Error: {e}")
    # Page never closed on error!
```

**Proposed Fix**:
```python
page = None
try:
    page = await browser_manager.get_page()
    await page.goto(url)
    # ... operations
finally:
    if page:
        try:
            await page.close()
        except Exception as e:
            logger.error(f"Failed to close page: {e}")
```

**Additional Fix - Context Manager**:
```python
# Better approach: Create context manager
class BrowserPage:
    def __init__(self, browser_manager):
        self.browser_manager = browser_manager
        self.page = None

    async def __aenter__(self):
        self.page = await self.browser_manager.get_page()
        return self.page

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.page:
            await self.page.close()

# Usage
async with BrowserPage(browser_manager) as page:
    await page.goto(url)
    # Automatically closed even on exception
```

**Verification**:
1. Run 200 XSS tests with random errors injected
2. Monitor open file descriptors: `lsof -p <pid> | wc -l`
3. Verify no growth over time

**Priority**: P0 - Fix immediately

---

### TASK-50: Fix Concurrent Parameter Testing Race
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/agents/xss_agent.py`
**Issue**: No locking on `self._tested_params` set (if used)
**Impact**: Duplicate testing or missed detection

**Proposed Fix**:
```python
class XSSAgent:
    def __init__(self):
        self._tested_params = set()
        self._tested_params_lock = asyncio.Lock()

    async def should_test_param(self, param):
        async with self._tested_params_lock:
            if param in self._tested_params:
                return False
            self._tested_params.add(param)
            return True
```

**Priority**: P0 - Fix immediately

---

## 🟠 HIGH Priority Tasks (5)

### TASK-51: Add CDP Console Event Listener Cleanup ✅ COMPLETED
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/cdp_client.py`
**Issue**: Console event listeners not removed after test
**Status**: ✅ COMPLETED (2026-01-26)

**Implementation**: Fixed in `CDPClient.stop()` method:
- Added `self._listeners.clear()` to clear all CDP event listeners
- Added `self._pending_responses.clear()` with future cancellation to prevent memory leaks
- Added `self._console_logs.clear()` and `self._network_requests.clear()` for state cleanup
- Also fixed RCE vulnerability: replaced `shell=True` subprocess calls with list arguments

**Priority**: P1 - Fix within 1 week

---

### TASK-52: Add XSS Context Detection Validation
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/xss_agent.py`
**Issue**: Context detection may be incorrect, leading to wrong payloads

**Proposed Fix**:
```python
def detect_context(self, reflection):
    contexts = []

    # HTML context
    if re.search(r'<[^>]*' + re.escape(reflection) + r'[^>]*>', html):
        contexts.append("HTML")

    # Attribute context
    if re.search(r'<[^>]+\s\w+=["\']?[^"\']*' + re.escape(reflection), html):
        contexts.append("ATTRIBUTE")

    # Script context
    if re.search(r'<script[^>]*>.*?' + re.escape(reflection), html, re.DOTALL):
        contexts.append("SCRIPT")

    # URL context
    if re.search(r'href=["\']?[^"\']*' + re.escape(reflection), html):
        contexts.append("URL")

    return contexts

# Test all detected contexts
for context in contexts:
    await self.test_payload_for_context(context, reflection)
```

**Priority**: P1 - Fix within 1 week

---

### TASK-53: Add Vision Validation Retry Logic
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/xss_agent.py`
**Issue**: Vision model fails due to transient errors

**Proposed Fix**:
```python
async def validate_with_vision(self, screenshot_path, max_retries=3):
    for attempt in range(max_retries):
        try:
            result = await llm_client.analyze_screenshot(screenshot_path)
            return result
        except httpx.TimeoutError:
            if attempt == max_retries - 1:
                raise
            logger.warning(f"Vision validation timeout, retry {attempt + 1}/{max_retries}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
```

**Priority**: P1 - Fix within 1 week

---

### TASK-54: Add XSS Payload Encoding
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/xss_agent.py`
**Issue**: Payloads not URL-encoded, causing false negatives

**Proposed Fix**:
```python
from urllib.parse import quote

def prepare_payload(self, payload, context):
    if context == "URL":
        return quote(payload)
    elif context == "HTML_ATTRIBUTE":
        return html.escape(payload, quote=True)
    return payload
```

**Priority**: P1 - Fix within 1 week

---

### TASK-55: Add DOM XSS Detection
**Severity**: 🟠 HIGH
**File**: `bugtrace/agents/xss_agent.py`
**Issue**: Only reflected XSS detected, DOM XSS missed

**Proposed Fix**:
```python
async def detect_dom_xss(self, page, payload):
    # Inject DOM XSS taint tracking
    await page.evaluate("""
        window.__xss_sources__ = [];

        // Override location.hash
        const originalHash = Object.getOwnPropertyDescriptor(Location.prototype, 'hash');
        Object.defineProperty(Location.prototype, 'hash', {
            get: function() {
                window.__xss_sources__.push('location.hash');
                return originalHash.get.call(this);
            }
        });

        // Override innerHTML setter
        const originalSetInnerHTML = Element.prototype.__lookupSetter__('innerHTML');
        Element.prototype.__defineSetter__('innerHTML', function(value) {
            if (window.__xss_sources__.length > 0) {
                console.log('DOM_XSS_DETECTED:', window.__xss_sources__);
            }
            return originalSetInnerHTML.call(this, value);
        });
    """)

    # Set payload in hash
    await page.goto(f"{url}#{payload}")

    # Check for DOM XSS
    sources = await page.evaluate("window.__xss_sources__")
    return len(sources) > 0
```

**Priority**: P1 - Fix within 2 weeks

---

## 🟡 MEDIUM Priority Tasks (6)

### TASK-56: Add XSS Payload Mutation
**Severity**: 🟡 MEDIUM
**Issue**: Static payloads easily blocked by WAF

**Proposed Fix**: Use mutation model to generate variations
**Priority**: P2 - Fix before release

---

### TASK-57: Add CSP Bypass Detection
**Severity**: 🟡 MEDIUM
**Issue**: XSS may be blocked by CSP, not detected

**Proposed Fix**: Parse CSP header and test for bypasses
**Priority**: P2 - Fix before release

---

### TASK-58: Add Screenshot Diff Analysis
**Severity**: 🟡 MEDIUM
**Issue**: Vision model may miss subtle changes

**Proposed Fix**:
```python
# Compare before/after screenshots
from PIL import Image
import imagehash

hash_before = imagehash.average_hash(Image.open(screenshot_before))
hash_after = imagehash.average_hash(Image.open(screenshot_after))

diff = hash_after - hash_before
if diff > threshold:
    # Visual change detected
    return True
```

**Priority**: P2 - Fix before release

---

### TASK-59: Add XSS Confirmation via Alert
**Severity**: 🟡 MEDIUM
**Issue**: Reflection doesn't guarantee execution

**Proposed Fix**:
```python
# Use dialog event to detect alert()
alerts = []
page.on("dialog", lambda dialog: alerts.append(dialog.message()))

await page.goto(url_with_payload)
await asyncio.sleep(1)

if alerts:
    logger.info(f"XSS confirmed via alert: {alerts}")
    return True
```

**Priority**: P2 - Fix before release

---

### TASK-60: Add XSS Severity Classification
**Severity**: 🟡 MEDIUM
**Issue**: All XSS treated as same severity

**Proposed Fix**:
```python
def classify_xss_severity(self, context, impact):
    if context == "SCRIPT":
        return "CRITICAL"  # Direct script execution
    elif context == "HTML" and "cookie" in impact:
        return "HIGH"  # Session hijacking
    elif context == "ATTRIBUTE" and "href" in impact:
        return "HIGH"  # JavaScript URL
    else:
        return "MEDIUM"  # Reflected content
```

**Priority**: P2 - Fix before release

---

### TASK-61: Add XSS Filter Bypass Testing
**Severity**: 🟡 MEDIUM
**Issue**: No testing for XSS filter bypasses

**Priority**: P3 - Next release

---

## 🟢 LOW Priority Tasks (4)

### TASK-62: Add XSS Payload Library
**Severity**: 🟢 LOW
**Issue**: Limited payload variety

**Priority**: P4 - Technical debt

---

### TASK-63: Add XSS Mutation History
**Severity**: 🟢 LOW
**Issue**: No tracking of payload evolution

**Priority**: P4 - Technical debt

---

### TASK-64: Add Unit Tests for XSS Agent
**Severity**: 🟢 LOW
**Issue**: ~25% test coverage

**Priority**: P4 - Technical debt

---

### TASK-65: Add XSS Documentation
**Severity**: 🟢 LOW
**Issue**: Detection logic under-documented

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 17
- 🔴 Critical: 2 (Resource leak)
- 🟠 High: 5 (Detection accuracy)
- 🟡 Medium: 6 (Coverage improvements)
- 🟢 Low: 4 (Technical debt)

**Estimated Effort**: 2-3 weeks for P0-P1 tasks
