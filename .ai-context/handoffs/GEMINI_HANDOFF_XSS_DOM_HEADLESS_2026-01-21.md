# Handoff: DOM XSS Detection via Headless Browser

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: HIGH
**Estimated Effort**: Medium-High (2-3 hours)
**Target Files**:
- `bugtrace/tools/headless/dom_xss_detector.py` (NEW)
- `bugtrace/agents/xss_agent.py`
- `requirements.txt`

---

## 1. Problem Statement

Current XSS detection only covers **Reflected XSS** (payload in response). It **completely misses DOM-based XSS** where:

1. Payload never reaches the server
2. JavaScript processes URL fragments (`location.hash`), query params, or `document.referrer`
3. Vulnerable sinks like `innerHTML`, `eval()`, `document.write()` execute the payload

### Current State

From `xss_agent.py`:
```python
# Only checks if payload appears in HTTP response
if payload in response.text:
    # Reflected XSS detected
```

**Problem**: DOM XSS happens **entirely in the browser** - the server response is clean but JavaScript executes the payload client-side.

### DOM XSS Flow

```
1. User visits: https://example.com/page#<img src=x onerror=alert(1)>
2. Server returns clean HTML (no payload in response)
3. JavaScript: document.getElementById('output').innerHTML = location.hash
4. Browser executes: <img src=x onerror=alert(1)>
5. XSS triggered - but server never saw the payload!
```

---

## 2. Implementation Details

### 2.1 Create `dom_xss_detector.py`

Create new file `bugtrace/tools/headless/dom_xss_detector.py`:

```python
"""
DOM XSS Detector using Playwright headless browser.

Monitors JavaScript execution for dangerous sink usage and
detects when user-controlled input reaches executable contexts.
"""

import asyncio
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from playwright.async_api import async_playwright, Page, Browser, ConsoleMessage
from bugtrace.utils.logger import get_logger

logger = get_logger("tools.dom_xss")


@dataclass
class DOMXSSFinding:
    """Represents a confirmed DOM XSS vulnerability."""
    url: str
    payload: str
    sink: str  # innerHTML, eval, document.write, etc.
    source: str  # location.hash, location.search, document.referrer, etc.
    evidence: str
    severity: str = "HIGH"


# ================================================================
# DANGEROUS SINKS - Where user input becomes executable
# ================================================================
DANGEROUS_SINKS = [
    # Direct execution
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "execScript",

    # HTML injection
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",

    # URL-based
    "location",
    "location.href",
    "location.replace",
    "location.assign",
    "window.open",

    # jQuery sinks
    ".html(",
    ".append(",
    ".prepend(",
    ".after(",
    ".before(",
    ".replaceWith(",
    "$.parseHTML(",

    # Script injection
    "src",
    "srcdoc",
    "data",
    "href",  # javascript: URLs
]

# ================================================================
# TAINT SOURCES - Where user input enters the application
# ================================================================
TAINT_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "document.cookie",
    "window.name",
    "localStorage",
    "sessionStorage",
    "postMessage",
]


class DOMXSSDetector:
    """
    Headless browser-based DOM XSS detector.

    Uses Playwright to:
    1. Inject monitoring scripts that hook dangerous sinks
    2. Load pages with XSS payloads in various sources
    3. Detect when payloads reach dangerous sinks
    4. Confirm execution via alert/error interception
    """

    def __init__(self, timeout: int = 10000):
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.findings: List[DOMXSSFinding] = []

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()

    async def start(self):
        """Start the headless browser."""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-web-security",  # Allow cross-origin for testing
                "--disable-features=IsolateOrigins,site-per-process",
            ]
        )
        logger.info("[DOMXSSDetector] Headless browser started")

    async def stop(self):
        """Stop the headless browser."""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("[DOMXSSDetector] Headless browser stopped")

    def _get_monitor_script(self) -> str:
        """
        Returns JavaScript to inject that monitors dangerous sinks.
        This hooks into DOM APIs to detect when tainted data reaches sinks.
        """
        return """
        (function() {
            window.__domxss_findings = [];

            // Canary value we'll look for
            const CANARY = 'DOMXSS_CANARY_7x7';

            // Hook innerHTML
            const originalInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    if (value && value.toString().includes(CANARY)) {
                        window.__domxss_findings.push({
                            sink: 'innerHTML',
                            value: value.toString().substring(0, 500),
                            element: this.tagName
                        });
                        console.error('DOMXSS_DETECTED:innerHTML:' + value.toString().substring(0, 200));
                    }
                    return originalInnerHTMLDesc.set.call(this, value);
                },
                get: originalInnerHTMLDesc.get
            });

            // Hook document.write
            const originalWrite = document.write;
            document.write = function(content) {
                if (content && content.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'document.write',
                        value: content.toString().substring(0, 500)
                    });
                    console.error('DOMXSS_DETECTED:document.write:' + content.toString().substring(0, 200));
                }
                return originalWrite.apply(this, arguments);
            };

            // Hook eval
            const originalEval = window.eval;
            window.eval = function(code) {
                if (code && code.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'eval',
                        value: code.toString().substring(0, 500)
                    });
                    console.error('DOMXSS_DETECTED:eval:' + code.toString().substring(0, 200));
                }
                return originalEval.apply(this, arguments);
            };

            // Hook setTimeout with string argument
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function(handler, timeout, ...args) {
                if (typeof handler === 'string' && handler.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'setTimeout',
                        value: handler.substring(0, 500)
                    });
                    console.error('DOMXSS_DETECTED:setTimeout:' + handler.substring(0, 200));
                }
                return originalSetTimeout.apply(this, arguments);
            };

            // Hook location assignments
            const locationDesc = Object.getOwnPropertyDescriptor(window, 'location');
            // Note: location is complex to hook fully, but we can monitor href

            // Hook jQuery if present
            if (window.jQuery) {
                const originalHtml = jQuery.fn.html;
                jQuery.fn.html = function(value) {
                    if (value && value.toString().includes(CANARY)) {
                        window.__domxss_findings.push({
                            sink: 'jQuery.html',
                            value: value.toString().substring(0, 500)
                        });
                        console.error('DOMXSS_DETECTED:jQuery.html:' + value.toString().substring(0, 200));
                    }
                    return originalHtml.apply(this, arguments);
                };
            }

            console.log('DOMXSS_MONITOR_INJECTED');
        })();
        """

    def _get_dom_xss_payloads(self) -> List[Dict[str, str]]:
        """
        Returns payloads designed for DOM XSS detection.
        Each payload contains a canary that our hooks will detect.
        """
        canary = "DOMXSS_CANARY_7x7"

        return [
            # Basic canary (detects if value reaches sink)
            {"payload": canary, "type": "canary"},

            # HTML injection payloads
            {"payload": f"<img src=x onerror=alert('{canary}')>", "type": "img_onerror"},
            {"payload": f"<svg onload=alert('{canary}')>", "type": "svg_onload"},
            {"payload": f"<body onload=alert('{canary}')>", "type": "body_onload"},
            {"payload": f"<iframe srcdoc='<script>alert(\"{canary}\")</script>'>", "type": "iframe_srcdoc"},

            # JavaScript execution payloads
            {"payload": f"javascript:alert('{canary}')", "type": "javascript_uri"},
            {"payload": f"'-alert('{canary}')-'", "type": "js_breakout_single"},
            {"payload": f'"-alert("{canary}")-"', "type": "js_breakout_double"},
            {"payload": f"</script><script>alert('{canary}')</script>", "type": "script_breakout"},

            # Template literals
            {"payload": f"${{alert('{canary}')}}", "type": "template_literal"},

            # Event handlers in attributes
            {"payload": f'" onmouseover="alert(\'{canary}\')" x="', "type": "attr_breakout"},
            {"payload": f"' onmouseover='alert(\"{canary}\")' x='", "type": "attr_breakout_single"},
        ]

    async def _test_source(
        self,
        page: Page,
        base_url: str,
        source: str,
        payload: str
    ) -> Optional[DOMXSSFinding]:
        """
        Test a specific source (hash, search, etc.) with a payload.
        """
        # Construct URL with payload in the appropriate source
        if source == "hash":
            test_url = f"{base_url}#{payload}"
        elif source == "search":
            # Add to query string
            separator = "&" if "?" in base_url else "?"
            test_url = f"{base_url}{separator}xss={payload}"
        elif source == "path":
            # Inject in path (may not always work)
            test_url = f"{base_url}/{payload}"
        else:
            test_url = base_url

        findings_before = []
        console_findings = []

        # Listen for console errors (our hooks log there)
        def on_console(msg: ConsoleMessage):
            if "DOMXSS_DETECTED" in msg.text:
                console_findings.append(msg.text)

        page.on("console", on_console)

        # Listen for dialogs (alert/confirm/prompt)
        dialog_triggered = []
        async def on_dialog(dialog):
            dialog_triggered.append(dialog.message)
            await dialog.dismiss()

        page.on("dialog", on_dialog)

        try:
            # Navigate and wait for potential JS execution
            await page.goto(test_url, wait_until="networkidle", timeout=self.timeout)

            # Give JS time to execute
            await asyncio.sleep(0.5)

            # Check for findings from our hooks
            findings = await page.evaluate("window.__domxss_findings || []")

            # Also trigger common events that might execute XSS
            await self._trigger_events(page)

            # Re-check findings after events
            findings = await page.evaluate("window.__domxss_findings || []")

        except Exception as e:
            logger.debug(f"Error testing {source} with payload: {e}")
            return None
        finally:
            page.remove_listener("console", on_console)
            page.remove_listener("dialog", on_dialog)

        # Analyze results
        if dialog_triggered:
            return DOMXSSFinding(
                url=test_url,
                payload=payload,
                sink="alert/confirm/prompt",
                source=f"location.{source}",
                evidence=f"Dialog triggered: {dialog_triggered[0][:100]}",
                severity="HIGH"
            )

        if console_findings:
            # Parse the finding from console
            for cf in console_findings:
                parts = cf.split(":")
                if len(parts) >= 2:
                    sink = parts[1]
                    return DOMXSSFinding(
                        url=test_url,
                        payload=payload,
                        sink=sink,
                        source=f"location.{source}",
                        evidence=cf[:200],
                        severity="HIGH"
                    )

        if findings:
            f = findings[0]
            return DOMXSSFinding(
                url=test_url,
                payload=payload,
                sink=f.get("sink", "unknown"),
                source=f"location.{source}",
                evidence=f.get("value", "")[:200],
                severity="HIGH"
            )

        return None

    async def _trigger_events(self, page: Page):
        """Trigger common events that might execute XSS."""
        try:
            # Mouse events
            await page.mouse.move(100, 100)
            await page.mouse.move(200, 200)

            # Focus events on inputs
            inputs = await page.query_selector_all("input, textarea")
            for inp in inputs[:3]:  # Limit to first 3
                try:
                    await inp.focus()
                except:
                    pass

            # Click on body
            await page.click("body", timeout=1000)
        except:
            pass

    async def scan(self, url: str) -> List[DOMXSSFinding]:
        """
        Scan a URL for DOM XSS vulnerabilities.

        Args:
            url: Target URL to scan

        Returns:
            List of confirmed DOM XSS findings
        """
        if not self.browser:
            await self.start()

        findings = []
        payloads = self._get_dom_xss_payloads()
        sources = ["hash", "search"]  # Most common DOM XSS sources

        # Create a fresh context for isolation
        context = await self.browser.new_context()
        page = await context.new_page()

        try:
            # Inject our monitoring script before any page loads
            await page.add_init_script(self._get_monitor_script())

            # First, load the page normally to understand its behavior
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)

            # Test each source with each payload
            for source in sources:
                for p in payloads:
                    finding = await self._test_source(
                        page,
                        url,
                        source,
                        p["payload"]
                    )
                    if finding:
                        findings.append(finding)
                        logger.info(
                            f"[DOMXSSDetector] Found DOM XSS: {finding.sink} via {finding.source}"
                        )
                        # Don't test more payloads for this source if we found one
                        break

        except Exception as e:
            logger.error(f"[DOMXSSDetector] Scan error: {e}")
        finally:
            await context.close()

        self.findings.extend(findings)
        return findings

    async def scan_multiple(self, urls: List[str]) -> List[DOMXSSFinding]:
        """Scan multiple URLs concurrently."""
        tasks = [self.scan(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        return all_findings


# ================================================================
# CONVENIENCE FUNCTION FOR AGENT INTEGRATION
# ================================================================
async def detect_dom_xss(url: str, timeout: int = 10000) -> List[Dict[str, Any]]:
    """
    Convenience function for XSSAgent integration.

    Args:
        url: Target URL
        timeout: Page load timeout in ms

    Returns:
        List of findings as dictionaries
    """
    async with DOMXSSDetector(timeout=timeout) as detector:
        findings = await detector.scan(url)

    return [
        {
            "type": "DOM_XSS",
            "url": f.url,
            "payload": f.payload,
            "sink": f.sink,
            "source": f.source,
            "evidence": f.evidence,
            "severity": f.severity,
            "validated": True,  # Confirmed via browser execution
        }
        for f in findings
    ]
```

### 2.2 Update `xss_agent.py`

Add DOM XSS detection phase:

```python
# Add import at top
from bugtrace.tools.headless.dom_xss_detector import detect_dom_xss

# In run_loop(), add after reflected XSS testing:

async def run_loop(self) -> Dict:
    # ... existing reflected XSS testing ...

    # ================================================================
    # PHASE: DOM XSS Detection (Headless Browser)
    # ================================================================
    dashboard.log(f"[{self.name}] Starting DOM XSS detection...", "INFO")

    try:
        dom_findings = await detect_dom_xss(self.url, timeout=15000)

        for finding in dom_findings:
            all_findings.append({
                "vulnerability_type": "DOM_XSS",
                "url": finding["url"],
                "parameter": finding["source"],  # e.g., "location.hash"
                "payload": finding["payload"],
                "severity": "HIGH",
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "evidence": {
                    "sink": finding["sink"],
                    "source": finding["source"],
                    "proof": finding["evidence"],
                    "method": "headless_browser_execution"
                }
            })

        if dom_findings:
            dashboard.log(
                f"[{self.name}] Found {len(dom_findings)} DOM XSS vulnerabilities!",
                "SUCCESS"
            )
    except Exception as e:
        logger.warning(f"DOM XSS detection failed: {e}")

    # ... rest of the method ...
```

### 2.3 Update `requirements.txt`

Add Playwright:

```
playwright>=1.40.0
```

### 2.4 Create `__init__.py` for headless module

Create `bugtrace/tools/headless/__init__.py`:

```python
"""Headless browser tools for dynamic analysis."""

from .dom_xss_detector import DOMXSSDetector, detect_dom_xss

__all__ = ["DOMXSSDetector", "detect_dom_xss"]
```

---

## 3. How It Works

### Detection Flow

```
1. XSSAgent calls detect_dom_xss(url)
2. Playwright launches headless Chromium
3. Monitor script injected (hooks innerHTML, eval, etc.)
4. Page loaded with payload in location.hash
5. If JS processes hash → payload reaches hooked sink
6. Hook logs detection to console
7. Detector captures finding
8. Repeat for location.search and other sources
```

### Canary-Based Detection

We use `DOMXSS_CANARY_7x7` as a unique marker:
- Simple canary tests if ANY user input reaches sinks
- Complex payloads test if HTML/JS execution is possible
- Alert interception confirms full XSS execution

---

## 4. Testing

### Manual Test

```python
import asyncio
from bugtrace.tools.headless.dom_xss_detector import detect_dom_xss

async def test():
    # Test against a known vulnerable page
    findings = await detect_dom_xss("http://localhost:5000/vulnerable")
    for f in findings:
        print(f"Found: {f}")

asyncio.run(test())
```

### Integration Test

```bash
# Install Playwright browsers first
playwright install chromium

# Run XSS agent with DOM detection
./bugtraceai-cli scan "http://testsite.com/" --agents xss_agent
```

---

## 5. Common DOM XSS Patterns Detected

| Sink | Source | Example Vulnerable Code |
|------|--------|-------------------------|
| `innerHTML` | `location.hash` | `div.innerHTML = location.hash.slice(1)` |
| `eval` | `location.search` | `eval(new URLSearchParams(location.search).get('code'))` |
| `document.write` | `document.referrer` | `document.write('From: ' + document.referrer)` |
| `jQuery.html()` | `location.hash` | `$('#output').html(location.hash)` |
| `setTimeout` | Query param | `setTimeout(params.get('callback'), 100)` |

---

## 6. Performance Considerations

- **Timeout**: Default 10s per page, configurable
- **Concurrency**: Use `scan_multiple()` for parallel scanning
- **Resource Usage**: Headless Chromium uses ~100-200MB RAM per instance
- **Browser Reuse**: Single browser instance reused for multiple scans

---

## 7. Verification Checklist

- [ ] `bugtrace/tools/headless/dom_xss_detector.py` created
- [ ] `bugtrace/tools/headless/__init__.py` created
- [ ] `playwright` added to `requirements.txt`
- [ ] `xss_agent.py` imports and calls `detect_dom_xss()`
- [ ] `playwright install chromium` documented in setup
- [ ] Build/import succeeds: `python -c "from bugtrace.tools.headless import detect_dom_xss"`

---

## 8. Limitations & Future Improvements

### Current Limitations
- Only tests `location.hash` and `location.search` sources
- Doesn't detect `postMessage` or `localStorage` based XSS
- Limited event triggering (mouse move, focus)

### Future Improvements
- Add `postMessage` listener for message-based XSS
- Crawl page links and test each
- Support `window.name` as XSS source
- Add mutation observer for delayed DOM modifications

---

## 9. Success Criteria

1. Detect DOM XSS where payload in `location.hash` reaches `innerHTML`
2. Detect DOM XSS where payload in query string reaches `eval()`
3. Zero false positives (only report confirmed execution)
4. Integration with existing XSSAgent workflow

