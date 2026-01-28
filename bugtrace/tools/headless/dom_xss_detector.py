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
        self.playwright = None
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
        TASK-55: Enhanced taint tracking for DOM XSS detection.
        Monitors dangerous sinks AND tracks tainted sources.
        """
        return """
        (function() {
            window.__domxss_findings = [];
            window.__domxss_sources = [];  // TASK-55: Track tainted sources

            // Canary value we'll look for
            const CANARY = 'DOMXSS_CANARY_7x7';

            // TASK-55: Source tracking - monitor when tainted sources are accessed
            const originalHashDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'hash');
            if (originalHashDesc && originalHashDesc.get) {
                Object.defineProperty(Location.prototype, 'hash', {
                    get: function() {
                        const value = originalHashDesc.get.call(this);
                        if (value && value.includes(CANARY)) {
                            window.__domxss_sources.push({source: 'location.hash', value: value});
                        }
                        return value;
                    },
                    set: originalHashDesc.set
                });
            }

            const originalSearchDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'search');
            if (originalSearchDesc && originalSearchDesc.get) {
                Object.defineProperty(Location.prototype, 'search', {
                    get: function() {
                        const value = originalSearchDesc.get.call(this);
                        if (value && value.includes(CANARY)) {
                            window.__domxss_sources.push({source: 'location.search', value: value});
                        }
                        return value;
                    },
                    set: originalSearchDesc.set
                });
            }

            // Track document.referrer access
            const originalReferrer = Object.getOwnPropertyDescriptor(Document.prototype, 'referrer');
            if (originalReferrer && originalReferrer.get) {
                Object.defineProperty(Document.prototype, 'referrer', {
                    get: function() {
                        const value = originalReferrer.get.call(this);
                        if (value && value.includes(CANARY)) {
                            window.__domxss_sources.push({source: 'document.referrer', value: value});
                        }
                        return value;
                    }
                });
            }

            // Hook innerHTML - with source correlation
            const originalInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (originalInnerHTMLDesc) {
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'innerHTML',
                                value: value.toString().substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]  // Capture sources at time of sink
                            });
                            console.error('DOMXSS_DETECTED:innerHTML:' + value.toString().substring(0, 200));
                        }
                        return originalInnerHTMLDesc.set.call(this, value);
                    },
                    get: originalInnerHTMLDesc.get
                });
            }

            // Hook outerHTML - TASK-55: Additional sink
            const originalOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
            if (originalOuterHTMLDesc && originalOuterHTMLDesc.set) {
                Object.defineProperty(Element.prototype, 'outerHTML', {
                    set: function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'outerHTML',
                                value: value.toString().substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:outerHTML:' + value.toString().substring(0, 200));
                        }
                        return originalOuterHTMLDesc.set.call(this, value);
                    },
                    get: originalOuterHTMLDesc.get
                });
            }

            // Hook document.write
            const originalWrite = document.write;
            document.write = function(content) {
                if (content && content.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'document.write',
                        value: content.toString().substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:document.write:' + content.toString().substring(0, 200));
                }
                return originalWrite.apply(this, arguments);
            };

            // Hook document.writeln - TASK-55: Additional sink
            const originalWriteln = document.writeln;
            document.writeln = function(content) {
                if (content && content.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'document.writeln',
                        value: content.toString().substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:document.writeln:' + content.toString().substring(0, 200));
                }
                return originalWriteln.apply(this, arguments);
            };

            // Hook eval
            const originalEval = window.eval;
            window.eval = function(code) {
                if (code && code.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'eval',
                        value: code.toString().substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:eval:' + code.toString().substring(0, 200));
                }
                return originalEval.apply(this, arguments);
            };

            // Hook Function constructor - TASK-55: Additional sink
            const OriginalFunction = window.Function;
            window.Function = function(...args) {
                const code = args.join(',');
                if (code.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'Function',
                        value: code.substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:Function:' + code.substring(0, 200));
                }
                return new OriginalFunction(...args);
            };

            // Hook setTimeout with string argument
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function(handler, timeout, ...args) {
                if (typeof handler === 'string' && handler.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'setTimeout',
                        value: handler.substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:setTimeout:' + handler.substring(0, 200));
                }
                return originalSetTimeout.apply(this, arguments);
            };

            // Hook setInterval with string argument - TASK-55: Additional sink
            const originalSetInterval = window.setInterval;
            window.setInterval = function(handler, timeout, ...args) {
                if (typeof handler === 'string' && handler.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'setInterval',
                        value: handler.substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:setInterval:' + handler.substring(0, 200));
                }
                return originalSetInterval.apply(this, arguments);
            };

            // Hook jQuery if present
            if (window.jQuery) {
                const originalHtml = jQuery.fn.html;
                jQuery.fn.html = function(value) {
                    if (value && value.toString().includes(CANARY)) {
                        window.__domxss_findings.push({
                            sink: 'jQuery.html',
                            value: value.toString().substring(0, 500),
                            sources: [...window.__domxss_sources]
                        });
                        console.error('DOMXSS_DETECTED:jQuery.html:' + value.toString().substring(0, 200));
                    }
                    return originalHtml.apply(this, arguments);
                };

                // TASK-55: Hook jQuery append
                const originalAppend = jQuery.fn.append;
                jQuery.fn.append = function(value) {
                    if (value && value.toString().includes(CANARY)) {
                        window.__domxss_findings.push({
                            sink: 'jQuery.append',
                            value: value.toString().substring(0, 500),
                            sources: [...window.__domxss_sources]
                        });
                        console.error('DOMXSS_DETECTED:jQuery.append:' + value.toString().substring(0, 200));
                    }
                    return originalAppend.apply(this, arguments);
                };
            }

            console.log('DOMXSS_MONITOR_INJECTED_V2');  // Version indicator
        })();
        """

    def _get_dom_xss_payloads(self) -> List[Dict[str, str]]:
        """
        Returns payloads designed for DOM XSS detection.
        Each payload contains a canary that our hooks will detect.
        """
        canary = "DOMXSS_CANARY_7x7"

        return [
            {"payload": canary, "type": "canary"},
            {"payload": f"<img src=x onerror=alert('{canary}')>", "type": "img_onerror"},
            {"payload": f"<svg onload=alert('{canary}')>", "type": "svg_onload"},
            {"payload": f"<body onload=alert('{canary}')>", "type": "body_onload"},
            {"payload": f"<iframe srcdoc='<script>alert(\"{canary}\")</script>'>", "type": "iframe_srcdoc"},
            {"payload": f"javascript:alert('{canary}')", "type": "javascript_uri"},
            {"payload": f"'-alert('{canary}')-'", "type": "js_breakout_single"},
            {"payload": f'"-alert("{canary}")-"', "type": "js_breakout_double"},
            {"payload": f"</script><script>alert('{canary}')</script>", "type": "script_breakout"},
        ]

    async def scan(self, url: str) -> List[DOMXSSFinding]:
        """Scan a URL for DOM XSS vulnerabilities."""
        if not self.browser:
            await self.start()

        findings = []
        payloads = self._get_dom_xss_payloads()
        sources = ["hash", "search"]

        context = None
        page = None

        try:
            context = await self.browser.new_context()
            page = await context.new_page()
            await page.add_init_script(self._get_monitor_script())

            for source in sources:
                for p in payloads:
                    payload = p["payload"]
                    if source == "hash":
                        test_url = f"{url}#{payload}"
                    else:
                        sep = "&" if "?" in url else "?"
                        test_url = f"{url}{sep}xss={payload}"

                    # Setup listeners with proper cleanup
                    dialog_messages = []

                    def dialog_handler(d):
                        dialog_messages.append(d.message)
                        asyncio.create_task(d.dismiss())

                    page.on("dialog", dialog_handler)

                    try:
                        await page.goto(test_url, wait_until="networkidle", timeout=self.timeout)
                        await asyncio.sleep(0.5)

                        # Check injected script findings
                        js_findings = await page.evaluate("window.__domxss_findings || []")

                        if dialog_messages or js_findings:
                            evidence = dialog_messages[0] if dialog_messages else js_findings[0]["value"]
                            sink = "alert" if dialog_messages else js_findings[0]["sink"]

                            findings.append(DOMXSSFinding(
                                url=test_url,
                                payload=payload,
                                sink=sink,
                                source=f"location.{source}",
                                evidence=evidence
                            ))
                            break # Found one for this source, move to next source
                    except Exception as e:
                        logger.debug(f"Error testing {test_url}: {e}")
                    finally:
                        # TASK-49/51: Remove event listener to prevent leaks
                        try:
                            page.remove_listener("dialog", dialog_handler)
                        except Exception as e:
                            logger.debug(f"Failed to remove dialog listener: {e}")

        except Exception as e:
            logger.error(f"[DOMXSSDetector] Scan error: {e}")
        finally:
            # TASK-49: Ensure page and context are always closed
            if page:
                try:
                    await page.close()
                except Exception as e:
                    logger.debug(f"Error closing page: {e}")
            if context:
                try:
                    await context.close()
                except Exception as e:
                    logger.debug(f"Error closing context: {e}")

        self.findings.extend(findings)
        return findings


async def detect_dom_xss(url: str, timeout: int = 10000) -> List[Dict[str, Any]]:
    """Convenience function for XSSAgent integration."""
    async with DOMXSSDetector(timeout=timeout) as detector:
        findings = await detector.scan(url)

    return [
        {
            "vulnerability_type": "DOM_XSS",
            "url": f.url,
            "payload": f.payload,
            "sink": f.sink,
            "source": f.source,
            "evidence": f.evidence,
            "severity": f.severity,
            "status": "VALIDATED_CONFIRMED",
            "validated": True
        }
        for f in findings
    ]
