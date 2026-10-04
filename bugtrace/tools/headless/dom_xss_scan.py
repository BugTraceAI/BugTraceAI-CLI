"""DOM XSS scan/test flow mixin (Playwright navigation + payload tests)."""

from __future__ import annotations

import asyncio
from typing import List, Dict, Optional, Any

from bugtrace.utils.logger import get_logger
from bugtrace.tools.headless.dom_xss_types import (
    DOMXSSFinding,
    DOM_REDIRECT_PARAMS,
    DOM_SEARCH_PARAMS,
    DOM_SINK_PARAMS,
)

logger = get_logger("tools.dom_xss")


class DOMXSSScanMixin:
    """Scan orchestration and payload testing for DOMXSSDetector."""

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

        import time as _time
        _start = _time.monotonic()
        # Soft budget for the lower-value tail phases (hash/postMessage/static).
        # The highest-value test (reflected URL-param DOM XSS, e.g. search ->
        # innerHTML) runs FIRST and unconditionally, so it is never starved by a
        # slow tail and survives even when the caller's hard timeout is near.
        _TAIL_BUDGET_S = 120.0

        findings = []
        payloads = self._get_dom_xss_payloads()

        context, page = await self._setup_scan_context()

        try:
            # HIGHEST VALUE FIRST: URL parameters (batched canary sweep + targeted
            # escalation). This is where reflected-param DOM XSS like V-002
            # (?search=<img onerror> -> dangerouslySetInnerHTML) is confirmed.
            param_findings = await self._test_url_parameters(url, payloads, page, discovered_params=discovered_params)
            findings.extend(param_findings)

            # Test hash source (single canary + javascript: URI = 2 page loads)
            if _time.monotonic() - _start < _TAIL_BUDGET_S:
                hash_finding = await self._test_payload(f"{url}#BUGTRACEAI_7x7", "BUGTRACEAI_7x7", "hash", page)
                if hash_finding:
                    findings.append(hash_finding)
                hash_js = await self._test_payload(f"{url}#javascript:alert('BUGTRACEAI_7x7')", "javascript:alert('BUGTRACEAI_7x7')", "hash", page)
                if hash_js:
                    findings.append(hash_js)

            # Test postMessage-based XSS (lower value — skip if running long)
            if _time.monotonic() - _start < _TAIL_BUDGET_S:
                postmsg_finding = await self._test_postmessage_xss(url, page)
                if postmsg_finding:
                    findings.append(postmsg_finding)

            # Static source→sink analysis for DOM XSS patterns in JS (skip if long)
            if _time.monotonic() - _start < _TAIL_BUDGET_S:
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
        canary_base = "BUGTRACEAI_7x7"
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

        # Phase 1.5: EARLY executable test on likely HTML-sink params.
        # The Phase 1 canary sweep only flags a param as "interesting" if a PLAIN
        # canary reaches a sink — which is timing-fragile and misses params that
        # render via innerHTML only after a framework re-render. Search params are
        # the classic reflected-DOM-XSS surface (e.g. ?search=<img onerror> ->
        # dangerouslySetInnerHTML), so test them with the EXECUTABLE img_onerror
        # payload right now, regardless of the canary sweep. Only a real execution
        # (alert/hook fires) yields a finding, so this adds no false positives.
        img_payload = next((p["payload"] for p in payloads if p.get("type") == "img_onerror"), None)
        _found_params = {f.source.split(":")[-1] for f in findings if getattr(f, "source", "")}
        early_targets = (
            interesting_params
            | (set(discovered_params or []) & all_param_names)
            | (set(DOM_SEARCH_PARAMS) & all_param_names)
        )
        if img_payload:
            for param_name in early_targets:
                if param_name in _found_params:
                    continue
                test_params_e = {k: v[0] for k, v in params.items()}
                test_params_e[param_name] = img_payload
                test_url_e = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(test_params_e), parsed.fragment
                ))
                finding = await self._test_payload(test_url_e, img_payload, f"param:{param_name}", page)
                if finding:
                    findings.append(finding)
                    interesting_params.add(param_name)
                    _found_params.add(param_name)

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
            canary = "BUGTRACEAI_7x7"
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

    async def _wait_for_spa_render(self, page) -> None:
        """
        Wait for SPA framework to finish rendering before checking for XSS.

        Fixed-sleep misses late renders on Angular/React/Vue apps.
        This method detects which framework is present and waits for its
        render lifecycle to complete (up to 3s), falling back to 1.5s sleep.
        """
        try:
            framework = await page.evaluate("""() => {
                if (window.angular) return 'angular';
                if (document.querySelector('[data-reactroot],[data-reactid],#__next,[id="root"] > *'))
                    return 'react';
                if (window.__VUE__ || document.querySelector('[data-v-]'))
                    return 'vue';
                return 'none';
            }""")

            if framework == "angular":
                # Wait for Angular to bootstrap and compile templates
                try:
                    await page.wait_for_function(
                        "window.angular && angular.element(document.body).injector()",
                        timeout=3000,
                    )
                    # Extra wait for digest cycle to process bindings
                    await asyncio.sleep(0.5)
                except Exception:
                    await asyncio.sleep(1.5)  # Fallback

            elif framework == "react":
                # Wait for React root to have rendered children
                try:
                    await page.wait_for_function(
                        """() => {
                            const root = document.querySelector(
                                '[data-reactroot],[data-reactid],#root,#__next,#app'
                            );
                            return root && root.childElementCount > 0;
                        }""",
                        timeout=3000,
                    )
                    await asyncio.sleep(0.3)
                except Exception:
                    await asyncio.sleep(1.5)

            elif framework == "vue":
                # Wait for Vue to mount
                try:
                    await page.wait_for_function(
                        "document.querySelector('[data-v-]') !== null",
                        timeout=3000,
                    )
                    await asyncio.sleep(0.3)
                except Exception:
                    await asyncio.sleep(1.5)

            else:
                # No framework detected — use original fixed sleep
                await asyncio.sleep(1.5)

        except Exception:
            # Any error in framework detection — safe fallback
            await asyncio.sleep(1.5)

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

            # SPA framework-aware wait: Angular/React/Vue need time to render templates
            # before user input reaches sinks. Fixed sleep misses late renders.
            await self._wait_for_spa_render(page)

            # Check hook findings before clicking
            # Primary: window.__domxss_findings (may be destroyed by document.write)
            # Fallback: console_findings (survives document.write DOM replacement)
            js_findings = await page.evaluate("window.__domxss_findings || []")
            if not js_findings and console_findings:
                js_findings = console_findings

            # Direct DOM check: if payload contains javascript: URI, check if any <a>
            # has OUR canary in a javascript: href. This catches jQuery .attr('href') which
            # may bypass our setter hooks, AND static javascript: hrefs the browser set from
            # HTML parsing (which never trip the JS setter hook).
            # CRITICAL: require the canary in the href. Without it, the page's OWN javascript:
            # links (ASP.NET __doPostBack, javascript:void(0)) match `startsWith('javascript:')`
            # and get reported as DOM XSS on EVERY param tested — pure false positives.
            if not js_findings and "javascript:" in payload.lower():
                js_href_found = await page.evaluate("""
                    () => {
                        const CANARY = 'BUGTRACEAI_7x7';
                        const links = document.querySelectorAll('a[href]');
                        for (const a of links) {
                            const h = a.getAttribute('href') || a.href || '';
                            if (h.toLowerCase().startsWith('javascript:') && h.includes(CANARY)) {
                                return {
                                    sink: 'a.href',
                                    value: h.substring(0, 500),
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

            # A javascript:-URI payload is only CONFIRMED by a real alert() dialog carrying our
            # canary. Hook-only signals (eval / a.href) self-trigger on pages that own javascript:
            # links or ASP.NET __doPostBack (the detector clicks them / triggers postbacks), which
            # produced phantom "DOM XSS" on EVERY param tested. Require genuine execution proof.
            _canary = "BUGTRACEAI_7x7"
            if "javascript:" in payload.lower() and not any(_canary in str(m) for m in dialog_messages):
                return None
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



