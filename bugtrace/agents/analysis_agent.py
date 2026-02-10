import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.utils.parsers import XmlParser
from bugtrace.core.event_bus import event_bus, EventType

from bugtrace.agents.base import BaseAgent

class DASTySASTAgent(BaseAgent):
    """
    DAST + SAST Analysis Agent.
    Performs 5-approach analysis on a URL to identify potential vulnerabilities.
    Phase 2 (Part A) of the Sequential Pipeline.
    """
    
    def __init__(self, url: str, tech_profile: Dict, report_dir: Path, state_manager: Any = None, scan_context: str = None, url_index: int = None):
        super().__init__("DASTySASTAgent", "Security Analysis", agent_id="analysis_agent")
        self.url = url
        self.tech_profile = tech_profile
        self.report_dir = report_dir
        self.state_manager = state_manager
        self.scan_context = scan_context or f"scan_{id(self)}"  # Default scan context
        self.url_index = url_index  # URL index for numbered reports

        # 6 different analysis approaches for maximum coverage
        # 5 core LLM approaches + 1 skeptical approach for early FP elimination
        self.approaches = ["pentester", "bug_bounty", "code_auditor", "red_team", "researcher", "skeptical_agent"]
        self.model = getattr(settings, "ANALYSIS_PENTESTER_MODEL", None) or settings.DEFAULT_MODEL
        
    async def run_loop(self):
        """Standard run loop executing the DAST+SAST analysis."""
        return await self.run()

    async def run(self) -> Dict:
        """Performs 6-approach analysis on the URL (DAST+SAST) with event emission."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Running DAST+SAST Analysis on {self.url[:50]}...", "INFO")

        # Use phase-specific analysis semaphore for tracking (v2.4)
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores, ScanPhase
            phase_semaphores.initialize()
            phase_ctx = phase_semaphores.acquire(ScanPhase.ANALYSIS)
        except ImportError:
            phase_ctx = None

        try:
            if phase_ctx:
                await phase_ctx.__aenter__()

            # 1. Prepare Context
            context = await self._run_prepare_context()

            # 2. Parallel Analysis
            valid_analyses = await self._run_execute_analyses(context)
            if not valid_analyses:
                dashboard.log(f"[{self.name}] All analysis approaches failed.", "ERROR")
                # Emit event even on failure (empty findings)
                await self._emit_url_analyzed([])
                return {"error": "Analysis failed", "vulnerabilities": []}

            # 3. Consolidate & Review
            consolidated = self._consolidate(valid_analyses)
            vulnerabilities = await self._skeptical_review(consolidated)

            # 4. Save Results
            await self._run_save_results(vulnerabilities)

            # 5. Emit url_analyzed event (Phase 17: DISC-04)
            await self._emit_url_analyzed(vulnerabilities)

            # Determine base filename based on url_index
            if self.url_index is not None:
                base_filename = str(self.url_index)
            else:
                # Fallback for compatibility with old calls
                base_filename = f"vulnerabilities_{self._get_safe_name()}"

            return {
                "url": self.url,
                "vulnerabilities": vulnerabilities,
                "json_report_file": str(self.report_dir / f"{base_filename}.json"),
                "url_index": self.url_index,
                "fp_stats": {
                    "total_findings": len(vulnerabilities),
                    "high_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) >= 0.7]),
                    "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get('fp_confidence', 0) < 0.7]),
                    "low_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) < 0.5])
                }
            }

        except Exception as e:
            logger.error(f"DASTySASTAgent failed: {e}", exc_info=True)
            # Emit event even on exception (empty findings)
            try:
                await self._emit_url_analyzed([])
            except Exception:
                pass  # Best effort
            return {"error": str(e), "vulnerabilities": []}
        finally:
            # Release phase semaphore (v2.4)
            if phase_ctx:
                await phase_ctx.__aexit__(None, None, None)

    async def _run_prepare_context(self) -> Dict:
        """Prepare analysis context with OOB payload, HTML content, and ACTIVE PROBES.

        IMPROVED (2026-02-01): Now runs active reconnaissance probes BEFORE LLM analysis.
        This ensures the LLM has CONCRETE evidence about parameter behavior, not just speculation.
        """
        from bugtrace.tools.interactsh import interactsh_client, get_oob_payload

        # Ensure registered (lazy init)
        if not interactsh_client.registered:
            await interactsh_client.register()

        oob_payload, oob_url = await get_oob_payload("generic")

        context = {
            "url": self.url,
            "tech_stack": self.tech_profile.get("frameworks", []),
            "html_content": "",
            "oob_info": {
                "callback_url": oob_url,
                "payload_template": oob_payload,
                "instructions": "Use this callback URL for Blind XSS/SSRF/RCE testing. If you inject this and it's triggered, we will detect it Out-of-Band."
            },
            "reflection_probes": []  # ADDED: Active recon results
        }

        # Fetch HTML Content
        try:
            from bugtrace.tools.visual.browser import browser_manager
            await browser_manager.start()
            capture = await browser_manager.capture_state(self.url)
            if capture and capture.get("html"):
                html_full = capture["html"]
                if len(html_full) > 15000:
                     context["html_content"] = html_full[:7500] + "\n...[TRUNCATED]...\n" + html_full[-7500:]
                else:
                    context["html_content"] = html_full

                logger.info(f"[{self.name}] Fetched HTML content ({len(context['html_content'])} chars) for analysis.")

                # FIX (2026-02-04): Detect frontend frameworks from HTML
                # This ensures CSTI detection even when Nuclei misses Angular/Vue
                self._detect_frontend_frameworks_from_html(html_full)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to fetch HTML content: {e}")

        # ADDED (2026-02-04): Detect JWTs and cookies in HTML/JavaScript
        # If found, emit findings for ThinkingAgent to route to JWT/IDOR queues
        try:
            await self._detect_auth_artifacts(context.get("html_content", ""))
        except Exception as e:
            logger.warning(f"[{self.name}] Auth artifact detection failed: {e}")

        # ADDED (2026-02-01): Run active reconnaissance probes
        # FIX (2026-02-04): Now passes HTML to extract form parameters, not just URL params
        if settings.ACTIVE_RECON_PROBES:
            try:
                probes = await self._run_reflection_probes(context.get("html_content", ""))
                context["reflection_probes"] = probes
                logger.info(f"[{self.name}] Active recon: {len(probes)} parameters probed")
            except Exception as e:
                logger.warning(f"[{self.name}] Active recon probes failed: {e}")

        return context

    async def _run_reflection_probes(self, html_content: str = "") -> List[Dict]:
        """
        ADDED (2026-02-01): Active reconnaissance probes.
        FIX (2026-02-04): Now extracts parameters from HTML forms, not just URL.

        Sends an Omni-Probe to each parameter and analyzes HOW it reflects.
        This provides CONCRETE evidence for the LLM instead of speculation.

        Args:
            html_content: HTML content to extract form parameters from.

        Returns:
            List of probe results with reflection context analysis.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import re

        probes = []
        marker = settings.OMNI_PROBE_MARKER

        parsed = urlparse(self.url)
        url_params = parse_qs(parsed.query)

        # FIX (2026-02-04): Extract parameters from HTML forms
        # This finds params like "searchTerm" that aren't in the URL
        html_params = self._extract_html_params(html_content) if html_content else []

        # Combine URL params + HTML params (URL params take priority)
        all_param_names = set(url_params.keys())
        for html_param in html_params:
            if html_param not in all_param_names:
                all_param_names.add(html_param)
                url_params[html_param] = [""]  # Empty default value for HTML-only params

        if not all_param_names:
            return probes

        logger.info(f"[{self.name}] Probing {len(all_param_names)} params: {list(all_param_names)}")

        # Use orchestrator for lifecycle-tracked connections
        async with orchestrator.session(DestinationType.TARGET) as session:
            # Cookie Fix: Make initial request to base URL to capture real Set-Cookie headers
            # aiohttp probes with markers won't trigger the same Set-Cookie behavior
            # The server sets cookies (TrackingId, session, etc.) on clean first visits
            try:
                base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, parsed.query, parsed.fragment))
                async with session.get(base_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as initial_resp:
                    await initial_resp.text()  # consume body
                    self._extract_cookies_from_http_headers(initial_resp)
                    if getattr(self, '_http_cookies', {}):
                        logger.info(f"[{self.name}] 🍪 Captured {len(self._http_cookies)} cookies from initial request")
            except Exception as e:
                logger.debug(f"[{self.name}] Initial cookie capture failed: {e}")

            for param_name in all_param_names:
                try:
                    # Build probe URL with marker
                    test_params = {k: v[0] if v else "" for k, v in url_params.items()}
                    test_params[param_name] = marker
                    probe_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params), parsed.fragment
                    ))

                    async with session.get(probe_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        html = await resp.text()
                        status = resp.status
                        # Gap 1: Capture Set-Cookie headers to find HttpOnly cookies
                        self._extract_cookies_from_http_headers(resp)
                        # Gap 2: Check for probe marker reflection in response headers
                        header_reflection = self._check_header_reflection(param_name, marker, resp)

                    # Analyze reflection
                    probe_result = self._analyze_reflection(param_name, marker, html, status)
                    # Merge header reflection data if found
                    if header_reflection:
                        probe_result["header_reflection"] = header_reflection
                        if not probe_result["reflects"]:
                            probe_result["reflects"] = True
                            probe_result["context"] = "response_header"
                    probes.append(probe_result)

                    if probe_result["reflects"]:
                        logger.info(f"[{self.name}] 🔍 {param_name}: {probe_result['context']} (chars survive: {probe_result['chars_survive']})")
                        dashboard.log(f"[{self.name}] Probe: {param_name} → {probe_result['context']}", "INFO")

                except Exception as e:
                    logger.debug(f"[{self.name}] Probe failed for {param_name}: {e}")
                    probes.append({
                        "parameter": param_name,
                        "reflects": False,
                        "context": "error",
                        "error": str(e)
                    })

        return probes

    def _extract_html_params(self, html: str) -> List[str]:
        """
        ADDED (2026-02-04): Extract parameter names from HTML forms.

        This finds parameters like "searchTerm" that exist in forms but
        aren't in the current URL. Critical for discovering hidden attack surfaces.

        Args:
            html: HTML content to parse.

        Returns:
            List of parameter names found in forms.
        """
        from bs4 import BeautifulSoup

        params = []
        if not html:
            return params

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Extract from all forms
            for form in soup.find_all('form'):
                # Get form method - we want GET forms for URL params
                method = form.get('method', 'GET').upper()

                # Extract all input elements
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()

                    # Skip if no name
                    if not name:
                        continue

                    # Skip CSRF tokens and submit buttons
                    if inp_type in ('submit', 'button', 'image', 'reset'):
                        continue
                    if name.lower() in ('csrf', 'token', '_token', 'csrfmiddlewaretoken', '__requestverificationtoken'):
                        continue

                    # Include both visible and hidden inputs (hidden can be vulnerable too!)
                    params.append(name)
                    logger.debug(f"[{self.name}] Found form param: {name} (type={inp_type}, method={method})")

            # Deduplicate while preserving order
            seen = set()
            unique_params = []
            for p in params:
                if p not in seen:
                    seen.add(p)
                    unique_params.append(p)

            if unique_params:
                logger.info(f"[{self.name}] Extracted {len(unique_params)} params from HTML forms: {unique_params}")

            return unique_params

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to extract HTML params: {e}")
            return []

    def _extract_cookies_from_http_headers(self, response) -> None:
        """
        Gap 1 Fix: Extract cookies from HTTP Set-Cookie headers.

        HttpOnly cookies are invisible to JavaScript (document.cookie) but
        are sent in HTTP Set-Cookie headers. These are the highest-value
        targets for Cookie SQLi because they often contain session/tracking data.

        Stores extracted cookies in self._http_cookies for use by _check_cookie_sqli_probes().
        """
        if not hasattr(self, '_http_cookies'):
            self._http_cookies = {}

        try:
            # response.headers is a CIMultiDictProxy; getall returns all Set-Cookie values
            set_cookie_headers = response.headers.getall('Set-Cookie', [])
            for header_val in set_cookie_headers:
                # Parse "name=value; HttpOnly; Secure; Path=/"
                parts = header_val.split(';')
                if not parts:
                    continue
                name_value = parts[0].strip()
                if '=' not in name_value:
                    continue
                name, value = name_value.split('=', 1)
                name = name.strip()
                value = value.strip()
                if not name:
                    continue

                # Check flags
                flags_lower = header_val.lower()
                is_httponly = 'httponly' in flags_lower

                # Store with metadata — HttpOnly cookies are the high-value targets
                if name not in self._http_cookies:
                    self._http_cookies[name] = {
                        "name": name,
                        "value": value,
                        "httponly": is_httponly,
                        "_source": "http_header"
                    }
                    if is_httponly:
                        logger.info(f"[{self.name}] 🍪 Captured HttpOnly cookie from headers: {name}")
                    else:
                        logger.debug(f"[{self.name}] Captured cookie from headers: {name}")
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to extract cookies from headers: {e}")

    def _check_header_reflection(self, param_name: str, marker: str, response) -> Optional[Dict]:
        """
        Gap 2 Fix: Check if the probe marker reflects in response headers.

        If the marker appears in any response header value, this indicates
        potential CRLF / Header Injection. Records the header name for
        auto-dispatch to HeaderInjectionAgent.

        Returns:
            Dict with header reflection details, or None if no reflection found.
        """
        try:
            for header_name, header_value in response.headers.items():
                if marker in header_value:
                    logger.info(f"[{self.name}] ⚠️ Probe marker reflects in response header '{header_name}' for param {param_name}")
                    return {
                        "header_name": header_name,
                        "header_value": header_value[:200],
                        "parameter": param_name,
                        "reflection_context": "response_header"
                    }
        except Exception as e:
            logger.debug(f"[{self.name}] Header reflection check failed: {e}")
        return None

    async def _detect_auth_artifacts(self, html_content: str):
        """
        ADDED (2026-02-04): Detect JWTs and session cookies during DAST analysis.

        Scans HTML content for:
        - JWTs (using regex pattern)
        - Session cookies (common patterns)

        Emits findings for ThinkingAgent to route to specialist queues.

        Args:
            html_content: HTML content to scan
        """
        import re
        from datetime import datetime

        if not html_content:
            return

        # JWT regex pattern (same as AuthDiscoveryAgent)
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*'
        jwt_matches = re.findall(jwt_pattern, html_content)

        # Deduplicate JWTs
        unique_jwts = list(set(jwt_matches))

        for token in unique_jwts:
            # Decode JWT for metadata
            try:
                import base64
                import json

                parts = token.split('.')
                if len(parts) >= 2:
                    # Decode header
                    header_json = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
                    header = json.loads(header_json)

                    # Decode payload (preview only - don't expose sensitive data)
                    payload_json = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
                    payload = json.loads(payload_json)

                    # Emit JWT finding
                    finding = {
                        "type": "JWT_DISCOVERED",
                        "url": self.url,
                        "token": token,
                        "source": "html_content",
                        "parameter": "embedded_in_html",
                        "context": "html_script",
                        "severity": "INFO",
                        "agent": self.name,
                        "timestamp": datetime.now().isoformat(),
                        "metadata": {
                            "header": header,
                            "payload_preview": {k: v for k, v in list(payload.items())[:5]},  # First 5 claims only
                            "signature_present": len(parts) == 3
                        }
                    }

                    # Emit to event bus for ThinkingAgent routing
                    self.emit_finding(finding)
                    logger.info(f"[{self.name}] 🔑 Detected JWT in HTML (alg={header.get('alg', 'unknown')})")

            except Exception as e:
                logger.debug(f"[{self.name}] Failed to decode JWT: {e}")

        # TODO: Add session cookie detection from Set-Cookie headers
        # This would require capturing response headers during browser navigation
        # For now, AuthDiscoveryAgent handles cookie discovery

        if unique_jwts:
            dashboard.log(f"[{self.name}] Found {len(unique_jwts)} JWT(s) in HTML", "INFO")

    def _detect_frontend_frameworks_from_html(self, html: str):
        """
        ADDED (2026-02-04): Detect frontend frameworks from HTML content.

        This ensures CSTIAgent gets dispatched even when Nuclei misses Angular/Vue.
        Updates self.tech_profile in-place with detected frameworks.

        Detection methods:
        - ng-app, ng-controller, ng-model: AngularJS
        - data-ng-*, x-ng-*: AngularJS alternative syntax
        - v-bind, v-model, v-if: Vue.js
        - angular.js, angularjs in script src: AngularJS
        """
        if not html:
            return

        detected = []
        html_lower = html.lower()

        # AngularJS detection
        angular_indicators = [
            'ng-app', 'ng-controller', 'ng-model', 'ng-bind', 'ng-repeat',
            'data-ng-app', 'data-ng-controller', 'x-ng-app',
            '{{', '}}',  # Angular template syntax
        ]
        if any(indicator in html_lower for indicator in angular_indicators):
            # Double-check for {{}} pattern (could be other template engines)
            if 'ng-app' in html_lower or 'ng-controller' in html_lower or 'angular' in html_lower:
                detected.append('AngularJS')
                logger.info(f"[{self.name}] 🔍 Detected AngularJS from HTML (ng-app/ng-controller/angular)")
            elif '{{' in html and '}}' in html:
                # Check if it's in a script context that looks like Angular
                if 'ng-' in html_lower or 'angular' in html_lower:
                    detected.append('AngularJS')
                    logger.info(f"[{self.name}] 🔍 Detected AngularJS from HTML (ng-* + {{}}))")

        # Vue.js detection
        vue_indicators = [
            'v-bind', 'v-model', 'v-if', 'v-for', 'v-on:', '@click', ':href',
            'vue.js', 'vue.min.js', 'vue@', 'vuejs'
        ]
        if any(indicator in html_lower for indicator in vue_indicators):
            detected.append('Vue.js')
            logger.info(f"[{self.name}] 🔍 Detected Vue.js from HTML")

        # React detection (less relevant for CSTI but good to know)
        react_indicators = ['data-reactroot', 'data-reactid', '__react', 'react-dom']
        if any(indicator in html_lower for indicator in react_indicators):
            detected.append('React')
            logger.info(f"[{self.name}] 🔍 Detected React from HTML")

        # Update tech_profile with detected frameworks
        if detected:
            existing = self.tech_profile.get('frameworks', [])
            for fw in detected:
                if fw not in existing:
                    existing.append(fw)
            self.tech_profile['frameworks'] = existing
            logger.info(f"[{self.name}] Updated tech_profile.frameworks: {self.tech_profile['frameworks']}")

    def _analyze_reflection(self, param: str, marker: str, html: str, status: int) -> Dict:
        """
        Analyze HOW the marker reflects in the HTML response.

        Detects reflection context:
        - html_text: Inside HTML body text (XSS possible with <script>)
        - html_attribute: Inside an attribute (XSS possible with " onmouseover=)
        - script_block: Inside <script> (XSS possible with ')
        - url_context: Inside href/src (Open Redirect possible)
        - no_reflection: Marker not found
        """
        import re

        result = {
            "parameter": param,
            "reflects": False,
            "context": "no_reflection",
            "html_snippet": "",
            "chars_survive": "",
            "line_number": None,
            "status_code": status
        }

        if marker not in html:
            return result

        result["reflects"] = True

        # Find the reflection location
        lines = html.split('\n')
        for i, line in enumerate(lines, 1):
            if marker in line:
                result["line_number"] = i
                # Extract snippet around marker (100 chars context)
                idx = line.find(marker)
                start = max(0, idx - 50)
                end = min(len(line), idx + len(marker) + 50)
                result["html_snippet"] = line[start:end].strip()
                break

        # Detect context
        # 1. Inside <script> block
        script_pattern = rf'<script[^>]*>[^<]*{re.escape(marker)}[^<]*</script>'
        if re.search(script_pattern, html, re.IGNORECASE | re.DOTALL):
            result["context"] = "script_block"
        # 2. Inside an attribute
        elif re.search(rf'["\'][^"\']*{re.escape(marker)}[^"\']*["\']', html):
            result["context"] = "html_attribute"
        # 3. Inside href/src (URL context)
        elif re.search(rf'(?:href|src|action)=["\'][^"\']*{re.escape(marker)}', html, re.IGNORECASE):
            result["context"] = "url_context"
        # 4. Plain HTML text
        else:
            result["context"] = "html_text"

        # Test which dangerous chars survive
        # Send follow-up probes with special chars
        chars_to_test = "<>\"'`"
        result["chars_survive"] = ""  # Will be populated by follow-up probes

        return result

    async def _probe_char_survival(self, param: str, original_params: Dict, char: str) -> bool:
        """Test if a specific character survives (not encoded) in the response."""
        from urllib.parse import urlparse, urlencode, urlunparse

        parsed = urlparse(self.url)
        test_params = original_params.copy()
        test_marker = f"{settings.OMNI_PROBE_MARKER}{char}end"
        test_params[param] = test_marker

        probe_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment
        ))

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(probe_url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    html = await resp.text()
                    # Check if character survives unencoded
                    return test_marker in html
        except Exception:
            return False

    async def _run_execute_analyses(self, context: Dict) -> List[Dict]:
        """Execute parallel analyses with all approaches."""
        # Run 5 core approaches in parallel first
        core_approaches = [a for a in self.approaches if a != "skeptical_agent"]
        tasks = [
            self._analyze_with_approach(context, approach)
            for approach in core_approaches
        ]

        # Add SQLi Probe Check (active testing for error-based SQLi)
        tasks.append(self._check_sqli_probes())

        # Add Cookie SQLi Probe Check (cookies need level=2 testing)
        tasks.append(self._check_cookie_sqli_probes())

        analyses = await asyncio.gather(*tasks, return_exceptions=True)
        valid_analyses = [a for a in analyses if isinstance(a, dict) and not a.get("error")]

        # Run skeptical_agent AFTER to review findings from core approaches
        if "skeptical_agent" in self.approaches:
            skeptical_result = await self._run_skeptical_approach(context, valid_analyses)
            if skeptical_result and not skeptical_result.get("error"):
                valid_analyses.append(skeptical_result)

        return valid_analyses

    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """
        Remove duplicate vulnerabilities based on type+normalized_parameter+url.

        This is a safety net deduplication layer that catches duplicates missed
        by the LLM (e.g., when the LLM generates slightly different parameter names
        for the same vulnerability).

        Args:
            vulns: List of vulnerability findings

        Returns:
            Deduplicated list of findings
        """
        if not vulns:
            return vulns

        seen = {}
        deduped = []

        def _normalize_param(param: str, vuln_type: str) -> str:
            """Normalize parameter name for deduplication."""
            param_lower = param.lower()

            # XXE: Normalize all POST body variations
            # Catch all variants: "POST Body", "XML Body", "stockCheckForm", etc.
            if vuln_type.lower() == "xxe":
                xxe_indicators = ["post", "body", "xml", "stock", "form"]
                if any(indicator in param_lower for indicator in xxe_indicators):
                    return "post_body"

            # SQLi: Normalize cookie names
            if "cookie:" in param_lower:
                parts = param_lower.split("cookie:")
                if len(parts) > 1:
                    cookie_name = parts[1].strip().split()[0]
                    return f"cookie:{cookie_name}"

            return param_lower

        for v in vulns:
            vuln_type = v.get('type', 'Unknown')
            param_raw = v.get('parameter', 'unknown')
            url = v.get('url', self.url)

            # Create dedup key with normalized parameter
            param_normalized = _normalize_param(param_raw, vuln_type)
            key = (vuln_type.lower(), param_normalized, url)

            if key not in seen:
                seen[key] = v
                deduped.append(v)
            else:
                # Keep the one with higher fp_confidence
                existing = seen[key]
                if v.get('fp_confidence', 0) > existing.get('fp_confidence', 0):
                    deduped.remove(existing)
                    deduped.append(v)
                    seen[key] = v

        if len(vulns) != len(deduped):
            logger.info(f"[{self.name}] Post-deduplication: {len(vulns)} → {len(deduped)} findings ({len(vulns)-len(deduped)} duplicates removed)")

        return deduped

    async def _run_save_results(self, vulnerabilities: List[Dict]):
        """Save vulnerabilities to state manager, JSON (structured data), and markdown report (human-readable)."""
        # Apply post-deduplication (safety net for LLM-generated duplicates)
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        logger.info(f"🔍 DASTySAST Result: {len(vulnerabilities)} candidates for {self.url[:50]}")

        for v in vulnerabilities:
            self._save_single_vulnerability(v)

        # Determine base filename
        if self.url_index is not None:
            base_filename = str(self.url_index)
        else:
            # Fallback for compatibility with old calls
            base_filename = f"vulnerabilities_{self._get_safe_name()}"

        # Save JSON report ONLY (structured data - 100% robust, no character interpretation)
        # NOTE: Markdown reports removed in v3.1 - payloads must be preserved exactly
        # JSON with ensure_ascii=False + indent=2 guarantees no payload corruption
        json_path = self.report_dir / f"{base_filename}.json"
        self._save_json_report(json_path, vulnerabilities)

        dashboard.log(f"[{self.name}] Found {len(vulnerabilities)} potential vulnerabilities.", "SUCCESS")

    def _save_single_vulnerability(self, v: Dict):
        """Save a single vulnerability to state manager with fp_confidence."""
        # Normalize field names
        v_name = v.get("vulnerability_name") or v.get("name") or v.get("vulnerability") or "Vulnerability"
        v_desc = v.get("description") or v.get("reasoning") or v.get("details") or "No description provided."

        # Ensure v_name is descriptive
        v_name = self._normalize_vulnerability_name(v_name, v_desc, v)

        # Get severity
        v_type_upper = (v.get("type") or v_name or "").upper()
        v_severity = self._get_severity_for_type(v_type_upper, v.get("severity"))

        self.state_manager.add_finding(
            url=self.url,
            type=str(v_name),
            description=str(v_desc),
            severity=str(v_severity),
            parameter=v.get("parameter") or v.get("vulnerable_parameter"),
            payload=v.get("payload") or v.get("logic") or v.get("exploitation_strategy"),
            evidence=v.get("evidence") or v.get("reasoning"),
            screenshot_path=v.get("screenshot_path"),
            validated=v.get("validated", False),
            # Phase 17: Add FP confidence fields
            fp_confidence=v.get("fp_confidence", 0.5),
            skeptical_score=v.get("skeptical_score", 5),
            fp_reason=v.get("fp_reason", ""),
            # Phase 27: Add reproduction command for probe validation
            reproduction_command=v.get("reproduction", "")
        )

    def _normalize_vulnerability_name(self, v_name: str, v_desc: str, v: Dict) -> str:
        """Normalize vulnerability name to be more descriptive."""
        if v_name.lower() not in ["vulnerability", "security issue", "finding"]:
            return v_name

        desc_lower = str(v_desc).lower()
        if "xss" in desc_lower or "script" in desc_lower:
            return "Potential XSS Issue"
        if "sql" in desc_lower:
            return "Potential SQL Injection Issue"
        return f"Potential {v.get('type', 'Security')} Issue"

    def _get_safe_name(self) -> str:
        """Generate safe filename from URL."""
        return self.url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:50]

    def _get_severity_for_type(self, vuln_type: str, llm_severity: Optional[str] = None) -> str:
        """
        Maps vulnerability type to appropriate severity.
        SQLi, RCE, XXE = CRITICAL
        XSS, Header Injection = HIGH  
        IDOR, SSRF, CSRF = MEDIUM
        Info Disclosure = LOW
        """
        vuln_type_upper = vuln_type.upper()
        
        # CRITICAL: Direct database/system compromise
        critical_patterns = ["SQL", "SQLI", "RCE", "REMOTE CODE", "COMMAND INJECTION", 
                           "XXE", "XML EXTERNAL", "DESERIALIZATION", "NOSQL", "SSTI"]
        for pattern in critical_patterns:
            if pattern in vuln_type_upper:
                return "Critical"
        
        # HIGH: Client-side execution or significant impact
        high_patterns = ["XSS", "CROSS-SITE SCRIPTING", "HEADER INJECTION", "CRLF", 
                        "RESPONSE SPLITTING", "LFI", "LOCAL FILE", "PATH TRAVERSAL",
                        "AUTHENTICATION BYPASS", "SESSION", "CSTI"]
        for pattern in high_patterns:
            if pattern in vuln_type_upper:
                return "High"
        
        # MEDIUM: Authorization/logic flaws
        medium_patterns = ["IDOR", "INSECURE DIRECT", "OBJECT REFERENCE", "BROKEN ACCESS",
                          "SSRF", "SERVER-SIDE REQUEST", "CSRF", "CROSS-SITE REQUEST",
                          "PROTOTYPE POLLUTION", "BUSINESS LOGIC", "OPEN REDIRECT"]
        for pattern in medium_patterns:
            if pattern in vuln_type_upper:
                return "Medium"
        
        # LOW: Information disclosure
        low_patterns = ["INFORMATION", "DISCLOSURE", "VERBOSE", "DEBUG", "STACK TRACE"]
        for pattern in low_patterns:
            if pattern in vuln_type_upper:
                return "Low"
        
        # Fallback to LLM's suggestion or default to High
        if llm_severity and llm_severity.capitalize() in ["Critical", "High", "Medium", "Low", "Information"]:
            return llm_severity.capitalize()
        return "High"

    async def _check_sqli_probes(self) -> Dict:
        """
        Active SQLi probe: Send basic payloads to detect error-based SQL injection.
        Uses two detection methods:
        1. SQL error messages in response body
        2. Status code differential (500 on ' but 200 on '' = classic SQLi)
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        # SQL error patterns for major databases
        SQL_ERRORS = [
            # MySQL
            "you have an error in your sql syntax",
            "mysql_fetch", "mysql_num_rows", "mysql_query",
            "warning: mysql",
            # PostgreSQL
            "postgresql.*error", "pg_query", "pg_exec",
            "unterminated quoted string",
            # MSSQL
            "microsoft sql server", "mssql_query",
            "unclosed quotation mark",
            # Oracle
            "ora-00933", "ora-00921", "ora-01756",
            "oracle.*driver", "oracle.*error",
            # SQLite
            "sqlite3.operationalerror", "sqlite_error",
            "unrecognized token",
            # Generic
            "sql syntax.*mysql", "valid sql statement",
            "sqlstate", "odbc.*driver",
        ]

        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if not params:
                return {"vulnerabilities": []}

            findings = []

            # Use orchestrator for lifecycle-tracked connections
            async with orchestrator.session(DestinationType.TARGET) as session:
                for param_name in params:
                    # Test: Single quote should break SQL, double quote should escape
                    test_params_single = {k: v[0] if v else "" for k, v in params.items()}
                    test_params_single[param_name] = "'"

                    test_params_double = {k: v[0] if v else "" for k, v in params.items()}
                    test_params_double[param_name] = "''"

                    url_single = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params_single), parsed.fragment
                    ))
                    url_double = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params_double), parsed.fragment
                    ))

                    try:
                        async with session.get(url_single, ssl=False) as resp_single:
                            status_single = resp_single.status
                            body_single = await resp_single.text()

                        async with session.get(url_double, ssl=False) as resp_double:
                            status_double = resp_double.status

                        # Detection Method 1: Status code differential
                        # If ' gives 500 but '' gives 200 = classic SQLi pattern
                        if status_single >= 500 and status_double < 400:
                            logger.info(f"[SQLi Probe] Status differential in {param_name}: '={status_single}, ''={status_double}")
                            findings.append({
                                "type": "SQLi",
                                "vulnerability": "SQL Injection (Error-based)",
                                "parameter": param_name,
                                "payload": "'",
                                "confidence": 0.9,
                                "severity": "Critical",
                                "probe_validated": True,  # Active test confirmed - don't override scores
                                "fp_confidence": 0.85,
                                "skeptical_score": 8,
                                "votes": 5,  # Boost votes for probe findings (counts as expert validation)
                                "evidence": f"Status code differential: single quote (') returns {status_single}, escaped quote ('') returns {status_double}",
                                "description": f"Error-based SQL injection detected in parameter '{param_name}'. Single quote causes server error (500) while escaped quote works normally, indicating SQL query breakage.",
                                "reproduction": f"[PROBE-VALIDATED] curl -s -o /dev/null -w '%{{http_code}}' '{url_single}' # Returns {status_single}"
                            })
                            continue  # Found SQLi, next param

                        # Detection Method 2: SQL error messages in body
                        body_lower = body_single.lower()
                        for error_pattern in SQL_ERRORS:
                            if error_pattern in body_lower:
                                logger.info(f"[SQLi Probe] Found SQL error '{error_pattern}' in {param_name}")
                                findings.append({
                                    "type": "SQLi",
                                    "vulnerability": "SQL Injection (Error-based)",
                                    "parameter": param_name,
                                    "payload": "'",
                                    "confidence": 0.95,
                                    "severity": "Critical",
                                    "probe_validated": True,  # Active test confirmed - don't override scores
                                    "fp_confidence": 0.9,
                                    "skeptical_score": 9,
                                    "votes": 5,  # Boost votes for probe findings (counts as expert validation)
                                    "evidence": f"SQL error detected: '{error_pattern}' in response",
                                    "description": f"Error-based SQL injection detected in parameter '{param_name}'. Database error message exposed in response.",
                                    "reproduction": f"[PROBE-VALIDATED] curl '{url_single}' | grep -i 'error\\|sql'"
                                })
                                break

                        # Detection Method 3: Time-based Blind SQLi
                        # Only if error-based didn't find anything
                        if not any(f.get("parameter") == param_name for f in findings):
                            import time
                            # Test with SLEEP payload (MySQL/MariaDB style, works on many DBs)
                            sleep_payloads = [
                                ("' AND SLEEP(3)--", "mysql"),
                                ("' WAITFOR DELAY '0:0:3'--", "mssql"),
                                ("'; SELECT pg_sleep(3);--", "postgresql"),
                            ]

                            for sleep_payload, db_type in sleep_payloads:
                                test_params_sleep = {k: v[0] if v else "" for k, v in params.items()}
                                original_value = test_params_sleep.get(param_name, "")
                                test_params_sleep[param_name] = f"{original_value}{sleep_payload}"

                                url_sleep = urlunparse((
                                    parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, urlencode(test_params_sleep), parsed.fragment
                                ))

                                try:
                                    start_time = time.time()
                                    async with session.get(url_sleep, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp_sleep:
                                        await resp_sleep.text()
                                    elapsed = time.time() - start_time

                                    # If response took > 2.5 seconds, likely blind SQLi
                                    if elapsed >= 2.5:
                                        logger.info(f"[SQLi Probe] Time-based blind SQLi in {param_name}: {elapsed:.2f}s delay ({db_type})")
                                        findings.append({
                                            "type": "SQLi",
                                            "vulnerability": f"SQL Injection (Time-based Blind - {db_type})",
                                            "parameter": param_name,
                                            "payload": sleep_payload,
                                            "confidence": 0.85,
                                            "severity": "Critical",
                                            "probe_validated": True,
                                            "fp_confidence": 0.8,
                                            "skeptical_score": 8,
                                            "votes": 5,
                                            "evidence": f"Response delayed by {elapsed:.2f}s with SLEEP payload (expected 3s)",
                                            "description": f"Time-based blind SQL injection detected in parameter '{param_name}'. The server response was delayed when SLEEP was injected, indicating the SQL was executed.",
                                            "reproduction": f"[PROBE-VALIDATED] time curl '{url_sleep}' # Should take ~3 seconds"
                                        })
                                        break  # Found blind SQLi, don't test other DB types
                                except asyncio.TimeoutError:
                                    # Timeout could also indicate SQLi (server waiting)
                                    logger.info(f"[SQLi Probe] Possible time-based blind SQLi (timeout) in {param_name} ({db_type})")
                                    findings.append({
                                        "type": "SQLi",
                                        "vulnerability": f"SQL Injection (Time-based Blind - {db_type})",
                                        "parameter": param_name,
                                        "payload": sleep_payload,
                                        "confidence": 0.7,
                                        "severity": "Critical",
                                        "probe_validated": True,
                                        "fp_confidence": 0.7,
                                        "skeptical_score": 7,
                                        "votes": 5,
                                        "evidence": "Request timed out with SLEEP payload (>8s)",
                                        "description": f"Possible time-based blind SQL injection in '{param_name}'. Request timed out when SLEEP payload was injected.",
                                        "reproduction": f"[PROBE-VALIDATED] time curl --max-time 10 '{url_sleep}'"
                                    })
                                    break
                                except Exception:
                                    continue  # Try next payload

                    except Exception as e:
                        logger.debug(f"[SQLi Probe] Network error testing {param_name}: {e}")
                        continue

            return {"vulnerabilities": findings}

        except Exception as e:
            logger.error(f"SQLi probe check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _check_cookie_sqli_probes(self) -> Dict:
        """
        Active SQLi probe for cookies: Test each cookie value for SQL injection.
        Handles Base64-encoded values (like TrackingId with JSON inside).
        Also tests synthetic cookies for common vulnerable patterns.
        """
        import base64
        import json
        from urllib.parse import urlparse

        logger.info(f"[Cookie SQLi Probe] Starting cookie probe for {self.url[:50]}...")
        findings = []

        try:
            # Get cookies from browser session (JavaScript document.cookie — misses HttpOnly!)
            from bugtrace.tools.visual.browser import browser_manager
            session_data = await browser_manager.get_session_data()
            cookies = session_data.get("cookies", [])
            logger.debug(f"[Cookie SQLi Probe] Got {len(cookies)} cookies from browser session")

            # Gap 1 Fix: Merge HttpOnly cookies captured from HTTP Set-Cookie headers
            # These are invisible to document.cookie but are the highest-value SQLi targets
            http_cookies = getattr(self, '_http_cookies', {})
            if http_cookies:
                existing_names = {c.get("name", "").lower() for c in cookies}
                for name, cookie_data in http_cookies.items():
                    if name.lower() not in existing_names:
                        cookies.append(cookie_data)
                        existing_names.add(name.lower())
                httponly_count = sum(1 for c in http_cookies.values() if c.get("httponly"))
                logger.info(f"[Cookie SQLi Probe] Merged {len(http_cookies)} HTTP header cookies ({httponly_count} HttpOnly)")

            # Add synthetic cookies for common vulnerable patterns
            # These are tested even if not present in the session
            synthetic_cookies = await self._generate_synthetic_cookies()

            # Merge: real cookies + synthetic (avoid duplicates)
            existing_names = {c.get("name", "").lower() for c in cookies}
            for sc in synthetic_cookies:
                if sc.get("name", "").lower() not in existing_names:
                    cookies.append(sc)

            logger.debug(f"[Cookie SQLi Probe] Testing {len(cookies)} cookies ({len(synthetic_cookies)} synthetic)")

            if not cookies:
                return {"vulnerabilities": []}

            parsed = urlparse(self.url)
            # Test cookies against multiple paths since cookies are domain-wide
            # and may only be processed by certain endpoints
            test_paths = [
                parsed.path,  # Current path
                "/",          # Root
                "/catalog",   # Common product page
                "/api",       # API endpoint
            ]
            # Remove duplicates and empty paths
            test_paths = list(dict.fromkeys([p for p in test_paths if p]))
            base_scheme_host = f"{parsed.scheme}://{parsed.netloc}"

            logger.debug(f"[Cookie SQLi Probe] Will test against {len(test_paths)} paths: {test_paths}")

            # Use orchestrator for lifecycle-tracked connections
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Test each cookie against each path (cookies are domain-wide)
                for test_path in test_paths:
                    test_url = f"{base_scheme_host}{test_path}"

                    for cookie in cookies:
                        cookie_name = cookie.get("name", "")
                        cookie_value = cookie.get("value", "")

                        if not cookie_name or not cookie_value:
                            continue

                        # Skip session/auth cookies (don't want to break session)
                        if cookie_name.lower() in ["session", "sessionid", "phpsessid", "jsessionid"]:
                            continue

                        # Skip if already found SQLi for this cookie (from previous path)
                        if any(f.get("parameter") == f"Cookie: {cookie_name}" for f in findings):
                            continue

                        # === Multi-strategy error-based SQLi detection ===
                        # Strategy: get baseline status, then test multiple injection chars.
                        # If ANY injection char causes 500 while baseline is <400 → SQLi.
                        # This catches diverse SQL dialects and encoding schemes.
                        injection_chars = ["'", '"', "\\", ")", ";"]

                        # Build injection test values: list of (label, injected_cookie_value, injection_char)
                        test_values = []

                        # Direct injection: append char to raw cookie value
                        for ic in injection_chars:
                            test_values.append((f"direct_{ic}", f"{cookie_value}{ic}", ic))

                        # Base64 decode and inject inside
                        try:
                            padded = cookie_value + "=" * (4 - len(cookie_value) % 4) if len(cookie_value) % 4 else cookie_value
                            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')

                            if decoded.strip().startswith('{'):
                                try:
                                    json_data = json.loads(decoded)
                                    for key in json_data:
                                        if isinstance(json_data[key], str):
                                            for ic in injection_chars:
                                                injected = json_data.copy()
                                                injected[key] = json_data[key] + ic
                                                val = base64.b64encode(json.dumps(injected).encode()).decode()
                                                test_values.append((f"b64_json_{key}_{ic}", val, ic))
                                except json.JSONDecodeError:
                                    pass
                            else:
                                for ic in injection_chars:
                                    val = base64.b64encode(f"{decoded}{ic}".encode()).decode()
                                    test_values.append((f"b64_plain_{ic}", val, ic))
                        except Exception:
                            pass  # Not Base64, skip

                        # Get baseline status (original cookie value)
                        other_cookies = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}
                        baseline_cookie_str = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={cookie_value}"])
                        try:
                            async with session.get(test_url, headers={"Cookie": baseline_cookie_str}, ssl=False) as resp_baseline:
                                status_baseline = resp_baseline.status
                        except Exception:
                            status_baseline = 0  # Can't get baseline, skip

                        if status_baseline >= 500:
                            # Baseline already errors, can't do differential detection
                            logger.debug(f"[Cookie SQLi Probe] {cookie_name} @ {test_path}: baseline={status_baseline}, skipping (already erroring)")
                            continue

                        # Test each injection
                        for test_type, val_injected, inj_char in test_values:
                            try:
                                cookies_injected = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={val_injected}"])

                                async with session.get(test_url, headers={"Cookie": cookies_injected}, ssl=False) as resp_injected:
                                    status_injected = resp_injected.status

                                logger.debug(f"[Cookie SQLi Probe] {cookie_name} @ {test_path} ({test_type}): injected={status_injected}, baseline={status_baseline}")

                                # Detection: injection causes 500, baseline was OK
                                if status_injected >= 500 and status_baseline < 400:
                                    logger.info(f"[Cookie SQLi Probe] DETECTED SQLi in cookie {cookie_name} @ {test_path} ({test_type}): {status_injected} vs baseline {status_baseline}")
                                    findings.append({
                                        "type": "SQLi",
                                        "vulnerability": "SQL Injection in Cookie (Error-based)",
                                        "parameter": f"Cookie: {cookie_name}",
                                        "url": self.url,
                                        "payload": inj_char if "b64" not in test_type else f"Base64-encoded {repr(inj_char)} in {test_type}",
                                        "confidence": 0.9,
                                        "severity": "Critical",
                                        "probe_validated": True,
                                        "fp_confidence": 0.85,
                                        "skeptical_score": 8,
                                        "votes": 5,
                                        "evidence": f"Status code differential: {repr(inj_char)} injection returns {status_injected}, original cookie returns {status_baseline}",
                                        "description": f"Error-based SQL injection detected in cookie '{cookie_name}' at {test_url} ({test_type}). Injecting {repr(inj_char)} causes server error while original value works normally.",
                                        "reproduction": f"[PROBE-VALIDATED] curl -b '{cookie_name}={val_injected}' '{test_url}' # Returns {status_injected}"
                                    })
                                    break  # Found SQLi in this cookie, move on

                            except Exception as e:
                                logger.debug(f"[Cookie SQLi Probe] Error testing {cookie_name}: {e}")
                                continue

                        # Time-based Blind SQLi Detection for Cookies
                        # Only if error-based didn't find anything for this cookie
                        if not any(f.get("parameter") == f"Cookie: {cookie_name}" for f in findings):
                            import time as time_module

                            sleep_payloads = [
                                ("' AND SLEEP(3)--", "mysql"),
                                ("' WAITFOR DELAY '0:0:3'--", "mssql"),
                                ("'; SELECT pg_sleep(3);--", "postgresql"),
                                ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "mysql_subquery"),
                            ]

                            for sleep_payload, db_type in sleep_payloads:
                                try:
                                    # Build cookie with sleep payload
                                    other_cookies = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}
                                    cookie_with_sleep = f"{cookie_value}{sleep_payload}"
                                    cookies_sleep = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={cookie_with_sleep}"])
                                    headers_sleep = {"Cookie": cookies_sleep}

                                    start_time = time_module.time()
                                    async with session.get(test_url, headers=headers_sleep, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp_sleep:
                                        await resp_sleep.text()
                                    elapsed = time_module.time() - start_time

                                    if elapsed >= 2.5:
                                        logger.info(f"[Cookie SQLi Probe] Time-based blind SQLi in cookie {cookie_name} @ {test_path}: {elapsed:.2f}s delay ({db_type})")
                                        findings.append({
                                            "type": "SQLi",
                                            "vulnerability": f"SQL Injection in Cookie (Time-based Blind - {db_type})",
                                            "parameter": f"Cookie: {cookie_name}",
                                            "url": self.url,
                                            "payload": sleep_payload,
                                            "confidence": 0.85,
                                            "severity": "Critical",
                                            "probe_validated": True,
                                            "fp_confidence": 0.8,
                                            "skeptical_score": 8,
                                            "votes": 5,
                                            "evidence": f"Response delayed {elapsed:.2f}s with SLEEP payload (expected ~3s)",
                                            "description": f"Time-based blind SQL injection detected in cookie '{cookie_name}' at {test_url}. The {db_type} SLEEP payload caused a {elapsed:.2f}s delay.",
                                            "reproduction": f"[PROBE-VALIDATED] curl -b '{cookie_name}={cookie_with_sleep}' '{test_url}' # Should take ~3s"
                                        })
                                        break  # Found SQLi via time-based, move to next cookie

                                except asyncio.TimeoutError:
                                    # Timeout could indicate SLEEP worked (server hung)
                                    logger.info(f"[Cookie SQLi Probe] Timeout (possible blind SQLi) in cookie {cookie_name} @ {test_path} with {db_type}")
                                    findings.append({
                                        "type": "SQLi",
                                        "vulnerability": f"SQL Injection in Cookie (Time-based Blind - {db_type}, Timeout)",
                                        "parameter": f"Cookie: {cookie_name}",
                                        "url": self.url,
                                        "payload": sleep_payload,
                                        "confidence": 0.75,
                                        "severity": "Critical",
                                        "probe_validated": True,
                                        "fp_confidence": 0.7,
                                        "skeptical_score": 7,
                                        "votes": 5,
                                        "evidence": f"Request timed out with SLEEP payload (likely hung on database)",
                                        "description": f"Possible time-based blind SQL injection in cookie '{cookie_name}' at {test_url}. Request timed out with {db_type} SLEEP payload.",
                                        "reproduction": f"[PROBE-VALIDATED] curl -b '{cookie_name}={cookie_value}{sleep_payload}' '{test_url}' # Should timeout"
                                    })
                                    break
                                except Exception as e:
                                    logger.debug(f"[Cookie SQLi Probe] Time-based test error for {cookie_name}: {e}")
                                    continue

            logger.info(f"[Cookie SQLi Probe] Completed: {len(findings)} findings")
            return {"vulnerabilities": findings}

        except Exception as e:
            logger.error(f"Cookie SQLi probe check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _generate_synthetic_cookies(self) -> list:
        """
        Generate synthetic cookies for common vulnerable patterns.
        These are tested even if they don't exist in the browser session.

        Patterns tested:
        1. TrackingId with Base64-encoded JSON (like PortSwigger labs)
        2. Common tracking/analytics cookies
        3. User preference cookies with serialized data
        """
        import base64
        import json
        import random
        import string

        synthetic = []

        # Generate a random value for the cookie
        random_value = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        # Pattern 1: TrackingId with JSON inside Base64 (PortSwigger pattern)
        # Format: {"type":"class","value":"<random>"}
        tracking_json = {"type": "class", "value": random_value}
        tracking_b64 = base64.b64encode(json.dumps(tracking_json).encode()).decode()
        synthetic.append({
            "name": "TrackingId",
            "value": tracking_b64,
            "_synthetic": True,
            "_pattern": "base64_json"
        })

        # Pattern 2: Simple tracking cookie (plain value)
        synthetic.append({
            "name": "tracking",
            "value": random_value,
            "_synthetic": True,
            "_pattern": "plain"
        })

        # Pattern 3: User ID cookie (numeric, common SQLi target)
        synthetic.append({
            "name": "userId",
            "value": str(random.randint(1000, 9999)),
            "_synthetic": True,
            "_pattern": "numeric"
        })

        # Pattern 4: Preference cookie with Base64 data
        pref_json = {"theme": "dark", "lang": "en", "user": random_value}
        pref_b64 = base64.b64encode(json.dumps(pref_json).encode()).decode()
        synthetic.append({
            "name": "preferences",
            "value": pref_b64,
            "_synthetic": True,
            "_pattern": "base64_json"
        })

        logger.info(f"[Cookie SQLi Probe] Generated {len(synthetic)} synthetic cookies for testing")
        return synthetic

    async def _analyze_with_approach(self, context: Dict, approach: str) -> Dict:
        """Analyze with a specific persona."""
        skill_context = self._approach_get_skill_context()
        system_prompt = self._get_system_prompt(approach)
        user_prompt = self._approach_build_prompt(context, skill_context)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                module_name="DASTySASTAgent",
                max_tokens=8000
            )

            if not response:
                return {"error": "Empty response from LLM"}

            return self._approach_parse_response(response)

        except Exception as e:
            logger.error(f"Failed to analyze with approach {approach}: {e}", exc_info=True)
            return {"vulnerabilities": []}

    def _approach_get_skill_context(self) -> str:
        """Get skill context for enrichment."""
        from bugtrace.agents.skills.loader import get_skills_for_findings

        if hasattr(self, "_prior_findings") and self._prior_findings:
            return get_skills_for_findings(self._prior_findings, max_skills=2)
        return ""

    def _approach_build_prompt(self, context: Dict, skill_context: str) -> str:
        """Build analysis prompt with context and ACTIVE PROBE RESULTS.

        IMPROVED (2026-02-01): Now includes reflection probe results.
        The LLM receives CONCRETE evidence about parameter behavior.
        """
        # Format reflection probes as evidence section
        probe_section = self._format_probe_evidence(context.get("reflection_probes", []))

        # Format tech profile for LLM context
        tech_info_parts = []
        if self.tech_profile.get('infrastructure'):
            tech_info_parts.append(f"Infrastructure: {', '.join(self.tech_profile['infrastructure'])}")
        if self.tech_profile.get('frameworks'):
            tech_info_parts.append(f"Frameworks: {', '.join(self.tech_profile['frameworks'])}")
        if self.tech_profile.get('servers'):
            tech_info_parts.append(f"Servers: {', '.join(self.tech_profile['servers'])}")
        if self.tech_profile.get('waf'):
            tech_info_parts.append(f"⚠️ WAF Detected: {', '.join(self.tech_profile['waf'])}")
        if self.tech_profile.get('cdn'):
            tech_info_parts.append(f"CDN: {', '.join(self.tech_profile['cdn'])}")

        tech_stack_summary = "\n".join(tech_info_parts) if tech_info_parts else "Basic web application (no specific technologies detected)"

        return f"""Analyze this URL for security vulnerabilities.

URL: {self.url}

=== TECHNOLOGY STACK (Use this to craft precise exploits) ===
{tech_stack_summary}

NOTE: Use detected technologies to:
- Generate version-specific exploits (e.g., AngularJS 1.7.7 CSTI bypasses)
- Identify infrastructure-specific attack vectors (e.g., AWS ALB header manipulation)
- Avoid wasting time on irrelevant attacks (e.g., PHP attacks on Node.js)
- Craft payloads that bypass detected WAF/CDN protections

=== ACTIVE RECONNAISSANCE RESULTS (MANDATORY EVIDENCE) ===
{probe_section if probe_section else "No parameters detected in URL."}

=== PAGE HTML SOURCE (Snippet) ===
{context.get('html_content', 'Not available')[:8000]}

=== ANALYSIS RULES (STRICT - NO SMOKE ALLOWED) ===

MANDATORY: Base your analysis ONLY on the probe results above.
- If a parameter REFLECTS, specify the EXACT context (html_text, html_attribute, script_block, url_context)
- If characters like < > " ' survive, that is EVIDENCE of XSS potential
- If NO reflection is detected, you CANNOT claim XSS - the parameter does NOT reflect

CONFIDENCE SCORING (Evidence-Based):
- 0-3: No probe evidence, speculation only → DO NOT REPORT
- 4-5: Reflection detected but chars are encoded → Low priority
- 6-7: Reflection in dangerous context (attribute/script) with some chars surviving
- 8-9: Reflection with < > " ' all surviving in dangerous context
- 10: Confirmed execution (script block with unfiltered input)

=== PROHIBITED (Will be rejected) ===
- "Could be vulnerable" without probe evidence
- "Potentially exploitable" without concrete context
- XSS claims on parameters that DO NOT reflect
- SQLi claims without error response or behavioral evidence
- Vague descriptions like "try injecting", "test for", "might work"

=== REQUIRED OUTPUT FORMAT ===

For EACH vulnerability, you MUST provide:
- html_evidence: The EXACT line/snippet where the vulnerability exists (from probe results)
- xss_context: For XSS, specify ONE OF: html_text, html_attribute, script_block, url_context, none
- chars_survive: Which special chars survive unencoded (< > " ' `)

OOB Callback: {context.get('oob_info', {}).get('callback_url', 'http://oast.fun')}

{f"=== SPECIALIZED KNOWLEDGE ==={chr(10)}{skill_context}{chr(10)}" if skill_context else ""}

OUTPUT FORMAT (XML):
<vulnerabilities>
  <vulnerability>
    <type>XSS (Reflected)</type>
    <parameter>search</parameter>
    <confidence_score>8</confidence_score>
    <xss_context>html_attribute</xss_context>
    <html_evidence>Line 47: &lt;input value="bugtraceomni7x9z"&gt;</html_evidence>
    <chars_survive>&lt; &gt; "</chars_survive>
    <reasoning>Parameter reflects in input value attribute at line 47. Chars &lt; &gt; survive unencoded.</reasoning>
    <severity>High</severity>
    <payload>" onfocus=alert(1) autofocus="</payload>
  </vulnerability>
</vulnerabilities>

Return ONLY valid XML tags. No markdown. No explanations.
"""

    def _format_probe_evidence(self, probes: List[Dict]) -> str:
        """Format probe results as evidence section for LLM."""
        if not probes:
            return ""

        lines = []
        for p in probes:
            param = p.get("parameter", "unknown")
            reflects = p.get("reflects", False)
            context = p.get("context", "unknown")
            snippet = p.get("html_snippet", "")
            line_num = p.get("line_number", "?")
            status = p.get("status_code", "?")

            if reflects:
                lines.append(f"✓ {param}: REFLECTS in {context} (line {line_num}, status {status})")
                if snippet:
                    lines.append(f"  Snippet: {snippet[:100]}")
            else:
                lines.append(f"✗ {param}: NO REFLECTION (status {status})")

        return "\n".join(lines)

    def _approach_parse_response(self, response: str) -> Dict:
        """Parse LLM response into vulnerabilities."""
        parser = XmlParser()
        vuln_contents = parser.extract_list(response, "vulnerability")

        vulnerabilities = []
        for vc in vuln_contents:
            vuln = self._parse_single_vulnerability(parser, vc)
            if vuln:
                vulnerabilities.append(vuln)

        return {"vulnerabilities": vulnerabilities}

    def _parse_single_vulnerability(self, parser: XmlParser, vc: str) -> Optional[Dict]:
        """Parse a single vulnerability entry."""
        try:
            conf = self._parse_confidence_score(parser, vc)

            # Extract payload/exploitation_strategy with HTML unescaping to preserve special chars
            # (e.g., convert &lt;?xml to <?xml)
            payload = (
                parser.extract_tag(vc, "payload", unescape_html=True) or
                parser.extract_tag(vc, "exploitation_strategy", unescape_html=True) or
                ""
            )

            return {
                "type": parser.extract_tag(vc, "type") or "Unknown",
                "parameter": parser.extract_tag(vc, "parameter") or "unknown",
                "confidence_score": conf,
                "reasoning": parser.extract_tag(vc, "reasoning") or "",
                "severity": parser.extract_tag(vc, "severity") or "Medium",
                "exploitation_strategy": payload
            }
        except Exception as ex:
            logger.warning(f"Failed to parse vulnerability entry: {ex}")
            return None

    def _parse_confidence_score(self, parser: XmlParser, vc: str) -> int:
        """Parse and validate confidence score."""
        conf_str = parser.extract_tag(vc, "confidence_score") or parser.extract_tag(vc, "confidence") or "5"
        try:
            conf = int(float(conf_str))
            return max(0, min(10, conf))  # Clamp to 0-10
        except (ValueError, TypeError):
            return 5

    def _get_system_prompt(self, approach: str) -> str:
        """Get system prompt from external config."""
        if approach == "skeptical_agent":
            return self._get_skeptical_system_prompt()

        personas = self.agent_config.get("personas", {})
        if approach in personas:
            return personas[approach].strip()

        return self.system_prompt or "You are an expert security analyst."

    def _get_skeptical_system_prompt(self) -> str:
        """
        Get system prompt for skeptical_agent approach.

        The skeptical agent's job is to:
        1. Challenge findings from other approaches
        2. Identify common false positive patterns
        3. Assign FP likelihood scores
        """
        return """You are a SKEPTICAL security auditor. Your job is to CHALLENGE vulnerability findings and identify FALSE POSITIVES.

SKEPTICAL MINDSET:
- Parameter names alone (id, user, file) are NOT evidence of vulnerability
- Generic patterns without concrete evidence are likely false positives
- Error messages must be SPECIFIC SQL/command errors, not generic 500s
- XSS requires UNESCAPED reflection in dangerous contexts, not just reflection
- WAF-blocked requests indicate the app HAS protections

FALSE POSITIVE INDICATORS:
- "Could be vulnerable" or "potentially" without concrete evidence
- Vulnerability based on parameter NAME only (id -> SQLi assumption)
- No specific payload that would trigger the issue
- Technology stack inference without actual testing
- Assumptions based on common patterns

LIKELY TRUE POSITIVE INDICATORS:
- Specific error messages (SQL syntax errors, stack traces)
- Unescaped user input in script/event handler contexts
- Demonstrated behavioral differences (time-based, boolean-based)
- OOB callbacks received
- Specific version with known CVE

For EACH potential vulnerability, assign a SKEPTICAL_SCORE:
- 0-3: LIKELY FALSE POSITIVE - Reject, based on weak evidence
- 4-5: UNCERTAIN - Could be either, needs specialist validation
- 6-7: PLAUSIBLE - Some evidence, worth specialist investigation
- 8-10: LIKELY TRUE POSITIVE - Strong evidence, high priority

REMEMBER: Being skeptical SAVES TIME. False positives waste specialist agent resources."""

    def _calculate_fp_confidence(self, finding: Dict) -> float:
        """
        Calculate false positive confidence score for a finding.

        FP Confidence Scale (0.0-1.0):
        - 0.0: Almost certainly a FALSE POSITIVE
        - 0.5: Uncertain - needs specialist investigation
        - 1.0: Almost certainly a TRUE POSITIVE

        Formula:
        fp_confidence = (skeptical_component + votes_component + evidence_component)

        Where:
        - skeptical_component = (skeptical_score / 10) * FP_SKEPTICAL_WEIGHT
        - votes_component = (votes / max_votes) * FP_VOTES_WEIGHT
        - evidence_component = evidence_quality * FP_EVIDENCE_WEIGHT

        Args:
            finding: Vulnerability finding dict

        Returns:
            float: FP confidence score between 0.0 and 1.0
        """
        # Get weights from config
        skeptical_weight = getattr(settings, 'FP_SKEPTICAL_WEIGHT', 0.4)
        votes_weight = getattr(settings, 'FP_VOTES_WEIGHT', 0.3)
        evidence_weight = getattr(settings, 'FP_EVIDENCE_WEIGHT', 0.3)

        # 1. Skeptical component (0.0 - 0.4)
        skeptical_score = finding.get('skeptical_score', 5)
        skeptical_component = (skeptical_score / 10.0) * skeptical_weight

        # 2. Votes component (0.0 - 0.3)
        votes = finding.get('votes', 1)
        max_votes = len([a for a in self.approaches if a != 'skeptical_agent'])  # 5 core approaches
        votes_component = min(votes / max_votes, 1.0) * votes_weight

        # 3. Evidence component (0.0 - 0.3)
        evidence_quality = self._assess_evidence_quality(finding)
        evidence_component = evidence_quality * evidence_weight

        # Sum components (max = 1.0)
        fp_confidence = skeptical_component + votes_component + evidence_component

        # Clamp to 0.0-1.0
        return max(0.0, min(1.0, fp_confidence))

    def _assess_evidence_quality(self, finding: Dict) -> float:
        """
        Assess the quality of evidence for a finding.

        Evidence Quality Scale (0.0-1.0):
        - 0.0: No concrete evidence (parameter name only)
        - 0.5: Some patterns/indicators
        - 1.0: Concrete proof (error messages, reflection, OOB callback)

        Args:
            finding: Vulnerability finding dict

        Returns:
            float: Evidence quality score between 0.0 and 1.0
        """
        evidence_score = 0.0
        reasoning = str(finding.get('reasoning', '')).lower()
        payload = str(finding.get('exploitation_strategy', finding.get('payload', ''))).lower()
        vuln_type = str(finding.get('type', '')).lower()

        # Strong evidence indicators (+0.3 each, max 1.0)
        strong_indicators = [
            # SQL error patterns
            ('sql' in vuln_type and any(err in reasoning for err in ['syntax error', 'mysql', 'postgresql', 'sqlite', 'ora-'])),
            # XSS reflection
            ('xss' in vuln_type and any(ind in reasoning for ind in ['unescaped', 'reflected', 'rendered', 'executed'])),
            # Error messages
            any(err in reasoning for err in ['stack trace', 'exception', 'error message', 'debug']),
            # OOB callback
            'callback' in reasoning or 'oob' in reasoning or 'interactsh' in reasoning,
            # Validated/confirmed
            finding.get('validated', False) or 'confirmed' in reasoning,
        ]

        for indicator in strong_indicators:
            if indicator:
                evidence_score += 0.3

        # Medium evidence indicators (+0.15 each)
        medium_indicators = [
            # Has specific payload
            len(payload) > 10 and any(c in payload for c in ["'", '"', '<', '>', '{', '}']),
            # Has confidence score >= 7
            finding.get('confidence_score', 5) >= 7,
            # Multiple votes
            finding.get('votes', 1) >= 3,
        ]

        for indicator in medium_indicators:
            if indicator:
                evidence_score += 0.15

        # Weak evidence penalty (-0.2 each)
        weak_indicators = [
            # Parameter name only
            'parameter name' in reasoning or 'common parameter' in reasoning,
            # Speculation
            'could be' in reasoning or 'might be' in reasoning or 'potentially' in reasoning,
            # No payload
            len(payload) < 5,
        ]

        for indicator in weak_indicators:
            if indicator:
                evidence_score -= 0.2

        return max(0.0, min(1.0, evidence_score))


    async def _run_skeptical_approach(self, context: Dict, prior_analyses: List[Dict]) -> Dict:
        """
        Run skeptical_agent approach to review findings from core approaches.

        The skeptical agent sees ALL prior findings and challenges them,
        assigning skeptical_scores to help filter false positives early.
        """
        # Consolidate prior findings for skeptical review
        prior_findings = []
        for analysis in prior_analyses:
            for vuln in analysis.get("vulnerabilities", []):
                prior_findings.append(vuln)

        if not prior_findings:
            return {"vulnerabilities": []}

        # Build skeptical review prompt
        system_prompt = self._get_skeptical_system_prompt()
        user_prompt = self._build_skeptical_prompt(context, prior_findings)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model_override=settings.SKEPTICAL_MODEL,  # Use fast model for efficiency
                module_name="DASTySASTAgent_Skeptical",
                max_tokens=4000
            )

            if not response:
                return {"error": "Empty response from skeptical agent"}

            return self._parse_skeptical_response(response, prior_findings)

        except Exception as e:
            logger.error(f"Skeptical approach failed: {e}", exc_info=True)
            return {"error": str(e)}

    def _build_skeptical_prompt(self, context: Dict, prior_findings: List[Dict]) -> str:
        """Build prompt for skeptical review of prior findings."""
        findings_summary = []
        for i, f in enumerate(prior_findings):
            findings_summary.append(
                f"{i+1}. {f.get('type', 'Unknown')} on '{f.get('parameter', 'unknown')}' "
                f"(confidence: {f.get('confidence_score', 5)}/10)\n"
                f"   Reasoning: {f.get('reasoning', 'No reasoning')[:200]}"
            )

        return f"""Review these vulnerability findings and identify FALSE POSITIVES:

=== TARGET ===
URL: {self.url}

=== FINDINGS TO REVIEW ({len(prior_findings)} total) ===
{chr(10).join(findings_summary)}

=== YOUR TASK ===
For EACH finding, assign a SKEPTICAL_SCORE (0-10):
- 0-3: LIKELY FALSE POSITIVE (reject)
- 4-5: UNCERTAIN (needs validation)
- 6-7: PLAUSIBLE (investigate)
- 8-10: LIKELY TRUE POSITIVE (high priority)

Return XML:
<skeptical_review>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <skeptical_score>3</skeptical_score>
    <fp_reason>Based on parameter name only, no evidence of reflection</fp_reason>
  </finding>
</skeptical_review>

Be RUTHLESS. False positives waste resources."""

    def _parse_skeptical_response(self, response: str, prior_findings: List[Dict]) -> Dict:
        """Parse skeptical review response and tag findings with skeptical scores."""
        parser = XmlParser()
        finding_blocks = parser.extract_list(response, "finding")

        scored_findings = []

        for block in finding_blocks:
            try:
                idx = int(parser.extract_tag(block, "index")) - 1
                if 0 <= idx < len(prior_findings):
                    finding = prior_findings[idx].copy()
                    finding["skeptical_score"] = int(parser.extract_tag(block, "skeptical_score") or "5")
                    finding["fp_reason"] = parser.extract_tag(block, "fp_reason") or ""
                    scored_findings.append(finding)
            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse skeptical finding: {e}")

        logger.info(f"[{self.name}] Skeptical review: {len(scored_findings)} findings scored")
        return {"vulnerabilities": scored_findings, "approach": "skeptical_agent"}

    def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
        """
        Consolidate findings from different approaches using voting/merging.

        IMPROVED (2026-02-01): Technical deduplication - keep the finding with
        the most precise HTML evidence, not the one that "explains better".

        Evidence quality scoring:
        - html_evidence field present: +3 points
        - xss_context specified: +2 points
        - chars_survive specified: +1 point
        - probe_validated: +5 points (highest priority)
        """
        merged = {}
        skeptical_data = {}  # Track skeptical scores separately

        def to_float(val, default=0.5):
            try:
                return float(val)
            except (ValueError, TypeError):
                return default

        def _evidence_quality(vuln: Dict) -> int:
            """Score a finding's evidence quality. Higher = better evidence."""
            score = 0
            if vuln.get("probe_validated"):
                score += 5
            if vuln.get("html_evidence"):
                score += 3
            if vuln.get("xss_context") and vuln.get("xss_context") != "none":
                score += 2
            if vuln.get("chars_survive"):
                score += 1
            # Bonus for specific reasoning with line numbers
            reasoning = vuln.get("reasoning", "")
            if "line" in reasoning.lower() or "snippet" in reasoning.lower():
                score += 1
            return score

        # First pass: collect all findings
        for analysis in analyses:
            is_skeptical = analysis.get("approach") == "skeptical_agent"

            for vuln in analysis.get("vulnerabilities", []):
                v_type = vuln.get("type", vuln.get("vulnerability", "Unknown"))
                v_param = vuln.get("parameter", "none")
                key = f"{v_type}:{v_param}"

                conf = int(vuln.get("confidence_score", 5))

                if is_skeptical:
                    # Store skeptical data for later merge
                    skeptical_data[key] = {
                        "skeptical_score": vuln.get("skeptical_score", 5),
                        "fp_reason": vuln.get("fp_reason", "")
                    }
                else:
                    # Standard consolidation for core approaches
                    if key not in merged:
                        merged[key] = vuln.copy()
                        merged[key]["votes"] = vuln.get("votes", 1)  # Preserve probe's boost
                        merged[key]["confidence_score"] = conf
                        merged[key]["_evidence_score"] = _evidence_quality(vuln)
                    else:
                        # TECHNICAL DEDUPLICATION: Keep finding with BETTER EVIDENCE
                        existing_evidence = merged[key].get("_evidence_score", 0)
                        new_evidence = _evidence_quality(vuln)

                        if new_evidence > existing_evidence:
                            # New finding has better evidence - replace but keep vote count
                            old_votes = merged[key].get("votes", 1)
                            old_conf = merged[key].get("confidence_score", 5)
                            merged[key] = vuln.copy()
                            merged[key]["votes"] = old_votes + 1
                            merged[key]["confidence_score"] = int((old_conf + conf) / 2)
                            merged[key]["_evidence_score"] = new_evidence
                            logger.debug(f"[{self.name}] Dedup: Replaced {key} with better evidence ({new_evidence} > {existing_evidence})")
                        else:
                            # Existing has better or equal evidence - just add vote
                            merged[key]["votes"] += 1
                            merged[key]["confidence_score"] = int((merged[key]["confidence_score"] + conf) / 2)

        # Second pass: merge skeptical scores and calculate fp_confidence
        for key, vuln in merged.items():
            # Probe-validated findings keep their original scores (active testing > LLM analysis)
            if vuln.get("probe_validated"):
                vuln["fp_reason"] = "Validated by active probe testing"
                # Don't override skeptical_score or fp_confidence - probe's scores are authoritative
            elif key in skeptical_data:
                vuln["skeptical_score"] = skeptical_data[key]["skeptical_score"]
                vuln["fp_reason"] = skeptical_data[key]["fp_reason"]
                # Calculate FP confidence (Phase 17 enhancement)
                vuln['fp_confidence'] = self._calculate_fp_confidence(vuln)
            else:
                # No skeptical review for this finding - default to uncertain
                vuln["skeptical_score"] = 5
                vuln["fp_reason"] = "Not reviewed by skeptical agent"
                vuln['fp_confidence'] = self._calculate_fp_confidence(vuln)

        # Apply consensus filter - require at least 4 votes to reduce false positives
        min_votes = getattr(settings, "ANALYSIS_CONSENSUS_VOTES", 4)
        filtered = [v for v in merged.values() if v.get("votes", 1) >= min_votes]

        # Log skeptical filtering stats
        low_skeptical = [v for v in filtered if v.get("skeptical_score", 5) <= 3]
        if low_skeptical:
            logger.info(f"[{self.name}] Skeptical filter: {len(low_skeptical)} findings flagged as likely FP")

        return filtered

    async def _skeptical_review(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Use a skeptical LLM (Claude Haiku) to review findings and filter false positives.
        This is the final gate before findings reach specialist agents.

        Phase 17: Now uses fp_confidence for smart pre-filtering.
        Findings with low fp_confidence AND low skeptical_score are rejected early.

        Phase 27: Probe-validated findings bypass LLM review (active testing > LLM analysis).
        """
        # 0. Separate probe-validated findings (they bypass LLM review)
        probe_validated = []
        llm_findings = []
        for v in vulnerabilities:
            if v.get("probe_validated"):
                probe_validated.append(v)
                logger.info(f"[{self.name}] Probe-validated finding bypasses skeptical review: {v.get('type')} on {v.get('parameter')}")
            else:
                llm_findings.append(v)

        # 1. Pre-filter based on fp_confidence threshold (Phase 17 enhancement)
        # FIX: Use correct config attribute name (was FP_CONFIDENCE_THRESHOLD, now THINKING_FP_THRESHOLD)
        threshold = getattr(settings, 'THINKING_FP_THRESHOLD', 0.5)

        pre_filtered = []
        rejected_count = 0
        for v in llm_findings:
            fp_conf = v.get('fp_confidence', 0.5)
            skeptical_score = v.get('skeptical_score', 5)

            # Reject if BOTH skeptical_score is low AND fp_confidence is below threshold
            if skeptical_score <= 3 and fp_conf < threshold:
                logger.info(f"[{self.name}] Pre-filtered FP: {v.get('type')} on '{v.get('parameter')}' "
                           f"(fp_confidence: {fp_conf:.2f}, skeptical: {skeptical_score})")
                rejected_count += 1
            else:
                pre_filtered.append(v)

        if rejected_count > 0:
            logger.info(f"[{self.name}] FP pre-filter: {rejected_count} removed (threshold: {threshold}), {len(pre_filtered)} remaining")

        if not pre_filtered:
            # Still return probe-validated findings
            return probe_validated

        # 2. Deduplicate
        vulnerabilities = self._review_deduplicate(pre_filtered)
        if not vulnerabilities:
            return probe_validated

        # 3. Build prompt
        prompt = self._review_build_prompt(vulnerabilities)

        # 4. Execute review
        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt="You are a skeptical security expert. Reject false positives ruthlessly.",
                model_override=settings.SKEPTICAL_MODEL,
                module_name="DASTySAST_Skeptical",
                max_tokens=2000
            )

            if not response:
                logger.warning(f"[{self.name}] Skeptical review empty - keeping all")
                return probe_validated + vulnerabilities

            # 4. Parse and approve, then add probe-validated
            llm_approved = self._review_parse_approval(response, vulnerabilities)
            return probe_validated + llm_approved

        except Exception as e:
            logger.error(f"[{self.name}] Skeptical review failed: {e}", exc_info=True)
            return probe_validated + vulnerabilities

    def _review_deduplicate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Deduplicate vulnerabilities by type+parameter, keeping highest confidence."""
        deduped = {}
        for v in vulnerabilities:
            key = (v.get('type'), v.get('parameter'))
            existing = deduped.get(key)
            if not existing or v.get('confidence', 0) > existing.get('confidence', 0):
                deduped[key] = v

        result = list(deduped.values())
        logger.info(f"[{self.name}] Deduplicated: {len(result)} unique findings")
        return result

    def _review_build_prompt(self, vulnerabilities: List[Dict]) -> str:
        """Build skeptical review prompt with enriched context."""
        from bugtrace.agents.skills.loader import get_scoring_guide, get_false_positives

        vulns_summary_parts = []
        for i, v in enumerate(vulnerabilities):
            vuln_type = v.get('type', 'Unknown')
            scoring_guide = get_scoring_guide(vuln_type)
            fp_guide = get_false_positives(vuln_type)

            part = f"""{i+1}. {vuln_type} on '{v.get('parameter')}'
   DASTySAST Score: {v.get('confidence_score', 5)}/10 | Votes: {v.get('votes', 1)}/5
   Reasoning: {v.get('reasoning') or 'No reasoning'}

   {scoring_guide[:500] if scoring_guide else ''}
   {fp_guide[:300] if fp_guide else ''}"""
            vulns_summary_parts.append(part)

        vulns_summary = "\n\n".join(vulns_summary_parts)

        return f"""You are a security expert reviewing vulnerability findings.

=== TARGET ===
URL: {self.url}

=== FINDINGS ({len(vulnerabilities)} total) ===
{vulns_summary}

=== YOUR TASK ===
For EACH finding, evaluate and assign a FINAL CONFIDENCE SCORE (0-10).

SCORING GUIDE:
- 0-3: REJECT - No evidence, parameter name only, "EXPECTED: SAFE" present
- 4-5: LOW - Weak indicators, probably false positive
- 6-7: MEDIUM - Some patterns, worth testing by specialist
- 8-9: HIGH - Clear evidence (SQL errors, unescaped reflection)
- 10: CONFIRMED - Obvious vulnerability

RULES:
1. If the "DASTySAST Score" is high AND "Votes" are 4/5 or 5/5, lean towards a higher FINAL SCORE (6+).
2. Parameter NAME alone (webhook, id, xml) is NOT enough for score > 5, UNLESS votes are 5/5.
3. If "EXPECTED: SAFE" is found in reasoning, REJECT immediately (score 0-3).
4. "EXPECTED: VULNERABLE" in context → score 8-10
5. SQL errors visible → score 8+
6. Unescaped HTML reflection → score 7+
7. Adjust DASTySAST score up/down based on your analysis

Return XML:
<reviewed>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <final_score>7</final_score>
    <reasoning>Brief explanation</reasoning>
  </finding>
</reviewed>
"""

    def _review_parse_approval(self, response: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """Parse skeptical review response and approve findings above threshold."""
        parser = XmlParser()
        finding_blocks = parser.extract_list(response, "finding")

        approved = []

        for block in finding_blocks:
            self._process_review_finding(parser, block, vulnerabilities, approved)

        logger.info(f"[{self.name}] Skeptical Review: {len(approved)} passed, {len(vulnerabilities)-len(approved)} rejected")
        return approved

    def _process_review_finding(self, parser: XmlParser, block: str,
                                vulnerabilities: List[Dict], approved: List[Dict]):
        """Process a single review finding."""
        try:
            idx = int(parser.extract_tag(block, "index")) - 1
            vuln_type = parser.extract_tag(block, "type") or "UNKNOWN"
            final_score = int(parser.extract_tag(block, "final_score") or "0")
            reasoning = parser.extract_tag(block, "reasoning") or ""

            if not (0 <= idx < len(vulnerabilities)):
                return

            vuln = vulnerabilities[idx]
            vuln["skeptical_score"] = final_score
            vuln["skeptical_reasoning"] = reasoning

            # Get type-specific threshold
            threshold = settings.get_threshold_for_type(vuln_type)

            if final_score >= threshold:
                logger.info(f"[{self.name}] ✅ APPROVED #{idx+1} {vuln_type} (score: {final_score}/10 >= {threshold}): {reasoning[:60]}")
                approved.append(vuln)
            else:
                logger.info(f"[{self.name}] ❌ REJECTED #{idx+1} {vuln_type} (score: {final_score}/10 < {threshold}): {reasoning[:60]}")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse finding: {e}")

    async def _emit_url_analyzed(self, vulnerabilities: List[Dict]):
        """
        Emit url_analyzed event with filtered findings.

        Event payload:
        - url: The analyzed URL
        - scan_context: Context for ordering guarantees
        - findings: List of findings with fp_confidence
        - stats: Summary statistics
        - report_files: Paths to JSON and MD reports (v2.1.0)

        This event is consumed by:
        - ThinkingConsolidationAgent (Phase 18): For deduplication and queue distribution
        - Dashboard: For real-time progress updates

        v2.1.0: Added report_files to allow specialists to read full payloads from JSON
        when event payload is truncated (>200 chars).
        """
        # Determine base filename based on url_index
        if self.url_index is not None:
            base_filename = str(self.url_index)
        else:
            # Fallback for compatibility with old calls
            base_filename = f"vulnerabilities_{self._get_safe_name()}"

        # Calculate report file paths
        json_report_path = str(self.report_dir / f"{base_filename}.json")
        md_report_path = str(self.report_dir / f"{base_filename}.md")

        # Prepare findings payload with essential fields
        findings_payload = []
        for v in vulnerabilities:
            findings_payload.append({
                "type": v.get("type", "Unknown"),
                "parameter": v.get("parameter", "unknown"),
                "url": self.url,
                "fp_confidence": v.get("fp_confidence", 0.5),
                "skeptical_score": v.get("skeptical_score", 5),
                "confidence_score": v.get("confidence_score", 5),
                "votes": v.get("votes", 1),
                "severity": v.get("severity", "Medium"),
                "reasoning": v.get("reasoning", "")[:500],  # Truncate for event size
                "payload": v.get("exploitation_strategy", v.get("payload", ""))[:200],  # Truncated - full version in JSON
                "fp_reason": v.get("fp_reason", "")[:200]
            })

        # Build event data
        event_data = {
            "url": self.url,
            "scan_context": self.scan_context,
            "findings": findings_payload,
            "stats": {
                "total": len(findings_payload),
                "high_confidence": len([f for f in findings_payload if f.get("fp_confidence", 0) >= 0.7]),
                "by_type": self._count_by_type(findings_payload)
            },
            "tech_profile": {
                "frameworks": self.tech_profile.get("frameworks", [])[:5]  # Limit for event size
            },
            "report_files": {  # v2.1.0: Allow specialists to read full payloads from JSON
                "json": json_report_path,
                "markdown": md_report_path,
                "url_index": self.url_index  # For correlation with urls.txt
            },
            "timestamp": __import__('time').time()
        }

        # Emit event
        try:
            await event_bus.emit(EventType.URL_ANALYZED, event_data)
            logger.info(f"[{self.name}] Emitted url_analyzed: {len(findings_payload)} findings for {self.url[:50]}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to emit url_analyzed event: {e}")


    def _count_by_type(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        counts = {}
        for f in findings:
            v_type = f.get("type", "Unknown")
            counts[v_type] = counts.get(v_type, 0) + 1
        return counts

    def _save_markdown_report(self, path: Path, vulnerabilities: List[Dict]):
        """Saves markdown report with FP confidence scores."""
        content = f"# Potential Vulnerabilities for {self.url}\n\n"

        if not vulnerabilities:
            content += "No vulnerabilities detected by DAST+SAST analysis.\n"
        else:
            content += "| Type | Parameter | FP Confidence | Skeptical Score | Votes |\n"
            content += "|------|-----------|---------------|-----------------|-------|\n"

            for v in sorted(vulnerabilities, key=lambda x: x.get('fp_confidence', 0), reverse=True):
                fp_conf = v.get('fp_confidence', 0.5)
                fp_indicator = '++' if fp_conf >= 0.7 else '+' if fp_conf >= 0.5 else '-'

                # Wrap parameter in code block to preserve special chars
                param_safe = f"`{v.get('parameter', 'N/A')}`"
                content += f"| {v.get('type', 'Unknown')} | {param_safe} | "
                content += f"{fp_conf:.2f} {fp_indicator} | {v.get('skeptical_score', 5)}/10 | "
                content += f"{v.get('votes', 1)}/5 |\n"

            content += "\n## Details\n\n"

            for v in vulnerabilities:
                # Wrap parameter in code block
                param_safe = f"`{v.get('parameter', 'N/A')}`"
                content += f"### {v.get('type')} on {param_safe}\n\n"
                content += f"- **FP Confidence**: {v.get('fp_confidence', 0.5):.2f}\n"
                content += f"- **Skeptical Score**: {v.get('skeptical_score', 5)}/10\n"
                content += f"- **Votes**: {v.get('votes', 1)}/5 approaches\n"

                # Wrap reasoning in code block if it contains payloads/evidence
                reasoning = v.get('reasoning', 'N/A')
                content += f"- **Reasoning**: {reasoning}\n"

                # Add payload in code block if present
                if v.get('payload') or v.get('exploitation_strategy'):
                    payload = v.get('payload') or v.get('exploitation_strategy')
                    content += f"- **Payload**: `{payload}`\n"

                # Add evidence in code block if present
                if v.get('evidence'):
                    evidence = v.get('evidence')
                    # If evidence is long, use code fence; otherwise inline code
                    if len(str(evidence)) > 100:
                        content += f"- **Evidence**:\n```\n{evidence}\n```\n"
                    else:
                        content += f"- **Evidence**: `{evidence}`\n"

                if v.get('fp_reason'):
                    content += f"- **FP Analysis**: {v.get('fp_reason')}\n"
                content += "\n"

        with open(path, "w") as f:
            f.write(content)

    def _save_json_report(self, path: Path, vulnerabilities: List[Dict]):
        """
        Saves JSON report with complete structured data for 100% payload preservation.

        This format ensures all special characters in payloads, parameters, and evidence
        are preserved exactly as-is, without any Markdown interpretation issues.
        """
        import time

        # Build complete report structure
        report = {
            "metadata": {
                "url": self.url,
                "url_index": self.url_index,
                "scan_context": self.scan_context,
                "timestamp": time.time(),
                "tech_profile": {
                    "frameworks": self.tech_profile.get("frameworks", []),
                    "libraries": self.tech_profile.get("libraries", []),
                    "server": self.tech_profile.get("server", ""),
                    "language": self.tech_profile.get("language", "")
                }
            },
            "statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "high_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) >= 0.7]),
                "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get('fp_confidence', 0) < 0.7]),
                "low_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) < 0.5]),
                "by_type": self._count_by_type(vulnerabilities)
            },
            "vulnerabilities": []
        }

        # Add vulnerabilities with all fields preserved
        for v in vulnerabilities:
            vuln_data = {
                "type": v.get("type", "Unknown"),
                "parameter": v.get("parameter", "N/A"),
                "fp_confidence": v.get("fp_confidence", 0.5),
                "skeptical_score": v.get("skeptical_score", 5),
                "votes": v.get("votes", 1),
                "severity": v.get("severity", "Medium"),
                "confidence_score": v.get("confidence_score", 5),
                "reasoning": v.get("reasoning", ""),
                "payload": v.get("payload", v.get("exploitation_strategy", "")),
                "evidence": v.get("evidence", ""),
                "fp_reason": v.get("fp_reason", ""),
                "validation_result": v.get("validation_result"),
                "http_method": v.get("http_method", ""),
                "url": v.get("url", self.url)
            }

            # Include any additional fields that might be present
            for key, value in v.items():
                if key not in vuln_data:
                    vuln_data[key] = value

            report["vulnerabilities"].append(vuln_data)

        # Sort vulnerabilities by FP confidence (highest first)
        report["vulnerabilities"].sort(key=lambda x: x.get('fp_confidence', 0), reverse=True)

        # Save JSON with proper formatting
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.debug(f"[{self.name}] Saved JSON report to {path}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to save JSON report to {path}: {e}")
