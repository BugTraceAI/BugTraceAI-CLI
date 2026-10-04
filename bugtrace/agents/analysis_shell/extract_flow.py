"""HTML/auth/param extraction.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)

class AnalysisExtractMixin:
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
                self._analysis_html = html_full  # Store full HTML for SQLi probes
                if len(html_full) > 15000:
                     context["html_content"] = html_full[:7500] + "\n...[TRUNCATED]...\n" + html_full[-7500:]
                else:
                    context["html_content"] = html_full

                logger.info(f"[{self.name}] Fetched HTML content ({len(context['html_content'])} chars) for analysis.")
                self._v.emit("discovery.url.html_captured", {"url": self.url, "html_length": len(context['html_content'])})

                # FIX (2026-02-04): Detect frontend frameworks from HTML
                # This ensures CSTI detection even when Nuclei misses Angular/Vue
                self._detect_frontend_frameworks_from_html(html_full)
                if self.tech_profile.get('frameworks'):
                    self._v.emit("discovery.url.frameworks_detected", {"url": self.url, "frameworks": self.tech_profile['frameworks'][:5]})
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
                self._reflection_probes = probes  # Store for auto-candidate injection
                reflecting = [p for p in probes if p.get("reflects")]
                self._v.emit("discovery.probe.completed", {
                    "url": self.url, "total": len(probes),
                    "reflecting": len(reflecting),
                    "non_reflecting": len(probes) - len(reflecting),
                })
                logger.info(f"[{self.name}] Active recon: {len(probes)} parameters probed")
            except Exception as e:
                logger.warning(f"[{self.name}] Active recon probes failed: {e}")

        return context

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

            # 5. JavaScript URL construction patterns (SPA parameter discovery)
            # Catches React/Vue/Angular SPAs that build URLs via JS instead of forms.
            # E.g., window.location.href = `/?search=${encodeURIComponent(term)}`
            # GUARD: skip on JSON API responses — the regex matches PoC URLs inside
            # JSON vulnerability descriptions (e.g. /api/debug/vulns cheat-sheets),
            # creating dozens of ghost params that produce false positives.
            import re
            content_trimmed = html.strip()[:20]
            is_json_response = (
                content_trimmed.startswith(("{", "["))
                or "application/json" in html[:500].lower()
            )

            js_count = 0
            if not is_json_response:
                _JS_PARAM_SKIP = frozenset({
                    "v", "ver", "version", "cb", "ts", "timestamp", "t", "hash",
                    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
                    "fbclid", "gclid", "nonce", "lang", "locale", "charset", "encoding",
                })
                for match in re.finditer(r'[?&]([a-zA-Z_]\w{1,30})=', html):
                    param_name = match.group(1)
                    if param_name.lower() in _JS_PARAM_SKIP:
                        continue
                    if param_name not in seen:
                        seen.add(param_name)
                        unique_params.append(param_name)
                        js_count += 1
                        logger.debug(f"[{self.name}] Found JS URL param: {param_name} (source=js_url_pattern)")
            if js_count:
                logger.info(f"[{self.name}] Extracted {js_count} params from JS URL patterns")

            if unique_params:
                logger.info(f"[{self.name}] Extracted {len(unique_params)} total params from HTML: {unique_params}")

            return unique_params

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to extract HTML params: {e}")
            return []

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

    def _approach_get_skill_context(self) -> str:
        """Get skill context for enrichment."""
        from bugtrace.agents.skills.loader import get_skills_for_findings

        if hasattr(self, "_prior_findings") and self._prior_findings:
            return get_skills_for_findings(self._prior_findings, max_skills=2)
        return ""

