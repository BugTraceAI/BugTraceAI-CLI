"""SQLi/cookie/reflection probes.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)

class AnalysisReflectionProbesMixin:
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

        self._v.emit("discovery.url.params_found", {"url": self.url, "params": list(all_param_names), "count": len(all_param_names)})
        self._v.emit("discovery.probe.started", {"url": self.url, "total_params": len(all_param_names)})
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
                        self._v.emit("discovery.probe.header_reflection", {"url": self.url, "param": param_name, "header": header_reflection.get("header", "")})
                        if not probe_result["reflects"]:
                            probe_result["reflects"] = True
                            probe_result["context"] = "response_header"
                    probes.append(probe_result)

                    self._v.emit("discovery.probe.result", {
                        "url": self.url, "param": param_name,
                        "reflects": probe_result["reflects"],
                        "context": probe_result.get("context", ""),
                        "chars": probe_result.get("chars_survive", ""),
                    })
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

    def _inject_param_based_candidates(self, consolidated: List[Dict]) -> List[Dict]:
        """
        Auto-generate specialist candidates based on parameter names/values.

        Ensures file-related params (file, path, image) always reach the LFI specialist
        and redirect-related params (url, redirect, next) reach the OpenRedirect specialist,
        even if the LLM only detected XSS reflection.
        """
        from urllib.parse import urlparse, parse_qs

        if not hasattr(self, '_reflection_probes'):
            self._reflection_probes = []

        # Parse original URL to get parameter values
        parsed = urlparse(self.url)
        url_params = parse_qs(parsed.query)

        # Collect all known params: from URL + from probes
        all_params = {}
        for k, v in url_params.items():
            all_params[k] = v[0] if v else ""
        for probe in self._reflection_probes:
            pname = probe.get("parameter", "")
            if pname and pname not in all_params:
                all_params[pname] = ""

        if not all_params:
            return consolidated

        # Track existing finding types per parameter
        existing = set()
        for f in consolidated:
            ftype = f.get("type", "").lower()
            fparam = f.get("parameter", "").lower()
            existing.add(f"{ftype}:{fparam}")

        # Map param -> reflection context from active probes (deterministic XSS net).
        # A param that reflects in script_block/html_text/html_attribute/url_context is
        # an XSS vector regardless of what the LLM labelled it (e.g. CSTI on an Angular
        # page). Without this, an Angular page's JS-string reflection is routed to CSTI
        # only and XSSAgent never gets the URL as a seed -> JS-string XSS is missed.
        probe_ctx = {}
        for probe in self._reflection_probes:
            if probe.get("reflects"):
                pname = probe.get("parameter", "")
                if pname:
                    probe_ctx[pname] = probe.get("context", "")

        injected = []
        for param_name, param_value in all_params.items():
            param_lower = param_name.lower()

            # --- LFI candidate ---
            is_lfi_name = param_lower in self._LFI_PARAM_HINTS or any(
                h in param_lower for h in ("file", "path", "dir", "doc", "include", "load", "read")
            )
            is_file_value = any(
                param_value.lower().endswith(ext) for ext in self._FILE_EXTENSIONS
            ) if param_value else False
            has_path_sep = ("/" in param_value or "\\" in param_value) if param_value else False

            if is_lfi_name or is_file_value or has_path_sep:
                # Check no existing LFI finding for this param
                has_lfi = any(
                    fparam == param_lower and ("lfi" in ftype or "traversal" in ftype or "file" in ftype)
                    for ftype_param in existing
                    for ftype, fparam in [ftype_param.split(":", 1)]
                )
                if not has_lfi:
                    injected.append({
                        "type": "LFI",
                        "parameter": param_name,
                        "confidence_score": 7,
                        "votes": 4,
                        "probe_validated": False,
                        "fp_confidence": 0.8,
                        "skeptical_score": 8,
                        "reasoning": (
                            f"Parameter '{param_name}' suggests file operations "
                            f"(value: '{param_value}'). Auto-candidate for LFI specialist."
                        ),
                        "exploitation_strategy": "../../../etc/passwd",
                        "url": self.url,
                        "_auto_dispatched": True,
                    })
                    existing.add(f"lfi:{param_lower}")
                    logger.info(f"[{self.name}] Auto-injected LFI candidate: param='{param_name}', value='{param_value}'")

            # --- Open Redirect candidate ---
            is_redirect_name = param_lower in self._REDIRECT_PARAM_HINTS or any(
                h in param_lower for h in ("url", "redirect", "return", "goto", "dest", "next")
            )
            has_url_value = param_value.startswith(("http", "//", "/")) if param_value else False

            if is_redirect_name or has_url_value:
                has_redirect = any(
                    fparam == param_lower and ("redirect" in ftype or "open redirect" in ftype)
                    for ftype_param in existing
                    for ftype, fparam in [ftype_param.split(":", 1)]
                )
                if not has_redirect:
                    injected.append({
                        "type": "Open Redirect",
                        "parameter": param_name,
                        "confidence_score": 6,
                        "votes": 4,
                        "probe_validated": False,
                        "fp_confidence": 0.7,
                        "skeptical_score": 7,
                        "reasoning": (
                            f"Parameter '{param_name}' suggests URL redirect "
                            f"(value: '{param_value}'). Auto-candidate for OpenRedirect specialist."
                        ),
                        "url": self.url,
                        "_auto_dispatched": True,
                    })
                    existing.add(f"open redirect:{param_lower}")
                    logger.info(f"[{self.name}] Auto-injected Open Redirect candidate: param='{param_name}'")

            # --- RCE candidate ---
            is_rce_name = param_lower in self._RCE_PARAM_HINTS or any(
                h in param_lower for h in ("cmd", "exec", "command", "shell", "run")
            )
            if is_rce_name:
                has_rce = any(
                    fparam == param_lower and ("rce" in ftype or "command" in ftype or "injection" in ftype)
                    for ftype_param in existing
                    for ftype, fparam in [ftype_param.split(":", 1)]
                )
                if not has_rce:
                    injected.append({
                        "type": "RCE",
                        "parameter": param_name,
                        "confidence_score": 7,
                        "votes": 4,
                        "probe_validated": False,
                        "fp_confidence": 0.8,
                        "skeptical_score": 8,
                        "reasoning": (
                            f"Parameter '{param_name}' suggests command execution. "
                            f"Auto-candidate for RCE specialist."
                        ),
                        "exploitation_strategy": "id",
                        "url": self.url,
                        "_auto_dispatched": True,
                    })
                    existing.add(f"rce:{param_lower}")
                    logger.info(f"[{self.name}] Auto-injected RCE candidate: param='{param_name}'")

            # --- SSRF candidate ---
            is_ssrf_name = param_lower in self._SSRF_PARAM_HINTS
            is_ssrf_value = param_value.startswith(("http", "//", "ftp")) if param_value else False
            if is_ssrf_name or is_ssrf_value:
                has_ssrf = any(
                    fparam == param_lower and ("ssrf" in ftype or "server-side" in ftype)
                    for ftype_param in existing
                    for ftype, fparam in [ftype_param.split(":", 1)]
                )
                if not has_ssrf:
                    injected.append({
                        "type": "SSRF",
                        "parameter": param_name,
                        "confidence_score": 6,
                        "votes": 4,
                        "probe_validated": False,
                        "fp_confidence": 0.7,
                        "skeptical_score": 7,
                        "reasoning": (
                            f"Parameter '{param_name}' suggests URL fetching "
                            f"(value: '{param_value}'). Auto-candidate for SSRF specialist."
                        ),
                        "url": self.url,
                        "_auto_dispatched": True,
                    })
                    existing.add(f"ssrf:{param_lower}")
                    logger.info(f"[{self.name}] Auto-injected SSRF candidate: param='{param_name}'")

            # --- XSS candidate (deterministic safety-net, model-independent) ---
            # If the param reflects in a dangerous context per active probe, always
            # create an XSS candidate so it routes to the xss queue and seeds XSSAgent
            # with this URL -- even when the LLM only emitted a CSTI/other candidate.
            xss_ctx = probe_ctx.get(param_name)
            if xss_ctx in ("script_block", "html_text", "html_attribute", "url_context"):
                has_xss = any(
                    fparam == param_lower and ("xss" in ftype or "cross-site script" in ftype)
                    for ftype_param in existing
                    for ftype, fparam in [ftype_param.split(":", 1)]
                )
                if not has_xss:
                    injected.append({
                        "type": "XSS",
                        "parameter": param_name,
                        "confidence_score": 6,
                        "votes": 4,
                        "probe_validated": False,
                        "fp_confidence": 0.7,
                        "skeptical_score": 7,
                        "reasoning": (
                            f"Parameter '{param_name}' reflects in a dangerous context "
                            f"('{xss_ctx}') per active reflection probe. Auto-candidate "
                            f"for XSS specialist regardless of LLM classification "
                            f"(deterministic net; XSSAgent does its own param discovery)."
                        ),
                        "exploitation_strategy": "",
                        "url": self.url,
                        # Measured reflection context as a field (stable 891f012)
                        "probe_context": xss_ctx,
                        "_auto_dispatched": True,
                    })
                    existing.add(f"xss:{param_lower}")
                    logger.info(f"[{self.name}] Auto-injected XSS candidate: param='{param_name}', context='{xss_ctx}'")

        # --- Dual-route: CSTI on client-side framework → also seed XSS queue ---
        # When the LLM classifies a reflecting param as CSTI (AngularJS/Vue), the
        # param only reaches CSTIAgent. But the same param may ALSO have a JS-string
        # breakout XSS (e.g. searchTerm on ginandjuice). Dual-routing ensures the
        # XSSAgent gets the URL as a seed for autonomous discovery.
        csti_frameworks = {"angular", "angularjs", "vue", "vuejs"}
        tech_profile = getattr(self, 'tech_profile', {}) or {}
        detected_fw = [fw.lower() for fw in tech_profile.get("frameworks", [])]
        is_client_csti = any(fw in csti_frameworks for fw in detected_fw)

        if is_client_csti:
            for f in list(consolidated) + list(injected):
                ftype = (f.get("type") or "").lower()
                if "csti" not in ftype and "template" not in ftype:
                    continue
                raw_param = f.get("parameter", "")
                if not raw_param or raw_param in ("_auto_discover", "auto_dispatch", "N/A"):
                    continue
                # LLM sometimes joins multiple params: "searchTerm, category"
                param_parts = [p.strip() for p in raw_param.replace(",", " ").split() if p.strip()]
                for fparam in param_parts:
                    fparam_lower = fparam.lower()
                    if f"xss:{fparam_lower}" in existing:
                        continue
                    injected.append({
                        "type": "XSS",
                        "parameter": fparam,
                        "confidence_score": 5,
                        "votes": 3,
                        "probe_validated": False,
                        "fp_confidence": 0.6,
                        "skeptical_score": 6,
                        "reasoning": (
                            f"Dual-route: '{fparam}' classified as CSTI on a client-side "
                            f"framework page. Also routing to XSS queue so XSSAgent can "
                            f"test JS-string breakout independently."
                        ),
                        "url": self.url,
                        "_auto_dispatched": True,
                        "_dual_routed_from": "CSTI",
                    })
                    existing.add(f"xss:{fparam_lower}")
                    logger.info(f"[{self.name}] Dual-route CSTI→XSS: param='{fparam}'")

        if injected:
            consolidated.extend(injected)
            logger.info(f"[{self.name}] Auto-injected {len(injected)} parameter-based candidates")

        return consolidated

    def _extract_link_sqli_targets(self, html: str) -> Dict[str, Dict[str, str]]:
        """
        Extract query parameters from <a> href links in the HTML.

        Returns a dict mapping endpoint URLs to their query params.
        Only same-origin links are included. This catches params like
        "category" that appear in navigation links but not in the current URL.

        Example return: {
            "https://example.com/catalog?category=Juice": {"category": "Juice"},
            "https://example.com/product?id=1": {"id": "1"},
        }
        """
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse, parse_qs, urljoin

        targets = {}
        if not html:
            return targets

        try:
            parsed_self = urlparse(self.url)
            soup = BeautifulSoup(html, "html.parser")

            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                    continue
                try:
                    resolved_url = urljoin(self.url, href)
                    resolved = urlparse(resolved_url)

                    # Same-origin only
                    if resolved.netloc and resolved.netloc != parsed_self.netloc:
                        continue

                    link_params = parse_qs(resolved.query)
                    if not link_params:
                        continue

                    # Build clean URL (scheme + host + path)
                    clean_url = f"{resolved.scheme}://{resolved.netloc}{resolved.path}"
                    if clean_url not in targets:
                        targets[clean_url] = {}

                    for p_name, p_vals in link_params.items():
                        if p_name not in targets[clean_url]:
                            targets[clean_url][p_name] = p_vals[0] if p_vals else ""

                except Exception:
                    continue

            if targets:
                total_params = sum(len(v) for v in targets.values())
                logger.info(
                    f"[{self.name}] Extracted {total_params} params from "
                    f"{len(targets)} link endpoints for SQLi probing"
                )

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to extract link params: {e}")

        return targets

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
                is_secure = 'secure' in flags_lower
                has_samesite = 'samesite' in flags_lower

                # Store with metadata — HttpOnly cookies are the high-value targets
                if name not in self._http_cookies:
                    self._http_cookies[name] = {
                        "name": name,
                        "value": value,
                        "httponly": is_httponly,
                        "secure": is_secure,
                        "samesite": has_samesite,
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
