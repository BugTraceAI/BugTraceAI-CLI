"""CSTI remaining helpers.

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
from bugtrace.tools.waf import waf_fingerprinter
from bugtrace.tools.interactsh import InteractshClient

logger = get_logger(__name__)

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.payloads import PAYLOAD_LIBRARY

class CSTIMiscMixin:
    async def _detect_waf_async(self) -> Tuple[str, float]:
        """Detect WAF using framework's intelligent fingerprinter."""
        try:
            waf_name, confidence = await waf_fingerprinter.detect(self.url)
            self._detected_waf = waf_name if waf_name != "unknown" else None
            self._waf_confidence = confidence

            if self._detected_waf:
                logger.info(f"[{self.name}] WAF Detected: {waf_name} ({confidence:.0%})")
                dashboard.log(f"[{self.name}] 🛡️ WAF: {waf_name} ({confidence:.0%})", "INFO")

            return waf_name, confidence
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return "unknown", 0.0

    def _configure_session(self, session: aiohttp.ClientSession):
        """Configure session with cookies and headers from authentication."""
        if hasattr(self, 'cookies') and self.cookies:
            # aiohttp handles CookieJar, but we can also set header for simplicity in some cases
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
            session.cookie_jar.update_cookies({"Cookie": cookie_str})
            logger.debug(f"[{self.name}] Applied {len(self.cookies)} cookies to session")
        
        if hasattr(self, 'headers') and self.headers:
            session._default_headers.update(self.headers)

    def _generate_repro_steps(self, url: str, param: str, payload: str, curl_cmd: str) -> List[str]:
        """Generate step-by-step reproduction instructions."""
        return [
            f"1. Navigate to the verified target: {url}",
            f"2. Locate the parameter `{param}`",
            f"3. Inject the payload: `{payload}`",
            f"4. Expected observation: The expression is evaluated (1000003*1000003 becomes 1000006000009).",
            f"5. Alternative: Run the provided cURL command:",
            f"   `{curl_cmd}`"
        ]

    async def _setup_interactsh(self):
        """Register with Interactsh for OOB validation."""
        try:
            self.interactsh = InteractshClient()
            await self.interactsh.register()
            self.interactsh_url = self.interactsh.get_url("csti_agent")
            logger.info(f"[{self.name}] Interactsh ready: {self.interactsh_url}")
        except Exception as e:
            logger.warning(f"Failed to setup Interactsh: {e}")
            self.interactsh = None

    async def _check_oob_hit(self, label: str) -> bool:
        """Check if we got an OOB callback."""
        if not self.interactsh:
            return False

        await asyncio.sleep(2)  # Wait for callback
        hit = await self.interactsh.check_hit(label)
        return hit is not None

    async def _fetch_page(self, session) -> str:
        """Fetch page content for fingerprinting."""
        try:
            async with session.get(self.url, timeout=10) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"_fetch_page failed: {e}")
            return ""

    def _should_stop_testing(self, payload: str, response: str, successful_count: int) -> Tuple[bool, str]:
        """Determine if we should stop based on Victory Hierarchy."""
        impact_tier = self._get_payload_impact_tier(payload, response)

        if impact_tier >= 3:
            self._max_impact_achieved = True
            return True, "🏆 MAXIMUM IMPACT: RCE or File Read achieved"

        if impact_tier >= 2:
            self._max_impact_achieved = True
            return True, "🏆 HIGH IMPACT: Internals access confirmed"

        if impact_tier >= 1 and successful_count >= 1:
            return True, "✅ Template evaluation confirmed"

        if successful_count >= 2:
            return True, "⚡ 2 successful payloads, moving on"

        return False, ""

    async def _test_post_injection(
        self,
        session: aiohttp.ClientSession,
        param: str,
        engines: List[str]
    ) -> Optional[Dict]:
        """Test POST parameters for template injection."""
        payloads = PAYLOAD_LIBRARY.get(engines[0], PAYLOAD_LIBRARY["universal"])[:5] if engines and engines[0] != "unknown" else PAYLOAD_LIBRARY["universal"][:5]

        for payload in payloads:
            finding = await self._test_single_post_payload(session, param, payload, engines)
            if finding:
                return finding

        return None

    def _check_post_injection_success(
        self,
        resp,
        content: str,
        payload: str,
        param: str,
        engines: List[str]
    ) -> Optional[Dict]:
        """Check if POST injection was successful."""
        if not ("1000006000009" in content and "1000003*1000003" in payload and payload not in content):
            return None

        engine = engines[0] if engines else "unknown"
        finding_obj = self._create_finding(f"POST:{param}", payload, "post_injection", verified_url=str(resp.url))
        finding_obj.template_engine = engine
        return self._finding_to_dict(finding_obj)

    async def _test_header_injection(
        self,
        session: aiohttp.ClientSession,
        engines: List[str]
    ) -> Optional[Dict]:
        """Test headers for template injection (rare but possible)."""
        test_headers = ["Referer", "X-Forwarded-For", "User-Agent"]
        payload = "{{1000003*1000003}}"

        for header in test_headers:
            finding = await self._test_single_header(session, header, payload)
            if finding:
                return finding

        return None

    async def _test_single_header(
        self,
        session: aiohttp.ClientSession,
        header: str,
        payload: str
    ) -> Optional[Dict]:
        """Test a single header for template injection."""
        try:
            headers = {header: payload}
            async with session.get(self.url, headers=headers, timeout=5) as resp:
                content = await resp.text()
                return self._check_header_injection_success(resp, content, header, payload)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return None

    def _check_header_injection_success(
        self,
        resp,
        content: str,
        header: str,
        payload: str
    ) -> Optional[Dict]:
        """Check if header injection was successful."""
        if "1000006000009" not in content:
            return None

        finding_obj = self._create_finding(f"HEADER:{header}", payload, "header_injection", verified_url=str(resp.url))
        return self._finding_to_dict(finding_obj)

    def _template_get_system_prompt(self) -> str:
        """Get system prompt for template analysis."""
        return """You are an elite Template Injection specialist.
CSTI (Client-Side): Angular, Vue - executes in browser
SSTI (Server-Side): Jinja2, Twig, Freemarker - executes on server (more dangerous)

For each engine, you must know:
- Angular 1.x: {{constructor.constructor('code')()}} - sandbox bypass needed
- Vue 2.x: {{_c.constructor('code')()}}
- Jinja2: {{config}}, {{lipsum.__globals__['os'].popen('cmd').read()}}
- Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}

CRITICAL: Generate payloads that:
1. Prove code execution (not just reflection)
2. Include OOB callback for blind detection
3. Escalate to RCE if SSTI (server-side)"""

    def _template_build_user_prompt(
        self, param: str, detected_engines: List[str], interactsh_url: str, html: str
    ) -> str:
        """Build user prompt for LLM template analysis."""
        return f"""Analyze this page for Template Injection:
URL: {self.url}
Parameter: {param}
Detected Engines: {detected_engines}
OOB Callback: {interactsh_url}

HTML (truncated):
```html
{html[:6000]}
```

Generate 1-3 PRECISE payloads for the detected engine(s).
For each payload, explain:
1. Target engine
2. What it exploits (sandbox bypass, RCE, etc.)
3. Expected output

Response format (XML):
<payloads>
  <payload>
    <engine>angular|vue|jinja2|twig|etc</engine>
    <code>THE_PAYLOAD</code>
    <exploitation>What it does</exploitation>
    <expected_output>What to look for</expected_output>
  </payload>
</payloads>"""

    async def _llm_smart_template_analysis(
        self,
        html: str,
        param: str,
        detected_engines: List[str],
        interactsh_url: str
    ) -> List[Dict]:
        """LLM-First Strategy: Analyze HTML and generate targeted CSTI/SSTI payloads."""
        system_prompt = self._template_get_system_prompt()
        user_prompt = self._template_build_user_prompt(param, detected_engines, interactsh_url, html)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                module_name="CSTI_SMART_ANALYSIS",
                system_prompt=system_prompt,
                model_override=settings.MUTATION_MODEL,
                max_tokens=3000,
                temperature=0.3
            )

            return self._parse_llm_payloads(response, interactsh_url)
        except Exception as e:
            logger.error(f"LLM Smart Analysis failed: {e}", exc_info=True)
            return []

    async def _run_llm_smart_analysis(self, session, param: str, engines: List[str], html: str) -> List[Dict]:
        """Run LLM smart analysis and test payloads."""
        findings = []
        interact_url_param = self.interactsh.get_url(f"csti_{param}") if self.interactsh else ""
        smart_payloads = await self._llm_smart_template_analysis(html, param, engines, interact_url_param)

        for sp in smart_payloads:
            if self._max_impact_achieved:
                break

            success_content, verified_url = await self._test_payload(session, param, sp["code"])
            if success_content:
                finding_obj = self._create_finding(param, sp["code"], "llm_smart_analysis", verified_url=verified_url)
                finding = self._finding_to_dict(finding_obj)
                findings.append(finding)

                should_stop, reason = self._should_stop_testing(sp["code"], success_content, len(findings))
                if should_stop:
                    dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                    break

        return findings

    async def _cleanup_scan(self):
        """Cleanup after template injection scan."""
        if self.interactsh:
            await self.interactsh.deregister()

    async def _get_baseline_content(self, session) -> str:
        """Fetch baseline content without injection to check for false positives."""
        try:
            async with session.get(self.url, timeout=5) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"_get_baseline_content failed: {e}")
            return ""

    async def _check_light_reflection(self, session, param: str) -> bool:
        """Quick check if a parameter is reflected at all to avoid wasting LLM costs."""
        probe = "BT7331"
        try:
            content, _ = await self._test_payload(session, param, probe)
            return probe in (content or "")
        except Exception:
            return False

    async def _check_arithmetic_evaluation(self, content: str, payload: str, session, final_url: str) -> bool:
        """Check for arithmetic evaluation (1000003*1000003=1000006000009)."""
        if "1000006000009" not in content:
            return False

        if "1000003*1000003" in payload:
            # Require the distinctive result and reject literal payload reflection.
            if payload in content:
                return False
            # CRITICAL: Baseline check
            baseline = await self._get_baseline_content(session)
            return "1000006000009" not in baseline

        if "{% if" in payload and "1000006000009" in payload:
            # Payload like {% if 1 %}49{% endif %} - check syntax stripped
            return "{%" not in content and "%}" not in content

        if "print" in payload:
            return "{%" not in content

        return False

    def _check_string_multiplication(self, content: str, payload: str) -> bool:
        """Check for string multiplication (7777777).

        Both operand orders are accepted because both evaluate: PAYLOAD_LIBRARY
        ships `{{7*'7'}}` / `${7*'7'}`, so matching only `'7'*7` rejected the very
        payloads the agent sends.
        """
        if "7777777" not in content:
            return False
        return ("'7'*7" in payload or "7*'7'" in payload) and payload not in content

    def _check_config_reflection(self, content: str, payload: str) -> bool:
        """Check for Config reflection (Jinja2)."""
        if "{{config}}" not in payload:
            return False
        has_config = "Config" in content or "&lt;Config" in content
        return has_config and payload not in content

    def _check_engine_signatures(self, content: str, payload: str) -> bool:
        """Check for engine-specific signatures."""
        # Twig
        if "{{dump(app)}}" in payload or "{{app.request}}" in payload:
            return "Symfony" in content or "Twig" in content

        # Smarty
        if "{$smarty.version}" in payload:
            return re.search(r"Smarty[- ]\d", content) is not None

        # Freemarker
        if "freemarker" in payload.lower():
            return "freemarker" in content.lower()

        return False

    def _check_error_signatures(self, content: str) -> bool:
        """Check for template error signatures."""
        error_signatures = [
            "jinja2.exceptions",
            "Twig_Error_Syntax",
            "FreeMarker template error",
            "VelocityException",
            "org.apache.velocity",
            "mako.exceptions"
        ]
        for sig in error_signatures:
            if sig in content:
                logger.info(f"[{self.name}] 🚨 Template Error Detected: {sig}")
                return True
        return False

    def _inject(self, param_name: str, payload: str) -> str:
        parsed = urlparse(self.url)
        q = parse_qs(parsed.query)
        q[param_name] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _detect_curly_brace_engine(self, payload: str) -> str:
        """Detect engine for curly brace syntax."""
        # AngularJS detection (client-side)
        if 'constructor' in payload.lower() or '$on' in payload or '$eval' in payload:
            return 'angular'

        # Vue.js detection (client-side)
        if '$emit' in payload or 'v-' in payload:
            return 'vue'

        # Jinja2 detection (server-side)
        if '__class__' in payload or 'config' in payload or 'lipsum' in payload:
            return 'jinja2'

        # Mako detection (server-side)
        if '${' in payload or '%>' in payload:
            return 'mako'

        # Check tech_profile from fingerprinting before defaulting
        if hasattr(self, 'tech_profile') and self.tech_profile:
            frameworks = self.tech_profile.get('frameworks', [])
            for fw in frameworks:
                fw_lower = fw.lower()
                if 'angular' in fw_lower:
                    return 'angular'
                if 'vue' in fw_lower:
                    return 'vue'

        # Also check _tech_stack_context (set by queue consumer)
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        for fw in tech_stack.get('frameworks', []):
            fw_lower = fw.lower()
            if 'angular' in fw_lower:
                return 'angular'
            if 'vue' in fw_lower:
                return 'vue'

        # Default to twig for unidentified {{ }} syntax (server-side)
        return 'twig'

    def _try_alternative_engine(self, current_engine: str) -> str:
        """Devuelve un payload para un motor diferente."""
        payloads = {
            'jinja2': '{{1000003*1000003}}',
            'twig': '{{1000003*1000003}}',
            'freemarker': '${1000003*1000003}',
            'velocity': '#set($x=1000003*1000003)$x',
            'pebble': '{{1000003*1000003}}',
            'thymeleaf': '[[${1000003*1000003}]]'
        }
        
        # Elegir uno diferente al actual
        for engine, payload in payloads.items():
            if engine != current_engine:
                return payload
        
        return '{{1000003*1000003}}'

    def _encode_template_chars(self, payload: str, stripped: List[str]) -> str:
        """Codifica caracteres filtrados en sintaxis de plantilla."""
        result = payload
        
        # Si filtraron llaves, probar con otras sintaxis
        if '{' in stripped or '}' in stripped:
            # Cambiar de {{ a ${
            result = result.replace('{{', '${').replace('}}', '}')
        
        # URL encoding para otros caracteres
        for char in stripped:
            if char not in '{}':
                result = result.replace(char, f'%{ord(char):02X}')
        
        return result

    def _try_char_encoding(self, original_payload: str, stripped_chars: Optional[str], tried_variants: List[str]) -> Optional[str]:
        """Try character encoding strategy."""
        if not stripped_chars:
            return None

        logger.info(f"[CSTIAgent] Characters filtered ({stripped_chars}), using template encoding...")
        encoded = self._encode_template_chars(original_payload, list(stripped_chars))

        if encoded not in tried_variants and encoded != original_payload:
            logger.info(f"[CSTIAgent] Generated encoded variant: {encoded[:80]}...")
            return encoded
        return None

    def _try_engine_switch(self, current_engine: str, tried_variants: List[str]) -> Optional[str]:
        """Try alternative engine payload."""
        alternative_payload = self._try_alternative_engine(current_engine)

        if alternative_payload and alternative_payload not in tried_variants:
            logger.info(f"[CSTIAgent] Generated alternative engine variant: {alternative_payload[:80]}...")
            return alternative_payload
        return None

    def _resolve_api_ssti_url(self, url: str, parameter: str) -> str:
        """
        Resolve mismatched URL when parameter looks like an endpoint path segment.

        DASTySAST sometimes creates findings where the URL is the page that *described*
        the vulnerability (e.g. /api/debug/vulns) while the parameter is the actual
        endpoint name (e.g. "email-preview"). This method looks up recon URLs to find
        the correct target endpoint.

        Returns the resolved URL (may be unchanged if no better match found).
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)

        # Only resolve if parameter looks like an endpoint path segment, not a query param
        # Typical endpoint segments: contain hyphens, or match known SSTI-related names
        ssti_endpoint_names = {'email-preview', 'email-template', 'email-templates', 'render',
                               'preview', 'template', 'report-preview', 'pdf-render'}
        is_endpoint_name = (
            '-' in parameter and parameter.lower() not in ('x-forwarded-for', 'x-custom-header')
        ) or parameter.lower() in ssti_endpoint_names

        if not is_endpoint_name:
            return url

        # Check if the parameter is already part of the URL path
        if parameter.lower() in parsed.path.lower():
            return url

        # Look up recon URLs for a URL containing this endpoint segment
        recon_urls = self._load_recon_urls()
        for recon_url in recon_urls:
            recon_parsed = urlparse(recon_url)
            if parameter.lower() in recon_parsed.path.lower() and '/api/' in recon_parsed.path:
                # Found the correct endpoint — use path without query params
                resolved = f"{recon_parsed.scheme}://{recon_parsed.netloc}{recon_parsed.path}"
                logger.info(f"[{self.name}] Resolved API SSTI URL: {url} → {resolved} (matched param '{parameter}')")
                return resolved

        return url

    def _load_recon_urls(self) -> List[str]:
        """Load discovered URLs from recon/urls.txt (cached per scan)."""
        if hasattr(self, '_cached_recon_urls'):
            return self._cached_recon_urls

        urls = []
        try:
            scan_dir = getattr(self, 'report_dir', None)
            if not scan_dir:
                from bugtrace.core.config import settings
                scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
                scan_dir = settings.BASE_DIR / "reports" / scan_id
            urls_file = scan_dir / "recon" / "urls.txt"
            if urls_file.exists():
                urls = [line.strip() for line in urls_file.read_text().splitlines() if line.strip()]
        except Exception as e:
            logger.debug(f"[{self.name}] Could not load recon URLs: {e}")

        self._cached_recon_urls = urls
        return urls

    async def _wait_for_api_ssti_auth(self, max_wait: int = 180) -> Dict:
        """Poll for JWT token from JWTAgent for API SSTI testing."""
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            # Check immediately first (token may already be available)
            headers = get_scan_auth_headers(self._scan_context, role="admin")
            if headers:
                return headers
            for wait_round in range(max_wait // 5):
                await asyncio.sleep(5)
                headers = get_scan_auth_headers(self._scan_context, role="admin")
                if headers:
                    logger.info(f"[{self.name}] JWT token appeared after {(wait_round + 1) * 5}s wait for API SSTI")
                    return headers
        except Exception:
            pass
        return {}

    async def _load_csti_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin to:
        1. Load tech_profile.json from report directory
        2. Detect likely template engines from framework/language
        3. Generate CSTI-specific prime directive for LLM prompts

        This context helps focus CSTI payloads on the detected template engines.
        """
        # Resolve report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            # Fallback: construct from scan_context
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._csti_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._csti_prime_directive = self.generate_csti_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        frameworks = self._tech_stack_context.get("frameworks", [])
        waf = self._tech_stack_context.get("waf")

        # Detect engines for logging
        raw_profile = self._tech_stack_context.get("raw_profile", {})
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        detected_engines = self._detect_template_engines(frameworks, tech_tags, lang)

        logger.info(f"[{self.name}] CSTI tech context loaded: lang={lang}, "
                   f"engines={detected_engines or ['unknown']}, waf={waf or 'none'}")

