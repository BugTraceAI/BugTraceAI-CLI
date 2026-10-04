"""CSTI escalation ladder shell.

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

logger = get_logger(__name__)

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.payloads import PAYLOAD_LIBRARY
from bugtrace.agents.csti.fingerprinter import TemplateEngineFingerprinter

class CSTIEscalationMixin:
    async def _csti_escalation_pipeline(
        self, url: str, param: str, finding: dict
    ) -> Optional[CSTIFinding]:
        """
        v3.4: 6-Level CSTI Escalation Pipeline.

        Each level is more expensive but catches more edge cases.
        Stops at the first level that confirms CSTI.

        L0: WET payload        → Test DASTySAST's payload first (free)
        L1: Template probe     → Polyglot arithmetic check (instant)
        L2: Bombing 1 (static) → Engine-specific + universal payloads via HTTP
        L3: Bombing 2 (LLM)    → LLM-generated payloads × WAF encodings via HTTP
        L4: HTTP Manipulator    → ManipulatorOrchestrator (SSTI strategy + WAF bypass)
        L5: Browser testing     → Playwright DOM execution (Angular/Vue)
        L6: CDP Validation      → Flag for AgenticValidator
        """
        reflecting_payloads = []  # Template syntax that reflects but isn't confirmed

        # Detect template engines from HTML and finding metadata
        engines = await self._detect_engines_for_escalation(url, finding)

        # ===== AUTONOMOUS PARAM DISCOVERY (Specialist Autonomy Pattern) =====
        # ThinkingConsolidation may mismatch params and URLs. Discover real params
        # from the URL and test all of them. The DRY list param is just a "signal".
        params_to_test = [param]
        try:
            discovered = await self._discover_csti_params(url)
            if discovered:
                discovered_names = list(discovered.keys())
                # Add discovered params that aren't already in the list
                for dp in discovered_names:
                    if dp not in params_to_test:
                        params_to_test.append(dp)
                if len(params_to_test) > 1:
                    logger.info(
                        f"[{self.name}] Autonomous discovery: {len(params_to_test)} params to test on {url[:60]}: {params_to_test}"
                    )
        except Exception as e:
            logger.debug(f"[{self.name}] Autonomous discovery failed: {e}")

        # Test each discovered param through the full pipeline
        for test_param in params_to_test:
            result = await self._run_escalation_for_param(
                url, test_param, finding, engines, reflecting_payloads
            )
            if result:
                return result

        dashboard.log(f"[{self.name}] All 6 levels exhausted for all params on {url[:60]}, no CSTI confirmed", "WARN")
        return None

    async def _run_escalation_for_param(
        self, url: str, param: str, finding: dict,
        engines: List[str], reflecting_payloads: list
    ) -> Optional[CSTIFinding]:
        """Run the full L0-L6 escalation pipeline for a single param."""
        # Fetch baseline (no injection) for false positive checking
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            baseline_html = await self._get_baseline_content(session)

        # ===== SMART PROBE: Skip if param doesn't reflect template syntax =====
        smart_result, should_continue = await self._escalation_smart_probe_csti(url, param, engines, baseline_html)
        if smart_result:
            return smart_result
        if not should_continue:
            return None

        # ===== L0: WET PAYLOAD FIRST (if available) =====
        wet_payload = finding.get("payload") or finding.get("exploitation_strategy") or finding.get("recommended_payload")
        if wet_payload:
            dashboard.log(f"[{self.name}] L0: Testing WET payload on '{param}'", "INFO")
            result = await self._escalation_l0_wet_payload(url, param, wet_payload, engines, baseline_html)
            if result:
                return result

        # ===== L1: TEMPLATE POLYGLOT PROBE =====
        dashboard.log(f"[{self.name}] L1: Template polyglot probe on '{param}'", "INFO")
        result = await self._escalation_l1_template_probe(url, param, baseline_html)
        if result:
            return result

        # ===== L2: BOMBING 1 - ENGINE-SPECIFIC + UNIVERSAL =====
        dashboard.log(f"[{self.name}] L2: Static bombardment on '{param}'", "INFO")
        result, l2_reflecting = await self._escalation_l2_static_bombing(url, param, engines, baseline_html)
        if result:
            return result
        reflecting_payloads.extend(l2_reflecting)

        # ===== L3: BOMBING 2 - LLM PAYLOADS × WAF ENCODINGS =====
        dashboard.log(f"[{self.name}] L3: LLM bombardment on '{param}'", "INFO")
        result, l3_reflecting = await self._escalation_l3_llm_bombing(url, param, engines, reflecting_payloads, baseline_html)
        if result:
            return result
        reflecting_payloads.extend(l3_reflecting)

        # ===== L4/L5: Engine-aware ordering =====
        # Client-side engines (Angular/Vue) only confirm in browser → L5 first
        # Server-side/unknown engines confirm via HTTP → L4 first
        has_client_side = any(e in ["angular", "vue"] for e in engines)

        if has_client_side:
            # For SPA apps, HTTP bombing may find zero reflections because the
            # response is a static shell rendered client-side. Seed L5 browser
            # candidates with engine-specific payloads so Playwright always runs.
            if not reflecting_payloads:
                spa_payloads = [p for p in PAYLOAD_LIBRARY.get("angular", [])[:10]]
                spa_payloads.extend(PAYLOAD_LIBRARY.get("universal", [])[:3])
                reflecting_payloads.extend(spa_payloads)
                logger.info(
                    f"[{self.name}] No HTTP reflections for client-side engine, seeding {len(spa_payloads)} browser payloads"
                )

            # Client-side: L5 Browser first, L4 Manipulator fallback
            if reflecting_payloads:
                dashboard.log(f"[{self.name}] L5: Browser testing {len(reflecting_payloads)} candidates on '{param}' (client-side priority)", "INFO")
                result = await self._escalation_l5_browser(url, param, reflecting_payloads)
                if result:
                    return result

            dashboard.log(f"[{self.name}] L4: HTTP Manipulator on '{param}' (fallback)", "INFO")
            result, l4_reflecting = await self._escalation_l4_http_manipulator(url, param)
            if result:
                return result
            reflecting_payloads.extend(l4_reflecting)
        else:
            # Server-side/unknown: L4 Manipulator first, L5 Browser fallback
            dashboard.log(f"[{self.name}] L4: HTTP Manipulator on '{param}'", "INFO")
            result, l4_reflecting = await self._escalation_l4_http_manipulator(url, param)
            if result:
                return result
            reflecting_payloads.extend(l4_reflecting)

            if reflecting_payloads:
                dashboard.log(f"[{self.name}] L5: Browser testing {len(reflecting_payloads)} candidates on '{param}'", "INFO")
                result = await self._escalation_l5_browser(url, param, reflecting_payloads)
                if result:
                    return result

        # ===== L6: CDP VALIDATION (AgenticValidator) =====
        if reflecting_payloads:
            dashboard.log(f"[{self.name}] L6: Flagging for CDP AgenticValidator on '{param}'", "INFO")
            result = await self._escalation_l6_cdp(url, param, reflecting_payloads)
            if result:
                return result

        dashboard.log(f"[{self.name}] All 6 levels exhausted for '{param}' on {url[:60]}", "WARN")
        return None

    async def _escalation_smart_probe_csti(
        self, url: str, param: str, engines: List[str], baseline_html: str
    ) -> tuple:
        """
        Smart probe: 1 request to check if template syntax reflects or evaluates.

        Returns:
            (CSTIFinding or None, should_continue: bool)
            - If finding returned: confirmed CSTI
            - should_continue=False: no reflection, skip this param entirely
            - should_continue=True: reflects, continue normal escalation
        """
        # Marker must NOT contain the digits "1000006000009": the eval check below looks for "1000006000009"
        # in the response, so a marker like BT_CSTI_49 would self-trigger a false
        # positive whenever the server reflects the marker but strips/doesn't eval {{1000003*1000003}}.
        probe = "BT_CSTI_PROBE{{1000003*1000003}}${1000003*1000003}"
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            response, verified_url = await self._send_csti_payload_raw(session, param, probe)
            if response is None:
                return None, True  # Network error, continue anyway

            # Check if probe marker reflects at all
            if "BT_CSTI_PROBE" not in response:
                # For client-side engines (Angular/Vue in SPA), params may only reflect
                # in the DOM after JavaScript rendering, not in raw HTTP response
                if any(e in ["angular", "vue"] for e in engines):
                    dashboard.log(
                        f"[{self.name}] Smart probe: no HTTP reflection for '{param}' but client-side engine detected, continuing to browser testing",
                        "INFO",
                    )
                    return None, True  # Continue — L5 Playwright will check DOM
                dashboard.log(
                    f"[{self.name}] Smart probe: no reflection for '{param}', skipping",
                    "INFO",
                )
                return None, False

            # Check if template evaluation produced the distinctive long result.
            # "1000006000009" in response AND "1000003*1000003" NOT in response AND not in baseline
            if "1000006000009" in response and "1000003*1000003" not in response and "1000006000009" not in baseline_html:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.signature_match", {"agent": "CSTI", "param": param, "payload": probe[:100], "method": "smart_probe"})
                dashboard.log(
                    f"[{self.name}] Smart probe: CONFIRMED CSTI on '{param}' ({{{{1000003*1000003}}}}=1000006000009)",
                    "INFO",
                )
                # Detect which engine evaluated
                engine = "unknown"
                if any(e in ["angular", "vue"] for e in engines):
                    engine = engines[0]
                finding = self._create_finding(param, "{{1000003*1000003}}", "smart_probe", verified_url=verified_url)
                finding.evidence = {
                    "method": "arithmetic_eval",
                    "proof": "{{1000003*1000003}} evaluated to 1000006000009",
                    "status": "VALIDATED_CONFIRMED",
                    "level": "smart_probe",
                    "engine": engine,
                }
                return finding, True

            dashboard.log(
                f"[{self.name}] Smart probe: '{param}' reflects, continuing escalation",
                "INFO",
            )
            return None, True

    async def _detect_engines_for_escalation(self, url: str, finding: dict) -> List[str]:
        """Detect template engines from HTML fingerprinting + finding metadata + tech_profile."""
        engines = []

        # From finding metadata
        suggested = finding.get("template_engine", "unknown")
        if suggested and suggested != "unknown":
            engines.append(suggested)

        # From tech_profile (Nuclei detection)
        if self.tech_profile and self.tech_profile.get("frameworks"):
            for framework in self.tech_profile["frameworks"]:
                fw_lower = framework.lower()
                if "angular" in fw_lower and "angular" not in engines:
                    engines.append("angular")
                elif "vue" in fw_lower and "vue" not in engines:
                    engines.append("vue")

        # From HTML fingerprinting
        try:
            async with http_manager.isolated_session(ConnectionProfile.PROBE) as session:
                html = await self._fetch_page(session)
                if html:
                    html_engines = TemplateEngineFingerprinter.fingerprint(html)
                    for e in html_engines:
                        if e != "unknown" and e not in engines:
                            engines.append(e)
        except Exception:
            pass

        logger.info(f"[{self.name}] Detected engines for escalation: {engines or ['unknown']}")
        return engines

    async def _escalation_l0_wet_payload(
        self, url: str, param: str, wet_payload: str, engines: List[str], baseline_html: str
    ) -> Optional[CSTIFinding]:
        """L0: Test the WET finding's payload first (from DASTySAST/Skeptic)."""
        dashboard.set_current_payload(wet_payload[:60], "CSTI L0", "WET payload", self.name)

        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            response, verified_url = await self._send_csti_payload_raw(session, param, wet_payload)
            if response is not None:
                confirmed, evidence = self._check_csti_confirmed(wet_payload, response, baseline_html)
                if confirmed:
                    evidence["level"] = "L0"
                    finding = self._create_finding(param, wet_payload, "L0_wet_payload", verified_url=verified_url)
                    finding.evidence = evidence
                    return finding

            # Try double-quote variant if single-quote payload failed
            if "'" in wet_payload:
                dq_payload = wet_payload.replace("'", '"')
                dashboard.set_current_payload(dq_payload[:60], "CSTI L0", "WET DQ variant", self.name)
                response, verified_url = await self._send_csti_payload_raw(session, param, dq_payload)
                if response is not None:
                    confirmed, evidence = self._check_csti_confirmed(dq_payload, response, baseline_html)
                    if confirmed:
                        evidence["level"] = "L0"
                        finding = self._create_finding(param, dq_payload, "L0_wet_dq_variant", verified_url=verified_url)
                        finding.evidence = evidence
                        return finding

        logger.info(f"[{self.name}] L0: WET payload not confirmed for '{param}'")
        return None

    async def _escalation_l1_template_probe(
        self, url: str, param: str, baseline_html: str
    ) -> Optional[CSTIFinding]:
        """L1: Send polyglot template probes, check HTTP arithmetic evaluation."""
        probes = [
            "{{1000003*1000003}}${1000003*1000003}<%= 1000003*1000003 %>#{1000003*1000003}",  # Multi-engine polyglot
            "{{1000003*1000003}}",
            "${1000003*1000003}",
            "<%= 1000003*1000003 %>",
            "#{1000003*1000003}",
            "{{7*'7'}}",
        ]

        confirmed_payloads = []
        first_finding = None

        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            for probe in probes:
                dashboard.set_current_payload(probe, "CSTI L1", "Polyglot", self.name)
                response, verified_url = await self._send_csti_payload_raw(session, param, probe)
                if response is None:
                    continue

                confirmed, evidence = self._check_csti_confirmed(probe, response, baseline_html)
                if confirmed:
                    confirmed_payloads.append(probe)
                    if not first_finding:
                        evidence["level"] = "L1"
                        first_finding = self._create_finding(param, probe, "L1_template_probe", verified_url=verified_url)
                        first_finding.evidence = evidence
                    if len(confirmed_payloads) >= 5:
                        break

        # Check Interactsh OOB
        if not first_finding and self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    first_finding = self._create_finding(param, probes[0], "L1_interactsh_oob")
                    first_finding.evidence = {"method": "L1_interactsh_oob", "oob": True, "level": "L1"}
                    confirmed_payloads.append(probes[0])
            except Exception:
                pass

        if first_finding:
            first_finding.successful_payloads = confirmed_payloads
            logger.info(f"[{self.name}] L1: {len(confirmed_payloads)} confirmed for '{param}'")
            return first_finding

        logger.info(f"[{self.name}] L1: No CSTI confirmed for '{param}'")
        return None

    async def _escalation_l2_static_bombing(
        self, url: str, param: str, engines: List[str], baseline_html: str
    ) -> tuple:
        """L2: Fire all engine-specific + universal payloads via HTTP."""
        # Build payload list: engine-specific first, then universal, polyglots, WAF bypass
        all_payloads = []
        seen = set()

        # Engine-specific payloads first (prioritized)
        for engine in engines:
            for p in PAYLOAD_LIBRARY.get(engine, []):
                if p not in seen:
                    seen.add(p)
                    all_payloads.append(p)

        # Universal + polyglots + WAF bypass
        for key in ["universal", "polyglots", "waf_bypass"]:
            for p in PAYLOAD_LIBRARY.get(key, []):
                if p not in seen:
                    seen.add(p)
                    all_payloads.append(p)

        # All remaining engine payloads (engines not yet covered)
        for engine_name in PAYLOAD_LIBRARY:
            if engine_name not in ["universal", "polyglots", "waf_bypass"] + engines:
                for p in PAYLOAD_LIBRARY.get(engine_name, []):
                    if p not in seen:
                        seen.add(p)
                        all_payloads.append(p)

        # Replace Interactsh placeholders
        if self.interactsh_url:
            all_payloads = [p.replace("{{INTERACTSH}}", self.interactsh_url) for p in all_payloads]

        # Apply WAF bypass encodings
        all_payloads = await self._get_encoded_payloads(all_payloads)

        logger.info(f"[{self.name}] L2: Bombing {len(all_payloads)} static payloads on '{param}'")

        confirmed_payloads = []
        first_finding = None
        reflecting = []

        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            for i, payload in enumerate(all_payloads):
                if hasattr(self, '_v'):
                    self._v.progress("exploit.specialist.progress", {"agent": "CSTI", "param": param, "payload": payload[:80], "i": i, "total": len(all_payloads)}, every=50)
                if i % 20 == 0 and i > 0:
                    dashboard.log(f"[{self.name}] L2: Progress {i}/{len(all_payloads)}", "DEBUG")
                dashboard.set_current_payload(payload[:60], "CSTI L2", f"{i+1}/{len(all_payloads)}", self.name)

                response, verified_url = await self._send_csti_payload_raw(session, param, payload)
                if response is None:
                    continue

                # Check for CSTI confirmation
                confirmed, evidence = self._check_csti_confirmed(payload, response, baseline_html)
                if confirmed:
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.signature_match", {"agent": "CSTI", "param": param, "payload": payload[:100], "method": "L2_static_bombing"})
                    confirmed_payloads.append(payload)
                    if not first_finding:
                        evidence["level"] = "L2"
                        first_finding = self._create_finding(param, payload, "L2_static_bombing", verified_url=verified_url)
                        first_finding.evidence = evidence
                    if len(confirmed_payloads) >= 5:
                        break
                    continue

                # Track payloads where template syntax reflects (for L5 browser)
                if payload in response or ("1000006000009" in response and "1000006000009" not in baseline_html):
                    reflecting.append(payload)

        # Batch OOB check
        if not first_finding and self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    best = all_payloads[0] if all_payloads else "{{1000003*1000003}}"
                    first_finding = self._create_finding(param, best, "L2_interactsh_oob")
                    first_finding.evidence = {"method": "L2_interactsh_oob", "oob": True, "level": "L2"}
                    confirmed_payloads.append(best)
            except Exception:
                pass

        if first_finding:
            first_finding.successful_payloads = confirmed_payloads
            logger.info(f"[{self.name}] L2: {len(confirmed_payloads)} confirmed, {len(reflecting)} reflecting for '{param}'")
            return first_finding, reflecting

        logger.info(f"[{self.name}] L2: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
        return None, reflecting

    async def _escalation_l3_llm_bombing(
        self, url: str, param: str, engines: List[str],
        existing_reflecting: list, baseline_html: str
    ) -> tuple:
        """L3: Generate LLM CSTI payloads × WAF encodings, fire via HTTP."""
        engine_hint = engines[0] if engines else "unknown"
        tech_context = self._csti_prime_directive if hasattr(self, '_csti_prime_directive') else ""

        user_prompt = (
            f"Target URL: {url}\nParameter: {param}\nDetected engine: {engine_hint}\n"
            f"Tech context: {tech_context}\n\n"
            f"Generate 50 advanced CSTI/SSTI payloads for template injection testing. "
            f"Include variations for: Angular, Vue, Jinja2, Twig, Freemarker, Mako, ERB, Velocity. "
            f"Focus on arithmetic evaluation (1000003*1000003=1000006000009), config access, sandbox bypasses, and RCE. "
            f"Include double-quote variants for servers that reject single quotes. "
            f"Return each payload in <payload> tags."
        )

        try:
            response = await llm_client.generate(user_prompt, system_prompt=self.system_prompt, module_name="CSTI_L3")
            llm_payloads = XmlParser.extract_list(response, "payload")
        except Exception as e:
            logger.error(f"[{self.name}] L3: LLM generation failed: {e}")
            llm_payloads = []

        if not llm_payloads:
            logger.info(f"[{self.name}] L3: LLM generated 0 payloads, skipping")
            return None, []

        # Apply WAF encodings
        llm_payloads = await self._get_encoded_payloads(llm_payloads)

        # Replace Interactsh placeholders
        if self.interactsh_url:
            llm_payloads = [p.replace("{{INTERACTSH}}", self.interactsh_url) for p in llm_payloads]

        logger.info(f"[{self.name}] L3: Bombing {len(llm_payloads)} LLM payloads on '{param}'")

        confirmed_payloads = []
        first_finding = None
        reflecting = []

        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            for i, payload in enumerate(llm_payloads):
                if i % 20 == 0 and i > 0:
                    dashboard.log(f"[{self.name}] L3: Progress {i}/{len(llm_payloads)}", "DEBUG")
                dashboard.set_current_payload(payload[:60], "CSTI L3", f"{i+1}/{len(llm_payloads)}", self.name)

                response, verified_url = await self._send_csti_payload_raw(session, param, payload)
                if response is None:
                    continue

                confirmed, evidence = self._check_csti_confirmed(payload, response, baseline_html)
                if confirmed:
                    confirmed_payloads.append(payload)
                    if not first_finding:
                        evidence["level"] = "L3"
                        first_finding = self._create_finding(param, payload, "L3_llm_bombing", verified_url=verified_url)
                        first_finding.evidence = evidence
                    if len(confirmed_payloads) >= 5:
                        break
                    continue

                if payload in response or ("1000006000009" in response and "1000006000009" not in baseline_html):
                    reflecting.append(payload)

        if first_finding:
            first_finding.successful_payloads = confirmed_payloads
            logger.info(f"[{self.name}] L3: {len(confirmed_payloads)} confirmed, {len(reflecting)} reflecting for '{param}'")
            return first_finding, reflecting

        logger.info(f"[{self.name}] L3: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
        return None, reflecting

    async def _escalation_l4_http_manipulator(self, url: str, param: str) -> tuple:
        """L4: ManipulatorOrchestrator - context detection, WAF bypass for SSTI."""
        reflecting = []
        try:
            parsed = urlparse(url)
            base_params = dict(parse_qs(parsed.query, keep_blank_values=True))
            # parse_qs returns lists, flatten to single values
            base_params = {k: v[0] if v else "" for k, v in base_params.items()}
            if param not in base_params:
                base_params[param] = "{{1000003*1000003}}"

            base_request = MutableRequest(
                method="GET",
                url=url.split("?")[0],
                params=base_params
            )

            manipulator = ManipulatorOrchestrator(
                rate_limit=0.3,
                enable_agentic_fallback=True,
                enable_llm_expansion=True
            )

            success, mutation = await manipulator.process_finding(
                base_request,
                strategies=[MutationStrategy.SSTI_INJECTION, MutationStrategy.BYPASS_WAF]
            )

            if success and mutation:
                working_payload = mutation.params.get(param, str(mutation.params))
                original_value = base_params.get(param, "{{1000003*1000003}}")

                # Verify the TARGET param was actually mutated (not a different param)
                if working_payload == original_value:
                    logger.info(f"[{self.name}] L4: ManipulatorOrchestrator exploited different param, not '{param}'")
                    await manipulator.shutdown()
                    return None, reflecting

                # Verify payload contains CSTI/SSTI indicators
                csti_indicators = ["{{", "${", "<%", "#{", "#set", "#if", "#include",
                                   "1000003*1000003", "constructor", "__class__", "config",
                                   "lipsum", "range(", "dump(", "system(", "exec(",
                                   "popen(", "Runtime", "Process", "forName"]
                if not any(ind in working_payload for ind in csti_indicators):
                    logger.info(f"[{self.name}] L4: ManipulatorOrchestrator payload rejected (no CSTI syntax): {working_payload[:80]}")
                    await manipulator.shutdown()
                    return None, reflecting

                # FIX (2026-02-16): Re-verify template evaluation via HTTP.
                # ManipulatorOrchestrator may flag payloads that merely REFLECT in
                # error messages (e.g., Pydantic validation errors) as "success".
                # Re-send the payload and verify with _check_csti_confirmed() to
                # confirm the template was actually EVALUATED, not just reflected.
                verify_url = url.split("?")[0]
                verify_params = dict(base_params)
                verify_params[param] = working_payload
                try:
                    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                        async with session.get(verify_url, params=verify_params, timeout=15) as resp:
                            verify_status = resp.status
                            verify_body = await resp.text()
                        # Also fetch baseline for comparison
                        baseline_params = dict(base_params)
                        baseline_params[param] = "btai_baseline_test"
                        async with session.get(verify_url, params=baseline_params, timeout=15) as resp:
                            baseline_body = await resp.text()
                    # A 4xx on the verify request means this is not a reflection sink — a stray
                    # "1000006000009" in the error page must not confirm. 5xx left flowing for error-signature SSTI.
                    if 400 <= verify_status < 500:
                        logger.info(
                            f"[{self.name}] L4: verify returned {verify_status} (not a reflection sink) — dropping: {param}"
                        )
                        reflecting.append(working_payload)
                        await manipulator.shutdown()
                        return None, reflecting
                    confirmed, confirm_evidence = self._check_csti_confirmed(
                        working_payload, verify_body, baseline_body
                    )
                    if not confirmed:
                        logger.info(
                            f"[{self.name}] L4: ManipulatorOrchestrator payload REFLECTED but NOT EVALUATED "
                            f"(likely error message reflection): {working_payload[:80]}"
                        )
                        reflecting.append(working_payload)
                        await manipulator.shutdown()
                        return None, reflecting
                except Exception as verify_err:
                    logger.debug(f"[{self.name}] L4 verification request failed: {verify_err}")

                logger.info(f"[{self.name}] L4: ManipulatorOrchestrator CONFIRMED: {param}={working_payload[:80]}")
                await manipulator.shutdown()
                finding = self._create_finding(param, working_payload, "L4_manipulator", verified_url=url)
                finding.evidence = {"http_confirmed": True, "level": "L4", "method": "L4_manipulator"}
                return finding, reflecting

            # Collect blood smell candidates for L5
            if hasattr(manipulator, 'blood_smell_history') and manipulator.blood_smell_history:
                for entry in sorted(manipulator.blood_smell_history, key=lambda x: x["smell"]["severity"], reverse=True)[:5]:
                    blood_payload = entry["request"].params.get(param, "")
                    if blood_payload:
                        reflecting.append(blood_payload)
                logger.info(f"[{self.name}] L4: {len(reflecting)} blood smell candidates for L5")

            await manipulator.shutdown()

        except Exception as e:
            logger.error(f"[{self.name}] L4: ManipulatorOrchestrator failed: {e}")

        return None, reflecting

    async def _escalation_l5_browser(
        self, url: str, param: str, reflecting_payloads: list
    ) -> Optional[CSTIFinding]:
        """L5: Browser validation (Playwright) for client-side CSTI (Angular/Vue)."""
        seen = set()
        candidates = []
        for p in reflecting_payloads:
            if p not in seen:
                seen.add(p)
                candidates.append(p)

        candidates = candidates[:10]  # Limit to 10 browser tests (expensive)
        logger.info(f"[{self.name}] L5: Browser testing {len(candidates)} reflecting payloads on '{param}'")

        screenshots_dir = Path(settings.LOG_DIR) / "csti_screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        confirmed_payloads = []
        first_finding = None

        for i, payload in enumerate(candidates):
            dashboard.set_current_payload(payload[:60], "CSTI L5 Browser", f"{i+1}/{len(candidates)}", self.name)
            try:
                evidence = {}
                if await self._validate_with_playwright(param, payload, screenshots_dir, evidence):
                    confirmed_payloads.append(payload)
                    if not first_finding:
                        logger.info(f"[{self.name}] L5: Playwright CONFIRMED: {payload[:60]}")
                        first_finding = self._create_finding(param, payload, "L5_browser")
                        first_finding.evidence = {**evidence, "playwright_confirmed": True, "level": "L5", "method": "L5_browser"}
                    if len(confirmed_payloads) >= 5:
                        break
            except Exception as e:
                logger.debug(f"[{self.name}] L5: Browser test {i+1} failed: {e}")

        if first_finding:
            first_finding.successful_payloads = confirmed_payloads
            logger.info(f"[{self.name}] L5: {len(confirmed_payloads)}/{len(candidates)} confirmed in browser for '{param}'")
            return first_finding

        logger.info(f"[{self.name}] L5: 0/{len(candidates)} confirmed in browser for '{param}'")
        return None

    async def _escalation_l6_cdp(
        self, url: str, param: str, reflecting_payloads: list
    ) -> Optional[CSTIFinding]:
        """L6: Flag best reflecting payload for CDP AgenticValidator."""
        if not reflecting_payloads:
            return None

        best_payload = reflecting_payloads[0]
        logger.info(f"[{self.name}] L6: Flagging '{param}' for CDP AgenticValidator (payload: {best_payload[:60]})")

        engine = self._detect_engine_from_payload(best_payload)
        engine_type = "client-side" if engine in ["angular", "vue"] else "server-side"

        return CSTIFinding(
            url=url,
            parameter=param,
            payload=best_payload,
            template_engine=engine,
            engine_type=engine_type,
            severity="MEDIUM",
            validated=False,
            status="NEEDS_CDP_VALIDATION",
            description=f"Potential {engine} CSTI: template syntax reflects. Best payload: {best_payload[:60]}. Flagged for CDP validation.",
            evidence={
                "method": "L6_cdp_flagged",
                "level": "L6",
                "reflecting_count": len(reflecting_payloads),
                "needs_cdp": True
            }
        )

