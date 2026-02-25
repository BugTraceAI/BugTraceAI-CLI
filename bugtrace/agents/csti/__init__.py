"""
CSTI Agent Module

This module provides CSTI/SSTI (Client/Server-Side Template Injection) detection capabilities.

The CSTIAgent class is the main entry point for template injection scanning.

Modules:
    - types: CSTIFinding dataclass
    - engines: PURE template engine detection and classification
    - payloads: PURE payload library and impact classification
    - validation: PURE arithmetic eval, engine signatures, error matching
    - discovery: I/O CSTI-specific parameter discovery
    - exploitation: I/O payload sending, finding creation
    - dedup: PURE CSTI fingerprint deduplication
    - reporting: I/O specialist report writing
    - pipeline: ORCHESTRATION escalation levels L0-L6, validation pipeline

Usage:
    from bugtrace.agents.csti import CSTIAgent, CSTIFinding

    agent = CSTIAgent(url="http://example.com", params=[{"parameter": "q"}])
    result = await agent.run_loop()

For backward compatibility, CSTIAgent can also be imported from:
    from bugtrace.agents.csti_agent import CSTIAgent
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.utils.logger import get_logger

# Re-export types
from bugtrace.agents.csti.types import CSTIFinding

# Re-export engine functions
from bugtrace.agents.csti.engines import (
    ENGINE_SIGNATURES,
    CLIENT_SIDE_ENGINES,
    fingerprint_engines,
    detect_engine_from_payload,
    classify_engine_type,
    is_client_side_engine,
    try_alternative_engine,
    encode_template_chars,
)

# Re-export payload data and functions
from bugtrace.agents.csti.payloads import (
    PAYLOAD_LIBRARY,
    HIGH_IMPACT_INDICATORS,
    MEDIUM_IMPACT_INDICATORS,
    HIGH_PRIORITY_PARAMS,
    get_payload_impact_tier,
    should_stop_testing,
    prioritize_params,
    prioritize_csti_params,
    build_l2_payload_list,
    get_universal_bypass_payloads,
)

# Re-export validation functions
from bugtrace.agents.csti.validation import (
    check_csti_confirmed,
    check_arithmetic_evaluation,
    check_string_multiplication,
    check_config_reflection,
    check_engine_signatures,
    check_error_signatures,
    validate_finding_before_emit,
)

# Re-export discovery functions
from bugtrace.agents.csti.discovery import (
    discover_csti_params,
    discover_all_params_sync,
    detect_engines_for_escalation,
)

# Re-export exploitation functions
from bugtrace.agents.csti.exploitation import (
    inject_param,
    create_finding,
    create_ambiguous_finding,
    generate_repro_steps,
    dict_to_finding,
    send_csti_payload_raw,
    get_encoded_payloads,
    test_post_injection,
    test_header_injection,
    fetch_page,
    get_baseline_content,
    check_light_reflection,
    test_api_ssti,
)

# Re-export dedup functions
from bugtrace.agents.csti.dedup import (
    generate_csti_fingerprint,
    fallback_fingerprint_dedup,
    normalize_csti_finding_params,
)

# Re-export reporting functions
from bugtrace.agents.csti.reporting import generate_specialist_report

# Re-export pipeline functions
from bugtrace.agents.csti.pipeline import (
    validate_csti,
    test_payload_with_validation,
    escalation_smart_probe,
    escalation_l0_wet_payload,
    escalation_l1_template_probe,
    escalation_l2_static_bombing,
    escalation_l3_llm_bombing,
    escalation_l4_http_manipulator,
    escalation_l5_browser,
    create_l6_cdp_finding,
    build_template_system_prompt,
    build_template_user_prompt,
    parse_llm_payloads,
    llm_smart_template_analysis,
    llm_analyze_and_dedup,
)


logger = get_logger("agents.csti")


# =========================================================================
# Legacy class kept for fingerprinting API compatibility
# =========================================================================

class TemplateEngineFingerprinter:
    """Detect which template engine is in use. Delegates to engines module."""

    ENGINE_SIGNATURES = ENGINE_SIGNATURES

    @classmethod
    def fingerprint(cls, html: str, headers: dict = None) -> List[str]:
        return fingerprint_engines(html, headers)


# =========================================================================
# CSTIAgent: Thin orchestrator class
# =========================================================================

class CSTIAgent(BaseAgent, TechContextMixin):
    """
    CSTI Agent V2 - Intelligent Template Injection Specialist.

    Feature Set:
    - Binomial Arithmetic Proof (7*7=49)
    - WAF Detection & Q-Learning Bypass (UCB1)
    - Template Engine Fingerprinting
    - Targeted & Polyglot Payloads
    - Blind SSTI Detection via Interactsh (OOB)
    - Context-aware technology stack integration (v3.2)

    This is a thin orchestrator that delegates all business logic
    to the subpackage modules (engines, payloads, validation, pipeline, etc.).
    """

    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="CSTIAgent",
            role="Template Injection Specialist",
            event_bus=event_bus,
            agent_id="csti_agent",
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._detected_waf = None
        self._waf_confidence = 0.0
        self.interactsh = None
        self.interactsh_url = None
        self._max_impact_achieved = False

        # Load technology profile for framework-specific CSTI attacks
        from bugtrace.utils.tech_loader import load_tech_profile
        self.tech_profile = load_tech_profile(self.report_dir)

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()

        # WET -> DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []

        self._worker_pool = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._csti_prime_directive: str = ""

    # =========================================================================
    # WAF Detection
    # =========================================================================

    async def _detect_waf_async(self) -> Tuple[str, float]:  # I/O
        """Detect WAF using framework's intelligent fingerprinter."""
        from bugtrace.tools.waf import waf_fingerprinter
        try:
            waf_name, confidence = await waf_fingerprinter.detect(self.url)
            self._detected_waf = waf_name if waf_name != "unknown" else None
            self._waf_confidence = confidence

            if self._detected_waf:
                logger.info(f"[{self.name}] WAF Detected: {waf_name} ({confidence:.0%})")
                dashboard.log(f"[{self.name}] WAF: {waf_name} ({confidence:.0%})", "INFO")

            return waf_name, confidence
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return "unknown", 0.0

    async def _get_encoded_payloads(self, payloads: List[str]) -> List[str]:  # I/O
        """Apply Q-Learning optimized encoding to payloads."""
        return await get_encoded_payloads(payloads, self._detected_waf)

    # =========================================================================
    # Interactsh OOB
    # =========================================================================

    async def _setup_interactsh(self):  # I/O
        """Register with Interactsh for OOB validation."""
        from bugtrace.tools.interactsh import InteractshClient
        try:
            self.interactsh = InteractshClient()
            await self.interactsh.register()
            self.interactsh_url = self.interactsh.get_url("csti_agent")
            logger.info(f"[{self.name}] Interactsh ready: {self.interactsh_url}")
        except Exception as e:
            logger.warning(f"Failed to setup Interactsh: {e}")
            self.interactsh = None

    async def _check_oob_hit(self, label: str) -> bool:  # I/O
        """Check if we got an OOB callback."""
        if not self.interactsh:
            return False
        await asyncio.sleep(2)
        hit = await self.interactsh.check_hit(label)
        return hit is not None

    # =========================================================================
    # Finding Validation (delegates to validation module)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """CSTI-specific validation before emitting finding."""
        parent_valid, parent_error = super()._validate_before_emit(finding)
        return validate_finding_before_emit(finding, parent_valid, parent_error)

    def _emit_csti_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit CSTI finding using BaseAgent.emit_finding() with validation."""
        if "type" not in finding_dict:
            finding_dict["type"] = "CSTI"
        if scan_context:
            finding_dict["scan_context"] = scan_context
        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # Recording (WAF Q-Learning feedback)
    # =========================================================================

    def _record_bypass_result(self, payload: str, success: bool):
        """Record result for Q-Learning feedback."""
        from bugtrace.tools.waf import strategy_router
        if not self._detected_waf:
            return
        encoding_used = "unknown"
        if "%25" in payload:
            encoding_used = "double_url_encode"
        elif "\\u00" in payload:
            encoding_used = "unicode_encode"
        elif "&#" in payload:
            encoding_used = "html_entity_encode"
        strategy_router.record_result(self._detected_waf, encoding_used, success)

    # =========================================================================
    # Probes (delegate to exploitation/pipeline modules)
    # =========================================================================

    async def _fetch_page(self, session) -> str:  # I/O
        """Fetch page content for fingerprinting."""
        return await fetch_page(session, self.url)

    async def _targeted_probe(self, session, param, engines) -> Optional[Dict]:  # I/O
        """Probe using payloads specific to detected engines."""
        tech_engines = []
        if self.tech_profile and self.tech_profile.get("frameworks"):
            for framework in self.tech_profile["frameworks"]:
                fw_lower = framework.lower()
                if "angular" in fw_lower:
                    tech_engines.append("angular")
                elif "vue" in fw_lower:
                    tech_engines.append("vue")

        prioritized_engines = list(dict.fromkeys(tech_engines + engines))

        for engine in prioritized_engines:
            payloads = PAYLOAD_LIBRARY.get(engine, [])
            payloads = await self._get_encoded_payloads(payloads)

            for p in payloads:
                dashboard.set_current_payload(p, f"CSTI:{param}", f"Targeted ({engine})")
                content, verified_url = await self._test_payload(session, param, p)
                if content:
                    finding_obj = create_finding(
                        self.url, param, p, f"targeted_probe_{engine}", self.name,
                        verified_url=verified_url, tech_profile=self.tech_profile,
                        tech_stack_context=self._tech_stack_context,
                    )
                    return finding_obj.to_dict()
        return None

    async def _universal_probe(self, session, param) -> Optional[Dict]:  # I/O
        """Probe using universal and polyglot payloads."""
        payloads = PAYLOAD_LIBRARY.get("universal", []) + PAYLOAD_LIBRARY.get("polyglots", [])
        payloads = await self._get_encoded_payloads(payloads)

        for p in payloads:
            dashboard.set_current_payload(p, f"CSTI:{param}", "Universal Probe")
            content, verified_url = await self._test_payload(session, param, p)
            if content:
                finding_obj = create_finding(
                    self.url, param, p, "universal_probe", self.name,
                    verified_url=verified_url, tech_profile=self.tech_profile,
                    tech_stack_context=self._tech_stack_context,
                )
                return finding_obj.to_dict()
        return None

    async def _oob_probe(self, session, param, engines) -> Optional[Dict]:  # I/O
        """Probe using OOB payloads injected with Interactsh URL."""
        if not self.interactsh_url:
            return None

        candidates = []
        for engine in engines:
            candidates.extend([p for p in PAYLOAD_LIBRARY.get(engine, []) if "{{INTERACTSH}}" in p])

        if not candidates:
            candidates.extend([p for p in PAYLOAD_LIBRARY.get("jinja2", []) if "{{INTERACTSH}}" in p])

        for p in candidates:
            label = f"csti_{param}"
            real_payload = p.replace("{{INTERACTSH}}", self.interactsh_url)

            dashboard.set_current_payload(real_payload[:20] + "...", f"CSTI:{param}", "OOB Blind")

            try:
                target_url = inject_param(self.url, param, real_payload)
                async with session.get(target_url, timeout=3):
                    pass
            except Exception:
                pass

            if await self._check_oob_hit(self.interactsh_url):
                finding_obj = create_finding(
                    self.url, param, real_payload, "blind_oob_confirmed", self.name,
                    tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
                )
                return finding_obj.to_dict()

        return None

    # =========================================================================
    # Core Test Methods
    # =========================================================================

    async def _test_payload(self, session, param, payload) -> Tuple[Optional[str], Optional[str]]:  # I/O
        """Injects payload and performs 4-level validation."""
        return await test_payload_with_validation(
            session, self.url, param, payload, self.name
        )

    def _inject(self, param_name: str, payload: str) -> str:  # PURE
        """Inject payload into URL parameter."""
        return inject_param(self.url, param_name, payload)

    def _create_finding(self, param: str, payload: str, method: str, verified_url: str = None) -> CSTIFinding:
        """Create a standardized finding object."""
        logger.info(f"[{self.name}] CSTI/SSTI CONFIRMED on {param}: {payload}")
        dashboard.log(f"[{self.name}] CSTI/SSTI CONFIRMED on '{param}'!", "SUCCESS")
        return create_finding(
            self.url, param, payload, method, self.name,
            verified_url=verified_url, original_url=self.url,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    def _create_ambiguous_finding(self, param: str, payload: str, engine: str) -> CSTIFinding:
        """Create a finding for potential but unconfirmed client-side CSTI."""
        logger.info(f"[{self.name}] Potential client-side CSTI on {param} ({engine}) - needs CDP")
        dashboard.log(f"[{self.name}] Potential CSTI on '{param}' ({engine}) - delegating to CDP", "WARN")
        return create_ambiguous_finding(self.url, param, payload, engine)

    def _finding_to_dict(self, finding: CSTIFinding) -> Dict:
        """Convert CSTIFinding to dict."""
        return finding.to_dict()

    def _generate_repro_steps(self, url: str, param: str, payload: str, curl_cmd: str) -> List[str]:
        """Generate reproduction steps."""
        return generate_repro_steps(url, param, payload, curl_cmd)

    def _detect_engine_from_payload(self, payload: str) -> str:
        """Detect engine from payload syntax."""
        return detect_engine_from_payload(payload, self.tech_profile, self._tech_stack_context)

    def _detect_curly_brace_engine(self, payload: str) -> str:
        """Detect engine for curly brace syntax."""
        from bugtrace.agents.csti.engines import _detect_curly_brace_engine
        return _detect_curly_brace_engine(payload, self.tech_profile, self._tech_stack_context)

    def _dict_to_finding(self, result: Dict) -> Optional[CSTIFinding]:
        """Convert finding dict to CSTIFinding."""
        return dict_to_finding(result, self.url)

    def _generate_csti_fingerprint(self, url: str, parameter: str, template_engine: str) -> tuple:
        """Generate CSTI finding fingerprint."""
        return generate_csti_fingerprint(url, parameter, template_engine)

    # =========================================================================
    # Impact / Victory Hierarchy
    # =========================================================================

    def _get_payload_impact_tier(self, payload: str, response: str) -> int:
        """Determine impact tier for CSTI/SSTI."""
        return get_payload_impact_tier(payload, response)

    def _should_stop_testing(self, payload: str, response: str, successful_count: int) -> Tuple[bool, str]:
        """Determine if we should stop based on Victory Hierarchy."""
        result = should_stop_testing(payload, response, successful_count)
        if result[0] and get_payload_impact_tier(payload, response) >= 2:
            self._max_impact_achieved = True
        return result

    def _prioritize_params(self, params: List[Dict]) -> List[Dict]:
        """Prioritize parameters."""
        return prioritize_params(params)

    # =========================================================================
    # Validation methods (delegates to validation/pipeline)
    # =========================================================================

    async def _validate(self, param, payload, response_html, screenshots_dir) -> tuple:
        """4-LEVEL VALIDATION PIPELINE."""
        return await validate_csti(
            self.url, param, payload, response_html, screenshots_dir,
            self.name, self.interactsh, self._check_oob_hit,
        )

    async def _validate_http_reflection(self, param, payload, response_html, evidence) -> bool:
        """Level 1: Fast HTTP static evaluation check."""
        from bugtrace.agents.csti.pipeline import _validate_http_reflection
        return await _validate_http_reflection(
            self.url, param, payload, response_html, evidence, self.name,
            check_oob_hit_fn=self._check_oob_hit,
        )

    async def _validate_with_ai_manipulator(self, param, payload, response_html, evidence) -> bool:
        """Level 2: AI-powered audit (placeholder)."""
        if not response_html or payload not in response_html:
            return False
        return False

    async def _validate_with_playwright(self, param, payload, screenshots_dir, evidence) -> bool:
        """Level 3: Playwright browser execution."""
        from bugtrace.agents.csti.pipeline import _validate_with_playwright
        return await _validate_with_playwright(
            self.url, param, payload, screenshots_dir, evidence, self.name
        )

    async def _get_baseline_content(self, session) -> str:
        """Fetch baseline content."""
        return await get_baseline_content(session, self.url)

    async def _check_light_reflection(self, session, param: str) -> bool:
        """Quick reflection check."""
        return await check_light_reflection(session, self.url, param)

    async def _check_arithmetic_evaluation(self, content, payload, session, final_url) -> bool:
        """Check arithmetic evaluation with baseline."""
        baseline = await get_baseline_content(session, self.url)
        return check_arithmetic_evaluation(content, payload, baseline)

    def _check_string_multiplication(self, content, payload) -> bool:
        return check_string_multiplication(content, payload)

    def _check_config_reflection(self, content, payload) -> bool:
        return check_config_reflection(content, payload)

    def _check_engine_signatures(self, content, payload) -> bool:
        return check_engine_signatures(content, payload)

    def _check_error_signatures(self, content) -> bool:
        return check_error_signatures(content)

    def _check_csti_confirmed(self, payload, response_html, baseline_html) -> Tuple[bool, Dict]:
        return check_csti_confirmed(payload, response_html, baseline_html)

    # =========================================================================
    # Bypass Variant Generation (Feedback Loop)
    # =========================================================================

    def _try_alternative_engine(self, current_engine: str) -> str:
        return try_alternative_engine(current_engine)

    def _encode_template_chars(self, payload: str, stripped: List[str]) -> str:
        return encode_template_chars(payload, stripped)

    async def _feedback_generate_waf_bypass(self, original: str) -> Tuple[Optional[str], str]:
        """Generate WAF bypass variant."""
        encoded = await self._get_encoded_payloads([original])
        if encoded and encoded[0] != original:
            return encoded[0], "waf_bypass"
        return None, ""

    def _feedback_generate_engine_switch(self, engine: str) -> Tuple[Optional[str], str]:
        """Generate engine switch variant."""
        variant = try_alternative_engine(engine)
        return variant, "engine_switch"

    def _feedback_generate_char_encoding(self, original: str, stripped_chars: List[str]) -> Tuple[Optional[str], str]:
        """Generate character encoding variant."""
        variant = encode_template_chars(original, stripped_chars)
        return variant, "char_encoding"

    async def _feedback_generate_llm_fallback(self, parameter: str) -> Tuple[Optional[str], str]:
        """Generate LLM fallback variant."""
        llm_result = await self._llm_probe(None, parameter)
        if llm_result:
            return llm_result.get("payload"), "llm_fallback"
        return None, ""

    async def handle_validation_feedback(self, feedback: ValidationFeedback) -> Optional[Dict[str, Any]]:
        """Receive feedback from AgenticValidator and generate a CSTI variant."""
        logger.info(f"[CSTIAgent] Received feedback: {feedback.failure_reason.value}")

        original = feedback.original_payload
        engine = self._detect_engine_from_payload(original)
        variant = None
        method = "feedback_adaptation"

        if feedback.failure_reason == FailureReason.WAF_BLOCKED:
            variant, method = await self._feedback_generate_waf_bypass(original)
        elif feedback.failure_reason == FailureReason.CONTEXT_MISMATCH:
            variant, method = self._feedback_generate_engine_switch(engine)
        elif feedback.failure_reason == FailureReason.ENCODING_STRIPPED:
            variant, method = self._feedback_generate_char_encoding(original, feedback.stripped_chars)

        if not variant or variant == original:
            variant, method = await self._feedback_generate_llm_fallback(feedback.parameter)

        if variant and variant != original and not feedback.was_variant_tried(variant):
            return {"payload": variant, "method": method, "engine_guess": engine}

        return None

    async def generate_bypass_variant(
        self,
        original_payload: str,
        failure_reason: str,
        waf_signature: Optional[str] = None,
        stripped_chars: Optional[str] = None,
        tried_variants: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Generate a bypass variant based on failure feedback."""
        logger.info(f"[CSTIAgent] Generating bypass variant for failed payload: {original_payload[:50]}...")

        tried_variants = tried_variants or []
        current_engine = self._detect_engine_from_payload(original_payload)
        logger.info(f"[CSTIAgent] Detected engine from payload: {current_engine}")

        # Try WAF bypass
        if waf_signature and waf_signature.lower() != "no identificado":
            logger.info(f"[CSTIAgent] WAF detected ({waf_signature}), using intelligent encoding...")
            encoded_variants = await self._get_encoded_payloads([original_payload])
            for variant in encoded_variants:
                if variant not in tried_variants and variant != original_payload:
                    return variant

        # Try char encoding
        if stripped_chars:
            encoded = encode_template_chars(original_payload, list(stripped_chars))
            if encoded not in tried_variants and encoded != original_payload:
                return encoded

        # Try engine switch
        alternative_payload = try_alternative_engine(current_engine)
        if alternative_payload and alternative_payload not in tried_variants:
            return alternative_payload

        # Try universal payloads
        for variant in get_universal_bypass_payloads():
            if variant not in tried_variants:
                return variant

        logger.warning("[CSTIAgent] Could not generate new variant (all strategies exhausted)")
        return None

    # =========================================================================
    # LLM Probes
    # =========================================================================

    def _template_get_system_prompt(self) -> str:
        return build_template_system_prompt()

    def _template_build_user_prompt(self, param, detected_engines, interactsh_url, html) -> str:
        return build_template_user_prompt(self.url, param, detected_engines, interactsh_url, html)

    async def _llm_smart_template_analysis(self, html, param, detected_engines, interactsh_url) -> List[Dict]:
        return await llm_smart_template_analysis(html, self.url, param, detected_engines, interactsh_url)

    def _parse_llm_payloads(self, content: str, interactsh_url: str) -> List[Dict]:
        return parse_llm_payloads(content, interactsh_url)

    async def _llm_probe(self, session, param: str) -> Optional[Dict]:  # I/O
        """Use LLM to generate custom bypasses."""
        from bugtrace.core.llm_client import llm_client
        from bugtrace.utils.parsers import XmlParser as Xp

        self.think(f"Generating advanced bypasses for parameter '{param}'")

        user_prompt = (
            f"Target URL: {self.url}\nParameter: {param}\n\n"
            f"Generate 5 advanced CSTI/SSTI bypasses for modern engines (Angular, Vue, Jinja2, Mako)."
        )

        try:
            response = await llm_client.generate(
                user_prompt, system_prompt=self.system_prompt, module_name="CSTI_AGENT"
            )
            ai_payloads = Xp.extract_list(response, "payload")
            ai_payloads = await self._get_encoded_payloads(ai_payloads)

            for ap in ai_payloads:
                dashboard.set_current_payload(ap, f"CSTI:{param}", "AI Advanced")
                if session:
                    content, verified_url = await self._test_payload(session, param, ap)
                    if content:
                        return self._create_finding(param, ap, "ai_bypass", verified_url=verified_url).to_dict()
        except Exception as e:
            logger.error(f"CSTI LLM check failed: {e}", exc_info=True)

        return None

    # =========================================================================
    # Parameter Test Orchestration
    # =========================================================================

    async def _param_run_standard_probes(self, session, param, engines) -> List[Dict]:
        """Run standard probes (targeted, universal, OOB)."""
        findings = []
        if engines != ["unknown"]:
            finding = await self._targeted_probe(session, param, engines)
            if finding:
                findings.append(finding)
                self._record_bypass_result(finding["payload"], success=True)

        finding = await self._universal_probe(session, param)
        if finding:
            findings.append(finding)
            self._record_bypass_result(finding["payload"], success=True)

        finding = await self._oob_probe(session, param, engines)
        if finding:
            findings.append(finding)
            self._record_bypass_result(finding["payload"], success=True)

        return findings

    async def _param_run_alternative_vectors(self, session, param, engines, param_findings) -> List[Dict]:
        """Run alternative attack vectors (POST, headers, LLM)."""
        findings = []

        finding = await test_post_injection(session, self.url, param, engines)
        if finding:
            findings.append(finding)

        if not param_findings:
            finding = await test_header_injection(session, self.url, engines)
            if finding:
                findings.append(finding)

        if self._detected_waf and not param_findings:
            finding = await self._llm_probe(session, param)
            if finding:
                findings.append(finding)

        return findings

    async def _test_parameter(self, session, item: Dict, html: str) -> List[Dict]:
        """Test a single parameter for CSTI/SSTI vulnerabilities."""
        param = item.get("parameter")
        if not param:
            return []

        param_findings = []
        engines = fingerprint_engines(html)

        is_client_side = any(e in ["angular", "vue"] for e in engines)
        is_js_rendered = len(html.strip()) < 500
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
        alternative_findings = await self._param_run_alternative_vectors(session, param, engines, param_findings)
        param_findings.extend(alternative_findings)

        return param_findings

    async def _run_llm_smart_analysis(self, session, param, engines, html) -> List[Dict]:
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
                finding = finding_obj.to_dict()
                findings.append(finding)
                stop, reason = self._should_stop_testing(sp["code"], success_content, len(findings))
                if stop:
                    dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                    break

        return findings

    # =========================================================================
    # Main run_loop (standalone mode)
    # =========================================================================

    async def run_loop(self) -> Dict:  # I/O
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting Template Injection analysis", "INFO")

        all_findings = []
        try:
            await self._prepare_scan()
            all_findings = await self._scan_all_parameters()
            await self._cleanup_scan()
        except Exception as e:
            logger.error(f"CSTIAgent error: {e}", exc_info=True)

        dashboard.log(f"[{self.name}] Complete. Findings: {len(all_findings)}", "SUCCESS")
        return {"findings": all_findings, "status": JobStatus.COMPLETED}

    async def _prepare_scan(self):  # I/O
        """Prepare for template injection scan."""
        try:
            discovered_params_dict = await discover_csti_params(self.url)
            discovered_params = prioritize_csti_params(discovered_params_dict)
        except Exception as e:
            logger.error(f"[{self.name}] Autonomous discovery failed: {e}, falling back to old method")
            discovered_params = discover_all_params_sync(self.url)

        discovered_names = {p.get("parameter") for p in discovered_params}
        for p in self.params:
            if p.get("parameter") not in discovered_names:
                discovered_params.append(p)

        self.params = discovered_params

        param_names = [p.get("parameter") for p in self.params]
        logger.info(f"[{self.name}] Parameters to test (CSTI-prioritized): {param_names}")
        dashboard.log(
            f"[{self.name}] Testing {len(self.params)} params: "
            f"{param_names[:5]}{'...' if len(param_names) > 5 else ''}",
            "INFO",
        )

        await self._detect_waf_async()
        await self._setup_interactsh()

    def _discover_all_params(self) -> List[Dict]:
        """DEPRECATED: Use discover_csti_params() instead."""
        return discover_all_params_sync(self.url)

    async def _discover_csti_params(self, url: str) -> Dict[str, str]:
        """CSTI-focused parameter discovery."""
        return await discover_csti_params(url)

    def _prioritize_csti_params(self, all_params: Dict[str, str]) -> List[Dict]:
        """Prioritize CSTI-related parameter names."""
        return prioritize_csti_params(all_params)

    async def _scan_all_parameters(self) -> List[Dict]:
        """Scan all parameters for template injection."""
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            html = await self._fetch_page(session)
            return await self._test_all_params(session, html)

    async def _test_all_params(self, session, html: str) -> List[Dict]:
        """Test all parameters with session and HTML (Parallel Mode)."""
        all_findings = []
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

    async def _cleanup_scan(self):  # I/O
        """Cleanup after template injection scan."""
        if self.interactsh:
            await self.interactsh.deregister()

    # =========================================================================
    # Queue Consumption Mode (Phase 20)
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:  # I/O
        """PHASE A: Drain WET findings from queue and deduplicate."""
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("csti")
        wet_findings = []

        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, "depth") else 0 > 0:
                break
            await asyncio.sleep(0.5)

        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                stable_empty_count += 1
                continue
            stable_empty_count = 0
            finding = item.get("finding", {}) if isinstance(item, dict) else {}
            if finding:
                wet_findings.append(finding)

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        auto_dispatch_items = [f for f in wet_findings if f.get("_auto_dispatched")]
        real_items = [f for f in wet_findings if not f.get("_auto_dispatched")]

        if real_items:
            dry_list = await llm_analyze_and_dedup(
                real_items, self._scan_context,
                tech_stack_context=self._tech_stack_context,
                csti_prime_directive=self._csti_prime_directive,
                csti_dedup_context_fn=self.generate_csti_dedup_context if hasattr(self, "generate_csti_dedup_context") else None,
                detect_engines_fn=self._detect_template_engines if hasattr(self, "_detect_template_engines") else None,
            )
        else:
            dry_list = []

        if auto_dispatch_items:
            existing_fps = set()
            for f in dry_list:
                fp = generate_csti_fingerprint(f.get("url", ""), f.get("parameter", ""), f.get("template_engine", "unknown"))
                existing_fps.add(fp)

            added = 0
            for f in auto_dispatch_items:
                fp = generate_csti_fingerprint(f.get("url", ""), f.get("parameter", ""), f.get("template_engine", "unknown"))
                if fp not in existing_fps:
                    existing_fps.add(fp)
                    dry_list.append(f)
                    added += 1
            logger.info(f"[{self.name}] Auto-dispatch bypass: {len(auto_dispatch_items)} items, {added} added to DRY list")

        self._dry_findings = dry_list

        logger.info(
            f"[{self.name}] Phase A: Deduplication complete. "
            f"{len(wet_findings)} WET -> {len(dry_list)} DRY "
            f"({len(wet_findings) - len(dry_list)} duplicates removed)"
        )
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM deduplication (delegates to pipeline module)."""
        return await llm_analyze_and_dedup(
            wet_findings, context,
            tech_stack_context=self._tech_stack_context,
            csti_prime_directive=self._csti_prime_directive,
            csti_dedup_context_fn=self.generate_csti_dedup_context if hasattr(self, "generate_csti_dedup_context") else None,
            detect_engines_fn=self._detect_template_engines if hasattr(self, "_detect_template_engines") else None,
        )

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        return fallback_fingerprint_dedup(wet_findings)

    def _normalize_csti_finding_params(self, findings: List[Dict]) -> List[Dict]:
        return normalize_csti_finding_params(findings)

    async def exploit_dry_list(self) -> List[Dict]:  # I/O
        """PHASE B: 6-Level Escalation Pipeline for each DRY finding."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list (6-Level Escalation) =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        # Load auth headers
        self._auth_headers = {}
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            self._auth_headers = get_scan_auth_headers(self._scan_context, role="admin") or {}
            if self._auth_headers:
                logger.info(f"[{self.name}] Using admin auth token from JWTAgent")
        except Exception:
            pass

        if not self.interactsh:
            await self._setup_interactsh()

        # Prioritize findings
        real_findings = [f for f in self._dry_findings if not f.get("_auto_dispatched")]
        auto_findings = [f for f in self._dry_findings if f.get("_auto_dispatched")]
        ssti_auto = [
            f for f in auto_findings
            if f.get("template_engine") in ("jinja2", "mako", "freemarker", "twig", "erb")
            or "ssti" in (f.get("reasoning") or "").lower()
        ]
        csti_auto = [f for f in auto_findings if f not in ssti_auto]

        real_nonapi = [f for f in real_findings if "/api/" not in f.get("url", "")]
        real_api = [f for f in real_findings if "/api/" in f.get("url", "")]
        ordered_findings = real_nonapi + ssti_auto + csti_auto + real_api

        ordered_findings = normalize_csti_finding_params(ordered_findings)
        api_count = len(real_api)
        logger.info(
            f"[{self.name}] Phase B: {len(real_findings)} real ({api_count} API->end) "
            f"+ {len(auto_findings)} auto-dispatch ({len(ordered_findings)} after normalization)"
        )

        for idx, finding in enumerate(ordered_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")
            is_api_endpoint = "/api/" in url
            template_engine = finding.get("template_engine", "unknown")

            logger.info(
                f"[{self.name}] Phase B: [{idx}/{len(ordered_findings)}] "
                f"Testing {url} param={parameter} engine={template_engine}"
            )

            if hasattr(self, "_v"):
                self._v.emit(
                    "exploit.specialist.param.started",
                    {"agent": "CSTI", "param": parameter, "url": url, "engine": template_engine, "idx": idx, "total": len(self._dry_findings)},
                )
                self._v.reset("exploit.specialist.progress")

            fingerprint = generate_csti_fingerprint(url, parameter, template_engine)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                if hasattr(self, "_v"):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx, "skipped": True})
                continue

            # API SSTI testing
            if is_api_endpoint:
                if not self._auth_headers:
                    try:
                        from bugtrace.services.scan_context import get_scan_auth_headers
                        fresh = get_scan_auth_headers(self._scan_context, role="admin") or {}
                        if fresh:
                            self._auth_headers = fresh
                            logger.info(f"[{self.name}] Refreshed auth before API SSTI tests")
                    except Exception:
                        pass
                try:
                    api_result = await asyncio.wait_for(
                        test_api_ssti(
                            url, parameter, finding, self._auth_headers, self.name,
                            recon_urls=self._load_recon_urls(),
                            wait_for_auth_fn=self._wait_for_api_ssti_auth,
                        ),
                        timeout=210.0,
                    )
                    if api_result and api_result.validated:
                        self._emitted_findings.add(fingerprint)
                        if hasattr(self, "_v"):
                            self._v.emit("exploit.specialist.confirmed", {"agent": "CSTI", "param": parameter, "url": url, "engine": api_result.template_engine, "payload": api_result.payload[:100], "status": "VALIDATED_CONFIRMED"})
                        finding_dict = {
                            "url": api_result.url,
                            "parameter": api_result.parameter,
                            "type": "CSTI",
                            "severity": "CRITICAL" if api_result.engine_type == "server-side" else "HIGH",
                            "template_engine": api_result.template_engine,
                            "engine_type": api_result.engine_type,
                            "payload": api_result.payload,
                            "validated": True,
                            "status": api_result.evidence.get("status", "VALIDATED_CONFIRMED"),
                            "description": f"Template Injection vulnerability detected. Expression '{api_result.payload}' was evaluated by the {api_result.engine_type} engine ({api_result.template_engine}). Method: API_POST_SSTI.",
                            "evidence": api_result.evidence,
                            "successful_payloads": api_result.successful_payloads,
                        }
                        validated_findings.append(finding_dict)
                        if settings.WORKER_POOL_EMIT_EVENTS:
                            self._emit_csti_finding(finding_dict, scan_context=self._scan_context)
                        logger.info(f"[{self.name}] SSTI confirmed on API endpoint {url} param={parameter}")
                        if hasattr(self, "_v"):
                            self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx})
                        continue
                except asyncio.TimeoutError:
                    logger.debug(f"[{self.name}] API SSTI test timeout for {url[:60]}")
                except Exception as e:
                    logger.debug(f"[{self.name}] API SSTI test failed: {e}")

            # 6-Level CSTI Escalation Pipeline
            try:
                self.url = url
                try:
                    result = await asyncio.wait_for(
                        self._csti_escalation_pipeline(url, parameter, finding),
                        timeout=180.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[{self.name}] Phase B: TIMEOUT (180s) for {parameter} on {url[:60]}, skipping")
                    result = None

                if result and result.validated:
                    self._emitted_findings.add(fingerprint)
                    if hasattr(self, "_v"):
                        self._v.emit("exploit.specialist.confirmed", {"agent": "CSTI", "param": parameter, "url": url, "engine": result.template_engine, "payload": result.payload[:100], "status": "VALIDATED_CONFIRMED"})

                    finding_dict = {
                        "url": result.url,
                        "parameter": result.parameter,
                        "type": "CSTI",
                        "severity": result.severity,
                        "template_engine": result.template_engine,
                        "engine_type": result.engine_type,
                        "payload": result.payload,
                        "validated": True,
                        "status": "VALIDATED_CONFIRMED",
                        "description": result.description,
                        "evidence": result.evidence if hasattr(result, "evidence") else {},
                    }
                    if result.successful_payloads:
                        finding_dict["successful_payloads"] = result.successful_payloads
                    validated_findings.append(finding_dict)

                    self._emit_csti_finding({
                        "type": "CSTI",
                        "url": result.url,
                        "parameter": result.parameter,
                        "severity": result.severity,
                        "template_engine": result.template_engine,
                        "engine_type": result.engine_type,
                        "payload": result.payload,
                        "evidence": result.evidence if hasattr(result, "evidence") else {},
                        "arithmetic_proof": result.arithmetic_proof if hasattr(result, "arithmetic_proof") else False,
                    }, scan_context=self._scan_context)
                    logger.info(f"[{self.name}] CSTI confirmed: {url} param={parameter} engine={template_engine}")
                else:
                    logger.debug(f"[{self.name}] CSTI not confirmed after 6-level escalation")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Escalation pipeline failed: {e}")
            finally:
                if hasattr(self, "_v"):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx})

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    # =========================================================================
    # 6-Level CSTI Escalation Pipeline
    # =========================================================================

    async def _csti_escalation_pipeline(
        self, url: str, param: str, finding: dict
    ) -> Optional[CSTIFinding]:  # I/O
        """v3.4: 6-Level CSTI Escalation Pipeline."""
        reflecting_payloads = []

        engines = await detect_engines_for_escalation(
            url, finding, tech_profile=self.tech_profile,
            fetch_page_fn=lambda session: fetch_page(session, url),
        )

        # Autonomous param discovery
        params_to_test = [param]
        try:
            discovered = await discover_csti_params(url)
            if discovered:
                for dp in discovered.keys():
                    if dp not in params_to_test:
                        params_to_test.append(dp)
                if len(params_to_test) > 1:
                    logger.info(
                        f"[{self.name}] Autonomous discovery: {len(params_to_test)} params "
                        f"to test on {url[:60]}: {params_to_test}"
                    )
        except Exception as e:
            logger.debug(f"[{self.name}] Autonomous discovery failed: {e}")

        for test_param in params_to_test:
            result = await self._run_escalation_for_param(url, test_param, finding, engines, reflecting_payloads)
            if result:
                return result

        dashboard.log(f"[{self.name}] All 6 levels exhausted for all params on {url[:60]}, no CSTI confirmed", "WARN")
        return None

    async def _run_escalation_for_param(
        self, url: str, param: str, finding: dict,
        engines: List[str], reflecting_payloads: list,
    ) -> Optional[CSTIFinding]:
        """Run the full L0-L6 escalation pipeline for a single param."""
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            baseline_html = await get_baseline_content(session, url)

        # Smart probe
        smart_result, should_continue = await escalation_smart_probe(
            url, param, engines, baseline_html, self.name,
            verbose_emitter=getattr(self, "_v", None),
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )
        if smart_result:
            return smart_result
        if not should_continue:
            return None

        # L0: WET payload
        wet_payload = finding.get("payload") or finding.get("exploitation_strategy") or finding.get("recommended_payload")
        if wet_payload:
            dashboard.log(f"[{self.name}] L0: Testing WET payload on '{param}'", "INFO")
            result = await escalation_l0_wet_payload(
                url, param, wet_payload, engines, baseline_html, self.name,
                tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
            )
            if result:
                return result

        # L1: Template polyglot probe
        dashboard.log(f"[{self.name}] L1: Template polyglot probe on '{param}'", "INFO")
        result = await escalation_l1_template_probe(
            url, param, baseline_html, self.name, self.interactsh,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )
        if result:
            return result

        # L2: Static bombardment
        dashboard.log(f"[{self.name}] L2: Static bombardment on '{param}'", "INFO")
        result, l2_reflecting = await escalation_l2_static_bombing(
            url, param, engines, baseline_html, self.name,
            interactsh_url=self.interactsh_url or "",
            detected_waf=self._detected_waf,
            interactsh_client=self.interactsh,
            verbose_emitter=getattr(self, "_v", None),
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )
        if result:
            return result
        reflecting_payloads.extend(l2_reflecting)

        # L3: LLM bombardment
        dashboard.log(f"[{self.name}] L3: LLM bombardment on '{param}'", "INFO")
        result, l3_reflecting = await escalation_l3_llm_bombing(
            url, param, engines, reflecting_payloads, baseline_html, self.name,
            system_prompt=self.system_prompt,
            csti_prime_directive=self._csti_prime_directive,
            interactsh_url=self.interactsh_url or "",
            detected_waf=self._detected_waf,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )
        if result:
            return result
        reflecting_payloads.extend(l3_reflecting)

        # L4/L5: Engine-aware ordering
        has_client_side = any(e in ["angular", "vue"] for e in engines)

        if has_client_side:
            if not reflecting_payloads:
                spa_payloads = [p for p in PAYLOAD_LIBRARY.get("angular", [])[:10]]
                spa_payloads.extend(PAYLOAD_LIBRARY.get("universal", [])[:3])
                reflecting_payloads.extend(spa_payloads)
                logger.info(
                    f"[{self.name}] No HTTP reflections for client-side engine, "
                    f"seeding {len(spa_payloads)} browser payloads"
                )

            if reflecting_payloads:
                dashboard.log(f"[{self.name}] L5: Browser testing {len(reflecting_payloads)} candidates on '{param}' (client-side priority)", "INFO")
                result = await escalation_l5_browser(
                    url, param, reflecting_payloads, self.name,
                    tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
                )
                if result:
                    return result

            dashboard.log(f"[{self.name}] L4: HTTP Manipulator on '{param}' (fallback)", "INFO")
            result, l4_reflecting = await escalation_l4_http_manipulator(url, param, self.name)
            if result:
                return result
            reflecting_payloads.extend(l4_reflecting)
        else:
            dashboard.log(f"[{self.name}] L4: HTTP Manipulator on '{param}'", "INFO")
            result, l4_reflecting = await escalation_l4_http_manipulator(url, param, self.name)
            if result:
                return result
            reflecting_payloads.extend(l4_reflecting)

            if reflecting_payloads:
                dashboard.log(f"[{self.name}] L5: Browser testing {len(reflecting_payloads)} candidates on '{param}'", "INFO")
                result = await escalation_l5_browser(
                    url, param, reflecting_payloads, self.name,
                    tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
                )
                if result:
                    return result

        # L6: CDP Validation
        if reflecting_payloads:
            dashboard.log(f"[{self.name}] L6: Flagging for CDP AgenticValidator on '{param}'", "INFO")
            result = create_l6_cdp_finding(
                url, param, reflecting_payloads, self.name,
                tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
            )
            if result:
                return result

        dashboard.log(f"[{self.name}] All 6 levels exhausted for '{param}' on {url[:60]}", "WARN")
        return None

    # =========================================================================
    # Escalation helpers (kept for backward compat, delegate to module fns)
    # =========================================================================

    async def _escalation_smart_probe_csti(self, url, param, engines, baseline_html):
        return await escalation_smart_probe(
            url, param, engines, baseline_html, self.name,
            verbose_emitter=getattr(self, "_v", None),
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    async def _detect_engines_for_escalation(self, url, finding):
        return await detect_engines_for_escalation(
            url, finding, tech_profile=self.tech_profile,
            fetch_page_fn=lambda session: fetch_page(session, url),
        )

    async def _send_csti_payload_raw(self, session, param, payload):
        return await send_csti_payload_raw(session, self.url, param, payload)

    async def _escalation_l0_wet_payload(self, url, param, wet_payload, engines, baseline_html):
        return await escalation_l0_wet_payload(
            url, param, wet_payload, engines, baseline_html, self.name,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    async def _escalation_l1_template_probe(self, url, param, baseline_html):
        return await escalation_l1_template_probe(
            url, param, baseline_html, self.name, self.interactsh,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    async def _escalation_l2_static_bombing(self, url, param, engines, baseline_html):
        return await escalation_l2_static_bombing(
            url, param, engines, baseline_html, self.name,
            interactsh_url=self.interactsh_url or "", detected_waf=self._detected_waf,
            interactsh_client=self.interactsh, verbose_emitter=getattr(self, "_v", None),
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    async def _escalation_l3_llm_bombing(self, url, param, engines, existing_reflecting, baseline_html):
        return await escalation_l3_llm_bombing(
            url, param, engines, existing_reflecting, baseline_html, self.name,
            system_prompt=self.system_prompt, csti_prime_directive=self._csti_prime_directive,
            interactsh_url=self.interactsh_url or "", detected_waf=self._detected_waf,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    async def _escalation_l4_http_manipulator(self, url, param):
        return await escalation_l4_http_manipulator(url, param, self.name)

    async def _escalation_l5_browser(self, url, param, reflecting_payloads):
        return await escalation_l5_browser(
            url, param, reflecting_payloads, self.name,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    async def _escalation_l6_cdp(self, url, param, reflecting_payloads):
        return create_l6_cdp_finding(
            url, param, reflecting_payloads, self.name,
            tech_profile=self.tech_profile, tech_stack_context=self._tech_stack_context,
        )

    # =========================================================================
    # API SSTI / Recon
    # =========================================================================

    def _resolve_api_ssti_url(self, url: str, parameter: str) -> str:
        from bugtrace.agents.csti.exploitation import _resolve_api_ssti_url
        return _resolve_api_ssti_url(url, parameter, self._load_recon_urls())

    def _load_recon_urls(self) -> List[str]:
        """Load discovered URLs from recon/urls.txt (cached per scan)."""
        if hasattr(self, "_cached_recon_urls"):
            return self._cached_recon_urls

        urls = []
        try:
            scan_dir = getattr(self, "report_dir", None)
            if not scan_dir:
                scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
                scan_dir = settings.BASE_DIR / "reports" / scan_id
            urls_file = scan_dir / "recon" / "urls.txt"
            if urls_file.exists():
                urls = [line.strip() for line in urls_file.read_text().splitlines() if line.strip()]
        except Exception as e:
            logger.debug(f"[{self.name}] Could not load recon URLs: {e}")

        self._cached_recon_urls = urls
        return urls

    async def _test_api_ssti(self, url: str, parameter: str, finding: dict) -> Optional[CSTIFinding]:
        return await test_api_ssti(
            url, parameter, finding, getattr(self, "_auth_headers", {}), self.name,
            recon_urls=self._load_recon_urls(),
            wait_for_auth_fn=self._wait_for_api_ssti_auth,
        )

    async def _wait_for_api_ssti_auth(self, max_wait: int = 180) -> Dict:
        """Poll for JWT token from JWTAgent for API SSTI testing."""
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
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

    # =========================================================================
    # Specialist Report
    # =========================================================================

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        await generate_specialist_report(
            validated_findings, self._dry_findings, self._scan_context,
            self.name, report_dir=getattr(self, "report_dir", None),
        )

    # =========================================================================
    # Queue Consumer Lifecycle
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:  # I/O
        """TWO-PHASE queue consumer (WET -> DRY). NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("CSTI", self._scan_context)

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")

        await self._load_csti_tech_context()

        queue = queue_manager.get_queue("csti")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)
        self._v.emit("exploit.specialist.started", {"agent": "CSTI", "queue_depth": initial_depth})

        # PHASE A
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "csti")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "CSTI", "processed": 0, "vulns": 0})
            return

        # PHASE B
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)
        self._v.emit("exploit.specialist.completed", {"agent": "CSTI", "processed": len(dry_list), "vulns": vulns_count})

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(EventType.WORK_QUEUED_CSTI.value, self._on_work_queued)

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _load_csti_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""
        scan_dir = getattr(self, "report_dir", None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._csti_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._csti_prime_directive = self.generate_csti_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        frameworks = self._tech_stack_context.get("frameworks", [])
        waf = self._tech_stack_context.get("waf")

        raw_profile = self._tech_stack_context.get("raw_profile", {})
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        detected_engines = self._detect_template_engines(frameworks, tech_tags, lang)

        logger.info(
            f"[{self.name}] CSTI tech context loaded: lang={lang}, "
            f"engines={detected_engines or ['unknown']}, waf={waf or 'none'}"
        )

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_csti notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[CSTIFinding]:
        """Process a single item from the csti queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        self.url = url
        return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(self, url, param, finding) -> Optional[CSTIFinding]:
        """Test a single parameter from queue for CSTI."""
        try:
            async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                html = await self._fetch_page(session)
                engines = fingerprint_engines(html)

                suggested_engine = finding.get("template_engine")
                if suggested_engine and suggested_engine != "unknown":
                    engines = [suggested_engine] + [e for e in engines if e != suggested_engine]

                # Test WET payload first
                wet_payload = finding.get("payload") or finding.get("exploitation_strategy") or finding.get("recommended_payload")
                if wet_payload:
                    logger.info(f"[{self.name}] Testing WET payload first: {wet_payload[:50]}...")
                    result = await self._test_wet_finding_payload(session, param, wet_payload, engines)
                    if result:
                        return dict_to_finding(result, self.url)

                if engines and engines[0] != "unknown":
                    result = await self._targeted_probe(session, param, engines)
                    if result:
                        return dict_to_finding(result, self.url)

                result = await self._universal_probe(session, param)
                if result:
                    return dict_to_finding(result, self.url)

                if not self.interactsh:
                    await self._setup_interactsh()
                if self.interactsh_url:
                    result = await self._oob_probe(session, param, engines)
                    if result:
                        return dict_to_finding(result, self.url)

            # Retry with admin auth
            try:
                from bugtrace.services.scan_context import get_scan_auth_headers
                auth_headers = get_scan_auth_headers(self._scan_context, role="admin")
                if auth_headers:
                    logger.info(f"[{self.name}] Retrying {url}?{param} with admin auth token")
                    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as auth_session:
                        auth_session._default_headers = {**(auth_session._default_headers or {}), **auth_headers}
                        result = await self._universal_probe(auth_session, param)
                        if result:
                            result["auth_required"] = True
                            result["description"] = f"SSTI on admin-protected endpoint. {result.get('description', '')}"
                            return dict_to_finding(result, self.url)
            except Exception as auth_err:
                logger.debug(f"[{self.name}] Auth retry failed: {auth_err}")

            return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _test_wet_finding_payload(self, session, param, payload, engines) -> Optional[Dict]:
        """Test the specific payload from WET finding."""
        dashboard.set_current_payload(payload[:30] + "...", f"CSTI:{param}", "WET Payload")

        content, verified_url = await self._test_payload(session, param, payload)
        if content is not None:
            engine = self._detect_engine_from_payload(payload)
            if engine == "unknown" and engines:
                engine = engines[0]
            finding_obj = self._create_finding(param, payload, "wet_payload_validated", verified_url=verified_url)
            return finding_obj.to_dict()

        # Double-quote variant
        if "'" in payload:
            dq_payload = payload.replace("'", '"')
            logger.info(f"[{self.name}] Single-quote payload failed, trying double-quote variant: {dq_payload[:50]}...")
            dashboard.set_current_payload(dq_payload[:30] + "...", f"CSTI:{param}", "WET DQ Variant")

            content, verified_url = await self._test_payload(session, param, dq_payload)
            if content is not None:
                finding_obj = self._create_finding(param, dq_payload, "wet_payload_validated_dq", verified_url=verified_url)
                return finding_obj.to_dict()

            # Backtick variant
            bt_payload = payload.replace("'", "`")
            logger.info(f"[{self.name}] Double-quote also failed, trying backtick variant: {bt_payload[:50]}...")
            dashboard.set_current_payload(bt_payload[:30] + "...", f"CSTI:{param}", "WET BT Variant")

            content, verified_url = await self._test_payload(session, param, bt_payload)
            if content is not None:
                finding_obj = self._create_finding(param, bt_payload, "wet_payload_validated_bt", verified_url=verified_url)
                return finding_obj.to_dict()

        return None

    async def _handle_queue_result(self, item: dict, result: Optional[CSTIFinding]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        finding_data = {
            "context": result.engine_type,
            "payload": result.payload,
            "validation_method": result.template_engine,
            "evidence": result.evidence,
        }
        needs_cdp = requires_cdp_validation(finding_data)

        fingerprint = generate_csti_fingerprint(result.url, result.parameter, result.template_engine)
        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate CSTI finding (already reported)")
            return

        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_csti_finding({
                "specialist": "csti",
                "type": "CSTI",
                "url": result.url,
                "parameter": result.parameter,
                "payload": result.payload,
                "template_engine": result.template_engine,
                "evidence": result.evidence if hasattr(result, "evidence") else {},
                "status": result.status,
                "validation_requires_cdp": needs_cdp,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed CSTI: {result.url}?{result.parameter} ({result.template_engine})")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}
        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }
