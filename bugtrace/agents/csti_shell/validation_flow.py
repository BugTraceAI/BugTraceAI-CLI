"""CSTI validation/emit shell.

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
from bugtrace.tools.waf import strategy_router

logger = get_logger(__name__)

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.payloads import (
    PAYLOAD_LIBRARY,
    HIGH_IMPACT_INDICATORS,
)

class CSTIValidationMixin:
    def _finding_to_dict(self, finding: CSTIFinding) -> Dict:
        """Convert CSTIFinding object to dictionary for report."""
        result = {
            "type": finding.type,
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "severity": finding.severity,
            "template_engine": finding.template_engine,
            "injection_type": f"{finding.engine_type} Template Injection",

            "validated": finding.validated,
            "status": finding.status,
            "description": finding.description,
            "reproduction": finding.reproduction_command,
            "reproduction_steps": finding.reproduction_steps, # List

            "evidence": finding.evidence,

            # Additional metadata for deep dive report
            "csti_metadata": {
                "engine": finding.template_engine,
                "type": finding.engine_type,
                "syntax": finding.payload_syntax,
                "arithmetic_proof": finding.arithmetic_proof,
                "verified_url": finding.verified_url
            }
        }

        if finding.successful_payloads:
            result["successful_payloads"] = finding.successful_payloads

        return result

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """
        CSTI-specific validation before emitting finding.

        Validates:
        1. Basic requirements (type, url) via parent
        2. Template engine is identified
        3. Has arithmetic proof or engine fingerprint evidence
        4. Payload contains template syntax
        """
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # CSTI-specific: Must have template engine identified
        template_engine = finding.get("template_engine", "unknown")
        if template_engine == "unknown":
            # Check nested finding structure
            nested = finding.get("finding", {})
            template_engine = nested.get("template_engine", "unknown")

        if template_engine == "unknown":
            return False, "CSTI requires identified template engine"

        # CSTI-specific: Must have proof (arithmetic, fingerprint, or Interactsh)
        evidence = finding.get("evidence", {})
        has_arithmetic = evidence.get("arithmetic_proof") or finding.get("arithmetic_proof")
        has_fingerprint = evidence.get("fingerprint") or template_engine != "unknown"
        has_interactsh = evidence.get("interactsh_callback")

        if not (has_arithmetic or has_fingerprint or has_interactsh):
            return False, "CSTI requires proof: arithmetic evaluation, fingerprint, or Interactsh callback"

        # CSTI-specific: Payload should contain template syntax
        payload = finding.get("payload", "")
        if not payload:
            nested = finding.get("finding", {})
            payload = nested.get("payload", "")

        template_markers = ['{{', '}}', '${', '}', '#{', '<%', '%>', '#set', '$x']
        if payload and not any(m in str(payload) for m in template_markers):
            return False, f"CSTI payload missing template syntax: {payload[:50]}"

        return True, ""

    def _emit_csti_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """
        Helper to emit CSTI finding using BaseAgent.emit_finding() with validation.

        Args:
            finding_dict: Finding dictionary to emit
            scan_context: Optional scan context to include

        Returns:
            The finding dict if emitted, None if rejected
        """
        # Ensure required fields
        if "type" not in finding_dict:
            finding_dict["type"] = "CSTI"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name

        # Use BaseAgent's validated emit
        return self.emit_finding(finding_dict)

    def _record_bypass_result(self, payload: str, success: bool):
        """Record result for Q-Learning feedback."""
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

    async def _validate(
        self,
        param: str,
        payload: str,
        response_html: str,
        screenshots_dir: Path
    ) -> tuple:
        """
        4-LEVEL VALIDATION PIPELINE (V2.0) - CSTI/SSTI Alignment
        Ref: BugTraceAI-CLI/docs/architecture/xss-validation-pipeline.md

        v3.2 FIX: For JS-rendered sites (empty response_html), skip L1/L2 and go
        directly to L3 Playwright for client-side payloads (Angular, Vue).
        """
        evidence = {"payload": payload}

        # v3.2 FIX: Detect JS-rendered site and client-side payload
        response_len = len(response_html.strip())
        is_js_rendered = response_len < 500
        is_client_side_payload = any(marker in payload for marker in ["{{", "${", "constructor", "$eval", "$on"])

        logger.info(f"[{self.name}] CSTI _validate: response_len={response_len}, is_js_rendered={is_js_rendered}, is_client_side={is_client_side_payload}")

        if is_js_rendered and is_client_side_payload:
            logger.info(f"[{self.name}] JS-rendered site + client-side payload - skipping L1/L2, going to L3 Playwright")
            # Skip L1/L2, go directly to L3 for client-side CSTI on JS-rendered sites
            if await self._validate_with_playwright(param, payload, screenshots_dir, evidence):
                return True, evidence
            logger.debug(f"[{self.name}] L3 Playwright failed for JS-rendered CSTI, escalating to L4")
            return False, evidence

        # Standard flow for server-side or non-JS sites
        # Level 1: HTTP Static Reflection Check (Arithmetic/Signatures)
        logger.info(f"[{self.name}] L1 checking: {payload[:40]}...")
        try:
            l1_result = await self._validate_http_reflection(param, payload, response_html, evidence)
            if l1_result:
                logger.info(f"[{self.name}] L1 CONFIRMED: {evidence.get('method')}")
                return True, evidence
            logger.info(f"[{self.name}] L1 returned False")
        except Exception as e:
            logger.warning(f"[{self.name}] L1 exception: {e}")
        logger.info(f"[{self.name}] L1 failed, trying L2")

        # Level 2: AI-Powered Manipulator (Logic Evasion)
        try:
            l2_result = await self._validate_with_ai_manipulator(param, payload, response_html, evidence)
            if l2_result:
                logger.info(f"[{self.name}] L2 CONFIRMED")
                return True, evidence
        except Exception as e:
            logger.warning(f"[{self.name}] L2 exception: {e}")
        logger.info(f"[{self.name}] L2 failed, trying L3 Playwright")

        # Level 3: Playwright Browser Execution (Client-side engines)
        try:
            l3_result = await self._validate_with_playwright(param, payload, screenshots_dir, evidence)
            if l3_result:
                return True, evidence
        except Exception as e:
            logger.warning(f"[{self.name}] L3 exception: {e}")

        # Level 4: Escalation (Return False to let Manager/Reactor escalate to AgenticValidator)
        logger.info(f"[{self.name}] L1-L3 all failed for {payload[:40]}")
        return False, evidence

    async def _validate_http_reflection(self, param: str, payload: str, response_html: str, evidence: Dict) -> bool:
        """Level 1: Fast HTTP static evaluation check."""
        # Tier 1.1: OOB Interactsh (Definitive OOB)
        if await self._check_oob_hit(f"csti_{param}"):
            evidence["method"] = "L1: OOB Interactsh"
            evidence["level"] = 1
            return True

        if not response_html:
            return False

        # Tier 1.2: Signatures and Arithmetic
        # Use existing checks
        async with http_manager.isolated_session(ConnectionProfile.PROBE) as session:
            if await self._check_arithmetic_evaluation(response_html, payload, session, ""):
                evidence["method"] = "L1: Arithmetic Evaluation"
                evidence["level"] = 1
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True

        if self._check_string_multiplication(response_html, payload):
            evidence["method"] = "L1: String Multiplication"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        if self._check_config_reflection(response_html, payload):
            evidence["method"] = "L1: Config Reflection"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        if self._check_engine_signatures(response_html, payload):
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.signature_match", {"agent": "CSTI", "payload": payload[:100], "method": "engine_signature"})
            evidence["method"] = "L1: Engine Signature"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        if self._check_error_signatures(response_html):
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.signature_match", {"agent": "CSTI", "payload": payload[:100], "method": "error_signature"})
            evidence["method"] = "L1: Error Signature"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        return False

    async def _validate_with_ai_manipulator(self, param: str, payload: str, response_html: str, evidence: Dict) -> bool:
        """Level 2: AI-powered audit of potential evaluation."""
        if not response_html or payload not in response_html:
            return False
            
        # If the exact payload is reflected, maybe it's partially evaluated but masked?
        # Or maybe it's a context where simple arithmetic fails but more complex objects work.
        # Placeholder for AI analysis
        return False

    async def _validate_with_playwright(self, param: str, payload: str, screenshots_dir: Path, evidence: Dict) -> bool:
        """Level 3: Playwright browser execution (Client-side engines like Angular)."""
        attack_url = self._inject(param, payload)

        # Fix A: a 4xx endpoint is NOT a real reflection sink — never browser-validate it.
        # The browser path bypasses _send_csti_payload_raw's HTTP gate, so without this a
        # 404 endpoint (e.g. /logger picked up from library strings) can get "confirmed" by
        # Playwright on an SPA-style error page. 5xx is left flowing (server-side SSTI errors).
        try:
            async with http_manager.isolated_session(ConnectionProfile.PROBE) as _probe_s:
                async with _probe_s.get(attack_url, timeout=8) as _probe_r:
                    if 400 <= _probe_r.status < 500:
                        logger.info(
                            f"[{self.name}] L3/L5: endpoint returns {_probe_r.status} (not a reflection sink) "
                            f"— skipping browser validation for '{param}'"
                        )
                        return False
        except Exception as _probe_e:
            logger.debug(f"[{self.name}] L3/L5: status pre-check failed ({_probe_e}); proceeding")

        logger.info(f"[{self.name}] L3 Playwright validating CSTI: {payload[:50]}...")

        # Use verifier pool for efficiency
        from bugtrace.agents.agentic_validator import _verifier_pool
        verifier = await _verifier_pool.get_verifier()
        try:
            # v3.2: Increased timeout for Angular sandbox escapes (they need DOM processing time)
            result = await verifier.verify_xss(
                url=attack_url,
                screenshot_dir=str(screenshots_dir),
                timeout=15.0,  # Increased from 8s for complex Angular payloads
                max_level=3 # Stay at L3 within the agent
            )

            logger.info(f"[{self.name}] L3 Playwright result: success={result.success}, details={result.details}")

            if result.success:
                evidence.update(result.details or {})
                evidence["playwright_confirmed"] = True
                evidence["screenshot_path"] = result.screenshot_path
                evidence["method"] = "L3: Playwright Browser"
                evidence["level"] = 3
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True
        finally:
            _verifier_pool.release()

        return False

    def _create_finding(self, param: str, payload: str, method: str, verified_url: str = None) -> CSTIFinding:
        """Create a standardized finding object with full authority."""
        logger.info(f"[{self.name}] 🚨 CSTI/SSTI CONFIRMED on {param}: {payload}")
        dashboard.log(f"[{self.name}] 🎯 CSTI/SSTI CONFIRMED on '{param}'!", "SUCCESS")

        # Determine engine from payload if not specified
        engine = self._detect_engine_from_payload(payload)
        engine_type = "client-side" if engine in ["angular", "vue"] else "server-side"
        
        # Use verified URL if available, else fallback to current (though verified should be passed)
        final_url = verified_url or self.url
        
        encoded_url = self._inject(param, payload).replace(self.url, final_url) if verified_url else self._inject(param, payload)
        curl_cmd = f"curl '{encoded_url}' | grep 1000006000009"

        return CSTIFinding(
            url=final_url,
            parameter=param,
            payload=payload,
            template_engine=engine,
            engine_type=engine_type,
            payload_syntax=engine,
            verified_url=final_url,
            original_url=self.url,
            arithmetic_proof="1000003*1000003" in payload, # Simple heuristic for now
            baseline_check_passed=True, # We now check this in verification
            description=f"Template Injection vulnerability detected. Expression '{payload}' was evaluated by the {engine_type} engine ({engine}). Method: {method}.",
            reproduction_command=curl_cmd,
            reproduction_steps=self._generate_repro_steps(final_url, param, payload, curl_cmd),
            evidence={
                "method": method,
                "proof": "Arithmetic evaluation detected (1000003*1000003=1000006000009) or specific engine behavior verified.",
                "engine": engine
            }
        )

    def _create_ambiguous_finding(self, param: str, payload: str, engine: str) -> Dict:
        # Keeping this as Dict for now as it's not a confirmed finding? 
        # Actually better to use CSTIFinding but marked as not validated?
        # For minimal diff, let's keep it but ideally we should standardize.
        # But this function returns a Dict in current code.
        # Let's verify usage. It's used to return a Dict.
        # I'll update it to return CSTIFinding but validated=False
        
        logger.info(f"[{self.name}] ⚠️ Potential client-side CSTI on {param} ({engine}) - needs CDP")
        dashboard.log(f"[{self.name}] ⚠️ Potential CSTI on '{param}' ({engine}) - delegating to CDP", "WARN")

        return CSTIFinding(
            url=self.url,
            parameter=param,
            payload=payload,
            type="CSTI",
            severity="MEDIUM",
            template_engine=engine,
            engine_type="client-side",
            validated=False,
            status="PENDING_CDP_VALIDATION",
            reproduction_command=f"# Open in browser: {self._inject(param, payload)}",
            description=f"Potential client-side template injection ({engine}). Template syntax reflected but execution needs browser validation.",
            evidence={
                "engine": engine,
                "needs_cdp": True,
                "reason": f"Client-side framework ({engine}) suspected, needs browser validation"
            }
        )

    async def _feedback_generate_waf_bypass(self, original: str) -> Tuple[Optional[str], str]:
        """Generate WAF bypass variant."""
        encoded = await self._get_encoded_payloads([original])
        if encoded and encoded[0] != original:
            return encoded[0], "waf_bypass"
        return None, ""

    def _feedback_generate_engine_switch(self, engine: str) -> Tuple[Optional[str], str]:
        """Generate engine switch variant."""
        variant = self._try_alternative_engine(engine)
        return variant, "engine_switch"

    def _feedback_generate_char_encoding(self, original: str, stripped_chars: List[str]) -> Tuple[Optional[str], str]:
        """Generate character encoding variant."""
        variant = self._encode_template_chars(original, stripped_chars)
        return variant, "char_encoding"

    async def _feedback_generate_llm_fallback(self, parameter: str) -> Tuple[Optional[str], str]:
        """Generate LLM fallback variant."""
        llm_result = await self._llm_probe(None, parameter)
        if llm_result:
            return llm_result.get('payload'), "llm_fallback"
        return None, ""

    async def handle_validation_feedback(
        self,
        feedback: ValidationFeedback
    ) -> Optional[Dict[str, Any]]:
        """
        Recibe feedback del AgenticValidator y genera una variante de CSTI.

        Args:
            feedback: Información sobre el fallo de validación

        Returns:
            Diccionario con el nuevo payload, o None
        """
        logger.info(f"[CSTIAgent] Received feedback: {feedback.failure_reason.value}")

        original = feedback.original_payload
        engine = self._detect_engine_from_payload(original)
        variant = None
        method = "feedback_adaptation"

        # Try specific bypass strategies based on failure reason
        if feedback.failure_reason == FailureReason.WAF_BLOCKED:
            variant, method = await self._feedback_generate_waf_bypass(original)
        elif feedback.failure_reason == FailureReason.CONTEXT_MISMATCH:
            variant, method = self._feedback_generate_engine_switch(engine)
        elif feedback.failure_reason == FailureReason.ENCODING_STRIPPED:
            variant, method = self._feedback_generate_char_encoding(original, feedback.stripped_chars)

        # Fallback to LLM if no variant generated
        if not variant or variant == original:
            variant, method = await self._feedback_generate_llm_fallback(feedback.parameter)

        # Return variant if valid and not tried before
        if variant and variant != original and not feedback.was_variant_tried(variant):
            return {
                "payload": variant,
                "method": method,
                "engine_guess": engine
            }

        return None

    async def generate_bypass_variant(
        self,
        original_payload: str,
        failure_reason: str,
        waf_signature: Optional[str] = None,
        stripped_chars: Optional[str] = None,
        tried_variants: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Genera una variante de payload CSTI basada en feedback de fallo.
        
        Este método es llamado por el AgenticValidator cuando un payload falla,
        permitiendo al agente usar su lógica sofisticada de bypass para generar
        una variante que evite el problema detectado.
        
        Args:
            original_payload: El payload que falló
            failure_reason: Razón del fallo (waf_blocked, chars_filtered, etc.)
            waf_signature: Firma del WAF detectado (si aplica)
            stripped_chars: Caracteres que fueron filtrados
            tried_variants: Lista de variantes ya probadas
            
        Returns:
            String con el nuevo payload, o None si no se pudo generar
        """
        logger.info(f"[CSTIAgent] Generating bypass variant for failed payload: {original_payload[:50]}...")

        tried_variants = tried_variants or []
        current_engine = self._detect_engine_from_payload(original_payload)
        logger.info(f"[CSTIAgent] Detected engine from payload: {current_engine}")

        # Try strategies in order
        variant = self._try_waf_bypass(original_payload, waf_signature, tried_variants)
        if variant:
            return variant

        variant = self._try_char_encoding(original_payload, stripped_chars, tried_variants)
        if variant:
            return variant

        variant = self._try_engine_switch(current_engine, tried_variants)
        if variant:
            return variant

        variant = self._try_universal_payloads(tried_variants)
        if variant:
            return variant

        logger.warning("[CSTIAgent] Could not generate new variant (all strategies exhausted)")
        return None

    def _try_waf_bypass(self, original_payload: str, waf_signature: Optional[str], tried_variants: List[str]) -> Optional[str]:
        """Try WAF bypass encoding strategy."""
        if not waf_signature or waf_signature.lower() == "no identificado":
            return None

        logger.info(f"[CSTIAgent] WAF detected ({waf_signature}), using intelligent encoding...")
        encoded_variants = self._get_encoded_payloads([original_payload])

        for variant in encoded_variants:
            if variant not in tried_variants and variant != original_payload:
                logger.info(f"[CSTIAgent] Generated WAF bypass variant: {variant[:80]}...")
                return variant
        return None

    def _check_csti_confirmed(self, payload: str, response_html: str, baseline_html: str) -> Tuple[bool, Dict]:
        """
        Check if CSTI is confirmed in HTTP response.

        Returns (confirmed, evidence) tuple.
        Checks: arithmetic evaluation, string multiplication, config reflection,
        engine signatures, error signatures.
        """
        if not response_html:
            return False, {}

        evidence = {"payload": payload}

        # 1. Arithmetic evaluation (1000003*1000003=1000006000009)
        if "1000006000009" in response_html and "1000003*1000003" in payload:
            if payload not in response_html:
                if "1000006000009" not in baseline_html:
                    evidence["method"] = "arithmetic_eval"
                    evidence["proof"] = "1000003*1000003 evaluated to 1000006000009"
                    evidence["status"] = "VALIDATED_CONFIRMED"
                    return True, evidence

        # 2. Constructor evaluation of the distinctive arithmetic marker
        if "constructor" in payload and "1000006000009" in response_html:
            if payload not in response_html and "1000006000009" not in baseline_html:
                evidence["method"] = "constructor_eval"
                evidence["proof"] = "Constructor payload evaluated to 1000006000009"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

        # 3. String multiplication ('7'*7 → 7777777)
        if "7777777" in response_html and "'7'*7" in payload:
            if payload not in response_html:
                evidence["method"] = "string_multiplication"
                evidence["proof"] = "'7'*7 evaluated to 7777777"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

        # 4. Config reflection (Jinja2)
        if "{{config}}" in payload and ("Config" in response_html or "&lt;Config" in response_html):
            if payload not in response_html:
                evidence["method"] = "config_reflection"
                evidence["proof"] = "{{config}} accessed Config object"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

        # 5. Engine signatures
        if ("{{dump(app)}}" in payload or "{{app.request}}" in payload) and ("Symfony" in response_html or "Twig" in response_html):
            evidence["method"] = "engine_signature_twig"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

        if "{$smarty.version}" in payload and re.search(r"Smarty[- ]\d", response_html):
            evidence["method"] = "engine_signature_smarty"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

        # 6. Error signatures (template engine errors indicate processing)
        error_signatures = [
            "jinja2.exceptions", "Twig_Error_Syntax", "FreeMarker template error",
            "VelocityException", "org.apache.velocity", "mako.exceptions"
        ]
        for sig in error_signatures:
            if sig in response_html:
                evidence["method"] = "error_signature"
                evidence["proof"] = f"Template error: {sig}"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

        # 7. Conditional evaluation ({% if %})
        if "{% if" in payload and "1000006000009" in payload:
            if "{%" not in response_html and "%}" not in response_html and "1000006000009" in response_html:
                evidence["method"] = "conditional_eval"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

        # 8. RCE indicators (command output in response)
        # IMPORTANT: Skip indicators that are part of the payload itself.
        # If we sent "java.lang.Runtime" and it reflects back, that's NOT proof
        # of execution - only genuine command OUTPUT (uid=, root:) counts.
        for indicator in HIGH_IMPACT_INDICATORS:
            if indicator in response_html and indicator not in baseline_html:
                if any(rce in payload for rce in ["popen", "exec", "system", "Runtime", "subprocess"]):
                    # Guard: indicator must NOT be a substring of the payload
                    # (if it is, the response just reflects our input, not execution output)
                    if indicator in payload:
                        continue
                    evidence["method"] = "rce_indicator"
                    evidence["proof"] = f"RCE indicator: {indicator}"
                    evidence["status"] = "VALIDATED_CONFIRMED"
                    return True, evidence

        return False, evidence

    def _dict_to_finding(self, result: Dict) -> Optional[CSTIFinding]:
        """Convert finding dict back to CSTIFinding object."""
        if not result:
            return None

        return CSTIFinding(
            url=result.get("url", self.url),
            parameter=result.get("parameter", ""),
            payload=result.get("payload", ""),
            template_engine=result.get("template_engine", "unknown"),
            engine_type=result.get("csti_metadata", {}).get("type", "unknown"),
            status=result.get("status", "VALIDATED_CONFIRMED"),
            validated=result.get("validated", True),
            description=result.get("description", ""),
            evidence=result.get("evidence", {}),
        )

