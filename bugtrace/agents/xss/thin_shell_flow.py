"""
Thin shell adapters and remaining medium helpers for XSSAgent.

Extracted so xss_agent.py stays <=1500 LOC (agent-workable hard max).
"""
from __future__ import annotations

# --- shell runtime deps (mixin methods used these from xss_agent module scope) ---
import asyncio
import aiohttp
import json
import re
import urllib.parse
import html as html_module
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch
from bugtrace.tools.external import external_tools
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.types import XSSFinding, InjectionContext, ValidationMethod
from bugtrace.agents.xss.constants import (
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
)
from bugtrace.agents.xss.finding_builder import (
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
    bypass_try_char_obfuscation as _pure_bypass_try_char_obfuscation,
    bypass_try_context_specific as _pure_bypass_try_context_specific,
)
from bugtrace.agents.xss.reporting import (
    save_phase1_report as _pure_save_phase1_report,
    save_phase3_report as _pure_save_phase3_report,
    save_phase4_report as _pure_save_phase4_report,
)
logger = get_logger(__name__)
from bugtrace.agents.xss.shell_constants import (
    _BROWSER_ONLY_CONTEXTS,
    _CDP_PROOF_LOCK,
    _L05_CHAR_PROBE,
    _LEGACY_PROBE_MARKER,
    _PROBE_NO_REFLECTION,
    _PROBE_NO_RESPONSE,
    _PROBE_REFLECTED,
    _REDIRECT_PARAM_SET,
    _REFLECTION_SNIPPET_RADIUS,
)
from bugtrace.agents.xss.context_reflection import as_context_set as _as_context_set
# --- end shell runtime deps ---

class XSSThinShellMixin:
    def _save_phase1_report(
        self,
        report_dir: Path,
        param: str,
        payloads: List[str],
        result: "FuzzResult"
    ) -> None:
        """Save Phase 1 bombardment report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase1_report."""
        _pure_save_phase1_report(report_dir, self.url, param, payloads, result)

    def _save_phase3_report(
        self,
        report_dir: Path,
        param: str,
        payloads: List[str],
        result: "FuzzResult"
    ) -> None:
        """Save Phase 3 amplification report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase3_report."""
        _pure_save_phase3_report(report_dir, self.url, param, payloads, result)

    def _save_phase4_report(
        self,
        report_dir: Path,
        finding: Optional[XSSFinding],
        validation_method: str
    ) -> None:
        """Save Phase 4 validation report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase4_report."""
        exploit_url_fallback = ""
        if finding:
            exploit_url_fallback = self._build_attack_url(finding.parameter, finding.payload)
        _pure_save_phase4_report(report_dir, finding, validation_method, exploit_url_fallback)

    def _prioritize_contexts(self, contexts: list) -> InjectionContext:
        """Select most dangerous context."""
        if not contexts:
            return InjectionContext(type="unknown", code_snippet="Context could not be automatically determined.")
        priority = ["script", "event_handler", "javascript_string", "url_href", "url_src",
                    "html_attribute", "html_body", "html_comment"]
        for p_ctx in priority:
            for ctx_type, snippet in contexts:
                if ctx_type == p_ctx:
                    return InjectionContext(type=ctx_type, code_snippet=snippet)
        return InjectionContext(type=contexts[0][0], code_snippet=contexts[0][1])

    def prepare_payload(self, payload: str, context: str) -> str:
        """
        TASK-54: Prepare payload with appropriate encoding based on context.
        Ensures payloads are properly encoded to avoid false negatives.
        """
        if context in ("url_href", "url_src"):
            return self._encode_for_url(payload)
        if context == "html_attribute":
            return self._encode_for_html_attribute(payload)
        if context == "javascript_string":
            return self._encode_for_js_string(payload)
        if context == "script":
            return self._encode_for_script(payload)
        # html_body or unknown - return as-is
        return payload

    def get_payloads_for_context(self, context: str, interactsh_url: str) -> List[str]:
        """
        TASK-54: Get context-specific payloads for more effective testing.
        """
        payload_map = self._get_context_payload_map()

        # Map URL contexts to single key
        if context in ("url_href", "url_src"):
            context = "url_context"

        # Get context-specific payloads or fallback to golden set
        base_payloads = payload_map.get(context, self.GOLDEN_PAYLOADS[:5])

        return self._replace_interactsh_placeholder(base_payloads, interactsh_url)

    def generate_verification_methods(self, url, param, context, payload) -> List[Dict]:
        """Pure owner: xss.policy.generate_verification_methods."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.generate_verification_methods(
            url,
            param,
            context,
            payload,
            build_url=self.build_exploit_url,
        )

    def _should_stop_testing(self, payload: str, evidence: Dict, successful_count: int) -> Tuple[bool, str]:
        """Victory hierarchy stop gate (policy pure + max-impact flag shell)."""
        from bugtrace.agents.xss import policy as _pol

        stop, reason, max_impact = _pol.should_stop_testing(
            payload, evidence, successful_count
        )
        if max_impact:
            self._max_impact_achieved = True
        return stop, reason

    def _has_dangerous_unencoded_reflection(self, evidence: Dict, finding_data: Dict) -> bool:
        from bugtrace.agents.xss import policy as _pol

        if _pol.has_dangerous_unencoded_reflection(evidence, finding_data):
            logger.info(
                f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Unencoded reflection - Context: "
                f"{finding_data.get('reflection_context')})"
            )
            return True
        return False

    def _record_bypass_result(self, payload: str, success: bool):
        """Record bypass result for Q-Learning feedback.
        Uses pure detection, then calls strategy_router for side-effect."""
        if not self._detected_waf:
            return

        try:
            encoding_used = _pure_detect_payload_encoding(payload)
            strategy_router.record_result(self._detected_waf, encoding_used, success)
            logger.debug(f"[{self.name}] Recorded bypass: {self._detected_waf}/{encoding_used} = {'SUCCESS' if success else 'FAIL'}")
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to record bypass: {e}")

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        seen, dry_list = set(), []
        for f in wet_findings:
            _ev = f.get("evidence") or {}
            fp = self._generate_xss_fingerprint(
                f.get("url",""), f.get("parameter",""), f.get("context","html"),
                sink=_ev.get("sink"), source=_ev.get("source")
            )
            if fp not in seen:
                seen.add(fp)
                dry_list.append(f)
        return dry_list

    def _cov_level(self, level: str, reflected: Optional[int] = None,
                   confirmed: bool = False, contexts: Optional[Iterable[str]] = None,
                   final_context: Optional[str] = None, note: str = "") -> None:
        """Record that a rung RAN, with what it measured."""
        if getattr(self, "_xss_cov", None) is None:
            return
        cov = xss_coverage.with_level(
            self._xss_cov, level, reflected=reflected, confirmed=confirmed, note=note
        )
        cov = xss_coverage.with_contexts(cov, contexts)
        if final_context and final_context not in ("unknown", "none", "blocked"):
            cov = xss_coverage.with_final_context(cov, final_context)
        self._xss_cov = cov

    async def _ensure_go_bridge(self) -> bool:
        """Lazy-initialize Go bridge for L2 acceleration. Returns True if available."""
        if self._go_bridge:
            return True
        try:
            concurrency = 50 if not self._detected_waf else 10
            timeout = 5 if not self._detected_waf else 10
            self._go_bridge = GoFuzzerBridge(concurrency=concurrency, timeout=timeout)
            await self._go_bridge.compile_if_needed()
            logger.info(f"[{self.name}] Go bridge initialized for L2 (concurrency={concurrency})")
            return True
        except Exception as e:
            logger.info(f"[{self.name}] Go bridge unavailable, using Python fallback: {e}")
            self._go_bridge = None
            return False

    def _payload_carries_oob(self, payload: str) -> bool:
        """True if a payload embeds this scan's Interactsh callback host/correlation id.

        OOB payloads carry a ``{id}.{server}`` URL (e.g. abc123.oast.fun) — the
        literal word "interactsh" NEVER appears, so attribution must match the
        real OAST host or correlation id, not the substring "interactsh".
        """
        if not payload or not self.interactsh:
            return False
        p = payload.lower()
        host = (getattr(self.interactsh, "server", "") or "").lower()
        cid = (getattr(self.interactsh, "correlation_id", "") or "").lower()
        return bool((host and host in p) or (cid and cid in p))

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
            "findings_confirmed": len(self.findings),
        }

    def _payload_check_early_stop(
        self,
        reflected_payload: str,
        evidence: Dict,
        successful_count: int
    ) -> bool:
        """Check if testing should stop early after successful payload."""
        should_stop, stop_reason = self._should_stop_testing(
            reflected_payload, evidence, successful_count
        )
        return should_stop

    def _payload_build_final_finding(
        self,
        param: str,
        best_state: Dict,
        reflection_type: str,
        surviving_chars: str,
        successful_payloads: List[str],
        injection_ctx: Any
    ) -> XSSFinding:
        """Build final XSS finding from successful payloads."""
        return self._create_xss_finding(
            param, best_state["payload"], best_state["finding_data"].get("context", "hybrid_payload"),
            "interactsh", best_state["evidence"], 1.0,
            reflection_type, surviving_chars, successful_payloads,
            injection_ctx, "hybrid_optimized",
            "Hybrid strategy found a working payload from known patterns."
        )

    def _llm_prepare_finding_data(
        self,
        evidence: Dict,
        llm_response: Dict,
        reflection_type: str
    ) -> Dict:
        """Prepare finding data from LLM response."""
        return {
            "evidence": evidence,
            "screenshot_path": evidence.get("screenshot_path"),
            "context": llm_response.get("context", "unknown"),
            "reflection_context": reflection_type
        }

    def _bypass_prepare_finding_data(
        self,
        evidence: Dict,
        bypass_response: Dict,
        reflection_type: str
    ) -> Dict:
        """Prepare finding data from bypass response."""
        return {
            "evidence": evidence,
            "screenshot_path": evidence.get("screenshot_path"),
            "context": bypass_response.get("strategy", "bypass"),
            "reflection_context": reflection_type
        }

    def _analyze_reflection_context(
        self, html: str, probe_prefix: str, marker: Optional[str] = None
    ) -> Dict:
        """Analyze WHERE a probe reflected in `html`.

        Canonical pure implementation: ``bugtrace.agents.xss.context_reflection``.
        Marker default remains LEGACY BT7331 (not probe_prefix) so payload-as-prefix
        call sites do not silently lose reflections.
        """
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.analyze_reflection_contexts(html, probe_prefix, marker=marker)

    async def _dom_call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call LLM for DOM analysis."""
        return await llm_client.generate(
            prompt=user_prompt,
            module_name="XSS_SMART_ANALYSIS",
            system_prompt=system_prompt,
            model_override=settings.MUTATION_MODEL,
            max_tokens=4000,
            temperature=0.3
        )

    def _analyze_build_system_prompt(self, interactsh_url: str, context_str: str) -> str:
        """Pure owner: xss.llm_payloads.build_analysis_system_prompt."""
        from bugtrace.agents.xss.llm_payloads import build_analysis_system_prompt

        return build_analysis_system_prompt(
            interactsh_url,
            context_str,
            getattr(self, "PROBE_STRING", "BT7331\"<>&"),
            system_prompt_override=getattr(self, "system_prompt", None) or None,
        )

    def _update_block_counter(self, status_code: int) -> None:
        """Update consecutive block counter based on response status."""
        if status_code == 200:
            if self.consecutive_blocks > 0:
                logger.info(f"[{self.name}] Target responded 200. Recovering...")
            self.consecutive_blocks = 0
            return

        if status_code in [403, 406, 501]:
            self.consecutive_blocks += 1
            logger.warning(f"[{self.name}] Potential WAF Block ({status_code}). Counter: {self.consecutive_blocks}")

    async def _fast_reflection_check(self, url: str, param: str, payloads: List[str]) -> List[Dict]:
        """
        Use Go fuzzer if available, otherwise fall back to Python.
        Returns list of reflection objects: [{"payload": "...", "encoded": False, "context": "..."}]
        """
        # Try Go fuzzer first
        go_result = await external_tools.run_go_xss_fuzzer(url, param, payloads)
        
        if go_result and go_result.get("reflections"):
            duration = go_result.get("metadata", {}).get("duration_ms", 0)
            logger.info(f"[{self.name}] Go fuzzer found {len(go_result['reflections'])} reflections in {duration}ms")
            return go_result["reflections"]
        
        # Fallback to Python (simulating reflection objects)
        reflected_payloads = await self._python_reflection_check(url, param, payloads)
        return [{"payload": p, "encoded": False, "context": "unknown"} for p in reflected_payloads]

    async def _python_reflection_check(self, url: str, param: str, payloads: List[str]) -> List[str]:
        """
        Fallback reflection check using Python aiohttp.
        """
        reflected = []
        for p in payloads:
            html = await self._send_payload(param, p)
            if p in html:
                reflected.append(p)
        return reflected

    def _check_reflection(self, payload: str, response_html: str, evidence: Dict) -> bool:
        """Check if payload is reflected in response. Pure owner: xss.reflection."""
        from bugtrace.agents.xss import reflection as _refl

        hit = _refl.check_reflection(
            payload, response_html, evidence, agent_name=self.name
        )
        if hit:
            dashboard.log(
                f"[{self.name}] 🔍 Reflection detected (possibly decoded).",
                "INFO",
            )
        return hit

    def _post_build_finding(
        self,
        form_action: str,
        param: str,
        payload: str,
        evidence: Dict
    ) -> XSSFinding:
        """Pure owner: xss.forms.build_post_finding."""
        from bugtrace.agents.xss.forms import build_post_finding

        return build_post_finding(form_action, param, payload, evidence)

    async def _fetch_page_forms(self, url: str) -> Optional[str]:
        """Fetch page HTML for form discovery."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.STANDARD) as session:
                async with session.get(url, headers=headers, ssl=False) as resp:
                    return await resp.text()
        except Exception as e:
            logger.warning(f"Failed to fetch page for form discovery: {e}")
            return None

    async def _handle_no_execution(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle no execution scenario."""
        logger.info("[XSSAgent] No execution, trying different technique")
        llm_result = await self._llm_generate_bypass(
            original,
            feedback.reflected_portion or "",
            self.interactsh.get_url("xss_agent_bypass") if self.interactsh else ""
        )
        if llm_result:
            return llm_result.get('payload'), "llm_alternative"
        return None, "llm_alternative"

    async def _generate_llm_fallback_variant(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Generate variant using LLM fallback."""
        logger.info("[XSSAgent] Falling back to LLM generation")
        llm_result = await self._llm_generate_bypass(
            original,
            feedback.reflected_portion or "",
            self.interactsh.get_url("xss_agent_fallback") if self.interactsh else ""
        )
        if llm_result:
            return llm_result.get('payload'), "llm_fallback"
        return None, "llm_fallback"

    def _bypass_try_char_obfuscation(
        self,
        stripped_chars: str,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate bypass variant using character obfuscation.
        Delegates to bugtrace.agents.xss.waf.bypass_try_char_obfuscation."""
        if not stripped_chars:
            return None
        logger.info(f"[XSSAgent] Characters filtered ({stripped_chars}), using obfuscation...")
        variant, _ = _pure_bypass_try_char_obfuscation(stripped_chars, tried_variants)
        if variant:
            logger.info(f"[XSSAgent] Generated obfuscation variant: {variant[:80]}...")
        return variant

    def _bypass_try_context_specific(
        self,
        detected_context: str,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate bypass variant based on detected HTML context.
        Delegates to bugtrace.agents.xss.waf.bypass_try_context_specific."""
        if not detected_context:
            return None
        variant, _ = _pure_bypass_try_context_specific(detected_context, tried_variants)
        if variant:
            logger.info(f"[XSSAgent] Generated context-specific variant: {variant[:80]}...")
        return variant

