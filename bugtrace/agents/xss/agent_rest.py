"""
XSSAgent V3 - LLM-Driven with Multi-Layer Validation

This is a complete rewrite of the XSS detection agent using:
1. LLM as the brain (analyzes HTML, decides payloads)
2. Interactsh for OOB validation (definitive proof)
3. Vision LLM for visual validation (screenshot analysis)
4. CDP for DOM-based validation (fallback)

Author: BugtraceAI Team
Version: 3.0.0
Date: 2026-01-10
"""

import asyncio
import aiohttp
import json
from typing import Dict, Iterable, List, NamedTuple, Optional, Any, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import Enum
from bisect import bisect_right
from functools import lru_cache
from operator import itemgetter as _itemgetter
import html as html_module
import re
import urllib.parse
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.external import external_tools
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch

# Import worker pool for queue consumption (Phase 19)
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter

# Import framework's WAF intelligence (Q-Learning based)
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

# Import reporting standards for consistent output
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status

# v2.1.0: Import specialist utilities for payload loading from JSON
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data

# v3.2.0: Import TechContextMixin for context-aware XSS detection
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.agents.xss.hybrid_flow import XSSHybridFlowMixin
from bugtrace.agents.xss.pipeline_v2_flow import XSSPipelineV2Mixin
from bugtrace.agents.xss.escalation_flow import XSSEscalationMixin
from bugtrace.agents.xss.dom_stored_flow import XSSDomStoredFlowMixin
from bugtrace.agents.xss.payload_queue_flow import XSSPayloadQueueMixin
from bugtrace.agents.xss.discovery_run_flow import XSSDiscoveryRunMixin
from bugtrace.agents.xss.param_browser_flow import XSSParamBrowserMixin
from bugtrace.agents.xss.llm_misc_flow import XSSLlmMiscMixin
from bugtrace.agents.xss.thin_shell_flow import XSSThinShellMixin

# v3.1.0: Hybrid Engine imports (Go Fuzzer + Payload Amplification)
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection

# v3.3: ManipulatorOrchestrator for Python-only HTTP attack campaigns
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
# Context → breakout table lives in the manipulator (single source of truth); L3 reuses it
# instead of keeping a second copy of the same prefixes here.
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext

# v3.4: Extracted pure modules
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
    bypass_try_waf_encoding as _pure_bypass_try_waf_encoding,
    bypass_try_char_obfuscation as _pure_bypass_try_char_obfuscation,
    bypass_try_context_specific as _pure_bypass_try_context_specific,
    bypass_try_universal_payloads as _pure_bypass_try_universal_payloads,
    generate_bypass_variant as _pure_generate_bypass_variant,
)
from bugtrace.agents.xss.feedback import (
    adapt_to_context as _pure_adapt_to_context,
    extract_js_code as _pure_extract_js_code,
    adapt_for_attribute as _pure_adapt_for_attribute,
    adapt_for_script as _pure_adapt_for_script,
    adapt_for_html as _pure_adapt_for_html,
    adapt_for_comment as _pure_adapt_for_comment,
    adapt_for_style as _pure_adapt_for_style,
    encode_stripped_chars as _pure_encode_stripped_chars,
    generate_csp_bypass_payload as _pure_generate_csp_bypass_payload,
    handle_waf_blocked as _pure_handle_waf_blocked,
    handle_context_mismatch as _pure_handle_context_mismatch,
    handle_encoding_stripped as _pure_handle_encoding_stripped,
    handle_partial_reflection as _pure_handle_partial_reflection,
    handle_csp_blocked as _pure_handle_csp_blocked,
    handle_timing_issue as _pure_handle_timing_issue,
    generate_variant_for_reason as _pure_generate_variant_for_reason,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.reporting import (
    get_snippet as _pure_get_snippet,
    save_phase1_report as _pure_save_phase1_report,
    save_phase2_report as _pure_save_phase2_report,
    save_phase3_report as _pure_save_phase3_report,
    save_phase4_report as _pure_save_phase4_report,
)
# P4-XSS-5: single type owner is package types (no dual class identity).
from bugtrace.agents.xss.types import (
    InjectionContext,
    ValidationMethod,
    XSSFinding,
)

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


# Reuse the OpenRedirect parameter vocabulary (DRY) so browser-only XSS — redirect/DOM-sink
# params like back=javascript:... that fire only on a real click — auto-escalate to the
# browser even at 'standard' scan depth.
from bugtrace.agents.openredirect_payloads import REDIRECT_PARAMS

logger = get_logger("agents.xss_v4")

# Serializes CDP-based proof-screenshot fallbacks. Chrome DevTools Protocol is
# single-threaded, so concurrent CDP captures across parallel XSS agents would
# contend; Playwright captures (the common, multi-threaded path) are unaffected.

# Browser-only XSS candidates can be confirmed ONLY in a real browser (a click / DOM
# execution), never by HTTP reflection — so they auto-escalate to L5/L6 regardless of scan
# depth. A redirect/DOM-sink parameter (value flows into an href/navigation) or a reflection
# that landed in one of these contexts qualifies.
# len>=3 drops noisy 1-2 char entries (u/r/l/q/to/go/rd) that would over-escalate common params.

# The historical hardcoded reflection marker. `_analyze_reflection_context()` searches for
# THIS string unless a caller passes an explicit `marker=`, because four of its six call
# sites pass a full PAYLOAD as `probe_prefix` — see the docstring there.

# How much HTML around the reflection point is handed to the L3 LLM prompt. A window, not a
# budget: too small and the model cannot see the enclosing tag, too large and it pays for
# unrelated markup. The L1 caller truncates the result again to its own limit.

# The L0.5 char-survival probe. Each special char is bracketed by its own marker pair so its
# survival is measured independently of the others. Module-level so the coverage record can
# state WHAT WAS SENT without the caller re-deriving (or drifting from) the literal.
# Format: BT7331A"BT7331B'BT7331C<BT7331D>BT7331E`BT7331F\BT7331G

# What the L0.5 probe observed. "no response" and "responded without the marker" are opposite
# facts — one is a broken/blocked target, the other is a parameter that is simply not
# injectable here — and reflects=False alone cannot tell them apart.


# Pure context-set normaliser: package owner is context_reflection.as_context_set.
from bugtrace.agents.xss.context_reflection import as_context_set as _as_context_set


# InjectionContext / ValidationMethod / XSSFinding: owned by bugtrace.agents.xss.types
# (re-exported above). Do not reintroduce dual class definitions here.


# --- Seed enrichment helpers: pure owner is finding_builder (thin adapters) ---
from bugtrace.agents.xss.finding_builder import (
    SENSITIVE_HEADERS as _SENSITIVE_HEADERS,
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)



# Reflection position / CSP pure block: package owner xss.position (P4-XSS-8).
# Reflection position / CSP pure block lives in xss.position (P4-XSS-8).
# Re-export the full module namespace so smoke_xss_context contracts and
# XSSAgent methods keep resolving symbols on this module.
import bugtrace.agents.xss.position as _xss_position  # noqa: E402

globals().update(
    {
        name: value
        for name, value in vars(_xss_position).items()
        if not name.startswith("__")
    }
)




# Breakout ranking pure block: package owner xss.breakouts (P4-XSS-9).
import bugtrace.agents.xss.breakouts as _xss_breakouts  # noqa: E402

globals().update(
    {
        name: value
        for name, value in vars(_xss_breakouts).items()
        if not name.startswith("__")
    }
)


from bugtrace.agents.base import BaseAgent


class XSSAgentRestMixin:
    """Remaining XSSAgent method surface."""

    def _save_phase2_report(self, report_dir: Path, analysis: Dict) -> None:
        """Save Phase 2 analysis report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase2_report."""
        _pure_save_phase2_report(report_dir, analysis)

    def _get_snippet(self, text: str, target: str, max_len: int = 200) -> str:
        """Extract snippet around the target string.
        Delegates to bugtrace.agents.xss.reporting.get_snippet."""
        return _pure_get_snippet(text, target, max_len)

    def detect_injection_context(self, html: str, probe: str = "USER_INPUT") -> InjectionContext:
        """
        TASK-52: Enhanced context detection with multiple context support.
        Detects where the user input is reflected in multiple possible contexts.
        """
        escaped_probe = re.escape(probe)
        contexts = self._check_contexts(html, probe, escaped_probe)
        return self._prioritize_contexts(contexts)

    def _detect_payload_encoding(self, payload: str) -> str:
        """Detect which encoding technique was used in the payload.
        Delegates to bugtrace.agents.xss.waf.detect_payload_encoding."""
        return _pure_detect_payload_encoding(payload)

    @staticmethod
    def _extract_resource_id(response_text: str) -> Optional[str]:
        """Pure owner: xss.stored.extract_resource_id."""
        from bugtrace.agents.xss.stored import extract_resource_id

        return extract_resource_id(response_text)

    @staticmethod
    def _check_stored_canary(body: str, canary: str, payload: str) -> bool:
        """Pure owner: xss.stored.check_stored_canary."""
        from bugtrace.agents.xss.stored import check_stored_canary

        return check_stored_canary(body, canary, payload)

    def _browser_only_candidate(
        self, param: str, contexts: Union[str, Iterable[str], None], reflecting_payloads: list
    ) -> bool:
        """Pure owner: xss.policy.browser_only_candidate."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.browser_only_candidate(param, contexts, reflecting_payloads)

    def _cov_probe(self, probe: str, reflected: Optional[bool],
                   surviving_chars: Optional[str] = None) -> None:
        """Record a probe string that was SENT and whether its marker came back."""
        if getattr(self, "_xss_cov", None) is not None:
            self._xss_cov = xss_coverage.with_probe(
                self._xss_cov, probe, reflected, surviving_chars
            )

    def _cov_note(self, note: str) -> None:
        """Record a rung that was deliberately NOT run, and why."""
        if getattr(self, "_xss_cov", None) is not None:
            self._xss_cov = xss_coverage.with_note(self._xss_cov, note)

    def _cov_exit(self, reason: str) -> None:
        """Close the open record at a pipeline exit."""
        if getattr(self, "_xss_cov", None) is not None:
            self._xss_cov = xss_coverage.finish(self._xss_cov, reason)

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_xss notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    def _detect_xss_root_cause(self, url: str, parameter: str, context: str,
                               sink: str = None, source: str = None) -> Optional[str]:
        """Pure owner: xss.policy.detect_xss_root_cause."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.detect_xss_root_cause(
            url, parameter, context, sink=sink, source=source
        )

    def _generate_xss_fingerprint(self, url: str, parameter: str, context: str,
                                  sink: str = None, source: str = None) -> tuple:
        """Pure owner: xss.policy.generate_xss_fingerprint."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.generate_xss_fingerprint(
            url, parameter, context, sink=sink, source=source
        )

    async def _payload_run_reflection_checks(
        self,
        param: str,
        hybrid_payloads: List[str],
        interactsh_url: str
    ) -> Optional[List[Dict]]:
        """Prepare payloads and run fast reflection check."""
        valid_payloads = [p.replace("{{interactsh_url}}", interactsh_url) for p in hybrid_payloads]
        return await self._fast_reflection_check(self.url, param, valid_payloads)

    def _clean_payload(self, payload: str, param: str) -> str:
        """Pure owner: xss.policy.clean_payload."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.clean_payload(payload, param)

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL before making requests. (Stability Improvement #3)"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception as e:
            logger.debug(f"_is_valid_url failed: {e}")
            return False

    def _is_waf_blocked(self, html: str) -> bool:
        """Check if response contains WAF block signatures."""
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.is_waf_blocked(html)

    def _reflection_snippet(self, html: str, marker: str) -> str:
        """The HTML immediately around the first reflection of `marker`."""
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.reflection_snippet(html, marker)

    def _find_reflection_contexts(self, html: str, prefix: str) -> List[str]:
        """EVERY HTML context the probe reflected in — text nodes and attributes."""
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.find_reflection_contexts(html, prefix)

    def _context_from_text_node(self, text_node) -> str:
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.context_from_text_node(text_node)

    def _contexts_from_soup_attributes(self, soup, prefix: str) -> List[str]:
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.contexts_from_soup_attributes(soup, prefix)

    def _context_from_attributes(self, html: str, prefix: str) -> str:
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.context_from_attributes(html, prefix)

    def _filter_payloads_by_context(self, payloads: List[str], context: str) -> List[str]:
        """Filter payloads by reflection context (package pure owner)."""
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.filter_payloads_by_context(payloads, context, max_payloads=100)

    def _is_payload_relevant(self, payload: str, context: str) -> bool:
        from bugtrace.agents.xss import context_reflection as _ctx

        return _ctx.is_payload_relevant(payload, context)

    def _is_html_tag_with_breakout(self, payload: str, p_lower: str) -> bool:
        if not payload.startswith("<"):
            return True
        if p_lower.startswith("</script>"):
            return True
        return any(payload.startswith(q) for q in ["'", "\"", "'; ", "\"; "])

    def _is_relevant_for_script_context(self, payload: str, p_lower: str) -> bool:
        return self._is_payload_relevant(payload, "script")

    def _add_safety_net_payloads(self, filtered: List[str], all_payloads: List[str]) -> List[str]:
        """Pure owner: xss.finding_builder.add_safety_net_payloads."""
        from bugtrace.agents.xss.finding_builder import add_safety_net_payloads

        return add_safety_net_payloads(filtered, all_payloads)

    def _analyze_global_context(self, html: str) -> str:
        """Pure owner: xss.dom.analyze_global_context."""
        from bugtrace.agents.xss.dom import analyze_global_context

        return analyze_global_context(html)

    def _dom_build_system_prompt(self) -> str:
        """Pure owner: xss.dom.build_dom_system_prompt."""
        from bugtrace.agents.xss.dom import build_dom_system_prompt

        return build_dom_system_prompt()

    def _dom_log_generated_payloads(self, payloads: List[Dict]):
        """Owner: xss.dom.log_generated_payloads."""
        from bugtrace.agents.xss.dom import log_generated_payloads

        log_generated_payloads(self.name, payloads)

    def _extract_dom_around_reflection(self, html: str, probe: str, context_chars: int = 500) -> str:
        """Pure owner: xss.dom.extract_dom_around_reflection."""
        from bugtrace.agents.xss.dom import extract_dom_around_reflection

        return extract_dom_around_reflection(html, probe, context_chars)

    def _parse_smart_analysis_response(self, response: str, interactsh_url: str) -> List[Dict]:
        """Pure owner: xss.dom.parse_smart_analysis_response."""
        from bugtrace.agents.xss.dom import parse_smart_analysis_response

        return parse_smart_analysis_response(
            response, interactsh_url, clean_payload_fn=self._clean_payload
        )

    def _extract_structured_payloads(self, response: str, interactsh_url: str) -> List[Dict]:
        """Pure owner: xss.dom.extract_structured_payloads."""
        from bugtrace.agents.xss.dom import extract_structured_payloads

        return extract_structured_payloads(
            response, interactsh_url, clean_payload_fn=self._clean_payload
        )

    def _parse_payload_block(self, block: str, interactsh_url: str) -> Optional[Dict]:
        """Pure owner: xss.dom.parse_payload_block."""
        from bugtrace.agents.xss.dom import parse_payload_block

        return parse_payload_block(
            block, interactsh_url, clean_payload_fn=self._clean_payload
        )

    def _replace_callback_urls(self, code: str, interactsh_url: str) -> str:
        """Pure owner: xss.dom.replace_callback_urls."""
        from bugtrace.agents.xss.dom import replace_callback_urls

        return replace_callback_urls(code, interactsh_url)

    def _extract_payloads_by_patterns(self, response: str) -> List[Dict]:
        """Pure owner: xss.dom.extract_payloads_by_patterns."""
        from bugtrace.agents.xss.dom import extract_payloads_by_patterns

        return extract_payloads_by_patterns(
            response, clean_payload_fn=self._clean_payload
        )

    def _analyze_parse_response(self, response: str, param: str) -> Optional[Dict]:
        """Pure owner: xss.llm_payloads.parse_analysis_response."""
        from bugtrace.agents.xss.llm_payloads import parse_analysis_response

        return parse_analysis_response(
            response, param, clean_payload_fn=self._clean_payload
        )

    def _handle_send_error(self) -> None:
        """Handle network error and potentially trigger stealth mode."""
        self.consecutive_blocks += 1
        logger.warning(f"[{self.name}] Network Failure / WAF TCP Reset. Counter: {self.consecutive_blocks}")

        if self.consecutive_blocks >= 3 and not self.stealth_mode:
            self.stealth_mode = True
            dashboard.log(f"[{self.name}] 🛡️ WAF DETECTED! Entering Stealth Mode (Slown-down & Random Delay)", "WARN")
            logger.warning(f"[{self.name}] WAF confirmed via network resets. Enabling Stealth Mode.")

    def _build_attack_url(self, param: str, payload: str) -> str:
        """Pure owner: shared.http_attack.build_attack_url / xss.validation."""
        from bugtrace.agents.shared.http_attack import build_attack_url

        return build_attack_url(self.url, param, payload)

    def _build_vision_prompt(self) -> str:
        """Owner: xss.validation.VISION_PROMPT."""
        from bugtrace.agents.xss.validation import VISION_PROMPT

        return VISION_PROMPT

    def _process_vision_result(self, vision_response: str, evidence: Dict) -> Optional[bool]:
        """Owner: xss.validation.process_vision_result (SI/NO → Optional[bool])."""
        from bugtrace.agents.xss.validation import process_vision_result

        return process_vision_result(vision_response, evidence, agent_name=self.name)

    def _is_executable_in_html_context(self, payload: str, response_html: str) -> bool:
        """Pure owner: xss.reflection.is_executable_in_html_context."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.is_executable_in_html_context(
            payload,
            response_html,
            response_is_xml=bool(getattr(self, "_response_is_xml", False)),
            agent_name=self.name,
        )

    def _is_executable_in_event_handler(self, payload: str, response_html: str) -> bool:
        """Pure owner: xss.reflection.is_executable_in_event_handler."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.is_executable_in_event_handler(
            payload, response_html, agent_name=self.name
        )

    def _is_executable_in_javascript_uri(self, payload: str, response_html: str) -> bool:
        """Pure owner: xss.reflection.is_executable_in_javascript_uri."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.is_executable_in_javascript_uri(
            payload, response_html, agent_name=self.name
        )

    def _is_executable_in_template(self, payload: str, response_html: str) -> bool:
        """Pure owner: xss.reflection.is_executable_in_template."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.is_executable_in_template(payload, response_html)

    def _is_executable_in_js_string_breakout(self, payload: str, response_html: str) -> bool:
        """Pure owner: xss.reflection.is_executable_in_js_string_breakout."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.is_executable_in_js_string_breakout(
            payload, response_html, agent_name=self.name
        )

    def _payload_reflects(self, payload: str, response: str) -> bool:
        """Pure owner: xss.reflection.payload_reflects."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.payload_reflects(payload, response)

    def _detect_execution_context(self, payload: str, response_html: str) -> Optional[str]:
        """Pure owner: xss.reflection.detect_execution_context."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.detect_execution_context(payload, response_html)

    def _requires_browser_validation(self, payload: str, response_html: str) -> bool:
        """Pure owner: xss.reflection.requires_browser_validation."""
        from bugtrace.agents.xss import reflection as _refl

        return _refl.requires_browser_validation(payload, response_html)

    def _fragment_build_url(self, payload: str) -> str:
        """Owner: shared.http_attack.fragment_build_url."""
        from bugtrace.agents.shared.http_attack import fragment_build_url

        return fragment_build_url(self.url, payload)

    def _fragment_build_finding(
        self,
        param: str,
        payload: str,
        result: Any
    ) -> XSSFinding:
        """Pure owner: xss.fragment.build_fragment_finding."""
        from bugtrace.agents.xss.fragment import build_fragment_finding

        return build_fragment_finding(self.url, param, payload, result)

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Pure owner: xss.param_discovery.prioritize_xss_params."""
        from bugtrace.agents.xss.param_discovery import prioritize_xss_params
        from bugtrace.agents.xss.constants import HIGH_PRIORITY_PARAMS as _HIGH_PRIORITY_PARAMS

        return prioritize_xss_params(
            params,
            high_priority_list=_HIGH_PRIORITY_PARAMS,
            agent_name=self.name,
        )

    def _extract_form_data(self, form, base_url: str) -> Tuple[str, Dict[str, str]]:
        """Pure owner: xss.forms.extract_form_data."""
        from bugtrace.agents.xss.forms import extract_form_data

        return extract_form_data(form, base_url)

    async def _handle_waf_blocked(self, original: str) -> Tuple[Optional[str], str]:
        """Handle WAF blocked scenario."""
        logger.info("[XSSAgent] WAF detected, trying encoded variants")
        encoded_variants = await self._get_waf_optimized_payloads([original], max_variants=1)
        if encoded_variants and encoded_variants[0] != original:
            return encoded_variants[0], "waf_bypass"
        return None, "waf_bypass"

    def _handle_context_mismatch(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle context mismatch scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_context_mismatch."""
        logger.info(f"[XSSAgent] Context mismatch, adapting to: {feedback.detected_context}")
        return _pure_handle_context_mismatch(original, feedback.detected_context)

    def _handle_encoding_stripped(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle encoding stripped scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_encoding_stripped."""
        logger.info(f"[XSSAgent] Chars stripped: {feedback.stripped_chars}")
        return _pure_handle_encoding_stripped(original, feedback.stripped_chars)

    def _handle_partial_reflection(self) -> Tuple[str, str]:
        """Handle partial reflection scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_partial_reflection."""
        logger.info("[XSSAgent] Partial reflection, trying simpler payload")
        return _pure_handle_partial_reflection()

    def _handle_csp_blocked(self) -> Tuple[Optional[str], str]:
        """Handle CSP blocked scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_csp_blocked."""
        logger.info("[XSSAgent] CSP blocked, trying CSP bypass")
        return _pure_handle_csp_blocked()

    def _handle_timing_issue(self, original: str) -> Tuple[str, str]:
        """Handle timing issue scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_timing_issue."""
        logger.info("[XSSAgent] Timing issue, adding load event")
        return _pure_handle_timing_issue(original)

    def _extract_js_code(self, payload: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.extract_js_code."""
        return _pure_extract_js_code(payload)

    def _adapt_for_attribute(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_attribute."""
        return _pure_adapt_for_attribute(js_code)

    def _adapt_for_script(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_script."""
        return _pure_adapt_for_script(js_code)

    def _adapt_for_html(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_html."""
        return _pure_adapt_for_html(js_code)

    def _adapt_for_comment(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_comment."""
        return _pure_adapt_for_comment(js_code)

    def _adapt_for_style(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_style."""
        return _pure_adapt_for_style(js_code)

    def _adapt_to_context(self, payload: str, context: Optional[str]) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_to_context."""
        return _pure_adapt_to_context(payload, context)

    def _generate_csp_bypass_payload(self) -> str:
        """Delegates to bugtrace.agents.xss.feedback.generate_csp_bypass_payload."""
        return _pure_generate_csp_bypass_payload()

    def _bypass_try_universal_payloads(
        self,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate universal bypass payloads as fallback.
        Delegates to bugtrace.agents.xss.waf.bypass_try_universal_payloads."""
        variant, _ = _pure_bypass_try_universal_payloads(tried_variants)
        if variant:
            logger.info(f"[XSSAgent] Generated universal variant: {variant[:80]}...")
        return variant

    def _finding_to_dict(self, finding: XSSFinding) -> Dict:
        """Convert finding to dictionary for JSON output.

        Canonical pure serializer lives in ``bugtrace.agents.xss.finding_builder``.
        This method is a thin adapter so live queue/direct paths keep one owner.
        """
        from bugtrace.agents.xss.finding_builder import finding_to_dict as package_finding_to_dict

        return package_finding_to_dict(finding)

