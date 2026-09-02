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


class XSSAgentEncodeMixin:
    """Encoding / repro / impact helpers."""

    def _encode_for_url(self, payload: str) -> str:
        """URL encode the payload."""
        from urllib.parse import quote
        return quote(payload, safe='')

    def _encode_for_html_attribute(self, payload: str) -> str:
        """HTML entity encode for attribute context."""
        import html
        return html.escape(payload, quote=True)

    def _encode_for_js_string(self, payload: str) -> str:
        """Escape for JavaScript string context."""
        return payload.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

    def _encode_for_script(self, payload: str) -> str:
        """Escape closing script tags."""
        return payload.replace("</script>", "<\\/script>")

    def _replace_interactsh_placeholder(self, payloads: List[str], interactsh_url: str) -> List[str]:
        """Replace interactsh placeholder in all payloads."""
        return [p.replace("{{interactsh_url}}", interactsh_url) for p in payloads]

    def build_exploit_url(self, url: str, param: str, payload: str, encoded: bool = False) -> str:
        """Pure owner: xss.policy.build_exploit_url."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.build_exploit_url(url, param, payload, encoded=encoded)

    def get_verification_warnings(self, context) -> List[str]:
        return ["alert() may be blocked by modern browsers", "Extensions like NoScript may block execution"]

    def generate_repro_steps(self, url, param, context, payload) -> List[str]:
        """Pure owner: xss.policy.generate_repro_steps."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.generate_repro_steps(url, param, context, payload)

    def _get_payload_impact_tier(self, payload: str, evidence: Dict = None) -> int:
        """Pure owner: xss.policy.get_payload_impact_tier."""
        from bugtrace.agents.xss import policy as _pol

        return _pol.get_payload_impact_tier(payload, evidence)

    def _has_interactsh_hit(self, evidence: Dict) -> bool:
        from bugtrace.agents.xss import policy as _pol

        if _pol.has_interactsh_hit(evidence):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Interactsh OOB interaction)")
            return True
        return False

    def _encode_stripped_chars(self, payload: str, stripped: List[str]) -> str:
        """Delegates to bugtrace.agents.xss.feedback.encode_stripped_chars."""
        return _pure_encode_stripped_chars(payload, stripped)

