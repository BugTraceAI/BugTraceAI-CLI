"""
Validation Core

PURE functions for validation strategy selection, evidence scoring,
CDP result analysis, prompt templates, and finding filtering.

Extracted from agentic_validator.py for modularity.
"""

import asyncio
import hashlib
import json
import re
from typing import Dict, List, Any, Tuple, Optional, Set
from pathlib import Path
from collections import OrderedDict
from dataclasses import dataclass, field
from loguru import logger
from urllib.parse import urlparse, parse_qs, urlencode


# =========================================================================
# VALIDATION RESULT CACHE (LRU)
# =========================================================================

@dataclass
class ValidationCache:
    """LRU Cache for validation results to avoid re-validating identical payloads."""
    max_size: int = 100
    _cache: OrderedDict = field(default_factory=OrderedDict)

    def get_key(self, url: str, payload: str) -> str:  # PURE
        """Generate cache key from full URL + payload hash."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params.items()), doseq=True) if params else ""
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sorted_query}" if sorted_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        content = f"{normalized_url}:{payload or 'none'}"
        return hashlib.md5(content.encode()).hexdigest()

    def get(self, url: str, payload: str) -> Optional[Dict]:  # PURE
        """Get cached result if exists."""
        key = self.get_key(url, payload)
        if key in self._cache:
            self._cache.move_to_end(key)
            logger.debug(f"Cache HIT for {url[:50]}...")
            return self._cache[key]
        return None

    def set(self, url: str, payload: str, result: Dict):  # PURE
        """Cache a validation result."""
        key = self.get_key(url, payload)
        self._cache[key] = result
        self._cache.move_to_end(key)
        while len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def clear(self):  # PURE
        self._cache.clear()

    def __len__(self):  # PURE
        return len(self._cache)


# =========================================================================
# VERIFIER POOL
# =========================================================================

class VerifierPool:
    """Pool of XSSVerifier instances to avoid recreation overhead."""

    def __init__(self, pool_size: int = 3):
        self.pool_size = pool_size
        self._verifiers: List = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._initialized = False

    async def initialize(self):  # I/O
        """Initialize verifier pool (lazy init)."""
        if self._initialized:
            return
        from bugtrace.tools.visual.verifier import XSSVerifier
        from bugtrace.core.config import settings
        self._semaphore = asyncio.Semaphore(self.pool_size)
        self._verifiers = [
            XSSVerifier(headless=settings.HEADLESS_BROWSER, prefer_cdp=True)
            for _ in range(self.pool_size)
        ]
        self._initialized = True
        logger.info(f"VerifierPool initialized with {self.pool_size} instances")

    async def get_verifier(self):  # I/O
        """Get an available verifier from the pool."""
        if not self._initialized:
            await self.initialize()
        await self._semaphore.acquire()
        return self._verifiers[0]

    def release(self):  # I/O
        """Release verifier back to pool."""
        if self._semaphore:
            self._semaphore.release()


# =========================================================================
# PROMPT TEMPLATES
# =========================================================================

XSS_PROMPT = """You are a security expert analyzing a screenshot for XSS vulnerability validation.

CONTEXT:
- BugTraceAI security scanner found a potential XSS vulnerability
- We injected a test payload that creates a visual banner or triggers an alert
- Our payloads create text containing: "HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED", or trigger alert dialogs

TASK:
Look at this screenshot and determine if the XSS was successful.

SUCCESS indicators (HIGH CONFIDENCE - mark success=true):
1. ANY text containing "HACKED", "BUGTRACEAI", "BUGTRACE", "PWNED", "XSS" appearing on the page (banner, div, any element)
2. A browser alert/confirm/prompt dialog box (usually a small popup with OK button)
3. Red or colored banner at top/bottom of page with security-related text
4. Text like "FRAGMENT XSS" or "MXSS DETECTED" visible anywhere

MEDIUM CONFIDENCE indicators (mark success=true, confidence=0.7):
1. Unusual HTML elements that look injected (e.g., floating divs, unexpected banners)
2. JavaScript code visible as rendered content (not escaped)
3. Page layout disruption suggesting DOM manipulation

FAILURE indicators (mark success=false):
1. Normal page content with no abnormalities
2. Error message like "Invalid input" or "Not found"
3. The payload is visible as escaped text (e.g., "&lt;script&gt;" shown literally)
4. WAF/security block page ("Request blocked", "Forbidden")

IMPORTANT: If you see ANY text containing "HACKED" or "BUGTRACEAI" or "XSS" that wasn't part of the original page content, this is SUCCESS - our payload executed.

Respond in JSON format:
{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence": "description of what you see that proves/disproves XSS",
    "recommendation": "next steps if any"
}"""

SQLI_PROMPT = """You are a security expert analyzing a screenshot for SQL Injection validation.

CONTEXT:
- A security scanner found a potential SQL Injection vulnerability
- We injected a test payload into the page
- Look for signs of SQL error messages or data exfiltration

SUCCESS indicators:
1. SQL error messages (MySQL, PostgreSQL, MSSQL syntax errors)
2. Database version disclosure
3. Unexpected data being displayed
4. "You have an error in your SQL syntax" message
5. Column/table names visible in error

FAILURE indicators:
1. Normal page with expected content
2. Generic "Invalid input" error (input validation, not SQLi)
3. WAF block page
4. HTTP 500 with no SQL-related info

Respond in JSON format:
{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence": "description of what you see",
    "sql_error_type": "MySQL/PostgreSQL/MSSQL/None",
    "recommendation": "next steps"
}"""

CSTI_PROMPT = """You are a security expert analyzing a screenshot for Template Injection validation.

CONTEXT:
- We injected a template payload like `{{7*7}}` or `{{111111+111111}}`
- We expect the server or client-side engine (Angular, Vue, Jinja2) to evaluate this math
- Seeing "49" or "222222" is proof of vulnerability

SUCCESS indicators (HIGH CONFIDENCE):
1. The number "49" is visible where the payload was injected (arithmetic evaluation)
2. The number "111111" etc. if other math was used
3. Text like "Config", "Smarty", "class 'os'" if object printing was used
4. "uid=..." or system command output (rare for visual)
5. Angular bindings visible (e.g., `ng-bind` attributes not rendered correctly, or successful interpolation)

FAILURE indicators:
1. The literal text `{{7*7}}` is displayed (means it was reflected but NOT evaluated)
2. Normal page content without numbers
3. "Invalid input" error
4. WAF Block Page

Respond in JSON (same format)."""

GENERAL_PROMPT = """You are a security expert analyzing a screenshot for vulnerability validation.

Examine the screenshot and determine if there are any signs of:
1. Security vulnerability exploitation
2. Error messages revealing sensitive information
3. Unexpected behavior that indicates a vulnerability
4. WAF/security tool blocking

Respond in JSON format:
{
    "anomaly_detected": true/false,
    "confidence": 0.0-1.0,
    "description": "what you observe",
    "security_implications": "potential impact if any"
}"""


# =========================================================================
# PURE FUNCTIONS
# =========================================================================

def detect_vuln_type(finding: Dict[str, Any]) -> str:  # PURE
    """Detect vulnerability type from finding data."""
    title = finding.get("title", "").upper()
    vuln_type = finding.get("type", "").upper()

    if "XSS" in title or "XSS" in vuln_type or "CROSS-SITE" in title:
        return "xss"
    elif "SQL" in title or "SQLI" in vuln_type:
        return "sqli"
    elif "CSTI" in title or "CSTI" in vuln_type or "TEMPLATE" in title or "SSTI" in vuln_type:
        return "csti"
    else:
        return "general"


def check_logs_for_execution(logs: List[str], vuln_type: str) -> bool:  # PURE
    """Check browser logs for successful exploitation indicators."""
    if not logs:
        return False

    success_markers = {
        "xss": ["alert", "prompt", "confirm", "XSS", "HACKED", "fetch"],
        "sqli": ["SQL syntax", "mysql_", "ORA-"],
        "lfi": ["root:x:0:0", "daemon:x:1:1"],
        "csti": ["49", "7777777"]
    }

    markers = success_markers.get(vuln_type.lower(), [])

    for log in logs:
        if any(marker in str(log) for marker in markers):
            return True

    return False


def parse_vision_response(response: str) -> Dict[str, Any]:  # PURE
    """Parse the JSON response from vision model."""
    try:
        start = response.find('{')
        end = response.rfind('}')
        if start != -1 and end != -1:
            json_str = response[start:end+1]
            json_str = json_str.strip('`').strip()
            data = json.loads(json_str)
            if 'success' not in data and 'validated' in data:
                data['success'] = data['validated']
            if 'evidence' not in data and 'description' in data:
                data['evidence'] = data['description']
            return data
    except Exception as e:
        logger.debug(f"JSON parsing failed: {e}")

    # Fallback: Parse as text
    positive = ["confirmed", "validated", "execution detected", "payload successful"]
    response_lower = response.lower()

    if '"success": false' in response_lower or '"validated": false' in response_lower:
        return {"success": False, "confidence": 1.0, "evidence": response[:500]}

    is_success = any(p in response_lower for p in positive)
    if '"success": true' in response_lower or '"validated": true' in response_lower:
        is_success = True

    return {
        "success": is_success,
        "confidence": 0.5 if is_success else 0.0,
        "evidence": response[:500]
    }


def validate_alert_impact(alert_message: str, target_url: str) -> Dict[str, str]:  # PURE
    """
    Validate the impact of an alert() call.
    Aligns with BugTraceAI V5 Impact Scoring.
    """
    parsed_url = urlparse(target_url)
    target_domain = parsed_url.netloc

    if alert_message == target_domain or alert_message in target_url:
        return {"impact": "HIGH", "reason": "Execution on TARGET domain confirmed (Impact: Session/CSRF)"}

    if "localhost" in alert_message or "127.0.0.1" in alert_message:
        return {"impact": "MEDIUM", "reason": "Execution confirmed but limited to local/loopback environment"}

    sandbox_indicators = [".googleusercontent.com", "sandbox", "null", "undefined"]
    for indicator in sandbox_indicators:
        if indicator in alert_message.lower():
            return {"impact": "LOW", "reason": f"Execution restricted to sandboxed environment ({indicator})"}

    if alert_message == "1" or alert_message == "undefined":
        return {"impact": "MEDIUM", "reason": "Execution confirmed with generic marker (Identity of domain unconfirmed)"}

    return {"impact": "MEDIUM", "reason": f"Execution confirmed with message: {alert_message}"}


def construct_payload_url(url: str, payload: Optional[str], param: Optional[str] = None) -> str:  # PURE
    """Construct URL with payload injected."""
    if not payload or payload in url:
        return url

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if param:
        qs[param] = [payload]
    elif parsed.query:
        for k in qs:
            qs[k] = payload
    else:
        return url

    new_query = urlencode(qs, doseq=True)
    return parsed._replace(query=new_query).geturl()


def generate_structural_key(vuln_type: str, url: str, parameter: str) -> str:  # PURE
    """
    Generate a structural key for deduplication.
    Format: VULN_TYPE:HOST:PATH:PARAMETER
    """
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        host = parsed.netloc
        param_lower = parameter.lower()

        if any(p in param_lower for p in ["cookie", "header", "user-agent", "referer", "bearer", "authorization"]):
            path = "*GLOBAL*"

        return f"{vuln_type.upper()}:{host}:{path}:{param_lower}"
    except Exception:
        return f"{vuln_type.upper()}:unknown:unknown:{parameter.lower()}"


def generate_manual_review_brief(
    finding: Dict, vision_result: Dict, browser_logs: List
) -> str:  # PURE
    """Constructs a detailed explanation for manual triagers."""
    url = finding.get("url", "N/A")
    param = finding.get("parameter", "N/A")
    payload = finding.get("payload", "N/A")
    vision_evidence = vision_result.get("evidence", "No evidence provided by vision model.")
    confidence = vision_result.get("confidence", 0.0)

    brief = [
        "### DETAILED MANUAL REVIEW BRIEF",
        f"**Target:** {url}",
        f"**Parameter:** `{param}`",
        f"**Payload:** `{payload}`",
        "",
        "#### HUNTER OBSERVATIONS",
        "- Reflection detected in raw HTML (possible decoded or mutated form).",
        "- WAF presence suspected or bypass attempts initiated.",
        "",
        "#### AUDITOR (AGENTIC) AUDIT",
        f"- **Vision Confidence:** {confidence:.0%}",
        f"- **Execution Events (CDP):** {'None' if not browser_logs else f'Detected {len(browser_logs)} events'}",
        f"- **Vision Analysis:** {vision_evidence}",
        "",
        "#### WHAT TO LOOK FOR (MANUAL CHECK)",
        "1. Open the target URL with the payload.",
        "2. Check if a **RED BANNER** with text **'HACKED BY BUGTRACEAI'** appears at the top.",
        "3. Check the Browser Console for successful `fetch` requests or execution logs.",
        "",
        "#### WHY MANUAL REVIEW?",
        "Automatic validation is inconclusive because " +
        ("the Vision AI detected a potential anomaly but no low-level protocol event (like an alert) was captured." if confidence >= 0.7
         else "there is a strong indicator of vulnerability (reflection) but visual proof is obscured or non-standard.")
    ]
    return "\n".join(brief)


def check_sql_errors(content: str) -> Optional[str]:  # PURE
    """Check page content for SQL error indicators. Returns error name if found."""
    sql_errors = [
        "SQL syntax",
        "mysql_",
        "ORA-",
        "PostgreSQL",
        "SQLITE_ERROR",
        "Microsoft SQL Server"
    ]

    content_lower = content.lower()
    for error in sql_errors:
        if error.lower() in content_lower:
            return error
    return None


def batch_filter_findings(
    findings: List[Dict[str, Any]],
) -> Tuple[List, List, List]:  # PURE
    """Filter findings into pre-validated, skipped, and needs validation."""
    pre_validated = []
    needs_validation = []
    skipped = []

    for finding in findings:
        if finding.get("validated") or finding.get("status") == "VALIDATED_CONFIRMED":
            pre_validated.append(finding)
            continue

        severity = finding.get("severity", "").upper()
        if severity in ["INFO", "SAFE", "INFORMATIONAL"]:
            skipped.append(finding)
            continue

        needs_validation.append(finding)

    return pre_validated, needs_validation, skipped


def select_best_verification_method(
    finding: Dict, url: str
) -> Tuple[str, Optional[str]]:  # PURE
    """Select best verification method from specialist options."""
    preferred = ["console_log", "window_variable", "dom_modification"]
    for p_type in preferred:
        for m in finding.get("verification_methods", []):
            if m.get("type") == p_type and m.get("url_encoded"):
                logger.info(f"Using specialized verification method: {p_type}")
                return m.get("url_encoded"), None
    return url, finding.get("payload")


def load_prompts(system_prompt: Optional[str] = None) -> Dict[str, str]:  # PURE
    """Load specialized prompts for different vulnerability types."""
    prompts = {
        "xss": XSS_PROMPT,
        "sqli": SQLI_PROMPT,
        "csti": CSTI_PROMPT,
        "general": GENERAL_PROMPT,
    }

    if system_prompt:
        parts = re.split(r'#+\s+', system_prompt)
        for part in parts:
            part_lower = part.lower()
            if part_lower.startswith("xss validation prompt"):
                prompts["xss"] = re.sub(r'^xss validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            elif part_lower.startswith("sqli validation prompt"):
                prompts["sqli"] = re.sub(r'^sqli validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            elif part_lower.startswith("csti/ssti validation prompt"):
                prompts["csti"] = re.sub(r'^csti/ssti validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            elif part_lower.startswith("general validation prompt"):
                prompts["general"] = re.sub(r'^general validation prompt\s*', '', part, flags=re.IGNORECASE).strip()

    return prompts
