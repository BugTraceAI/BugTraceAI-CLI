"""Pure XSS agent policy helpers (victory hierarchy, fingerprint, gates).

P4-XSS-11: extracted from ``xss_agent`` so offline tests freeze stop/find/
fingerprint contracts without agent I/O. Agent methods become thin adapters
(side effects like ``_max_impact_achieved`` and logging stay in the shell).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from bugtrace.agents.openredirect_payloads import REDIRECT_PARAMS
from bugtrace.agents.xss.context_reflection import as_context_set

# Browser-only: confirmed only via real click / DOM execution (auto-escalate L5/L6).
BROWSER_ONLY_CONTEXTS = frozenset({"href", "url_context", "dom_xss", "js_url"})
# len>=3 drops noisy 1-2 char redirect params that over-escalate common names.
REDIRECT_PARAM_SET = frozenset(p.lower() for p in REDIRECT_PARAMS if len(p) >= 3)


# =============================================================================
# VICTORY HIERARCHY
# =============================================================================

def get_payload_impact_tier(payload: str, evidence: Optional[Dict] = None) -> int:
    """Impact tier of a successful XSS payload.

    3 = MAXIMUM (cookie/domain) · 2 = HIGH (storage/exfil) ·
    1 = MEDIUM (alert/confirm) · 0 = LOW (reflection only)
    """
    payload_lower = payload.lower()
    evidence_str = str(evidence or {}).lower()
    combined = payload_lower + " " + evidence_str

    if any(ind in combined for ind in ("document.cookie", "document.domain")):
        return 3
    if any(
        ind in combined
        for ind in ("localstorage", "sessionstorage", "fetch(", "xmlhttprequest")
    ):
        return 2
    if any(
        ind in combined for ind in ("alert(", "confirm(", "prompt(", "eval(")
    ):
        return 1
    return 0


def should_stop_testing(
    payload: str, evidence: Dict, successful_count: int
) -> Tuple[bool, str, bool]:
    """Victory hierarchy stop gate.

    Returns ``(should_stop, reason, max_impact_achieved)``.
    The third flag lets the agent shell set ``_max_impact_achieved``.
    """
    impact_tier = get_payload_impact_tier(payload, evidence)

    if impact_tier >= 3:
        return True, "🏆 MAXIMUM IMPACT: Cookie/Domain access achieved", True
    if impact_tier >= 2:
        return True, "🏆 HIGH IMPACT: Data exfiltration capability confirmed", True
    if impact_tier >= 1 and successful_count >= 1:
        return True, "✅ Execution confirmed, escalation attempted", False
    if successful_count >= 2:
        return True, "⚡ 2 successful payloads found, moving on", False
    return False, "", False


# =============================================================================
# FINGERPRINT / ROOT CAUSE
# =============================================================================

def detect_xss_root_cause(
    url: str,
    parameter: str,
    context: str,
    sink: Optional[str] = None,
    source: Optional[str] = None,
) -> Optional[str]:
    """Global DOM-XSS root-cause id, or None if URL-specific."""
    if (
        parameter == "postMessage"
        or source == "postMessage"
        or parameter == "window.postMessage"
        or source == "window.postMessage"
    ):
        sink_name = str(sink).lower() if sink else "unknown"
        if "eval" in sink_name:
            return "postMessage_eval_global"
        return f"postMessage_{sink_name}_global"

    if parameter == "location.search" and context == "dom_xss":
        if sink and "document.write" in str(sink).lower():
            return "location_search_docwrite_global"

    return None


def generate_xss_fingerprint(
    url: str,
    parameter: str,
    context: str,
    sink: Optional[str] = None,
    source: Optional[str] = None,
) -> tuple:
    """Dedup fingerprint: global root-cause or (XSS, host, path, param, context)."""
    root_cause = detect_xss_root_cause(
        url, parameter, context, sink=sink, source=source
    )
    parsed = urllib.parse.urlparse(url)
    if root_cause:
        return ("XSS_GLOBAL", parsed.netloc, root_cause, context)

    normalized_path = parsed.path.rstrip("/")
    return ("XSS", parsed.netloc, normalized_path, parameter.lower(), context)


# =============================================================================
# FINDING / VALIDATION GATES
# =============================================================================

def has_interactsh_hit(evidence: Dict) -> bool:
    return bool(evidence.get("interactsh_hit"))


def has_dialog_detected(evidence: Dict) -> bool:
    return bool(evidence.get("dialog_detected") or evidence.get("alert_detected"))


def has_vision_proof(evidence: Dict) -> bool:
    return bool(evidence.get("vision_confirmed"))


def has_dom_mutation_proof(evidence: Dict) -> bool:
    return bool(evidence.get("dom_mutation") or evidence.get("marker_found"))


def has_console_execution_proof(evidence: Dict) -> bool:
    console = evidence.get("console_output")
    return bool(console and "executed" in str(console).lower())


def has_dangerous_unencoded_reflection(
    evidence: Dict, finding_data: Dict
) -> bool:
    dangerous_contexts = ["html_text", "script", "attribute_unquoted", "tag_name"]
    is_bugtrace_payload = "BUGTRACE" in str(finding_data.get("payload", ""))
    return bool(
        evidence.get("unencoded_reflection", False)
        and (
            finding_data.get("reflection_context") in dangerous_contexts
            or is_bugtrace_payload
        )
    )


def has_fragment_xss_with_screenshot(finding_data: Dict) -> bool:
    return (
        finding_data.get("context") == "dom_xss_fragment"
        and bool(finding_data.get("screenshot_path"))
    )


def determine_validation_status(
    test_result: Dict,
    *,
    self_validate: bool = True,
) -> Tuple[str, bool]:
    """Authority gate for VALIDATED_CONFIRMED vs PENDING_VALIDATION."""
    evidence = test_result.get("evidence", {}) or {}
    finding_data = test_result.get("finding_data", test_result) or {}

    if self_validate:
        if has_interactsh_hit(evidence):
            return "VALIDATED_CONFIRMED", True
        if (
            has_dialog_detected(evidence)
            or has_vision_proof(evidence)
            or has_dom_mutation_proof(evidence)
            or has_console_execution_proof(evidence)
            or has_dangerous_unencoded_reflection(evidence, finding_data)
            or has_fragment_xss_with_screenshot(finding_data)
        ):
            return "VALIDATED_CONFIRMED", True
        if evidence.get("http_confirmed") or evidence.get("ai_confirmed"):
            return "VALIDATED_CONFIRMED", True

    return "PENDING_VALIDATION", False


def should_create_finding(test_result: Dict) -> bool:
    """True when evidence is strong enough to emit a finding."""
    evidence = test_result.get("evidence", {}) or {}

    if evidence.get("http_confirmed") or evidence.get("ai_confirmed"):
        return True

    if not any(
        [
            evidence.get("dialog_detected"),
            evidence.get("marker_found"),
            evidence.get("dom_mutation"),
            evidence.get("console_output"),
            evidence.get("interactsh_hit"),
        ]
    ):
        return False

    return True


# =============================================================================
# PAYLOAD / URL HELPERS
# =============================================================================

def clean_payload(payload: str, param: str = "") -> str:
    """Strip LLM/markdown pollution from a payload string."""
    if not payload:
        return ""

    cleaned = payload.strip()
    cleaned = re.sub(
        r"```[a-z]*\n?(.*?)\n?```", r"\1", cleaned, flags=re.DOTALL
    )
    cleaned = cleaned.strip("`")
    cleaned = re.sub(
        r"^(payload|vector|bypass|solution|new payload|\*\*.*?\*\*)\s*:\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    if param:
        param_pattern = re.compile(f"^{re.escape(param)}=", re.IGNORECASE)
        cleaned = param_pattern.sub("", cleaned).strip()
    cleaned = re.sub(r"</?payload>", "", cleaned, flags=re.IGNORECASE)

    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ):
        cleaned = cleaned[1:-1]

    return cleaned


def build_exploit_url(
    url: str, param: str, payload: str, *, encoded: bool = False
) -> str:
    """Build exploit URL with payload in the named query param."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    full_url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, "", new_query, "")
    )
    if not encoded:
        return urllib.parse.unquote(full_url)
    return full_url


def generate_repro_steps(
    url: str, param: str, context: Any, payload: str
) -> List[str]:
    return [
        f"Navigate to {url}",
        f"Inject the payload into parameter '{param}'",
        f"Payload: {payload}",
        "Observe the execution (popup, console log, or page change)",
    ]


def generate_verification_methods(
    url: str,
    param: str,
    context: Any,
    payload: str,
    *,
    build_url=None,
) -> List[Dict]:
    """Verification method menu (console/DOM/window/alert).

    ``build_url`` defaults to :func:`build_exploit_url`.
    """
    if build_url is None:
        build_url = build_exploit_url

    methods: List[Dict] = []
    console_payload = payload.replace("alert(1)", 'console.log("XSS-VERIFIED")').replace(
        "alert('XSS')", 'console.log("XSS-VERIFIED")'
    )
    methods.append(
        {
            "type": "console_log",
            "name": "Console Log (Recommended)",
            "payload": console_payload,
            "url_encoded": build_url(url, param, console_payload, encoded=True),
            "instructions": "Open DevTools (F12) -> Console tab -> Look for 'XSS-VERIFIED'",
            "reliability": "high",
        }
    )
    dom_payload = payload.replace(
        "alert(1)", 'document.body.innerHTML="<h1>XSS-HACKED</h1>"'
    )
    methods.append(
        {
            "type": "dom_modification",
            "name": "DOM Modification",
            "payload": dom_payload,
            "url_encoded": build_url(url, param, dom_payload, encoded=True),
            "instructions": "Page content will be replaced with 'XSS-HACKED'",
            "reliability": "high",
        }
    )
    var_payload = payload.replace("alert(1)", "window.XSS_CONFIRMED=true")
    methods.append(
        {
            "type": "window_variable",
            "name": "Window Variable",
            "payload": var_payload,
            "url_encoded": build_url(url, param, var_payload, encoded=True),
            "instructions": "In console, type: window.XSS_CONFIRMED (should return true)",
            "reliability": "high",
        }
    )
    methods.append(
        {
            "type": "alert",
            "name": "Alert Popup",
            "payload": payload,
            "url_encoded": build_url(url, param, payload, encoded=True),
            "instructions": "Alert popup should appear",
            "reliability": "medium",
            "warning": "May be blocked by modern browsers or extensions",
        }
    )
    return methods


def calculate_confidence(reflection: Any) -> float:
    """Score a reflection object (duck-typed: encoded, context, payload)."""
    confidence = 0.5
    if not getattr(reflection, "encoded", True):
        confidence += 0.3
    ctx = getattr(reflection, "context", "") or ""
    if ctx in ("javascript", "script"):
        confidence += 0.15
    elif ctx in ("event_handler", "attribute_value"):
        confidence += 0.10
    elif ctx in ("html_text", "html_body"):
        confidence += 0.05
    payload = getattr(reflection, "payload", "") or ""
    if "HACKED BY BUGTRACEAI" in payload or "bt-pwn" in payload:
        confidence += 0.05
    return min(confidence, 1.0)


def browser_only_candidate(
    param: str,
    contexts: Union[str, Iterable[str], None],
    reflecting_payloads: list,
    *,
    redirect_params: Optional[Iterable[str]] = None,
    browser_only_contexts: Optional[frozenset] = None,
) -> bool:
    """True when XSS can be confirmed only in a real browser.

    Requires a reflecting payload plus either a redirect/DOM-sink param name
    or any browser-only context in the reflection set.
    """
    if not reflecting_payloads:
        return False
    redirects = (
        REDIRECT_PARAM_SET
        if redirect_params is None
        else frozenset(p.lower() for p in redirect_params if len(p) >= 3)
    )
    only_ctx = (
        BROWSER_ONLY_CONTEXTS
        if browser_only_contexts is None
        else browser_only_contexts
    )
    if (param or "").lower() in redirects:
        return True
    return bool(as_context_set(contexts) & only_ctx)


__all__ = [
    "get_payload_impact_tier",
    "should_stop_testing",
    "detect_xss_root_cause",
    "generate_xss_fingerprint",
    "has_interactsh_hit",
    "has_dialog_detected",
    "has_vision_proof",
    "has_dom_mutation_proof",
    "has_console_execution_proof",
    "has_dangerous_unencoded_reflection",
    "has_fragment_xss_with_screenshot",
    "determine_validation_status",
    "should_create_finding",
    "clean_payload",
    "build_exploit_url",
    "generate_repro_steps",
    "generate_verification_methods",
    "calculate_confidence",
    "browser_only_candidate",
    "BROWSER_ONLY_CONTEXTS",
    "REDIRECT_PARAM_SET",
]
