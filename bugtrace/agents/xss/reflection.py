"""Pure reflection and HTTP confirmation analysis for XSS.

Examines HTTP responses to determine if XSS payloads reach an executable
context. No network I/O — only string/HTML analysis plus optional evidence
mutation.

**P4-XSS-10:** this module is the *live* owner of the confirmation gate
(aligned with the position classifier + CSP/content-type rules). The stale
regex-only extract was replaced; ``XSSAgent`` methods are thin adapters that
inject agent state (content-type, CSP header) and stamp repro artifacts.

Public pure surface:
- can_confirm_from_http_response
- is_executable_in_html_context / event_handler / javascript_uri / template
- is_executable_in_js_string_breakout
- payload_reflects / check_reflection
- detect_execution_context
- requires_browser_validation
"""

from __future__ import annotations

import html as html_mod
import re
import urllib.parse
from typing import Dict, Optional

from bugtrace.agents.xss.position import (
    _EXECUTABLE_CONTENT_TYPES,
    _XML_CONTENT_TYPES,
    _attribute_injection_contexts,
    _csp_blocks_inline,
    _document_csp,
    _inline_script_bodies,
    _js_breakout_parses,
    _js_span_escapes,
    _position_executes,
    _reflected_forms,
    _reflection_occurrences,
)
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.xss.reflection")


# =========================================================================
# MAIN CONFIRMATION (PURE)
# =========================================================================

def can_confirm_from_http_response(
    payload: str,
    response_html: str,
    evidence: Dict,
    agent_name: str = "XSSAgent",
    *,
    content_type: str = "",
    csp_header: str = "",
) -> bool:
    """Confirm XSS from HTTP response without browser.

    STRICT: only confirms when the payload lands in a truly executable
    context without being neutered (escaped/encoded).

    ``content_type`` and ``csp_header`` are explicit inputs (formerly agent
    attributes). Does **not** stamp confirming_request — that stays in the
    agent shell (``_stamp_repro``).

    Mutates ``evidence`` in place. PURE w.r.t. network/FS/agent instance.
    """
    # Reflected HTML/JS only executes when the browser PARSES the response as a
    # document. ALLOWLIST of scriptable media types; absent/empty CT fails OPEN.
    _ct = (content_type or "").split(";")[0].strip().lower()
    if _ct and _ct not in _EXECUTABLE_CONTENT_TYPES:
        evidence["fp_suppressed"] = f"non-executable content-type: {_ct}"
        return False

    response_is_xml = _ct in _XML_CONTENT_TYPES

    ctx = None
    if is_executable_in_html_context(
        payload, response_html, response_is_xml=response_is_xml, agent_name=agent_name
    ):
        ctx = "html_tag"
    elif is_executable_in_event_handler(payload, response_html, agent_name=agent_name):
        ctx = "event_handler"
    elif is_executable_in_javascript_uri(payload, response_html, agent_name=agent_name):
        ctx = "javascript_uri"
    elif is_executable_in_template(payload, response_html):
        ctx = "template_expression"
    elif is_executable_in_js_string_breakout(
        payload, response_html, agent_name=agent_name
    ):
        ctx = "js_string_breakout"

    # CSP last, only when something would otherwise confirm.
    if ctx:
        try:
            if (
                _csp_blocks_inline(csp_header or "")
                or _csp_blocks_inline(_document_csp(response_html))
            ):
                evidence["fp_suppressed"] = "CSP forbids inline script"
                evidence["http_confirmed"] = False
                return False
        except Exception as e:  # unknown policy → fail OPEN
            logger.debug(f"[{agent_name}] CSP analysis failed, assuming executable: {e}")

    if ctx:
        evidence["http_confirmed"] = True
        evidence["execution_context"] = ctx
        evidence["validation_method"] = "http_response_analysis"
        return True

    evidence["http_confirmed"] = False
    return False


# =========================================================================
# CONTEXT-SPECIFIC CHECKS (PURE)
# =========================================================================

def is_executable_in_html_context(
    payload: str,
    response_html: str,
    *,
    response_is_xml: bool = False,
    agent_name: str = "XSSAgent",
) -> bool:
    """True if any reflection occurrence is executable per the HTML tokenizer."""
    try:
        occurrences = _reflection_occurrences(
            response_html, payload, bool(response_is_xml)
        )
    except Exception as e:
        logger.debug(
            f"[{agent_name}] Reflection classification failed, assuming executable: {e}"
        )
        return True

    positions = [p for p, _t, _c, _h in occurrences]

    if any(
        _position_executes(p, payload, tag, tail, host)
        for p, tag, tail, host in occurrences
    ):
        return True

    # <iframe srcdoc="..."> is entity-decoded then reparsed as a full document.
    try:
        if "srcdoc" in _attribute_injection_contexts(response_html, payload):
            return True
    except Exception as e:
        logger.debug(f"[{agent_name}] srcdoc analysis failed, assuming executable: {e}")
        return True

    if positions:
        logger.debug(
            f"[{agent_name}] Reflection is inert in every position "
            f"({', '.join(sorted(set(positions)))}) - not confirming from HTTP: "
            f"{payload[:60]}"
        )
    return False


def is_executable_in_event_handler(
    payload: str,
    response_html: str,
    *,
    agent_name: str = "XSSAgent",
) -> bool:
    """True if payload can execute via an event handler attribute."""
    try:
        return "event_handler" in _attribute_injection_contexts(response_html, payload)
    except Exception as e:
        logger.debug(
            f"[{agent_name}] Event-handler analysis failed, assuming executable: {e}"
        )
        return True


def is_executable_in_javascript_uri(
    payload: str,
    response_html: str,
    *,
    agent_name: str = "XSSAgent",
) -> bool:
    """True if payload can execute via a javascript: URI attribute."""
    try:
        return "javascript_uri" in _attribute_injection_contexts(response_html, payload)
    except Exception as e:
        logger.debug(
            f"[{agent_name}] javascript: URI analysis failed, assuming executable: {e}"
        )
        return True


def is_executable_in_template(payload: str, response_html: str) -> bool:
    """Template expressions need client-side eval — never confirm from HTTP alone."""
    return False


def is_executable_in_js_string_breakout(
    payload: str,
    response_html: str,
    agent_name: str = "XSSAgent",
) -> bool:
    """True if payload breaks out of a JS string inside an inline <script>."""
    try:
        forms = _reflected_forms(payload)
        for body, _ in _inline_script_bodies(response_html):
            for form in forms:
                at = body.find(form)
                while at != -1:
                    end = at + len(form)
                    if _js_span_escapes(body, at, end) and _js_breakout_parses(
                        body, at, end
                    ):
                        logger.info(
                            f"[{agent_name}] JS string breakout confirmed: reflected as "
                            f"'{form[:40]}' in code position"
                        )
                        return True
                    at = body.find(form, at + 1)
    except Exception as e:
        logger.debug(
            f"[{agent_name}] JS breakout analysis failed, assuming executable: {e}"
        )
        return True
    return False


# =========================================================================
# REFLECTION DETECTION (PURE)
# =========================================================================

def check_reflection(
    payload: str,
    response_html: str,
    evidence: Dict,
    agent_name: str = "XSSAgent",
) -> bool:
    """Check if payload is reflected (multi-decode). Mutates evidence on hit."""
    p_decoded = urllib.parse.unquote(payload)
    p_double_decoded = urllib.parse.unquote(p_decoded)
    p_html_decoded = html_mod.unescape(p_decoded)

    reflections = [payload, p_decoded, p_double_decoded, p_html_decoded]

    for ref in set(reflections):
        if ref and ref in response_html:
            evidence["reflected"] = True
            evidence["status"] = "VALIDATED_CONFIRMED"
            logger.info(f"[{agent_name}] Reflection detected (possibly decoded).")
            return True

    return False


def payload_reflects(payload: str, response: str) -> bool:
    """Check if payload reflects, accounting for server transformations."""
    if payload in response:
        return True

    if "\\" in payload:
        transformed = payload.replace("\\", "\\\\")
        if transformed in response:
            return True

    for breakout in ["\\'", '\\"', "';", '";']:
        if breakout in payload:
            exec_part = payload.split(breakout, 1)[1]
            if exec_part and len(exec_part) > 5 and exec_part in response:
                return True

    return False


def detect_execution_context(payload: str, response_html: str) -> Optional[str]:
    """Heuristic context label (regex). Prefer position classifier for confirm."""
    escaped = re.escape(payload)

    if re.search(
        rf"<script[^>]*>.*?{escaped}.*?</script>",
        response_html,
        re.DOTALL | re.IGNORECASE,
    ):
        return "script_block"

    if re.search(
        rf'on\w+\s*=\s*["\'][^"\']*{escaped}', response_html, re.IGNORECASE
    ):
        return "event_handler"

    if payload.lower().startswith("javascript:"):
        if re.search(
            rf'(href|src|action)\s*=\s*["\']?{escaped}',
            response_html,
            re.IGNORECASE,
        ):
            return "javascript_uri"
    else:
        if re.search(
            rf'(href|src|action)\s*=\s*["\']?javascript:[^"\']*{escaped}',
            response_html,
            re.IGNORECASE,
        ):
            return "javascript_uri"

    if re.search(rf"\{{\{{[^}}]*{escaped}[^}}]*\}}\}}", response_html) or re.search(
        rf"\$\{{[^}}]*{escaped}[^}}]*\}}", response_html
    ):
        return "template_expression"

    return None


def requires_browser_validation(payload: str, response_html: str) -> bool:
    """True when Playwright validation is required for this payload/response."""
    dom_sinks = [
        "location.hash",
        "location.search",
        "document.URL",
        "document.referrer",
        "postMessage",
        "innerHTML",
        "outerHTML",
        "document.write",
    ]
    for sink in dom_sinks:
        if sink.lower() in payload.lower():
            return True

    interaction_patterns = [
        r"autofocus.*onfocus",
        r"onfocus.*autofocus",
        r"onblur\s*=",
        r"onmouseover\s*=",
        r"onmouseenter\s*=",
    ]
    for pattern in interaction_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True

    complex_sinks = [
        r"eval\s*\(",
        r"Function\s*\(",
        r"setTimeout\s*\([^)]*[\"']",
        r"setInterval\s*\([^)]*[\"']",
    ]
    for pattern in complex_sinks:
        if re.search(pattern, response_html):
            return True

    template_patterns = [
        r"\{\{",
        r"\$\{",
        r"#\{",
        r"\{%",
        r"<%",
    ]
    for pattern in template_patterns:
        if re.search(pattern, payload):
            return True

    if re.search(
        r"angular|ng-app|vue\.js|v-bind|v-model", response_html, re.IGNORECASE
    ):
        return True

    return False


# Back-compat: old name used by smoke_confirm / early extracts
def detect_js_string_delimiter(block: str, pos: int) -> str:
    """Legacy delimiter guess (kept for import stability; lexer is preferred)."""
    lookback_start = max(0, pos - 300)
    lookback = block[lookback_start:pos]

    last_single = -1
    last_double = -1

    for m in re.finditer(r"""[=\(,+]\s*'""", lookback):
        last_single = m.end()
    for m in re.finditer(r'''[=\(,+]\s*"''', lookback):
        last_double = m.end()

    if last_single > last_double:
        return "'"
    if last_double > last_single:
        return '"'
    return ""


__all__ = [
    "can_confirm_from_http_response",
    "is_executable_in_html_context",
    "is_executable_in_event_handler",
    "is_executable_in_javascript_uri",
    "is_executable_in_template",
    "detect_js_string_delimiter",
    "is_executable_in_js_string_breakout",
    "check_reflection",
    "payload_reflects",
    "detect_execution_context",
    "requires_browser_validation",
]
