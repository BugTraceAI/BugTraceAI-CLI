"""
Pure reflection and HTTP confirmation analysis for XSS.

Examines HTTP responses to determine if XSS payloads reach an
executable context. No I/O - only string/HTML analysis.

Extracted from xss_agent.py:
- _can_confirm_from_http_response (line 7678)
- _is_executable_in_html_context (line 7744)
- _is_executable_in_event_handler (line 7786)
- _is_executable_in_javascript_uri (line 7819)
- _is_executable_in_template (line 7837)
- _detect_js_string_delimiter (line 7849)
- _is_executable_in_js_string_breakout (line 7876)
- _payload_reflects (line 7961)
- _detect_execution_context (line 7990)
- _check_reflection (line 7653)
- _requires_browser_validation (line 8026)
"""

import re
import html as html_mod
import urllib.parse
from typing import Dict, Optional

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
) -> bool:
    """
    Confirm XSS from HTTP response without browser.

    STRICT validation: Only confirms when payload lands in a truly
    executable context WITHOUT being neutered (escaped/encoded).

    Key insight:
    - In HTML: <, >, " must NOT be HTML-encoded (&lt; &gt; &quot;)
    - In JS strings: quotes must NOT be backslash-escaped (\\' or \\")
    - Payload inside a JS string literal does NOT execute

    PURE function.

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response to analyze.
        evidence: Dict to populate with validation details (mutated in place).
        agent_name: Agent name for logging.

    Returns:
        True if XSS can be confirmed from HTTP response, False otherwise.
    """
    # 1. Check for unescaped payload in HTML tag context
    if is_executable_in_html_context(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "html_tag"
        evidence["validation_method"] = "http_response_analysis"
        return True

    # 2. Check for unescaped payload in event handler
    if is_executable_in_event_handler(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "event_handler"
        evidence["validation_method"] = "http_response_analysis"
        return True

    # 3. Check for javascript: URI execution
    if is_executable_in_javascript_uri(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "javascript_uri"
        evidence["validation_method"] = "http_response_analysis"
        return True

    # 4. Check for template expression execution
    if is_executable_in_template(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "template_expression"
        evidence["validation_method"] = "http_response_analysis"
        return True

    # 5. Check for JS string breakout (backslash-quote pattern)
    # Detects: payload \';alert()// -> server returns \\';alert()// inside <script>
    # The \\ is an escaped backslash, the ' closes the JS string -> code executes
    if is_executable_in_js_string_breakout(payload, response_html, agent_name):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "js_string_breakout"
        evidence["validation_method"] = "http_response_analysis"
        return True

    # No executable context found
    evidence["http_confirmed"] = False
    return False


# =========================================================================
# CONTEXT-SPECIFIC CHECKS (PURE)
# =========================================================================

def is_executable_in_html_context(payload: str, response_html: str) -> bool:
    """
    Check if payload creates a new HTML tag that could execute JS.

    Returns True only if:
    - Payload contains < and > (to create a tag)
    - These chars appear RAW (not as &lt; &gt;) in the response
    - The context is outside of script tags

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.

    Returns:
        True if payload appears as executable HTML.
    """
    # Must have tag-creating chars
    if '<' not in payload or '>' not in payload:
        return False

    # Check for raw payload outside of <script> blocks
    # Remove script blocks from consideration
    html_without_scripts = re.sub(
        r'<script[^>]*>.*?</script>', '', response_html,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Check if raw payload appears in the cleaned HTML
    if payload not in html_without_scripts:
        return False

    # Verify < and > are NOT escaped at the payload location
    pos = html_without_scripts.find(payload)
    if pos == -1:
        return False

    # Check context before payload for HTML encoding markers
    check_start = max(0, pos - 10)
    before_context = html_without_scripts[check_start:pos]

    # If we see HTML encoding markers right before, it's escaped
    if '&lt;' in before_context or '&quot;' in before_context:
        return False

    # Payload appears raw in HTML - likely executable
    return True


def is_executable_in_event_handler(payload: str, response_html: str) -> bool:
    """
    Check if payload can execute via event handler attribute.

    Event handlers like onclick="PAYLOAD" execute JS.
    But if payload's quotes are HTML-encoded, it won't break out.

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.

    Returns:
        True if payload appears in executable event handler context.
    """
    # Look for payload in event handler context
    # Pattern: on[event]="...[payload]..."
    event_pattern = rf'on\w+\s*=\s*(["\'])([^"\']*?){re.escape(payload)}'
    match = re.search(event_pattern, response_html, re.IGNORECASE)

    if not match:
        return False

    # Check if payload breaks out of the attribute
    # If payload contains the same quote type, it must NOT be escaped
    quote_char = match.group(1)  # The quote used: " or '

    if quote_char in payload:
        # Check if quote in payload is HTML-encoded
        encoded_quote = '&quot;' if quote_char == '"' else '&#39;'
        payload_with_encoded = payload.replace(quote_char, encoded_quote)

        # If the encoded version is what's in the response, payload is neutered
        if payload_with_encoded in response_html:
            return False

    # Payload in event handler without proper encoding - executable
    return True


def is_executable_in_javascript_uri(payload: str, response_html: str) -> bool:
    """
    Check if payload can execute via javascript: URI.

    href="javascript:PAYLOAD" executes when clicked.

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.

    Returns:
        True if payload appears in executable javascript: URI context.
    """
    # Pattern: href/src/action="javascript:...[payload]..."
    if payload.lower().startswith('javascript:'):
        # Payload is the full javascript: URI
        pattern = rf'(href|src|action)\s*=\s*["\']?{re.escape(payload)}'
    else:
        # Payload is the code part
        pattern = rf'(href|src|action)\s*=\s*["\']?javascript:[^"\']*{re.escape(payload)}'

    return bool(re.search(pattern, response_html, re.IGNORECASE))


def is_executable_in_template(payload: str, response_html: str) -> bool:
    """
    Check if payload appears in template expression.

    {{payload}} or ${payload} in Angular/Vue/etc could execute.
    BUT: This requires browser to evaluate, so returns False here
    and lets browser validation handle it.

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.

    Returns:
        Always False - template expressions need client-side evaluation.
    """
    # Template expressions need client-side evaluation
    # We can't confirm execution from HTTP alone
    return False


# =========================================================================
# JS STRING BREAKOUT DETECTION (PURE)
# =========================================================================

def detect_js_string_delimiter(block: str, pos: int) -> str:
    """
    Detect the JS string delimiter type that wraps the injection point.

    Looks backward from pos to find the nearest string assignment pattern
    (= '...' or = "...") that opened the JS string containing our injection.

    PURE function.

    Args:
        block: JavaScript code block content.
        pos: Position in the block to look backward from.

    Returns:
        "'" or '"' or "" (if unable to determine).
    """
    lookback_start = max(0, pos - 300)
    lookback = block[lookback_start:pos]

    # Find last occurrence of string assignment patterns
    # e.g. `= '`, `= "`, `('`, `("`, `,'`, `,"`, `+ '`, `+ "`
    last_single = -1
    last_double = -1

    for m in re.finditer(r"""[=\(,+]\s*'""", lookback):
        last_single = m.end()
    for m in re.finditer(r'''[=\(,+]\s*"''', lookback):
        last_double = m.end()

    if last_single > last_double:
        return "'"
    elif last_double > last_single:
        return '"'
    return ""


def is_executable_in_js_string_breakout(
    payload: str,
    response_html: str,
    agent_name: str = "XSSAgent",
) -> bool:
    """
    Check if payload achieves JS string breakout via backslash-quote pattern.

    TRUE breakout requires EVEN backslashes before the quote:
      \\\\' -> JS: \\\\ (literal backslash) + ' (free quote) = BREAKOUT
      \\\\\\\\' -> JS: \\\\\\\\ (two literal backslashes) + ' (free quote) = BREAKOUT

    FALSE positive has ODD backslashes before the quote:
      \\\\\\' -> JS: \\\\ (literal backslash) + \\' (escaped quote) = NO BREAKOUT

    Additionally validates that the breakout quote type matches the JS string
    delimiter: a ' breakout inside "..." is NOT a breakout (and vice versa).

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.
        agent_name: Agent name for logging.

    Returns:
        True if JS string breakout is confirmed.
    """
    # Map: (breakout sequence we send, quote character to look for)
    breakout_checks = [
        ("\\'", "'"),   # single quote breakout
        ('\\"', '"'),   # double quote breakout
    ]

    for sent_seq, quote_char in breakout_checks:
        if sent_seq not in payload:
            continue

        # Extract <script> blocks from response
        script_blocks = re.findall(
            r'<script[^>]*>(.*?)</script>', response_html,
            re.DOTALL | re.IGNORECASE,
        )

        # Extract the executable part of the payload (after the breakout)
        exec_part = payload.split(sent_seq, 1)[1]  # e.g. "alert(document.domain)//"
        if not exec_part:
            continue

        for block in script_blocks:
            # Scan for every occurrence of the quote character
            idx = 0
            while idx < len(block):
                pos = block.find(quote_char, idx)
                if pos == -1:
                    break

                # Count consecutive backslashes immediately before this quote
                bs_count = 0
                check_pos = pos - 1
                while check_pos >= 0 and block[check_pos] == '\\':
                    bs_count += 1
                    check_pos -= 1

                # Breakout condition: EVEN backslashes >= 2 before the quote
                # Even = all backslashes form \\ pairs (literal), quote is FREE
                # Odd = last backslash escapes the quote, NO breakout
                if bs_count >= 2 and bs_count % 2 == 0:
                    # Verify quote type matches the JS string delimiter
                    delimiter = detect_js_string_delimiter(block, pos)
                    if delimiter and quote_char != delimiter:
                        logger.debug(
                            f"[{agent_name}] JS breakout rejected: "
                            f"quote '{quote_char}' doesn't match "
                            f"string delimiter '{delimiter}'"
                        )
                        idx = pos + 1
                        continue

                    # The executable part must appear AFTER this free quote
                    after_quote = block[pos + 1:]
                    if exec_part[:20] in after_quote:
                        logger.info(
                            f"[{agent_name}] JS string breakout confirmed: "
                            f"sent '{sent_seq}' -> {bs_count} backslashes + free "
                            f"{quote_char} + executable code '{exec_part[:30]}...'"
                        )
                        return True

                idx = pos + 1

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
    """
    Check if payload is reflected in response using multiple decoding levels.

    PURE function (mutates evidence dict).

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.
        evidence: Dict to populate with reflection data.
        agent_name: Agent name for logging.

    Returns:
        True if any variant of the payload is reflected.
    """
    # Test multiple decoding levels
    p_decoded = urllib.parse.unquote(payload)
    p_double_decoded = urllib.parse.unquote(p_decoded)
    p_html_decoded = html_mod.unescape(p_decoded)

    reflections = [payload, p_decoded, p_double_decoded, p_html_decoded]

    # Check if any variant is reflected
    for ref in set(reflections):
        if ref and ref in response_html:
            evidence["reflected"] = True
            evidence["status"] = "VALIDATED_CONFIRMED"  # v3.2.1: CDP disabled
            return True

    return False


def payload_reflects(payload: str, response: str) -> bool:
    """
    Check if payload reflects in the response, accounting for server transformations.

    Handles:
    1. Exact match (original behavior)
    2. Backslash doubling: server escapes \\ to \\\\\\\\ (e.g. \\' -> \\\\')
    3. Executable part match: for breakout payloads, check if the code after
       the breakout sequence appears in the response

    PURE function.

    Args:
        payload: The XSS payload string.
        response: The response body to check.

    Returns:
        True if any form of the payload is reflected.
    """
    # 1. Exact match (original)
    if payload in response:
        return True

    # 2. Server transforms \ to \\ (common escaping)
    if '\\' in payload:
        transformed = payload.replace('\\', '\\\\')
        if transformed in response:
            return True

    # 3. Executable part match for breakout payloads
    for breakout in ["\\'", '\\"', "';", '";']:
        if breakout in payload:
            exec_part = payload.split(breakout, 1)[1]
            if exec_part and len(exec_part) > 5 and exec_part in response:
                return True

    return False


def detect_execution_context(payload: str, response_html: str) -> Optional[str]:
    """
    Detect the execution context where payload landed.

    Returns context type for high-confidence execution, or None.
    Priority order: script_block > event_handler > javascript_uri > template_expression

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.

    Returns:
        Context type string or None if no executable context found.
    """
    escaped = re.escape(payload)

    # 1. Script block - highest priority (direct execution in <script> tags)
    if re.search(
        rf'<script[^>]*>.*?{escaped}.*?</script>',
        response_html, re.DOTALL | re.IGNORECASE,
    ):
        return "script_block"

    # 2. Event handler attributes (onclick, onerror, onload, etc.)
    if re.search(
        rf'on\w+\s*=\s*["\'][^"\']*{escaped}',
        response_html, re.IGNORECASE,
    ):
        return "event_handler"

    # 3. javascript: URI scheme (href, src, action attributes)
    if payload.lower().startswith('javascript:'):
        if re.search(
            rf'(href|src|action)\s*=\s*["\']?{escaped}',
            response_html, re.IGNORECASE,
        ):
            return "javascript_uri"
    else:
        if re.search(
            rf'(href|src|action)\s*=\s*["\']?javascript:[^"\']*{escaped}',
            response_html, re.IGNORECASE,
        ):
            return "javascript_uri"

    # 4. Template expressions (Angular/Vue/etc.)
    if re.search(rf'\{{\{{[^}}]*{escaped}[^}}]*\}}\}}', response_html):
        return "template_expression"
    if re.search(rf'\$\{{[^}}]*{escaped}[^}}]*\}}', response_html):
        return "template_expression"

    return None


def requires_browser_validation(payload: str, response_html: str) -> bool:
    """
    Determine if Playwright browser validation is required for this payload/response.

    PURE function.

    Args:
        payload: The XSS payload string.
        response_html: The HTML response body.

    Returns:
        True if browser validation is needed.
    """
    # 1. DOM-based sink patterns in payload
    dom_sinks = [
        "location.hash", "location.search", "document.URL",
        "document.referrer", "postMessage", "innerHTML",
        "outerHTML", "document.write",
    ]
    for sink in dom_sinks:
        if sink.lower() in payload.lower():
            return True

    # 2. Event handlers requiring interaction
    interaction_patterns = [
        r'autofocus.*onfocus',
        r'onfocus.*autofocus',
        r'onblur\s*=',
        r'onmouseover\s*=',
        r'onmouseenter\s*=',
    ]
    for pattern in interaction_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True

    # 3. Complex sink analysis in response (not payload)
    complex_sinks = [
        r'eval\s*\(',
        r'Function\s*\(',
        r'setTimeout\s*\([^)]*["\']',
        r'setInterval\s*\([^)]*["\']',
    ]
    for pattern in complex_sinks:
        if re.search(pattern, response_html):
            return True

    # 4. Template syntax in payload (CSTI - Angular, Vue, etc.)
    template_patterns = [
        r'\{\{',      # Angular/Vue mustache syntax
        r'\$\{',      # JS template literals
        r'#\{',       # Ruby ERB / Pug
        r'\{%',       # Jinja2/Twig
        r'<%',        # EJS/ASP
    ]
    for pattern in template_patterns:
        if re.search(pattern, payload):
            return True

    # 5. Check if response has Angular/Vue and payload reflected
    if re.search(r'angular|ng-app|vue\.js|v-bind|v-model', response_html, re.IGNORECASE):
        return True

    return False


__all__ = [
    # Main confirmation
    "can_confirm_from_http_response",
    # Context checks
    "is_executable_in_html_context",
    "is_executable_in_event_handler",
    "is_executable_in_javascript_uri",
    "is_executable_in_template",
    # JS string breakout
    "detect_js_string_delimiter",
    "is_executable_in_js_string_breakout",
    # Reflection detection
    "check_reflection",
    "payload_reflects",
    "detect_execution_context",
    "requires_browser_validation",
]
