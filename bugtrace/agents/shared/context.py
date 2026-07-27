"""
Pure injection context detection and analysis.

Analyzes HTML responses to determine where payloads land and how they can
execute. Used for context-aware payload selection, HTTP-only confirmation,
and deciding when browser validation is required.

No I/O, no state mutation, no logging -- just regex-based HTML analysis.

Extracted from xss_agent.py for reuse across agents.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class InjectionContext:
    """
    Represents an injection context found in an HTML response.

    Attributes:
        context_type: The kind of context where the probe was found
            (e.g. "script", "event_handler", "html_body", "html_attribute",
            "javascript_string", "url_href", "url_src", "html_comment",
            "unknown").
        code_snippet: A snippet of surrounding HTML showing the reflection.
    """
    context_type: str
    code_snippet: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_snippet(text: str, target: str, max_len: int = 200) -> str:
    """
    Extract a snippet of *text* centered around *target*.

    Returns up to 50 characters before and 100 characters after the first
    occurrence of *target*, stripped of leading/trailing whitespace.

    Args:
        text: The full text to search in.
        target: The substring to center the snippet around.
        max_len: Maximum snippet length (reserved for future use).

    Returns:
        A trimmed substring, or "" if *target* is not found.
    """
    idx = text.find(target)
    if idx == -1:
        return ""
    start = max(0, idx - 50)
    end = min(len(text), idx + len(target) + 100)
    return text[start:end].strip()


# ---------------------------------------------------------------------------
# Context detection (probe-based)
# ---------------------------------------------------------------------------

# Priority order for selecting the most dangerous context.
_CONTEXT_PRIORITY = [
    "script",
    "event_handler",
    "javascript_string",
    "url_href",
    "url_src",
    "html_attribute",
    "html_body",
    "html_comment",
]


def check_contexts(html: str, probe: str, escaped_probe: str) -> List[Tuple[str, str]]:
    """
    Scan HTML for all contexts where a probe string is reflected.

    Each check uses a regex pattern targeted at a specific HTML context
    (script block, JS string literal, attribute value, href/src attribute,
    event handler, body text, or HTML comment).

    Args:
        html: The full HTML response body.
        probe: The raw probe string (e.g. "USER_INPUT").
        escaped_probe: The regex-escaped version of *probe*.

    Returns:
        A list of (context_type, code_snippet) tuples for every context
        where the probe was found. May contain duplicates if the probe
        appears in multiple locations of the same context type.
    """
    contexts: List[Tuple[str, str]] = []

    if re.search(r'<script[^>]*>.*?' + escaped_probe + r'.*?</script>', html, re.DOTALL | re.IGNORECASE):
        contexts.append(("script", _get_snippet(html, probe)))

    if re.search(r"['`\"][^'`\"]*" + escaped_probe + r"[^'`\"]*['`\"]", html):
        contexts.append(("javascript_string", _get_snippet(html, probe)))

    if re.search(r'<[^>]+\s\w+=["\']?[^"\']*' + escaped_probe, html):
        contexts.append(("html_attribute", _get_snippet(html, probe)))

    if re.search(r'href=["\']?[^"\']*' + escaped_probe, html, re.IGNORECASE):
        contexts.append(("url_href", _get_snippet(html, probe)))

    if re.search(r'src=["\']?[^"\']*' + escaped_probe, html, re.IGNORECASE):
        contexts.append(("url_src", _get_snippet(html, probe)))

    if re.search(r'on\w+=["\'][^"\']*' + escaped_probe, html, re.IGNORECASE):
        contexts.append(("event_handler", _get_snippet(html, probe)))

    if re.search(r'>[^<]*' + escaped_probe + r'[^<]*<', html):
        contexts.append(("html_body", _get_snippet(html, probe)))

    if re.search(r'<!--[^>]*' + escaped_probe + r'[^>]*-->', html):
        contexts.append(("html_comment", _get_snippet(html, probe)))

    return contexts


def prioritize_contexts(contexts: List[Tuple[str, str]]) -> InjectionContext:
    """
    Select the most dangerous injection context from a list of candidates.

    Contexts are ranked by exploitability: script > event_handler >
    javascript_string > url_href > url_src > html_attribute > html_body >
    html_comment. If no contexts are provided, returns an "unknown" context.

    Args:
        contexts: A list of (context_type, code_snippet) tuples as returned
            by :func:`check_contexts`.

    Returns:
        The highest-priority :class:`InjectionContext`, or an "unknown"
        context if the list is empty.
    """
    if not contexts:
        return InjectionContext(
            context_type="unknown",
            code_snippet="Context could not be automatically determined.",
        )

    for p_ctx in _CONTEXT_PRIORITY:
        for ctx_type, snippet in contexts:
            if ctx_type == p_ctx:
                return InjectionContext(context_type=ctx_type, code_snippet=snippet)

    return InjectionContext(context_type=contexts[0][0], code_snippet=contexts[0][1])


def detect_injection_context(html: str, probe: str = "USER_INPUT") -> InjectionContext:
    """
    Detect the most dangerous injection context for a probe in an HTML response.

    This is the main entry point for context detection. It escapes the probe
    for regex use, scans all contexts, and returns the highest-priority match.

    Args:
        html: The full HTML response body.
        probe: The probe string to search for (default ``"USER_INPUT"``).

    Returns:
        The highest-priority :class:`InjectionContext` found, or "unknown".
    """
    escaped_probe = re.escape(probe)
    contexts = check_contexts(html, probe, escaped_probe)
    return prioritize_contexts(contexts)


# ---------------------------------------------------------------------------
# Execution context analysis (payload-based)
# ---------------------------------------------------------------------------

def is_executable_in_html_context(payload: str, response_html: str) -> bool:
    """
    Check if a payload creates a new HTML tag that could execute JavaScript.

    Returns True only when:
    - The payload contains ``<`` and ``>`` (tag-creating characters)
    - Those characters appear RAW (not as ``&lt;`` / ``&gt;``) in the response
    - The payload is found outside of ``<script>`` blocks (to avoid double-counting)

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        True if the payload creates an executable HTML tag in the response.
    """
    # Must have tag-creating chars
    if '<' not in payload or '>' not in payload:
        return False

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

    # Check that we're not inside a JS string or HTML attribute value
    # where the payload would be data, not code
    payload_start = pos
    check_start = max(0, payload_start - 10)
    before_context = html_without_scripts[check_start:payload_start]

    # If we see HTML encoding markers right before, it's escaped
    if '&lt;' in before_context or '&quot;' in before_context:
        return False

    # Payload appears raw in HTML - likely executable
    return True


def is_executable_in_event_handler(payload: str, response_html: str) -> bool:
    """
    Check if a payload can execute via an event handler attribute.

    Event handlers like ``onclick="PAYLOAD"`` execute JavaScript. However, if
    the payload's quote characters are HTML-encoded (``&quot;`` / ``&#39;``),
    the payload cannot break out of the attribute and is neutered.

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        True if the payload appears in an event handler without proper encoding.
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
    Check if a payload can execute via a ``javascript:`` URI scheme.

    URIs like ``href="javascript:PAYLOAD"`` execute when clicked. Handles
    both cases: payload that IS the full ``javascript:`` URI, and payload
    that appears inside an existing ``javascript:`` URI.

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        True if the payload appears in an executable ``javascript:`` URI.
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
    Check if a payload appears in a template expression.

    Template expressions like ``{{payload}}`` or ``${payload}`` in
    Angular/Vue/etc. require client-side evaluation. Since execution cannot
    be confirmed from HTTP alone, this always returns False and defers to
    browser validation.

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        Always False -- template expressions require browser validation.
    """
    # Template expressions need client-side evaluation
    # We can't confirm execution from HTTP alone
    return False


def detect_js_string_delimiter(block: str, pos: int) -> str:
    """
    Detect the JS string delimiter type that wraps the injection point.

    Looks backward from *pos* to find the nearest string assignment pattern
    (``= '...'`` or ``= "..."``) that opened the JS string containing the
    injection point.

    Args:
        block: The JavaScript code block (content between ``<script>`` tags).
        pos: The character position of the injection point within *block*.

    Returns:
        ``"'"`` or ``'"'`` depending on which delimiter was found, or ``""``
        if the delimiter could not be determined.
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


def is_executable_in_js_string_breakout(payload: str, response_html: str) -> bool:
    """
    Check if a payload achieves JS string breakout via backslash-quote pattern.

    TRUE breakout requires EVEN backslashes before the quote character::

        \\\\' -> JS sees: \\\\ (literal backslash) + ' (free quote) = BREAKOUT
        \\\\\\\\' -> JS sees: \\\\\\\\ (two literal backslashes) + ' = BREAKOUT

    FALSE positive has ODD backslashes before the quote::

        \\\\\\' -> JS sees: \\\\ (literal backslash) + \\' (escaped quote) = NO BREAKOUT

    Additionally validates that the breakout quote type matches the JS string
    delimiter (a ``'`` breakout inside ``"..."`` is NOT a breakout).

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        True if the payload achieves a confirmed JS string breakout.
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
                        idx = pos + 1
                        continue

                    # The executable part must appear AFTER this free quote
                    after_quote = block[pos + 1:]
                    if exec_part[:20] in after_quote:
                        return True

                idx = pos + 1

    return False


def detect_execution_context(payload: str, response_html: str) -> Optional[str]:
    """
    Detect the execution context where a payload landed in the response.

    Checks contexts in priority order: script_block > event_handler >
    javascript_uri > template_expression. Returns the context type for
    high-confidence execution, or None if the payload is not in any
    executable context.

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        A context type string (``"script_block"``, ``"event_handler"``,
        ``"javascript_uri"``, or ``"template_expression"``), or None.
    """
    escaped = re.escape(payload)

    # 1. Script block - highest priority (direct execution in <script> tags)
    if re.search(rf'<script[^>]*>.*?{escaped}.*?</script>', response_html, re.DOTALL | re.IGNORECASE):
        return "script_block"

    # 2. Event handler attributes (onclick, onerror, onload, etc.)
    if re.search(rf'on\w+\s*=\s*["\'][^"\']*{escaped}', response_html, re.IGNORECASE):
        return "event_handler"

    # 3. javascript: URI scheme (href, src, action attributes)
    if payload.lower().startswith('javascript:'):
        # Payload already has javascript: - look for it directly in href/src/action
        if re.search(rf'(href|src|action)\s*=\s*["\']?{escaped}', response_html, re.IGNORECASE):
            return "javascript_uri"
    else:
        # Payload without javascript: - look for it inside javascript: URI
        if re.search(rf'(href|src|action)\s*=\s*["\']?javascript:[^"\']*{escaped}', response_html, re.IGNORECASE):
            return "javascript_uri"

    # 4. Template expressions (Angular/Vue/etc.)
    if re.search(rf'\{{\{{[^}}]*{escaped}[^}}]*\}}\}}', response_html) or \
       re.search(rf'\$\{{[^}}]*{escaped}[^}}]*\}}', response_html):
        return "template_expression"

    return None


def requires_browser_validation(payload: str, response_html: str) -> bool:
    """
    Determine if Playwright browser validation is required.

    Browser validation is needed when:
    1. The payload targets DOM-based sinks (location.hash, innerHTML, etc.)
    2. The payload requires user interaction (autofocus+onfocus, onmouseover)
    3. The response contains complex sinks (eval, Function, setTimeout with strings)
    4. The payload uses template syntax (Angular/Vue/Jinja2/etc.)
    5. The response contains a JS framework (Angular/Vue) and the payload reflects

    Args:
        payload: The XSS payload that was sent.
        response_html: The HTML response body.

    Returns:
        True if browser validation is required to confirm execution.
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
    # These require browser to evaluate if JS framework processes them
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
        # Framework detected - any reflection needs browser validation
        return True

    return False


def payload_reflects(payload: str, response: str) -> bool:
    """
    Check if a payload reflects in the response, accounting for server transformations.

    Handles three levels of matching:
    1. Exact match (original payload appears as-is)
    2. Backslash doubling (server escapes ``\\`` to ``\\\\``)
    3. Executable part match (for breakout payloads, the code after the
       breakout sequence appears in the response)

    Args:
        payload: The XSS payload that was sent.
        response: The HTTP response body.

    Returns:
        True if the payload (or a server-transformed variant) appears in the
        response.
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
