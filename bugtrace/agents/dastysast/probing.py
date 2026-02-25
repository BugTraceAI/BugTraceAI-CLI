"""
PURE functions for reflection analysis and probe evidence formatting.

Functions here examine pre-fetched data (HTML strings, response
metadata) and return structured results.  No network I/O.
"""
import re
from typing import Dict, List, Optional

from loguru import logger


def analyze_reflection(
    param: str, marker: str, html: str, status: int
) -> Dict:
    """
    Analyse HOW *marker* reflects in *html*.

    Detects reflection context:
      - ``html_text``      : Inside HTML body text (XSS via ``<script>``)
      - ``html_attribute`` : Inside an attribute (XSS via ``" onmouseover=``)
      - ``script_block``   : Inside ``<script>`` (XSS via ``'``)
      - ``url_context``    : Inside ``href`` / ``src`` (Open Redirect)
      - ``no_reflection``  : Marker not found

    Args:
        param:  Parameter name.
        marker: Omni-Probe marker string.
        html:   Full response HTML body.
        status: HTTP response status code.

    Returns:
        Dict with keys ``parameter``, ``reflects``, ``context``,
        ``html_snippet``, ``chars_survive``, ``line_number``,
        ``status_code``.
    """  # PURE
    result: Dict = {
        "parameter": param,
        "reflects": False,
        "context": "no_reflection",
        "html_snippet": "",
        "chars_survive": "",
        "line_number": None,
        "status_code": status,
    }

    if marker not in html:
        return result

    result["reflects"] = True

    # Locate the first line containing the marker
    lines = html.split("\n")
    for i, line in enumerate(lines, 1):
        if marker in line:
            result["line_number"] = i
            idx = line.find(marker)
            start = max(0, idx - 50)
            end = min(len(line), idx + len(marker) + 50)
            result["html_snippet"] = line[start:end].strip()
            break

    # Determine context
    # 1. Inside <script> block
    script_pattern = rf"<script[^>]*>[^<]*{re.escape(marker)}[^<]*</script>"
    if re.search(script_pattern, html, re.IGNORECASE | re.DOTALL):
        result["context"] = "script_block"
    # 2. Inside an attribute value
    elif re.search(rf"""[\"'][^\"']*{re.escape(marker)}[^\"']*[\"']""", html):
        result["context"] = "html_attribute"
    # 3. Inside href/src (URL context)
    elif re.search(
        rf"(?:href|src|action)=[\"'][^\"']*{re.escape(marker)}",
        html,
        re.IGNORECASE,
    ):
        result["context"] = "url_context"
    # 4. Plain HTML text
    else:
        result["context"] = "html_text"

    # chars_survive is populated by separate follow-up probes (I/O)
    result["chars_survive"] = ""

    return result


def check_header_reflection(
    param_name: str, marker: str, response_headers: dict,
    agent_name: str = "DASTySAST",
) -> Optional[Dict]:
    """
    Check if the probe *marker* reflects in any response header value.

    If it does, this indicates potential CRLF / Header Injection.

    Args:
        param_name:       Parameter that was probed.
        marker:           Omni-Probe marker string.
        response_headers: Dict-like mapping of response headers.
        agent_name:       Agent name for log context.

    Returns:
        Dict with header reflection details, or ``None``.
    """  # PURE
    try:
        for header_name, header_value in response_headers.items():
            if marker in header_value:
                logger.info(
                    f"[{agent_name}] Probe marker reflects in response "
                    f"header '{header_name}' for param {param_name}"
                )
                return {
                    "header_name": header_name,
                    "header_value": header_value[:200],
                    "parameter": param_name,
                    "reflection_context": "response_header",
                }
    except Exception as e:
        logger.debug(f"[{agent_name}] Header reflection check failed: {e}")
    return None


def format_probe_evidence(probes: List[Dict]) -> str:
    """
    Format probe results as a human-readable evidence section for the LLM.

    Args:
        probes: List of probe result dicts (from ``analyze_reflection``).

    Returns:
        Multi-line string summarising each probe's outcome.
    """  # PURE
    if not probes:
        return ""

    lines: List[str] = []
    for p in probes:
        param = p.get("parameter", "unknown")
        reflects = p.get("reflects", False)
        context = p.get("context", "unknown")
        snippet = p.get("html_snippet", "")
        line_num = p.get("line_number", "?")
        status = p.get("status_code", "?")

        if reflects:
            lines.append(
                f"✓ {param}: REFLECTS in {context} "
                f"(line {line_num}, status {status})"
            )
            if snippet:
                lines.append(f"  Snippet: {snippet[:100]}")
        else:
            lines.append(f"✗ {param}: NO REFLECTION (status {status})")

    return "\n".join(lines)


def extract_cookies_from_http_headers(
    set_cookie_headers: List[str],
    existing_cookies: Dict[str, Dict],
    agent_name: str = "DASTySAST",
) -> Dict[str, Dict]:
    """
    Parse ``Set-Cookie`` header values and merge into *existing_cookies*.

    HttpOnly cookies are invisible to ``document.cookie`` but are
    the highest-value targets for Cookie SQLi.

    Args:
        set_cookie_headers: Raw ``Set-Cookie`` header strings.
        existing_cookies:   Already-known cookies dict (mutated in place
                            for backward compatibility, but the return
                            value should be preferred).
        agent_name:         Agent name for log context.

    Returns:
        Updated cookies dict.
    """  # PURE (aside from logger side-effect)
    result = dict(existing_cookies)

    for header_val in set_cookie_headers:
        parts = header_val.split(";")
        if not parts:
            continue
        name_value = parts[0].strip()
        if "=" not in name_value:
            continue
        name, value = name_value.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue

        flags_lower = header_val.lower()
        is_httponly = "httponly" in flags_lower
        is_secure = "secure" in flags_lower
        has_samesite = "samesite" in flags_lower

        if name not in result:
            result[name] = {
                "name": name,
                "value": value,
                "httponly": is_httponly,
                "secure": is_secure,
                "samesite": has_samesite,
                "_source": "http_header",
            }
            if is_httponly:
                logger.info(
                    f"[{agent_name}] Captured HttpOnly cookie from headers: {name}"
                )
            else:
                logger.debug(
                    f"[{agent_name}] Captured cookie from headers: {name}"
                )

    return result
