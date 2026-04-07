"""
Auth Discovery Agent — PURE functions.

All functions in this module are free functions (no self), side-effect free,
and receive all data as explicit parameters.

Contents:
    - JWT_PATTERN: Compiled regex for JWT detection
    - is_jwt: Validate JWT format
    - is_session_cookie: Detect session cookies by name patterns
    - decode_jwt_parts: Decode JWT header and payload for metadata
    - base64url_decode: Base64Url decode helper
    - find_jwt_context_in_html: Determine where in HTML a JWT appears
    - is_duplicate_jwt: Check if JWT already discovered
    - is_duplicate_cookie: Check if cookie already discovered
    - format_jwt_finding: Format JWT info as a standard finding
    - format_cookie_finding: Format cookie info as a standard finding
    - build_markdown_report: Generate human-readable Markdown report content
"""

import re
import json
import base64
from typing import Dict, List, Optional
from datetime import datetime


# JWT regex pattern
JWT_PATTERN = re.compile(
    r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)'
)


def is_jwt(token: str) -> bool:  # PURE
    """Validate JWT format (3 parts, base64).

    Args:
        token: The string to validate.

    Returns:
        True if the string looks like a valid JWT.
    """
    if not token or not isinstance(token, str):
        return False

    parts = token.split('.')
    if len(parts) != 3:
        return False

    if len(parts[0]) < 4 or len(parts[1]) < 4:
        return False

    return True


def is_session_cookie(name: str) -> bool:  # PURE
    """Detect session cookies by name patterns.

    Args:
        name: The cookie name.

    Returns:
        True if the name matches common session cookie patterns.
    """
    if not name:
        return False

    session_patterns = [
        "session", "sessid", "phpsessid", "jsessionid",
        "asp.net_sessionid", "connect.sid", "_session",
        "sid", "csrf", "xsrf", "sessionid",
    ]

    name_lower = name.lower()
    return any(pattern in name_lower for pattern in session_patterns)


def base64url_decode(data: str) -> str:  # PURE
    """Base64Url decode helper.

    Args:
        data: Base64Url-encoded string.

    Returns:
        Decoded UTF-8 string, or empty string on failure.
    """
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except Exception:
        return ""


def decode_jwt_parts(token: str) -> Dict:  # PURE
    """Decode JWT header and payload for metadata.

    Args:
        token: The JWT token string.

    Returns:
        Dict with 'header', 'payload', and 'signature_present' keys.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}

        header_data = base64url_decode(parts[0])
        header = json.loads(header_data) if header_data else {}

        payload_data = base64url_decode(parts[1])
        payload = json.loads(payload_data) if payload_data else {}

        signature_present = bool(parts[2])

        return {
            "header": header,
            "payload": payload,
            "signature_present": signature_present,
        }
    except Exception:
        return {}


def find_jwt_context_in_html(html: str, token: str) -> str:  # PURE
    """Determine where in HTML the JWT appears.

    Args:
        html: The full HTML content.
        token: The JWT token to locate.

    Returns:
        Context string: 'inline_script', 'data_attribute', 'input_value',
        'html_text', or 'unknown'.
    """
    for line in html.split('\n'):
        if token in line:
            line_lower = line.lower()
            if '<script' in line_lower or '</script>' in line_lower:
                return "inline_script"
            elif 'data-' in line:
                return "data_attribute"
            elif 'value=' in line:
                return "input_value"
            else:
                return "html_text"
    return "unknown"


def is_duplicate_jwt(token: str, discovered_jwts: List[Dict]) -> bool:  # PURE
    """Check if JWT already discovered.

    Args:
        token: The JWT token string.
        discovered_jwts: List of previously discovered JWT info dicts.

    Returns:
        True if the token is already in the list.
    """
    return any(jwt["token"] == token for jwt in discovered_jwts)


def is_duplicate_cookie(
    name: str,
    value: str,
    discovered_cookies: List[Dict],
) -> bool:  # PURE
    """Check if cookie already discovered.

    Args:
        name: The cookie name.
        value: The cookie value.
        discovered_cookies: List of previously discovered cookie info dicts.

    Returns:
        True if the cookie name+value is already in the list.
    """
    return any(
        c["name"] == name and c["value"] == value
        for c in discovered_cookies
    )


def format_jwt_finding(jwt_info: Dict, agent_name: str) -> Dict:  # PURE
    """Format JWT info as a standard finding.

    Args:
        jwt_info: JWT discovery info dict.
        agent_name: Name of the agent for attribution.

    Returns:
        Standardized finding dict.
    """
    decoded = decode_jwt_parts(jwt_info["token"])

    return {
        "type": "JWT_DISCOVERED",
        "url": jwt_info["url"],
        "token": jwt_info["token"],
        "source": jwt_info["source"],
        "parameter": jwt_info.get("storage_key", jwt_info.get("cookie_name", "N/A")),
        "context": jwt_info.get("context", "unknown"),
        "severity": "INFO",
        "agent": agent_name,
        "timestamp": datetime.now().isoformat(),
        "metadata": {
            "header": decoded.get("header", {}),
            "payload_preview": decoded.get("payload", {}),
            "signature_present": decoded.get("signature_present", False),
        },
    }


def format_cookie_finding(cookie_info: Dict, agent_name: str) -> Dict:  # PURE
    """Format cookie info as a standard finding.

    Args:
        cookie_info: Cookie discovery info dict.
        agent_name: Name of the agent for attribution.

    Returns:
        Standardized finding dict.
    """
    return {
        "type": "SESSION_COOKIE_DISCOVERED",
        "url": cookie_info["url"],
        "cookie_name": cookie_info["name"],
        "cookie_value": cookie_info["value"],
        "source": cookie_info["source"],
        "severity": "INFO",
        "agent": agent_name,
        "timestamp": datetime.now().isoformat(),
        "metadata": cookie_info.get("metadata", {}),
    }


def build_markdown_report(
    target: str,
    agent_name: str,
    discovered_jwts: List[Dict],
    discovered_cookies: List[Dict],
) -> str:  # PURE
    """Generate human-readable Markdown report content.

    Args:
        target: The target URL.
        agent_name: Name of the agent.
        discovered_jwts: List of discovered JWT info dicts.
        discovered_cookies: List of discovered cookie info dicts.

    Returns:
        Markdown content as a string.
    """
    lines: List[str] = []
    lines.append("# Authentication Discovery Report\n")
    lines.append(f"**Target**: {target}  ")
    lines.append(f"**Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Agent**: {agent_name}\n")
    lines.append("---\n")

    # Summary
    lines.append("## Summary\n")
    lines.append(f"- **JWTs Discovered**: {len(discovered_jwts)}")
    lines.append(f"- **Session Cookies Discovered**: {len(discovered_cookies)}\n")
    lines.append("---\n")

    # JWT Findings
    if discovered_jwts:
        lines.append("## JWT Findings\n")
        for idx, jwt_info in enumerate(discovered_jwts, 1):
            decoded = decode_jwt_parts(jwt_info["token"])
            header = decoded.get("header", {})
            payload = decoded.get("payload", {})

            lines.append(f"### {idx}. JWT in {jwt_info['source']}\n")
            lines.append(f"- **URL**: {jwt_info['url']}")
            lines.append(f"- **Source**: {jwt_info['source']}")
            if "storage_key" in jwt_info:
                lines.append(f"- **Storage Key**: {jwt_info['storage_key']}")
            if "cookie_name" in jwt_info:
                lines.append(f"- **Cookie Name**: {jwt_info['cookie_name']}")

            if header:
                lines.append(f"- **Algorithm**: {header.get('alg', 'unknown')}")

            if payload:
                lines.append("- **Payload Preview**:")
                lines.append("  ```json")
                lines.append(f"  {json.dumps(payload, indent=2)}")
                lines.append("  ```")

            lines.append("")
    else:
        lines.append("## JWT Findings\n")
        lines.append("No JWTs discovered.\n")

    lines.append("---\n")

    # Cookie Findings
    if discovered_cookies:
        lines.append("## Session Cookie Findings\n")
        for idx, cookie_info in enumerate(discovered_cookies, 1):
            metadata = cookie_info.get("metadata", {})

            lines.append(f"### {idx}. {cookie_info['name']}\n")
            lines.append(f"- **Value**: {cookie_info['value'][:20]}... (truncated)")
            lines.append(f"- **URL**: {cookie_info['url']}")
            lines.append(f"- **Domain**: {metadata.get('domain', 'N/A')}")
            lines.append(f"- **Secure**: {metadata.get('secure', False)}")
            lines.append(f"- **HttpOnly**: {metadata.get('httpOnly', False)}")
            lines.append(f"- **SameSite**: {metadata.get('sameSite', 'None')}")

            if not metadata.get('secure'):
                lines.append("  - WARNING: Cookie not marked as Secure")
            if not metadata.get('httpOnly'):
                lines.append("  - WARNING: Cookie not marked as HttpOnly")

            lines.append("")
    else:
        lines.append("## Session Cookie Findings\n")
        lines.append("No session cookies discovered.\n")

    lines.append("---\n")

    # Next Steps
    lines.append("## Next Steps\n")
    if discovered_jwts:
        lines.append("**JWTs** will be analyzed by **JWTAgent** for:")
        lines.append("- 'none' algorithm bypass")
        lines.append("- Weak secret bruteforce")
        lines.append("- Key confusion attacks (RS256 -> HS256)\n")

    if discovered_cookies:
        lines.append("**Session cookies** will be tested by **IDORAgent** for:")
        lines.append("- Session fixation")
        lines.append("- Predictable session IDs")
        lines.append("- Authorization bypass\n")

    return "\n".join(lines)
