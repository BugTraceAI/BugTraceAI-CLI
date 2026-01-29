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
