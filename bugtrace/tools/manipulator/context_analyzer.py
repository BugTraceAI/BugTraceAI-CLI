"""
Context Analyzer - Detects WHERE payloads are reflected and maps to appropriate breakouts.

This module analyzes HTTP responses to determine the reflection context (HTML attribute,
JavaScript string, SQL error, etc.) and recommends targeted breakout prefixes.
"""

import re
from typing import List, Dict, Optional, Set
from enum import Enum
from bugtrace.utils.logger import get_logger

logger = get_logger("tools.manipulator.context_analyzer")


class ReflectionContext(str, Enum):
    """Detected reflection contexts."""
    HTML_ATTRIBUTE_SINGLE = "html_attr_single"    # value='PROBE'
    HTML_ATTRIBUTE_DOUBLE = "html_attr_double"    # value="PROBE"
    HTML_TAG_BODY = "html_tag_body"               # <div>PROBE</div>
    HTML_COMMENT = "html_comment"                 # <!-- PROBE -->
    JAVASCRIPT_STRING_SINGLE = "js_string_single" # var x = 'PROBE'
    JAVASCRIPT_STRING_DOUBLE = "js_string_double" # var x = "PROBE"
    JAVASCRIPT_TEMPLATE = "js_template"           # var x = `PROBE`
    JAVASCRIPT_CODE = "js_code"                   # eval(PROBE)
    SCRIPT_TAG = "script_tag"                     # <script>PROBE</script>
    STYLE_TAG = "style_tag"                       # <style>PROBE</style>
    JSON_STRING = "json_string"                   # {"key": "PROBE"}
    URL_PARAMETER = "url_param"                   # href="?x=PROBE"
    SQL_ERROR = "sql_error"                       # SQL error with PROBE
    TEMPLATE_ENGINE = "template_engine"           # {{PROBE}} or ${PROBE}
    NO_REFLECTION = "no_reflection"               # Not reflected
    UNKNOWN = "unknown"                           # Reflected but context unclear


class ContextAnalyzer:
    """
    Analyzes response to detect WHERE the probe is reflected.
    Then maps context to appropriate breakout prefixes.
    """

    # Regex patterns to detect context
    CONTEXT_PATTERNS = {
        # HTML Attribute contexts
        ReflectionContext.HTML_ATTRIBUTE_SINGLE: [
            r"<\w+[^>]*\s+\w+='[^']*{probe}[^']*'",     # <input value='PROBE'>
            r"<\w+[^>]*\s+\w+='[^']*{probe}",            # <input value='PROBE (unclosed)
        ],
        ReflectionContext.HTML_ATTRIBUTE_DOUBLE: [
            r'<\w+[^>]*\s+\w+="[^"]*{probe}[^"]*"',     # <input value="PROBE">
            r'<\w+[^>]*\s+\w+="{probe}',                 # <input value="PROBE (unclosed)
        ],

        # JavaScript contexts
        ReflectionContext.JAVASCRIPT_STRING_SINGLE: [
            r"<script[^>]*>.*?'[^']*{probe}[^']*'",     # var x = 'PROBE'
            r"'[^']*{probe}[^']*'",                      # Generic JS single quote
        ],
        ReflectionContext.JAVASCRIPT_STRING_DOUBLE: [
            r'<script[^>]*>.*?"[^"]*{probe}[^"]*"',     # var x = "PROBE"
            r'"[^"]*{probe}[^"]*"',                      # Generic JS double quote
        ],
        ReflectionContext.JAVASCRIPT_TEMPLATE: [
            r'<script[^>]*>.*?`[^`]*{probe}[^`]*`',     # var x = `PROBE`
            r'`[^`]*{probe}[^`]*`',                      # Template literal
        ],
        ReflectionContext.SCRIPT_TAG: [
            r'<script[^>]*>{probe}',                     # <script>PROBE
            r'<script[^>]*>.*?{probe}.*?</script>',      # Inside script tag
        ],

        # Template engines
        ReflectionContext.TEMPLATE_ENGINE: [
            r'\{\{[^}]*{probe}[^}]*\}\}',                # {{PROBE}}
            r'\$\{[^}]*{probe}[^}]*\}',                  # ${PROBE}
            r'\{%[^%]*{probe}[^%]*%\}',                  # {% PROBE %}
        ],

        # HTML contexts
        ReflectionContext.HTML_TAG_BODY: [
            r'<\w+[^>]*>{probe}</\w+>',                  # <div>PROBE</div>
            r'<body[^>]*>.*?{probe}.*?</body>',          # Body content
        ],
        ReflectionContext.HTML_COMMENT: [
            r'<!--[^>]*{probe}[^>]*-->',                 # <!-- PROBE -->
        ],
        ReflectionContext.STYLE_TAG: [
            r'<style[^>]*>.*?{probe}.*?</style>',        # <style>PROBE</style>
        ],

        # JSON context
        ReflectionContext.JSON_STRING: [
            r'\{"[^"]*":\s*"[^"]*{probe}[^"]*"\}',       # {"key": "PROBE"}
            r'\["[^"]*{probe}[^"]*"\]',                  # ["PROBE"]
        ],

        # URL context
        ReflectionContext.URL_PARAMETER: [
            r'href="[^"]*\?[^"]*{probe}[^"]*"',          # href="?x=PROBE"
            r'src="[^"]*\?[^"]*{probe}[^"]*"',           # src="?x=PROBE"
        ],

        # SQL errors
        ReflectionContext.SQL_ERROR: [
            r'(SQL|MySQL|PostgreSQL|Oracle).*error.*{probe}',
            r'syntax error.*{probe}',
            r'near.*{probe}',
        ],
    }

    # Map context to appropriate breakout prefixes
    CONTEXT_BREAKOUTS = {
        ReflectionContext.HTML_ATTRIBUTE_SINGLE: [
            "'", "'>", "'><", "' onload='", "' autofocus onfocus='", "'//", "'><svg/onload="
        ],
        ReflectionContext.HTML_ATTRIBUTE_DOUBLE: [
            '"', '">', '"><', '" onload="', '" autofocus onfocus="', '"//','"><svg/onload='
        ],
        ReflectionContext.HTML_TAG_BODY: [
            "<", "</", "><", "<script>", "<img src=x onerror=", "<svg/onload=", "<!--"
        ],
        ReflectionContext.JAVASCRIPT_STRING_SINGLE: [
            "';", "'//", "'+", "'-", "')", "\\n", "\\'", "`"
        ],
        ReflectionContext.JAVASCRIPT_STRING_DOUBLE: [
            '";', '"//', '"+', '"-', '")', "\\n", '\\"', "`"
        ],
        ReflectionContext.JAVASCRIPT_TEMPLATE: [
            "`", "${", "\\n", "}}", "'+", '"+', ";"
        ],
        ReflectionContext.SCRIPT_TAG: [
            "</script><", ";", "//", "/*", "*/", "'", '"', "`"
        ],
        ReflectionContext.TEMPLATE_ENGINE: [
            "{{", "}}", "${", "{%", "%}", "<%", "%>", "#{", "]]", "[[", "*{", "}*"
        ],
        ReflectionContext.HTML_COMMENT: [
            "-->", "--!>", "--><", "><!--"
        ],
        ReflectionContext.JSON_STRING: [
            '"', '",', '"}', '"]', '\\"', "\\n"
        ],
        ReflectionContext.SQL_ERROR: [
            "'", '"', "'--", "'#", "'/*", "')", "')--", "'))--", "' OR '1'='1", "' UNION"
        ],
        ReflectionContext.URL_PARAMETER: [
            "&", "?", "#", "%0a", "%0d%0a", "../", "javascript:", "data:"
        ],
        ReflectionContext.STYLE_TAG: [
            "</style><", "}", ";", "/*", "*/"
        ],
    }

    def __init__(self, probe_marker: str = "bugtraceomni7x9z"):
        self.probe_marker = probe_marker

    def analyze_reflection(self, response_body: str, probe: str = None) -> Dict:
        """
        Analyze response to detect reflection context.

        Args:
            response_body: HTTP response body
            probe: Probe string to look for (default: self.probe_marker)

        Returns:
            {
                "contexts": [ReflectionContext, ...],
                "confidence": float,
                "recommended_breakouts": [str, ...],
                "analysis": str
            }
        """
        probe = probe or self.probe_marker

        if probe not in response_body:
            return {
                "contexts": [ReflectionContext.NO_REFLECTION],
                "confidence": 1.0,
                "recommended_breakouts": [],
                "analysis": "Probe not reflected in response"
            }

        # Detect all matching contexts
        detected_contexts = self._detect_contexts(response_body, probe)

        if not detected_contexts:
            return {
                "contexts": [ReflectionContext.UNKNOWN],
                "confidence": 0.5,
                "recommended_breakouts": self._get_generic_breakouts(),
                "analysis": f"Probe reflected but context unclear. Found at: {self._get_reflection_snippet(response_body, probe)}"
            }

        # Get breakouts for all detected contexts
        recommended_breakouts = self._merge_breakouts(detected_contexts)

        analysis = self._generate_analysis(detected_contexts, response_body, probe)

        return {
            "contexts": detected_contexts,
            "confidence": 0.9,
            "recommended_breakouts": recommended_breakouts,
            "analysis": analysis
        }

    def _detect_contexts(self, response: str, probe: str) -> List[ReflectionContext]:
        """Detect all reflection contexts in response."""
        detected = []

        for context, patterns in self.CONTEXT_PATTERNS.items():
            for pattern in patterns:
                # Use replace instead of format to avoid issues with { and } in regex
                regex = pattern.replace('{probe}', re.escape(probe))
                if re.search(regex, response, re.IGNORECASE | re.DOTALL):
                    detected.append(context)
                    break  # Found match for this context, move to next

        return detected

    def _merge_breakouts(self, contexts: List[ReflectionContext]) -> List[str]:
        """Merge breakouts from multiple contexts, removing duplicates."""
        breakouts = set()

        for context in contexts:
            if context in self.CONTEXT_BREAKOUTS:
                breakouts.update(self.CONTEXT_BREAKOUTS[context])

        return sorted(list(breakouts))

    def _get_generic_breakouts(self) -> List[str]:
        """Fallback breakouts when context is unclear."""
        return ["'", '"', "'>", '">','<', '>', ';', '{{', '${', '</script><']

    def _get_reflection_snippet(self, response: str, probe: str, context_size: int = 100) -> str:
        """Extract snippet showing where probe is reflected."""
        index = response.find(probe)
        if index == -1:
            return ""

        start = max(0, index - context_size)
        end = min(len(response), index + len(probe) + context_size)
        snippet = response[start:end]

        # Highlight probe
        snippet = snippet.replace(probe, f">>>{probe}<<<")
        return f"...{snippet}..."

    def _generate_analysis(self, contexts: List[ReflectionContext], response: str, probe: str) -> str:
        """Generate human-readable analysis."""
        context_names = [ctx.value for ctx in contexts]
        snippet = self._get_reflection_snippet(response, probe, 80)

        return f"Detected contexts: {', '.join(context_names)}. Reflection: {snippet}"


# Singleton
context_analyzer = ContextAnalyzer()
