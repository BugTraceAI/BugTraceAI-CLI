"""
CSTI Engine Detection

PURE functions for template engine detection, classification, and fingerprinting.
No I/O, no self, no state mutation.
"""

import re
from typing import Dict, List, Optional


# =========================================================================
# ENGINE SIGNATURES: Patterns and probes for each template engine
# =========================================================================

ENGINE_SIGNATURES: Dict[str, Dict] = {
    "angular": {
        "patterns": ["ng-app", "ng-model", "ng-bind", "angular.js", "angular.min.js"],
        "probe": "{{constructor.constructor('return 1')()}}",
        "success_indicator": "1",
    },
    "vue": {
        "patterns": ["v-if", "v-for", "v-model", "vue.js", "vue.min.js"],
        "probe": "{{7*7}}",
        "success_indicator": "49",
    },
    "jinja2": {
        "patterns": ["jinja", "flask", "werkzeug"],
        "probe": "{{config}}",
        "success_indicator": "Config",
    },
    "twig": {
        "patterns": ["twig", "symfony"],
        "probe": "{{7*7}}",
        "success_indicator": "49",
    },
    "freemarker": {
        "patterns": ["freemarker", ".ftl"],
        "probe": "${7*7}",
        "success_indicator": "49",
    },
    "velocity": {
        "patterns": ["velocity", ".vm"],
        "probe": "#set($x=7*7)$x",
        "success_indicator": "49",
    },
    "mako": {
        "patterns": ["mako"],
        "probe": "${7*7}",
        "success_indicator": "49",
    },
    "pebble": {
        "patterns": ["pebble"],
        "probe": "{{ 7*7 }}",
        "success_indicator": "49",
    },
    "smarty": {
        "patterns": ["smarty"],
        "probe": "{$smarty.version}",
        "success_indicator": "Smarty",
    },
    "erb": {
        "patterns": ["erb", "ruby", "rails"],
        "probe": "<%= 7*7 %>",
        "success_indicator": "49",
    },
}

# Engines that run in the browser (client-side template injection)
CLIENT_SIDE_ENGINES = {"angular", "vue", "knockout", "ember", "react"}


def fingerprint_engines(html: str, headers: Optional[dict] = None) -> List[str]:  # PURE
    """
    Return list of likely template engines detected from HTML content.

    Args:
        html: HTML page content
        headers: Optional HTTP response headers (reserved for future use)

    Returns:
        List of engine names detected, or ["unknown"] if none found
    """
    detected = []
    html_lower = html.lower()

    for engine, data in ENGINE_SIGNATURES.items():
        for pattern in data["patterns"]:
            if pattern.lower() in html_lower:
                detected.append(engine)
                break

    return detected if detected else ["unknown"]


def detect_engine_from_payload(
    payload: str,
    tech_profile: Optional[Dict] = None,
    tech_stack_context: Optional[Dict] = None,
) -> str:  # PURE
    """
    Detect the template engine based on payload syntax.

    Args:
        payload: The injection payload string
        tech_profile: Optional tech profile from recon (has 'frameworks' key)
        tech_stack_context: Optional tech stack context (has 'frameworks' key)

    Returns:
        Engine name string (e.g. 'angular', 'jinja2', 'twig', 'unknown')
    """
    if "{{" in payload and "}}" in payload:
        return _detect_curly_brace_engine(payload, tech_profile, tech_stack_context)
    if "${" in payload:
        return "freemarker"
    if "#set" in payload or "$!" in payload:
        return "velocity"
    if "{%" in payload:
        return "jinja2"
    return "unknown"


def _detect_curly_brace_engine(
    payload: str,
    tech_profile: Optional[Dict] = None,
    tech_stack_context: Optional[Dict] = None,
) -> str:  # PURE
    """Detect engine for curly brace {{ }} syntax."""
    # AngularJS detection (client-side)
    if "constructor" in payload.lower() or "$on" in payload or "$eval" in payload:
        return "angular"

    # Vue.js detection (client-side)
    if "$emit" in payload or "v-" in payload:
        return "vue"

    # Jinja2 detection (server-side)
    if "__class__" in payload or "config" in payload or "lipsum" in payload:
        return "jinja2"

    # Mako detection (server-side)
    if "${" in payload or "%>" in payload:
        return "mako"

    # Check tech_profile from fingerprinting before defaulting
    if tech_profile and tech_profile.get("frameworks"):
        for fw in tech_profile["frameworks"]:
            fw_lower = fw.lower()
            if "angular" in fw_lower:
                return "angular"
            if "vue" in fw_lower:
                return "vue"

    # Also check tech_stack_context (set by queue consumer)
    if tech_stack_context:
        for fw in tech_stack_context.get("frameworks", []):
            fw_lower = fw.lower()
            if "angular" in fw_lower:
                return "angular"
            if "vue" in fw_lower:
                return "vue"

    # Default to twig for unidentified {{ }} syntax (server-side)
    return "twig"


def classify_engine_type(engine: str) -> str:  # PURE
    """
    Classify engine as client-side or server-side.

    Args:
        engine: Engine name string

    Returns:
        'client-side' or 'server-side'
    """
    if engine.lower() in CLIENT_SIDE_ENGINES:
        return "client-side"
    return "server-side"


def is_client_side_engine(engine: str) -> bool:  # PURE
    """Check if the given engine is client-side (Angular, Vue, etc.)."""
    return engine.lower() in CLIENT_SIDE_ENGINES


def try_alternative_engine(current_engine: str) -> str:  # PURE
    """
    Return a payload for a different engine.

    Args:
        current_engine: The engine that already failed

    Returns:
        A payload string for an alternative engine
    """
    payloads = {
        "jinja2": "{{7*7}}",
        "twig": "{{7*7}}",
        "freemarker": "${7*7}",
        "velocity": "#set($x=7*7)$x",
        "pebble": "{{7*7}}",
        "thymeleaf": "[[${7*7}]]",
    }

    for engine, payload in payloads.items():
        if engine != current_engine:
            return payload

    return "{{7*7}}"


def encode_template_chars(payload: str, stripped: List[str]) -> str:  # PURE
    """
    Encode characters that were filtered by the server.

    Args:
        payload: Original payload string
        stripped: List of characters that were stripped/filtered

    Returns:
        Encoded payload with filtered characters replaced
    """
    result = payload

    # If braces were filtered, try alternative syntax
    if "{" in stripped or "}" in stripped:
        result = result.replace("{{", "${").replace("}}", "}")

    # URL encoding for other characters
    for char in stripped:
        if char not in "{}":
            result = result.replace(char, f"%{ord(char):02X}")

    return result
