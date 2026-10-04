"""Template engine fingerprinter for CSTI/SSTI."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)

class TemplateEngineFingerprinter:
    """Detect which template engine is in use."""

    ENGINE_SIGNATURES = {
        "angular": {
            "patterns": ["ng-app", "ng-model", "ng-bind", "angular.js", "angular.min.js"],
            "probe": "{{constructor.constructor('return 1')()}}",
            "success_indicator": "1"
        },
        "vue": {
            "patterns": ["v-if", "v-for", "v-model", "vue.js", "vue.min.js"],
            "probe": "{{1000003*1000003}}",
            "success_indicator": "1000006000009"
        },
        "jinja2": {
            "patterns": ["jinja", "flask", "werkzeug"],
            "probe": "{{config}}",
            "success_indicator": "Config"
        },
        "twig": {
            "patterns": ["twig", "symfony"],
            "probe": "{{1000003*1000003}}",
            "success_indicator": "1000006000009"
        },
        "freemarker": {
            "patterns": ["freemarker", ".ftl"],
            "probe": "${1000003*1000003}",
            "success_indicator": "1000006000009"
        },
        "velocity": {
            "patterns": ["velocity", ".vm"],
            "probe": "#set($x=1000003*1000003)$x",
            "success_indicator": "1000006000009"
        },
        "mako": {
            "patterns": ["mako"],
            "probe": "${1000003*1000003}",
            "success_indicator": "1000006000009"
        },
        "pebble": {
            "patterns": ["pebble"],
            "probe": "{{ 1000003*1000003 }}",
            "success_indicator": "1000006000009"
        },
        "smarty": {
            "patterns": ["smarty"],
            "probe": "{$smarty.version}",
            "success_indicator": "Smarty"
        },
        "erb": {
            "patterns": ["erb", "ruby", "rails"],
            "probe": "<%= 1000003*1000003 %>",
            "success_indicator": "1000006000009"
        }
    }

    @classmethod
    def fingerprint(cls, html: str, headers: dict = None) -> List[str]:
        """Return list of likely template engines."""
        detected = []
        html_lower = html.lower()

        for engine, data in cls.ENGINE_SIGNATURES.items():
            for pattern in data["patterns"]:
                if pattern.lower() in html_lower:
                    detected.append(engine)
                    break

        return detected if detected else ["unknown"]

