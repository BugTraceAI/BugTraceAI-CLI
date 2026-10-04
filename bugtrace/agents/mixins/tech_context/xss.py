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


class TechContextXssMixin:
    def generate_xss_context_prompt(self, stack: Dict) -> str:
        """
        Generate XSS-specific 'Prime Directive' context block for LLM prompts.

        This context helps the LLM focus on relevant XSS payloads and techniques
        based on the detected technology stack.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted XSS-focused prompt section
        """
        server = stack.get("server", "Unknown")
        lang = stack.get("lang", "Unknown")
        waf = stack.get("waf")
        frameworks = stack.get("frameworks", [])
        raw_profile = stack.get("raw_profile", {})

        # Detect frontend frameworks from tech tags
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        frontend_frameworks = self._detect_frontend_frameworks(frameworks, tech_tags)

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (XSS CONTEXT)",
            f"- Web Server: {server}",
            f"- Backend Language: {lang}",
        ]

        if frontend_frameworks:
            prompt_parts.append(f"- Frontend Frameworks: {', '.join(frontend_frameworks)}")

        if frameworks:
            prompt_parts.append(f"- Backend Frameworks: {', '.join(frameworks[:3])}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        # Strategic implications based on detected stack
        prompt_parts.append("")
        prompt_parts.append("## XSS STRATEGIC IMPLICATIONS")

        # Frontend framework-specific guidance
        if "react" in frontend_frameworks:
            prompt_parts.extend([
                "- React detected: dangerouslySetInnerHTML is primary vector",
                "- React: Focus on server-side rendering (SSR) XSS if Next.js detected",
                "- React: Look for DOM-based XSS via useRef, getElementById patterns",
            ])
        if "angular" in frontend_frameworks:
            prompt_parts.extend([
                "- Angular detected: bypassSecurityTrust* functions are key vectors",
                "- Angular: Template injection via {{ }} interpolation (CSTI overlap)",
                "- Angular: Look for [innerHTML] binding misuse",
            ])
        if "vue" in frontend_frameworks:
            prompt_parts.extend([
                "- Vue detected: v-html directive is primary vector",
                "- Vue: Template injection via {{ }} interpolation",
                "- Vue: Look for :href and @click event handler injection",
            ])

        # Backend-specific XSS guidance
        if lang != "generic" and lang != "Unknown":
            prompt_parts.append(f"- Backend ({lang}): Check for improper output encoding")

            if lang == "PHP":
                prompt_parts.extend([
                    "- PHP: Look for echo/print without htmlspecialchars()",
                    "- PHP: WordPress has many unescaped shortcode patterns",
                ])
            elif lang == "Python":
                prompt_parts.extend([
                    "- Python: Jinja2 |safe filter, mark_safe() are vectors",
                    "- Python: Django autoescape may be disabled in templates",
                ])
            elif lang == "Node.js":
                prompt_parts.extend([
                    "- Node.js: EJS <%- %> unescaped output, Pug != operator",
                    "- Node.js: Express res.send() without encoding",
                ])
            elif lang == "Java":
                prompt_parts.extend([
                    "- Java: JSP scriptlets, EL expressions ${} are vectors",
                    "- Java: Spring Thymeleaf th:utext for unescaped output",
                ])
            elif lang == "ASP.NET":
                prompt_parts.extend([
                    "- ASP.NET: @Html.Raw(), Response.Write() without encoding",
                    "- ASP.NET: Razor <%: %> vs <%= %> (unescaped)",
                ])

        # WAF evasion strategies
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Apply evasion techniques:",
                "  * Case variation: <ScRiPt>, <IMG SRC=x>",
                "  * Event handlers: onfocus, onmouseover (avoid onclick)",
                "  * Encoding: HTML entities, Unicode, double-encoding",
                "  * Tag alternatives: <svg>, <math>, <details>",
                "  * Payloads without spaces: <svg/onload=alert(1)>",
            ])
        else:
            prompt_parts.append("- No WAF detected: Standard payloads likely effective")

        return "\n".join(prompt_parts)

    def generate_xss_dedup_context(self, stack: Dict) -> str:
        """
        Generate XSS-specific context for WET→DRY deduplication prompts.

        XSS deduplication must consider:
        - Injection context (HTML body, attribute, JavaScript, URL)
        - Same parameter in different contexts = DIFFERENT vulnerabilities
        - Same parameter with same context = DUPLICATE

        Args:
            stack: Normalized tech stack

        Returns:
            XSS deduplication-focused context string
        """
        lang = stack.get("lang", "generic")
        waf = stack.get("waf")
        frameworks = stack.get("frameworks", [])

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR XSS DEDUPLICATION",
            f"- Detected Backend: {lang}",
            f"- WAF Present: {'Yes - ' + waf if waf else 'No'}",
            "",
            "## XSS DEDUPLICATION RULES",
            "",
            "### Context-Based Deduplication (CRITICAL)",
            "XSS findings are DIFFERENT if injection context differs, even for same URL+param:",
            "- HTML Body context: <div>PAYLOAD</div>",
            "- HTML Attribute context: <input value=\"PAYLOAD\">",
            "- JavaScript String context: var x = 'PAYLOAD';",
            "- JavaScript Template context: `${PAYLOAD}`",
            "- URL/href context: <a href=\"PAYLOAD\">",
            "- CSS context: style=\"background:url(PAYLOAD)\"",
            "",
            "### Scope Rules",
            "- Reflected XSS: PER-ENDPOINT scope (same param on different pages = DIFFERENT)",
            "- DOM XSS: PER-PAGE scope (different DOM sinks = DIFFERENT)",
            "- Stored XSS: GLOBAL scope (same storage location = DUPLICATE)",
            "",
            "### Examples",
            "- param 'q' @ /search (HTML body) ≠ param 'q' @ /search (JS context) → DIFFERENT",
            "- param 'id' @ /page?id=1 = param 'id' @ /page?id=2 (same context) → DUPLICATE",
            "- param 'name' @ /profile ≠ param 'name' @ /settings → DIFFERENT endpoints",
        ]

        # Framework-specific dedup notes
        if any("angular" in f.lower() for f in frameworks):
            context_parts.append("- Angular: Template injection and DOM XSS are DIFFERENT vuln types")
        if any("react" in f.lower() for f in frameworks):
            context_parts.append("- React: SSR XSS vs DOM XSS are DIFFERENT vulnerability classes")

        return "\n".join(context_parts)
