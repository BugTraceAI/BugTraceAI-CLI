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


class TechContextLoadMixin:
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
            tag_lower = (tag or "").lower()
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
                framework_lower = (framework or "").lower()
                for fw_hint, db_type in FRAMEWORK_TO_DB.items():
                    if fw_hint in framework_lower:
                        stack["db"] = db_type
                        logger.debug(f"Database inferred from framework '{framework}': {db_type}")
                        break
                if stack["db"] != "generic":
                    break

        # 3. Server detection
        for server in servers:
            server_lower = (server or "").lower()
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
