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


class TechContextAccessMixin:
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
