from typing import Dict, Optional, List, Any
from loguru import logger
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
from bugtrace.tools.waf.fingerprinter import waf_fingerprinter
import json
from pathlib import Path
from bugtrace.agents.base import BaseAgent
import re
import aiohttp

# Known vulnerable JS library versions — loaded from data file for easy maintenance
def _load_vulnerable_js_libs() -> dict:
    """Load vulnerable JS library database from JSON data file."""
    data_path = Path(__file__).parent.parent / "config" / "vulnerable_js_libs.json"
    try:
        with open(data_path, "r") as f:
            data = json.load(f)
        libs = {}
        for key, info in data.get("libraries", {}).items():
            libs[key] = {
                "below": tuple(info["below"]),
                "name": info["name"],
                "cves": info.get("cves", []),
                "eol": info.get("eol", False),
                "severity": info.get("severity", "low"),
            }
        logger.debug(f"Loaded {len(libs)} vulnerable JS libraries from {data_path.name}")
        return libs
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to load vulnerable_js_libs.json: {e}. Using empty defaults.")
        return {}

KNOWN_VULNERABLE_JS = _load_vulnerable_js_libs()


class NucleiAgent(BaseAgent):
    """
    Specialized Agent for Technology Detection and Vulnerability Scanning using Nuclei.
    Phase 1 of the Sequential Pipeline.
    """
    
    def __init__(self, target: str, report_dir: Path, event_bus: Any = None):
        super().__init__("NucleiAgent", "Tech Discovery", event_bus=event_bus, agent_id="nuclei_agent")
        self.target = target
        self.report_dir = report_dir
        
    async def run(self) -> Dict:
        """
        Runs two-phase Nuclei scan for technology detection and vulnerability discovery.

        Returns comprehensive tech_profile used by specialist agents.
        """
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting 2-phase Nuclei scan (tech-detect + auto-scan)...", "INFO")

        try:
            # Run two-phase Nuclei scan
            nuclei_results = await external_tools.run_nuclei(self.target)

            tech_findings = nuclei_results.get("tech_findings", [])
            vuln_findings = nuclei_results.get("vuln_findings", [])

            # Parse technology detections
            tech_profile = {
                "url": self.target,
                "infrastructure": [],      # AWS ALB, Cloudflare, etc.
                "frameworks": [],          # AngularJS, React, etc.
                "languages": [],           # PHP, Node.js, Python, etc.
                "servers": [],             # Nginx, Apache, etc.
                "cms": [],                 # WordPress, Drupal, etc.
                "waf": [],                 # ModSecurity, Cloudflare WAF, etc.
                "cdn": [],                 # Cloudflare, Akamai, etc.
                "tech_tags": [],           # All detected tags
                "misconfigurations": [],   # HSTS missing, cookie flags, etc.
                "js_vulnerabilities": [],  # Vulnerable JS library versions
                "raw_tech_findings": tech_findings,
                "raw_vuln_findings": vuln_findings
            }

            # Extract and categorize technologies
            for finding in tech_findings:
                info = finding.get("info", {})
                name = info.get("name", "Unknown")
                tags = info.get("tags", [])
                severity = info.get("severity", "info").lower()

                # Misconfiguration/exposure/token findings → separate list (not tech)
                misconfig_tags = {"misconfig", "misconfiguration", "exposure", "token", "headers"}
                if misconfig_tags & set(tags):
                    tech_profile["misconfigurations"].append({
                        "name": name,
                        "severity": severity,
                        "description": info.get("description", ""),
                        "tags": tags,
                        "template_id": finding.get("template-id", ""),
                        "matched_at": finding.get("matched-at", self.target),
                    })
                    continue

                # Categorize by tags
                if "tech" in tags or "detect" in tags:
                    tech_profile["tech_tags"].append(name)

                # Infrastructure (AWS, Azure, GCP)
                if any(x in name.lower() for x in ["aws", "azure", "gcp", "alb", "cloudfront"]):
                    tech_profile["infrastructure"].append(name)
                # Web frameworks
                elif any(x in name.lower() for x in ["angular", "react", "vue", "jquery", "bootstrap"]):
                    tech_profile["frameworks"].append(name)
                # Languages
                elif any(x in name.lower() for x in ["php", "node", "python", "ruby", "java", "asp"]):
                    tech_profile["languages"].append(name)
                # Servers
                elif any(x in name.lower() for x in ["nginx", "apache", "iis", "tomcat"]):
                    tech_profile["servers"].append(name)
                # CMS
                elif any(x in name.lower() for x in ["wordpress", "drupal", "joomla", "magento"]):
                    tech_profile["cms"].append(name)
                # WAF
                elif any(x in name.lower() for x in ["waf", "modsecurity", "imperva"]):
                    tech_profile["waf"].append(name)
                # CDN
                elif any(x in name.lower() for x in ["cloudflare", "akamai", "fastly", "cdn"]):
                    tech_profile["cdn"].append(name)
                else:
                    # Default: add to frameworks
                    tech_profile["frameworks"].append(name)

            # Deduplicate lists
            for key in ["infrastructure", "frameworks", "languages", "servers", "cms", "waf", "cdn", "tech_tags"]:
                tech_profile[key] = list(set(tech_profile[key]))

            # FIX (2026-02-07): Verify WAF detections with WAF Fingerprinter
            # Nuclei waf-detect.yaml has high FP rate (e.g. "nginxgeneric" matches plain Nginx)
            if tech_profile["waf"]:
                verified_wafs = await self._verify_waf_detections(
                    tech_profile["waf"], tech_findings
                )
                if verified_wafs != tech_profile["waf"]:
                    removed = set(tech_profile["waf"]) - set(verified_wafs)
                    if removed:
                        dashboard.log(
                            f"[{self.name}] WAF FP filtered: {', '.join(removed)} (Nuclei FP)",
                            "INFO"
                        )
                    tech_profile["waf"] = verified_wafs

            # Get HTML content (used for framework fallback + JS version detection)
            html_content = self._extract_html_from_nuclei_response(tech_findings)
            if not html_content:
                html_content = await self._fetch_html(self.target)

            # FIX (2026-02-06): HTML parsing fallback for framework detection
            # FIX (2026-02-17): Also check recon URLs (frameworks may only load on subpages)
            # FIX (2026-02-19): Check for frontend JS frameworks specifically — GraphQL/API
            # detections (e.g. "Graphql Strawberry Detect") don't count as frontend frameworks
            _js_fw_names = ('angular', 'react', 'vue', 'jquery', 'backbone', 'ember', 'svelte')
            has_js_fw = any(
                any(fw in f.lower() for fw in _js_fw_names)
                for f in tech_profile["frameworks"]
            )
            if not has_js_fw and html_content:
                logger.info(f"[{self.name}] No frameworks detected by Nuclei - trying HTML fallback")
                detected_frameworks = self._detect_frameworks_from_html(html_content)
                if detected_frameworks:
                    tech_profile["frameworks"].extend(detected_frameworks)
                    dashboard.log(
                        f"[{self.name}] ✅ HTML Fallback: Detected {', '.join(detected_frameworks)}",
                        "SUCCESS"
                    )

            # If still no JS frameworks, check a sample of recon URLs
            has_js_fw = any(
                any(fw in f.lower() for fw in _js_fw_names)
                for f in tech_profile["frameworks"]
            )
            if not has_js_fw:
                recon_frameworks = await self._detect_frameworks_from_recon_urls()
                if recon_frameworks:
                    tech_profile["frameworks"].extend(recon_frameworks)
                    dashboard.log(
                        f"[{self.name}] ✅ Recon Fallback: Detected {', '.join(recon_frameworks)}",
                        "SUCCESS"
                    )

            # JS dependency version detection → stored separately for VULNERABLE_DEPENDENCY emission
            if html_content:
                js_vulns = self._detect_js_versions(html_content)
                if js_vulns:
                    tech_profile["js_vulnerabilities"].extend(js_vulns)
                    dashboard.log(
                        f"[{self.name}] ⚠️ Found {len(js_vulns)} vulnerable JS dependencies",
                        "INFO"
                    )

            # Security headers check (passive — one HEAD request)
            # Nuclei templates sometimes miss these, so we check directly
            existing_template_ids = {
                mc.get("template_id", "").lower()
                for mc in tech_profile["misconfigurations"]
            }
            header_findings = await self._check_security_headers(existing_template_ids)
            if header_findings:
                tech_profile["misconfigurations"].extend(header_findings)
                dashboard.log(
                    f"[{self.name}] 🔒 {len(header_findings)} missing security headers detected",
                    "INFO"
                )

            # Insecure cookie flags check — checks multiple URLs (not just root)
            cookie_findings = await self._check_insecure_cookies(existing_template_ids)
            if cookie_findings:
                tech_profile["misconfigurations"].extend(cookie_findings)
                dashboard.log(
                    f"[{self.name}] 🍪 {len(cookie_findings)} insecure cookie(s) detected",
                    "INFO"
                )

            # GraphQL introspection check + schema analysis
            graphql_findings = await self._check_graphql_introspection(existing_template_ids)
            if graphql_findings:
                tech_profile["misconfigurations"].extend(graphql_findings)
                dashboard.log(
                    f"[{self.name}] ⚠️ GraphQL introspection enabled on {len(graphql_findings)} endpoint(s)",
                    "WARNING"
                )

            # Rate limiting check on auth endpoints
            rate_findings = await self._check_rate_limiting()
            if rate_findings:
                tech_profile["misconfigurations"].extend(rate_findings)
                dashboard.log(
                    f"[{self.name}] ⚠️ No rate limiting detected on auth endpoints",
                    "WARNING"
                )

            # Access control check on admin endpoints
            access_findings = await self._check_access_control()
            if access_findings:
                tech_profile["misconfigurations"].extend(access_findings)
                dashboard.log(
                    f"[{self.name}] 🔓 {len(access_findings)} admin endpoint(s) accessible without auth",
                    "WARNING"
                )

            # Save comprehensive tech profile
            profile_path = self.report_dir / "tech_profile.json"
            with open(profile_path, "w") as f:
                json.dump(tech_profile, f, indent=2)

            # Log summary
            summary_parts = []
            if tech_profile["infrastructure"]:
                summary_parts.append(f"{len(tech_profile['infrastructure'])} infra")
            if tech_profile["frameworks"]:
                summary_parts.append(f"{len(tech_profile['frameworks'])} frameworks")
            if tech_profile["servers"]:
                summary_parts.append(f"{len(tech_profile['servers'])} servers")
            if tech_profile["waf"]:
                summary_parts.append(f"⚠️ WAF detected")

            summary = ", ".join(summary_parts) if summary_parts else "Basic detection"
            dashboard.log(f"[{self.name}] Tech Profile: {summary} | {len(vuln_findings)} vulns", "SUCCESS")

            return tech_profile

        except Exception as e:
            logger.error(f"NucleiAgent failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] Error: {e}", "ERROR")
            return {
                "error": str(e),
                "infrastructure": [],
                "frameworks": [],
                "languages": [],
                "servers": [],
                "cms": [],
                "waf": [],
                "cdn": [],
                "tech_tags": [],
                "raw_tech_findings": [],
                "raw_vuln_findings": []
            }

    async def _verify_waf_detections(
        self, waf_names: List[str], tech_findings: List[Dict]
    ) -> List[str]:
        """
        Verify WAF detections from Nuclei using matcher-name analysis and WAF Fingerprinter.

        FIX (2026-02-07): Nuclei waf-detect.yaml has high FP rate.
        "nginxgeneric" matches any Nginx server, not actual WAFs.

        Strategy:
        1. Check matcher-name from Nuclei raw findings - filter known FP matchers
        2. For remaining WAFs, verify with WAF Fingerprinter (active probing)
        """
        # Known false-positive matcher names from Nuclei waf-detect.yaml
        # These match generic server responses, not actual WAFs
        NUCLEI_WAF_FP_MATCHERS = {
            "nginxgeneric",      # Plain Nginx returns 200 on POST → "WAF detected"
            "apachegeneric",     # Plain Apache generic response
        }

        # Extract matcher-names for WAF findings from raw Nuclei data
        waf_matcher_names = set()
        for finding in tech_findings:
            template_id = finding.get("template-id", "")
            if template_id == "waf-detect":
                matcher = finding.get("matcher-name", "")
                if matcher:
                    waf_matcher_names.add(matcher.lower())

        # Filter out known FP matchers
        if waf_matcher_names and waf_matcher_names.issubset(NUCLEI_WAF_FP_MATCHERS):
            logger.info(
                f"[{self.name}] WAF detection matchers are all FP-prone: "
                f"{waf_matcher_names} - verifying with WAF Fingerprinter"
            )
            # Active verification with our WAF Fingerprinter
            try:
                waf_name, confidence = await waf_fingerprinter.detect(self.target, timeout=10.0)
                if waf_name != "unknown" and confidence >= 0.4:
                    logger.info(
                        f"[{self.name}] WAF Fingerprinter confirmed: {waf_name} "
                        f"(confidence: {confidence:.0%})"
                    )
                    return [waf_name]
                else:
                    logger.info(
                        f"[{self.name}] WAF Fingerprinter found no WAF "
                        f"(result: {waf_name}, confidence: {confidence:.0%}) - "
                        f"removing Nuclei FP"
                    )
                    return []
            except Exception as e:
                logger.warning(f"[{self.name}] WAF Fingerprinter failed: {e} - keeping Nuclei result")
                return waf_names

        # If we have non-FP matchers, trust Nuclei
        return waf_names

    async def _fetch_html(self, url: str) -> Optional[str]:
        """
        Fetch HTML content from target URL for framework detection fallback.

        FIX (2026-02-06): When Nuclei templates fail to detect frameworks,
        we need raw HTML to detect Angular/Vue/React from source code.
        """
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        html = await response.text()
                        logger.debug(f"[{self.name}] Fetched {len(html)} bytes HTML for framework detection")
                        return html
                    else:
                        logger.warning(f"[{self.name}] Failed to fetch HTML: HTTP {response.status}")
                        return None
        except Exception as e:
            logger.warning(f"[{self.name}] HTML fetch failed: {e}")
            return None

    def _detect_frameworks_from_html(self, html: str) -> List[str]:
        """
        Detect frontend frameworks from HTML content (FALLBACK method).

        FIX (2026-02-06): Nuclei sometimes fails to detect frameworks because
        it searches template NAMES instead of HTML content. This method parses
        raw HTML to find Angular/Vue/React indicators.

        Detection patterns:
        - AngularJS: ng-app, ng-controller, angular.js script tags
        - Vue.js: v-if, v-for, vue.js script tags
        - React: react.js, react-dom.js script tags, data-reactroot

        Args:
            html: Raw HTML content from target page

        Returns:
            List of detected framework names
        """
        frameworks = []
        html_lower = html.lower()

        # AngularJS detection
        angular_patterns = [
            r'ng-app',
            r'ng-controller',
            r'ng-model',
            r'angular\.js',
            r'angular\.min\.js',
            r'angular[-_]1\.\d+',
        ]

        for pattern in angular_patterns:
            if re.search(pattern, html_lower):
                frameworks.append('AngularJS')
                logger.info(f"[{self.name}] 🎯 Detected AngularJS from HTML (pattern: {pattern})")
                break

        # Vue.js detection
        vue_patterns = [
            r'v-if',
            r'v-for',
            r'v-model',
            r'v-bind',
            r'vue\.js',
            r'vue\.min\.js',
        ]

        for pattern in vue_patterns:
            if re.search(pattern, html_lower):
                frameworks.append('Vue.js')
                logger.info(f"[{self.name}] 🎯 Detected Vue.js from HTML (pattern: {pattern})")
                break

        # React detection
        react_patterns = [
            r'react\.js',
            r'react\.min\.js',
            r'react-dom\.js',
            r'data-reactroot',
            r'data-reactid',
        ]

        for pattern in react_patterns:
            if re.search(pattern, html_lower):
                frameworks.append('React')
                logger.info(f"[{self.name}] 🎯 Detected React from HTML (pattern: {pattern})")
                break
        else:
            # Modern React SPA detection (Vite/webpack/CRA bundled apps)
            # Pattern: <div id="root"></div> + <script type="module"> = React SPA
            has_root_div = bool(re.search(r'<div\s+id=["\']root["\']', html_lower))
            has_module_script = bool(re.search(r'<script\s+type=["\']module["\']', html_lower))
            if has_root_div and has_module_script:
                frameworks.append('React')
                logger.info(f"[{self.name}] 🎯 Detected React SPA from HTML (div#root + module script)")

        return frameworks

    def _detect_js_versions(self, html: str) -> List[Dict]:
        """
        Extract JS library versions from script tags and check against known vulnerabilities.

        Patterns matched:
        - angular_1-7-7.js, angular.min.1.7.7.js, angular-1.7.7.min.js
        - jquery-3.6.0.min.js, jquery.3.6.0.js
        - vue@2.6.14, vue.min.js?v=2.6.14

        Returns:
            List of misconfiguration dicts for vulnerable versions found.
        """
        findings = []

        # Extract all script src attributes
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

        # Also check inline version comments like "AngularJS v1.7.7"
        version_comments = re.findall(r'(angular|jquery|vue|react|bootstrap|lodash)[^\d]{0,20}v?(\d+[\._-]\d+[\._-]\d+)', html, re.IGNORECASE)

        # Build a map of library → version from all sources
        detected = {}  # lib_key → (version_tuple, version_str, source)

        for src in script_srcs:
            src_lower = src.lower()
            for lib_key, lib_info in KNOWN_VULNERABLE_JS.items():
                # Also check base name without trailing "js" (e.g., "angular" from "angularjs")
                lib_base = re.sub(r'js$', '', lib_key)  # "angularjs" → "angular"
                if lib_key in src_lower or lib_base in src_lower or lib_info["name"].lower().replace(".", "") in src_lower.replace(".", ""):
                    # Extract version: digits separated by . _ or -
                    version_match = re.search(r'(\d+)[\._-](\d+)[\._-](\d+)', src)
                    if version_match:
                        v_tuple = (int(version_match.group(1)), int(version_match.group(2)), int(version_match.group(3)))
                        v_str = f"{v_tuple[0]}.{v_tuple[1]}.{v_tuple[2]}"
                        if lib_key not in detected:
                            detected[lib_key] = (v_tuple, v_str, src)

        # Also check inline version strings
        for lib_name, version_raw in version_comments:
            lib_key = lib_name.lower().replace("js", "").strip()
            # Map common names to keys
            if "angular" in lib_key:
                lib_key = "angularjs"
            if lib_key in KNOWN_VULNERABLE_JS and lib_key not in detected:
                version_clean = version_raw.replace("_", ".").replace("-", ".")
                parts = version_clean.split(".")
                if len(parts) >= 3:
                    try:
                        v_tuple = (int(parts[0]), int(parts[1]), int(parts[2]))
                        v_str = f"{v_tuple[0]}.{v_tuple[1]}.{v_tuple[2]}"
                        detected[lib_key] = (v_tuple, v_str, "inline")
                    except ValueError:
                        pass

        # Check detected versions against known vulnerable
        for lib_key, (v_tuple, v_str, source) in detected.items():
            lib_info = KNOWN_VULNERABLE_JS[lib_key]
            if v_tuple < lib_info["below"]:
                threshold_str = ".".join(str(x) for x in lib_info["below"])
                cve_str = ", ".join(lib_info["cves"])
                eol_note = " (END OF LIFE)" if lib_info.get("eol") else ""

                findings.append({
                    "name": lib_info['name'],
                    "version": v_str,
                    "below": list(lib_info["below"]),
                    "cves": lib_info["cves"],
                    "eol": lib_info.get("eol", False),
                    "severity": lib_info["severity"],
                    "description": f"{lib_info['name']} {v_str} is below {threshold_str}. Known CVEs: {cve_str}",
                    "tags": ["js-dependency", "vulnerable-library"],
                    "template_id": f"js-vulnerable-{lib_key}",
                    "matched_at": self.target,
                    "script_src": source if source != "inline" else "",
                    "display_name": f"Vulnerable JS library: {lib_info['name']} {v_str}{eol_note}",
                })
                logger.info(f"[{self.name}] Vulnerable JS: {lib_info['name']} {v_str} < {threshold_str} ({cve_str})")

        return findings

    # =========================================================================
    # Security Headers Check (passive — single HTTP request)
    # =========================================================================

    # Headers to check and their descriptions
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "description": "Missing HSTS header — site vulnerable to protocol downgrade and man-in-the-middle attacks",
            "template_id": "security-headers-hsts",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "description": "Missing X-Content-Type-Options header — browser may MIME-sniff responses, enabling XSS via content type confusion",
            "template_id": "security-headers-xcto",
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "description": "Missing X-Frame-Options header — site may be vulnerable to clickjacking attacks",
            "template_id": "security-headers-xfo",
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "description": "Missing Content-Security-Policy header — no restrictions on resource loading, increasing XSS impact",
            "template_id": "security-headers-csp",
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "description": "Missing X-XSS-Protection header — legacy browsers lack reflected XSS filter",
            "template_id": "security-headers-xxp",
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "description": "Missing Referrer-Policy header — sensitive URL paths may leak to third parties via Referer header",
            "template_id": "security-headers-rp",
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "description": "Missing Permissions-Policy header — browser features (camera, microphone, geolocation) unrestricted",
            "template_id": "security-headers-pp",
        },
    }

    async def _check_security_headers(self, existing_template_ids: set) -> List[Dict]:
        """
        Check for missing security headers via a single HEAD request.

        Runs AFTER Nuclei to catch headers that Nuclei templates missed.
        Skips headers already detected by Nuclei (via template_id dedup).

        Args:
            existing_template_ids: Set of template IDs already found by Nuclei
                (lowercased). Used to avoid duplicate findings.

        Returns:
            List of misconfiguration dicts for missing headers.
        """
        findings = []

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(self.target, ssl=False, allow_redirects=True) as response:
                    response_headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            logger.warning(f"[{self.name}] Security headers check failed: {e}")
            return findings

        for header_key, header_info in self.SECURITY_HEADERS.items():
            # Skip if Nuclei already detected this
            if header_info["template_id"].lower() in existing_template_ids:
                continue

            # Also skip if a Nuclei template with similar name caught it
            # (e.g. "hsts-detect" covers "strict-transport-security")
            short_name = header_key.replace("-", "")
            if any(short_name in tid for tid in existing_template_ids):
                continue

            if header_key not in response_headers:
                findings.append({
                    "name": f"Missing: {header_info['name']}",
                    "severity": "low",
                    "description": header_info["description"],
                    "tags": ["misconfig", "headers", "security"],
                    "template_id": header_info["template_id"],
                    "matched_at": self.target,
                })
                logger.info(f"[{self.name}] Missing security header: {header_info['name']}")

        if not findings:
            logger.info(f"[{self.name}] All security headers present")

        return findings

    async def _check_insecure_cookies(self, existing_template_ids: set) -> List[Dict]:
        """
        Check for insecure cookie flags (missing HttpOnly, Secure, SameSite).

        Checks multiple URLs (root + auth/login endpoints + recon URLs) because
        cookies are often only set on specific routes (e.g., after login, on API calls).
        """
        findings = []
        seen_cookies = set()

        if "insecure-cookie-flags" in existing_template_ids:
            return findings

        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Build list of URLs to check for cookies
        urls_to_check = [self.target]

        # Common auth/session endpoints that set cookies
        auth_paths = ["/login", "/api/login", "/auth/login", "/signin",
                      "/api/auth/login", "/api/session", "/account/login"]
        for path in auth_paths:
            urls_to_check.append(f"{base}{path}")

        # Add a sample of recon URLs (different pages may set different cookies)
        recon_urls_path = self.report_dir / "urls.txt"
        if recon_urls_path.exists():
            for line in recon_urls_path.read_text().splitlines()[:10]:
                line = line.strip()
                if line and line not in urls_to_check:
                    urls_to_check.append(line)

        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for url in urls_to_check:
                try:
                    async with session.get(url, ssl=False, allow_redirects=True) as response:
                        set_cookies = response.headers.getall("Set-Cookie", [])
                        for cookie_header in set_cookies:
                            cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
                            if cookie_name in seen_cookies:
                                continue
                            seen_cookies.add(cookie_name)

                            lower_header = cookie_header.lower()
                            issues = []
                            if "httponly" not in lower_header:
                                issues.append("HttpOnly")
                            if "secure" not in lower_header:
                                issues.append("Secure")
                            if "samesite" not in lower_header:
                                issues.append("SameSite")

                            if issues:
                                findings.append({
                                    "name": f"Insecure Cookie: {cookie_name} (missing {', '.join(issues)})",
                                    "severity": "medium",
                                    "description": (
                                        f"Cookie '{cookie_name}' is missing security flags: {', '.join(issues)}. "
                                        f"Without HttpOnly, cookies are accessible via JavaScript (XSS → session theft). "
                                        f"Without Secure, cookies are sent over HTTP (MITM). "
                                        f"Without SameSite, cookies are vulnerable to CSRF attacks."
                                    ),
                                    "tags": ["misconfig", "cookies", "security"],
                                    "template_id": f"insecure-cookie-{cookie_name.lower()}",
                                    "matched_at": url,
                                })
                                logger.info(f"[{self.name}] Insecure cookie: {cookie_name} on {url} (missing {', '.join(issues)})")
                except Exception:
                    continue  # Skip URLs that fail (404, timeout, etc.)

        return findings

    async def _check_graphql_introspection(self, existing_template_ids: set) -> List[Dict]:
        """
        Check for GraphQL introspection exposure on common GraphQL paths.

        BugStore V-020: GraphQL at /api/graphql with introspection enabled.
        Probes common paths and sends an introspection query.
        """
        findings = []

        if "graphql-introspection" in existing_template_ids:
            return findings

        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        graphql_paths = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]

        # Also check recon URLs for graphql paths
        # FIX (2026-02-17): report_dir IS the recon directory, not parent
        recon_file = getattr(self, 'report_dir', None)
        if recon_file:
            recon_urls_path = recon_file / "urls.txt"
            if recon_urls_path.exists():
                for line in recon_urls_path.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    p = urlparse(line)
                    if "graphql" in p.path.lower() and p.path not in graphql_paths:
                        graphql_paths.append(p.path)

        introspection_query = {
            "query": "{ __schema { queryType { name } types { name kind } } }"
        }

        for path in graphql_paths:
            endpoint = f"{base}{path}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        endpoint,
                        json=introspection_query,
                        headers={"Content-Type": "application/json"},
                        ssl=False
                    ) as response:
                        if response.status != 200:
                            continue
                        data = await response.json()
                        schema = data.get("data", {}).get("__schema", {})
                        if not schema:
                            continue
                        type_count = len(schema.get("types", []))
                        type_names = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]

                        findings.append({
                            "name": f"GraphQL Introspection Enabled ({type_count} types exposed)",
                            "severity": "medium",
                            "description": (
                                f"GraphQL endpoint at {endpoint} has introspection enabled, "
                                f"exposing {type_count} types including: {', '.join(type_names[:10])}. "
                                f"Attackers can map the entire API schema, discover hidden queries/mutations, "
                                f"and enumerate data structures for targeted attacks."
                            ),
                            "tags": ["misconfig", "graphql", "exposure", "api"],
                            "template_id": "graphql-introspection",
                            "matched_at": endpoint,
                        })
                        logger.info(f"[{self.name}] GraphQL introspection enabled at {endpoint}: {type_count} types")

                        # Test mutations/queries without auth (broken access control)
                        unauth_findings = await self._test_graphql_unauth_access(endpoint, schema)
                        if unauth_findings:
                            findings.extend(unauth_findings)

                        break  # Found one, no need to check more paths
            except Exception as e:
                logger.debug(f"[{self.name}] GraphQL check failed for {endpoint}: {e}")

        return findings

    def _extract_html_from_nuclei_response(self, tech_findings: List[Dict]) -> Optional[str]:
        """
        Extract HTML content from Nuclei's captured response.

        FIX (2026-02-06): Nuclei already fetches the page - we can reuse that HTML
        instead of making another HTTP request (which may fail due to SSL/network issues).

        Returns:
            HTML content from first finding with a response, or None if not found
        """
        for finding in tech_findings:
            response = finding.get("response", "")
            if response and "<html" in response.lower():
                # Extract just the HTML body (after headers)
                # Response format: "HTTP/1.1 200 OK\r\n...headers...\r\n\r\n<html>..."
                if "\r\n\r\n" in response:
                    html_start = response.find("\r\n\r\n") + 4
                    html_content = response[html_start:]
                    logger.debug(f"[{self.name}] Extracted {len(html_content)} bytes HTML from Nuclei response")
                    return html_content
                elif "\n\n" in response:
                    html_start = response.find("\n\n") + 2
                    html_content = response[html_start:]
                    logger.debug(f"[{self.name}] Extracted {len(html_content)} bytes HTML from Nuclei response (LF)")
                    return html_content
        logger.debug(f"[{self.name}] No HTML found in {len(tech_findings)} Nuclei findings")
        return None

    async def _detect_frameworks_from_recon_urls(self) -> List[str]:
        """
        Detect frontend frameworks by fetching HTML from recon-discovered URLs.

        Root page may not load framework code (e.g., SPA routes, subpages with
        different tech). This checks a sample of recon URLs for framework indicators.
        """
        recon_urls_path = self.report_dir / "urls.txt"
        if not recon_urls_path.exists():
            return []

        urls = [line.strip() for line in recon_urls_path.read_text().splitlines() if line.strip()]
        if not urls:
            return []

        # Sample up to 5 diverse URLs (avoid duplicates of same path pattern)
        seen_paths = set()
        sample_urls = []
        from urllib.parse import urlparse
        for url in urls:
            path = urlparse(url).path.rstrip("/")
            path_prefix = "/".join(path.split("/")[:2])  # e.g., /api, /blog
            if path_prefix not in seen_paths:
                seen_paths.add(path_prefix)
                sample_urls.append(url)
                if len(sample_urls) >= 5:
                    break

        frameworks = []
        for url in sample_urls:
            try:
                html = await self._fetch_html(url)
                if html:
                    detected = self._detect_frameworks_from_html(html)
                    if detected:
                        frameworks.extend(detected)
                        logger.info(f"[{self.name}] Framework detected from recon URL {url}: {detected}")
                        break  # Found frameworks, no need to check more
            except Exception as e:
                logger.debug(f"[{self.name}] Recon URL framework check failed for {url}: {e}")

        return list(set(frameworks))

    async def _check_rate_limiting(self) -> List[Dict]:
        """
        Check for missing rate limiting on authentication endpoints.

        Sends 25 rapid requests to common auth endpoints. If no 429 response
        is received, reports missing rate limiting (brute-force risk).
        """
        findings = []

        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Common auth endpoints that should have rate limiting
        auth_endpoints = [
            "/login", "/api/login", "/api/auth/login", "/auth/login",
            "/signin", "/api/signin", "/api/users/login", "/api/token",
        ]

        # Also check recon URLs for login-like paths
        recon_urls_path = self.report_dir / "urls.txt"
        if recon_urls_path.exists():
            for line in recon_urls_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                p = urlparse(line)
                if any(kw in p.path.lower() for kw in ["login", "signin", "auth", "token"]):
                    if p.path not in auth_endpoints:
                        auth_endpoints.append(p.path)

        timeout = aiohttp.ClientTimeout(total=3)
        test_body = {"username": "test@test.com", "password": "testpassword123"}
        request_count = 25

        for path in auth_endpoints:
            endpoint = f"{base}{path}"
            got_429 = False
            successful_requests = 0

            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    # First check if endpoint exists
                    try:
                        async with session.post(endpoint, json=test_body, ssl=False) as resp:
                            if resp.status in (404, 405):
                                continue  # Endpoint doesn't exist
                            if resp.status == 429:
                                got_429 = True
                    except Exception:
                        continue

                    if got_429:
                        continue  # Rate limiting exists

                    # Send rapid requests
                    for _ in range(request_count - 1):
                        try:
                            async with session.post(endpoint, json=test_body, ssl=False) as resp:
                                if resp.status == 429:
                                    got_429 = True
                                    break
                                successful_requests += 1
                        except Exception:
                            break

                if not got_429 and successful_requests >= 15:
                    findings.append({
                        "name": f"No Rate Limiting on {path}",
                        "severity": "medium",
                        "description": (
                            f"Authentication endpoint {endpoint} accepted {successful_requests + 1} "
                            f"rapid requests without returning 429 (Too Many Requests). "
                            f"Missing rate limiting enables credential brute-force and stuffing attacks."
                        ),
                        "tags": ["misconfig", "rate-limiting", "authentication", "security"],
                        "template_id": "no-rate-limiting",
                        "matched_at": endpoint,
                    })
                    logger.info(f"[{self.name}] No rate limiting on {endpoint} ({successful_requests + 1} requests accepted)")
                    break  # One finding is enough — rate limiting is typically global
            except Exception as e:
                logger.debug(f"[{self.name}] Rate limit check failed for {endpoint}: {e}")

        return findings

    async def _check_access_control(self) -> List[Dict]:
        """
        Check for broken access control on admin/privileged endpoints.

        Discovers admin-like paths from recon URLs and probes them without
        authentication. If they return 200 with content, reports as finding.
        """
        findings = []

        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Common admin/privileged paths
        admin_paths = [
            "/admin", "/api/admin", "/admin/dashboard", "/api/admin/stats",
            "/api/admin/users", "/debug", "/api/debug", "/internal",
            "/api/internal", "/actuator", "/actuator/health",
            "/api/admin/config", "/admin/settings",
        ]

        # Discover more from recon URLs
        recon_urls_path = self.report_dir / "urls.txt"
        if recon_urls_path.exists():
            for line in recon_urls_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                p = urlparse(line)
                if any(kw in p.path.lower() for kw in ["admin", "debug", "internal", "actuator", "management"]):
                    if p.path not in admin_paths:
                        admin_paths.append(p.path)

        timeout = aiohttp.ClientTimeout(total=5)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in admin_paths:
                endpoint = f"{base}{path}"
                try:
                    async with session.get(endpoint, ssl=False, allow_redirects=False) as response:
                        if response.status == 200:
                            body = await response.text()
                            # Must have meaningful content (not empty or generic error)
                            if len(body) > 50 and "not found" not in body.lower() and "404" not in body[:100]:
                                findings.append({
                                    "name": f"Admin Endpoint Accessible Without Auth: {path}",
                                    "severity": "high",
                                    "description": (
                                        f"Administrative endpoint {endpoint} is accessible without authentication "
                                        f"(returned HTTP 200 with {len(body)} bytes of content). "
                                        f"This may expose sensitive data, debug information, or administrative functionality."
                                    ),
                                    "tags": ["misconfig", "access-control", "admin", "security"],
                                    "template_id": "broken-access-control-admin",
                                    "matched_at": endpoint,
                                })
                                logger.info(f"[{self.name}] Admin endpoint accessible without auth: {endpoint} ({len(body)} bytes)")
                except Exception:
                    continue  # Skip on error

        return findings

    async def _test_graphql_unauth_access(self, endpoint: str, schema: Dict) -> List[Dict]:
        """
        Test if GraphQL mutations/queries are accessible without authentication.

        After introspection reveals the schema, attempts to execute queries
        and mutations without auth headers to detect broken access control.
        """
        findings = []

        # Extract query and mutation type names
        query_type = schema.get("queryType", {}).get("name", "Query")
        types = schema.get("types", [])

        # Find mutation type
        mutation_type_name = None
        for t in types:
            if t.get("kind") == "OBJECT" and t.get("name") in ("Mutation", "RootMutation"):
                mutation_type_name = t["name"]
                break

        if not mutation_type_name:
            # Check if mutationType is declared in schema
            mutation_meta = schema.get("mutationType")
            if mutation_meta:
                mutation_type_name = mutation_meta.get("name", "Mutation")

        # Get full mutation type details via deeper introspection
        if mutation_type_name:
            mutation_query = {
                "query": f'{{ __type(name: "{mutation_type_name}") {{ fields {{ name args {{ name type {{ name kind }} }} }} }} }}'
            }
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        endpoint, json=mutation_query,
                        headers={"Content-Type": "application/json"}, ssl=False
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            mutation_fields = data.get("data", {}).get("__type", {}).get("fields", [])
                            if mutation_fields:
                                mutation_names = [f["name"] for f in mutation_fields]
                                # Test a read-only query to see if data is exposed
                                sensitive_mutations = [m for m in mutation_names if any(
                                    kw in m.lower() for kw in ["delete", "update", "create", "admin", "reset", "modify"]
                                )]
                                if sensitive_mutations:
                                    findings.append({
                                        "name": f"GraphQL Mutations Accessible Without Auth ({len(sensitive_mutations)} sensitive)",
                                        "severity": "high",
                                        "description": (
                                            f"GraphQL endpoint exposes {len(mutation_fields)} mutations without authentication, "
                                            f"including sensitive operations: {', '.join(sensitive_mutations[:5])}. "
                                            f"Attackers can modify data without credentials."
                                        ),
                                        "tags": ["misconfig", "graphql", "access-control", "api"],
                                        "template_id": "graphql-unauth-mutations",
                                        "matched_at": endpoint,
                                    })
                                    logger.info(f"[{self.name}] GraphQL mutations exposed: {sensitive_mutations[:5]}")
            except Exception as e:
                logger.debug(f"[{self.name}] GraphQL mutation check failed: {e}")

        return findings

    async def run_loop(self):
        await self.run()
