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
            if not tech_profile["frameworks"] and html_content:
                logger.info(f"[{self.name}] No frameworks detected by Nuclei - trying HTML fallback")
                detected_frameworks = self._detect_frameworks_from_html(html_content)
                if detected_frameworks:
                    tech_profile["frameworks"] = detected_frameworks
                    dashboard.log(
                        f"[{self.name}] ✅ HTML Fallback: Detected {', '.join(detected_frameworks)}",
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

    async def run_loop(self):
        await self.run()
