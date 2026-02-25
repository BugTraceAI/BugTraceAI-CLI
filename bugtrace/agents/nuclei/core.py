"""
Nuclei Agent — PURE functions.

All functions in this module are free functions (no self), side-effect free,
and receive all data as explicit parameters.

Contents:
    - load_vulnerable_js_libs: Load vulnerable JS library database from JSON
    - KNOWN_VULNERABLE_JS: Pre-loaded vulnerable JS library database
    - SECURITY_HEADERS: Security header definitions
    - categorize_tech_finding: Categorize a Nuclei tech finding into profile buckets
    - detect_frameworks_from_html: Detect frontend frameworks from HTML content
    - detect_js_versions: Extract JS library versions and check vulnerabilities
    - extract_html_from_nuclei_response: Extract HTML from Nuclei captured response
    - check_header_missing: Check if a security header is missing from response headers
    - parse_cookie_issues: Parse cookie header for missing security flags
    - filter_fp_waf_matchers: Filter known false-positive WAF matchers
"""

import json
import re
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from loguru import logger


def load_vulnerable_js_libs() -> dict:  # PURE (deterministic file read, no side effects)
    """Load vulnerable JS library database from JSON data file.

    Returns:
        Dictionary mapping library key to vulnerability info.
    """
    data_path = Path(__file__).parent.parent.parent / "config" / "vulnerable_js_libs.json"
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


# Pre-loaded at module import time
KNOWN_VULNERABLE_JS = load_vulnerable_js_libs()


# Security headers to check and their descriptions
SECURITY_HEADERS: Dict[str, Dict[str, str]] = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "description": "Missing HSTS header -- site vulnerable to protocol downgrade and man-in-the-middle attacks",
        "template_id": "security-headers-hsts",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Missing X-Content-Type-Options header -- browser may MIME-sniff responses, enabling XSS via content type confusion",
        "template_id": "security-headers-xcto",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Missing X-Frame-Options header -- site may be vulnerable to clickjacking attacks",
        "template_id": "security-headers-xfo",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "description": "Missing Content-Security-Policy header -- no restrictions on resource loading, increasing XSS impact",
        "template_id": "security-headers-csp",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Missing X-XSS-Protection header -- legacy browsers lack reflected XSS filter",
        "template_id": "security-headers-xxp",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Missing Referrer-Policy header -- sensitive URL paths may leak to third parties via Referer header",
        "template_id": "security-headers-rp",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Missing Permissions-Policy header -- browser features (camera, microphone, geolocation) unrestricted",
        "template_id": "security-headers-pp",
    },
}


def categorize_tech_finding(
    finding: Dict,
    target: str,
) -> Tuple[Optional[str], Dict]:  # PURE
    """Categorize a single Nuclei tech finding into a profile bucket.

    Args:
        finding: A single Nuclei tech finding dict.
        target: The target URL (used as fallback for matched_at).

    Returns:
        Tuple of (category_name, finding_data) where category_name is one of:
        'misconfigurations', 'infrastructure', 'frameworks', 'languages',
        'servers', 'cms', 'waf', 'cdn', or None for tech_tags-only.
        finding_data contains the categorized data.
    """
    info = finding.get("info", {})
    name = info.get("name", "Unknown")
    tags = info.get("tags", [])
    severity = info.get("severity", "info").lower()

    # Misconfiguration/exposure/token findings -> separate list (not tech)
    misconfig_tags = {"misconfig", "misconfiguration", "exposure", "token", "headers"}
    if misconfig_tags & set(tags):
        return ("misconfigurations", {
            "name": name,
            "severity": severity,
            "description": info.get("description", ""),
            "tags": tags,
            "template_id": finding.get("template-id", ""),
            "matched_at": finding.get("matched-at", target),
        })

    # Categorize by name content
    name_lower = name.lower()

    if any(x in name_lower for x in ["aws", "azure", "gcp", "alb", "cloudfront"]):
        return ("infrastructure", name)
    elif any(x in name_lower for x in ["angular", "react", "vue", "jquery", "bootstrap"]):
        return ("frameworks", name)
    elif any(x in name_lower for x in ["php", "node", "python", "ruby", "java", "asp"]):
        return ("languages", name)
    elif any(x in name_lower for x in ["nginx", "apache", "iis", "tomcat"]):
        return ("servers", name)
    elif any(x in name_lower for x in ["wordpress", "drupal", "joomla", "magento"]):
        return ("cms", name)
    elif any(x in name_lower for x in ["waf", "modsecurity", "imperva"]):
        return ("waf", name)
    elif any(x in name_lower for x in ["cloudflare", "akamai", "fastly", "cdn"]):
        return ("cdn", name)
    else:
        # Default: add to frameworks
        return ("frameworks", name)


def detect_frameworks_from_html(html: str) -> List[str]:  # PURE
    """Detect frontend frameworks from HTML content (FALLBACK method).

    Detection patterns:
    - AngularJS: ng-app, ng-controller, angular.js script tags
    - Vue.js: v-if, v-for, vue.js script tags
    - React: react.js, react-dom.js, data-reactroot, div#root + module script

    Args:
        html: Raw HTML content from target page.

    Returns:
        List of detected framework names.
    """
    frameworks: List[str] = []
    html_lower = html.lower()

    # AngularJS detection
    angular_patterns = [
        r'ng-app', r'ng-controller', r'ng-model',
        r'angular\.js', r'angular\.min\.js', r'angular[-_]1\.\d+',
    ]
    for pattern in angular_patterns:
        if re.search(pattern, html_lower):
            frameworks.append('AngularJS')
            break

    # Vue.js detection
    vue_patterns = [
        r'v-if', r'v-for', r'v-model', r'v-bind',
        r'vue\.js', r'vue\.min\.js',
    ]
    for pattern in vue_patterns:
        if re.search(pattern, html_lower):
            frameworks.append('Vue.js')
            break

    # React detection
    react_patterns = [
        r'react\.js', r'react\.min\.js', r'react-dom\.js',
        r'data-reactroot', r'data-reactid',
    ]
    react_found = False
    for pattern in react_patterns:
        if re.search(pattern, html_lower):
            frameworks.append('React')
            react_found = True
            break

    if not react_found:
        # Modern React SPA detection (Vite/webpack/CRA bundled apps)
        has_root_div = bool(re.search(r'<div\s+id=["\']root["\']', html_lower))
        has_module_script = bool(re.search(r'<script\s+type=["\']module["\']', html_lower))
        if has_root_div and has_module_script:
            frameworks.append('React')

    return frameworks


def detect_js_versions(
    html: str,
    target: str,
    known_vulnerable_js: Dict = None,
) -> List[Dict]:  # PURE
    """Extract JS library versions from script tags and check against known vulnerabilities.

    Patterns matched:
    - angular_1-7-7.js, angular.min.1.7.7.js, angular-1.7.7.min.js
    - jquery-3.6.0.min.js, jquery.3.6.0.js
    - vue@2.6.14, vue.min.js?v=2.6.14

    Args:
        html: Raw HTML content.
        target: The target URL (for matched_at field).
        known_vulnerable_js: Vulnerable JS library database. Defaults to KNOWN_VULNERABLE_JS.

    Returns:
        List of misconfiguration dicts for vulnerable versions found.
    """
    if known_vulnerable_js is None:
        known_vulnerable_js = KNOWN_VULNERABLE_JS

    findings: List[Dict] = []

    # Extract all script src attributes
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

    # Also check inline version comments like "AngularJS v1.7.7"
    version_comments = re.findall(
        r'(angular|jquery|vue|react|bootstrap|lodash)[^\d]{0,20}v?(\d+[\._-]\d+[\._-]\d+)',
        html, re.IGNORECASE,
    )

    # Build a map of library -> version from all sources
    detected: Dict[str, Tuple] = {}  # lib_key -> (version_tuple, version_str, source)

    for src in script_srcs:
        src_lower = src.lower()
        for lib_key, lib_info in known_vulnerable_js.items():
            lib_base = re.sub(r'js$', '', lib_key)
            if (lib_key in src_lower or lib_base in src_lower
                    or lib_info["name"].lower().replace(".", "") in src_lower.replace(".", "")):
                version_match = re.search(r'(\d+)[\._-](\d+)[\._-](\d+)', src)
                if version_match:
                    v_tuple = (
                        int(version_match.group(1)),
                        int(version_match.group(2)),
                        int(version_match.group(3)),
                    )
                    v_str = f"{v_tuple[0]}.{v_tuple[1]}.{v_tuple[2]}"
                    if lib_key not in detected:
                        detected[lib_key] = (v_tuple, v_str, src)

    # Also check inline version strings
    for lib_name, version_raw in version_comments:
        lib_key = lib_name.lower().replace("js", "").strip()
        if "angular" in lib_key:
            lib_key = "angularjs"
        if lib_key in known_vulnerable_js and lib_key not in detected:
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
        lib_info = known_vulnerable_js[lib_key]
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
                "matched_at": target,
                "script_src": source if source != "inline" else "",
                "display_name": f"Vulnerable JS library: {lib_info['name']} {v_str}{eol_note}",
            })

    return findings


def extract_html_from_nuclei_response(
    tech_findings: List[Dict],
) -> Optional[str]:  # PURE
    """Extract HTML content from Nuclei's captured response.

    Nuclei already fetches the page -- we can reuse that HTML instead of
    making another HTTP request.

    Args:
        tech_findings: List of Nuclei tech finding dicts.

    Returns:
        HTML content from first finding with a response, or None.
    """
    for finding in tech_findings:
        response = finding.get("response", "")
        if response and "<html" in response.lower():
            if "\r\n\r\n" in response:
                html_start = response.find("\r\n\r\n") + 4
                return response[html_start:]
            elif "\n\n" in response:
                html_start = response.find("\n\n") + 2
                return response[html_start:]
    return None


def check_header_missing(
    header_key: str,
    header_info: Dict[str, str],
    response_headers: Dict[str, str],
    existing_template_ids: Set[str],
    target: str,
) -> Optional[Dict]:  # PURE
    """Check if a single security header is missing from response headers.

    Args:
        header_key: The header name to check (lowercase).
        header_info: Metadata about the header (name, description, template_id).
        response_headers: Response headers dict (keys lowercased).
        existing_template_ids: Set of template IDs already found by Nuclei.
        target: The target URL (for matched_at).

    Returns:
        Misconfiguration dict if header is missing, or None.
    """
    # Skip if Nuclei already detected this
    if header_info["template_id"].lower() in existing_template_ids:
        return None

    # Also skip if a Nuclei template with similar name caught it
    short_name = header_key.replace("-", "")
    if any(short_name in tid for tid in existing_template_ids):
        return None

    if header_key not in response_headers:
        return {
            "name": f"Missing: {header_info['name']}",
            "severity": "low",
            "description": header_info["description"],
            "tags": ["misconfig", "headers", "security"],
            "template_id": header_info["template_id"],
            "matched_at": target,
        }

    return None


def parse_cookie_issues(
    cookie_header: str,
    cookie_name: str,
    url: str,
) -> Optional[Dict]:  # PURE
    """Parse a Set-Cookie header for missing security flags.

    Args:
        cookie_header: The raw Set-Cookie header value.
        cookie_name: The cookie name extracted from the header.
        url: The URL where the cookie was set.

    Returns:
        Misconfiguration dict if issues found, or None.
    """
    lower_header = cookie_header.lower()
    issues: List[str] = []
    if "httponly" not in lower_header:
        issues.append("HttpOnly")
    if "secure" not in lower_header:
        issues.append("Secure")
    if "samesite" not in lower_header:
        issues.append("SameSite")

    if issues:
        return {
            "name": f"Insecure Cookie: {cookie_name} (missing {', '.join(issues)})",
            "severity": "medium",
            "description": (
                f"Cookie '{cookie_name}' is missing security flags: {', '.join(issues)}. "
                f"Without HttpOnly, cookies are accessible via JavaScript (XSS -> session theft). "
                f"Without Secure, cookies are sent over HTTP (MITM). "
                f"Without SameSite, cookies are vulnerable to CSRF attacks."
            ),
            "tags": ["misconfig", "cookies", "security"],
            "template_id": f"insecure-cookie-{cookie_name.lower()}",
            "matched_at": url,
        }

    return None


def filter_fp_waf_matchers(
    waf_names: List[str],
    tech_findings: List[Dict],
) -> Tuple[bool, Set[str]]:  # PURE
    """Filter known false-positive WAF matcher names from Nuclei.

    Args:
        waf_names: List of WAF names detected by Nuclei.
        tech_findings: Raw Nuclei tech findings.

    Returns:
        Tuple of (all_are_fp, waf_matcher_names) where all_are_fp is True
        if all detected matchers are known false positives.
    """
    NUCLEI_WAF_FP_MATCHERS = {
        "nginxgeneric",
        "apachegeneric",
    }

    waf_matcher_names: Set[str] = set()
    for finding in tech_findings:
        template_id = finding.get("template-id", "")
        if template_id == "waf-detect":
            matcher = finding.get("matcher-name", "")
            if matcher:
                waf_matcher_names.add(matcher.lower())

    all_are_fp = bool(waf_matcher_names) and waf_matcher_names.issubset(NUCLEI_WAF_FP_MATCHERS)
    return (all_are_fp, waf_matcher_names)
