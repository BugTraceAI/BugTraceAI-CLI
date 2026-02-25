"""
Finding formatting, severity display, markdown generation, reproduction steps,
curl commands, validation methods.

All functions are PURE (no self, no I/O, data in -> data out).
"""

from typing import Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.reporting_mod.types import (
    SEVERITY_BADGES,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    IMPACT_DESCRIPTIONS,
    TYPE_SPECIFIC_CONTEXTS,
    DISPLAY_NAMES,
    MISCONFIG_PREFIXES,
    CATEGORY_MAP,
)
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    get_reference_cve,
    format_cve,
)
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.formatters")


# PURE
def get_impact_for_type(vuln_type: str) -> str:
    """Get standard impact description for vulnerability type."""
    return IMPACT_DESCRIPTIONS.get(vuln_type.upper(), "This vulnerability may compromise the security of the application.")


# PURE
def get_remediation_for_type(vuln_type: str) -> str:
    """
    Get standard remediation for vulnerability type.
    Delegates to centralized standards module for consistency.
    """
    return get_remediation_for_vuln(vuln_type)


# PURE
def get_cwe_for_type(vuln_type: str) -> str:
    """
    Get CWE reference for vulnerability type.
    Delegates to centralized standards module.
    """
    return get_cwe_for_vuln(vuln_type) or "N/A"


# PURE
def get_type_specific_context(vuln_type: str) -> str:
    """Get type-specific context for LLM prompt."""
    return TYPE_SPECIFIC_CONTEXTS.get(
        vuln_type.upper(),
        "**Context:** This is a confirmed security vulnerability. Explain the real-world impact."
    )


# PURE
def extract_validation_method(finding: Dict) -> str:
    """
    Extract and normalize validation method from findings.

    Maps various validation method indicators to standardized labels.
    """
    raw_method = finding.get("validation_method")
    if not raw_method:
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            raw_method = evidence.get("validation_method")
    if not raw_method:
        raw_method = ""
    raw_method = str(raw_method).lower()

    if "interactsh" in raw_method or "oob" in raw_method:
        return "OOB (Interactsh)"
    if "http" in raw_method or raw_method == "http_response_analysis":
        return "HTTP Response Analysis"
    if "playwright" in raw_method or "browser" in raw_method:
        return "Playwright Browser"
    if finding.get("cdp_validated") or "cdp" in raw_method or "vision" in raw_method:
        return "CDP + Vision AI"
    if "sqlmap" in raw_method:
        return "SQLMap Automated"

    template_engines = ["jinja", "twig", "freemarker", "velocity", "mako", "smarty"]
    if raw_method and any(engine in raw_method for engine in template_engines):
        return f"Template Engine ({raw_method.title()})"

    if "fuzzer" in raw_method:
        return "Fuzzer Validation"

    vuln_type = (finding.get("type") or "").upper()
    if vuln_type in ["SQLI", "SQL"]:
        return "SQLMap/Error Detection"
    if vuln_type == "XSS":
        return "HTTP/Playwright"

    return raw_method.title() if raw_method else "Automated Check"


# PURE
def get_validation_method(finding: Dict) -> str:
    """
    Get validation method based on finding.
    Delegates to extract_validation_method for consistent extraction.
    """
    return extract_validation_method(finding)


# PURE
def get_validation_notes(finding: Dict) -> str:
    """Generate detailed validation notes based on finding type."""
    vuln_type = finding.get("type", "").upper()

    if vuln_type in ["SQLI", "SQLi"]:
        notes = []
        notes.append("**SQLMap Validation Results:**")

        if finding.get("db_type"):
            notes.append(f"- Database Type: {finding.get('db_type')}")
        if finding.get("payload"):
            notes.append(f"- Injection Technique: {finding.get('payload')}")
        if finding.get("tamper_used"):
            notes.append(f"- WAF Bypass: {finding.get('tamper_used')}")
        if finding.get("confidence"):
            notes.append(f"- Confidence: {finding.get('confidence')*100:.0f}%")
        if finding.get("evidence"):
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                evidence = str(evidence)
            evidence_preview = evidence[:200] if len(evidence) > 200 else evidence
            suffix = "..." if len(evidence) > 200 else ""
            notes.append(f"\n**Evidence:**\n```\n{evidence_preview}{suffix}\n```")

        return "\n".join(notes)
    else:
        return finding.get("validator_notes", "Confirmed by specialist agent (CDP not required)")


# PURE
def generate_curl(finding: Dict) -> str:
    """
    Generate reproduction command for the finding.
    """
    # Priority 1: Use specialist-provided reproduction command
    if finding.get("reproduction"):
        return finding.get("reproduction")

    vuln_type = (finding.get("type") or "").upper()
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    payload = finding.get("payload", "")

    if vuln_type in ["SQLI", "SQL"]:
        return _curl_build_sqli(url, param)
    if vuln_type in ["CSTI", "SSTI"]:
        return _curl_build_csti(url, param, payload)
    if vuln_type == "XSS":
        return _curl_build_xss(url, param, payload)
    if vuln_type == "SSRF":
        return f"# SSRF: Use Burp Collaborator or webhook.site to test OOB callbacks\ncurl '{url}'"
    if vuln_type == "LFI":
        return _curl_build_lfi(url, param)
    if vuln_type == "IDOR":
        return f"# IDOR: Test with different user IDs/values\ncurl '{url}'"

    return _curl_build_fallback(url, param, payload)


# PURE
def _curl_build_sqli(url: str, param: str) -> str:
    """Build SQLi reproduction command."""
    if param:
        return f"sqlmap -u \"{url}\" -p {param} --batch --dbs"
    return f"sqlmap -u \"{url}\" --batch --dbs"


# PURE
def _curl_build_csti(url: str, param: str, payload: str) -> str:
    """Build CSTI/SSTI reproduction command."""
    default_payload = "{{7*7}}"
    test_payload = payload if payload else default_payload

    if param and param.startswith("HEADER:"):
        header_name = param.replace("HEADER:", "")
        return f"curl -H '{header_name}: {test_payload}' '{url}' | grep 49"
    elif param and param.startswith("POST:"):
        param_name = param.replace("POST:", "")
        return f"curl -X POST '{url}' -d '{param_name}={test_payload}' | grep 49"
    elif param and payload:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
        return f"curl '{test_url}' | grep 49"
    return f"# CSTI on {url} - inject {{{{7*7}}}} in parameter {param}"


# PURE
def _curl_build_xss(url: str, param: str, payload: str) -> str:
    """Build XSS reproduction command."""
    if param and payload:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
        return f"# Open in browser to trigger XSS:\n{test_url}"
    elif payload:
        return f"# XSS Payload: {payload}\n# Inject in parameter: {param or 'unknown'}"
    return f"# XSS on {url} - test with <script>alert(1)</script> in {param or 'input fields'}"


# PURE
def _curl_build_lfi(url: str, param: str) -> str:
    """Build LFI reproduction command."""
    if param:
        return f"curl '{url}' --data-urlencode '{param}=../../../etc/passwd'"
    return f"# LFI on {url} - test with ../../etc/passwd"


# PURE
def _curl_build_fallback(url: str, param: str, payload: str) -> str:
    """Build fallback reproduction command."""
    if url and param:
        return f"# Vulnerable endpoint: {url}\n# Parameter: {param}\n# Payload: {payload or 'N/A'}"
    elif url:
        return f"# Vulnerable endpoint: {url}"
    else:
        return "# No reproduction command available"


# PURE
def generate_reproduction_steps(finding: Dict) -> List[str]:
    """
    Generate detailed, triager-ready reproduction steps based on vulnerability type.
    """
    vuln_type = (finding.get("type") or "").upper()

    if vuln_type == "XXE":
        return _build_xxe_steps(finding)
    if vuln_type in ["SQLI", "SQL_INJECTION"]:
        return _build_sqli_steps(finding)
    if vuln_type in ["XSS", "STORED_XSS", "REFLECTED_XSS"]:
        return _build_xss_steps(finding)
    if vuln_type == "SSRF":
        return _build_ssrf_steps(finding)
    if vuln_type in ["CSRF", "SECURITY_MISCONFIGURATION"]:
        return _build_csrf_steps(finding)
    if vuln_type == "OPEN_REDIRECT":
        return _build_open_redirect_steps(finding)

    return _build_generic_steps(finding)


# PURE
def _build_xxe_steps(finding: Dict) -> List[str]:
    """Build reproduction steps for XXE vulnerabilities."""
    url = finding.get("url", "")
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    post_endpoint = f"{base_url}/catalog/product/stock"

    return [
        f"1. Navigate to the product page: {url}",
        "2. Open browser DevTools (F12) -> Network tab",
        "3. Click the 'Check stock' button to observe the normal XML request",
        f"4. Intercept the POST request to: {post_endpoint}",
        "5. Replace the XML body with the malicious payload containing the XXE entity",
        "6. Forward the request and observe the out-of-band callback on your server",
        "7. **Expected Result:** Your OOB server receives a DNS/HTTP callback from the target server"
    ]


# PURE
def _build_sqli_steps(finding: Dict) -> List[str]:
    """Build reproduction steps for SQLi vulnerabilities."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    payload = finding.get("payload", "")

    is_time_based = any(kw in payload.lower() for kw in ["sleep", "benchmark", "pg_sleep", "waitfor", "delay"])
    is_error_based = any(kw in payload.lower() for kw in ["cast", "convert", "extractvalue", "updatexml"])

    if is_time_based:
        return [
            f"1. Navigate to: {url}",
            f"2. Locate the `{param}` parameter in the URL/form",
            f"3. Inject the time-based payload: `{payload}`",
            "4. Submit the request and start a timer",
            "5. **Expected Result:** Response takes 5+ seconds (indicating SQL SLEEP executed)",
            "6. Compare with normal request time (should be <1 second)",
            "7. Difference in response time confirms blind SQL injection"
        ]
    elif is_error_based:
        return [
            f"1. Navigate to: {url}",
            f"2. Locate the `{param}` parameter",
            f"3. Inject the error-based payload: `{payload}`",
            "4. Submit the request",
            "5. **Expected Result:** Response contains database data in error message",
            "6. Look for extracted values (usernames, passwords, etc.) in the error output"
        ]
    else:
        return [
            f"1. Navigate to: {url}",
            f"2. Locate the `{param}` parameter",
            f"3. Inject the payload: `{payload}`",
            "4. Submit the request",
            "5. **Expected Result:** SQL error message or altered response indicating injection",
            f"6. For further exploitation, use SQLMap: `sqlmap -u \"{url}\" -p {param} --batch`"
        ]


# PURE
def _build_xss_steps(finding: Dict) -> List[str]:
    """Build reproduction steps for XSS vulnerabilities."""
    return [
        f"1. Copy the full exploit URL with payload",
        f"2. Open a new browser window/incognito session",
        f"3. Paste the URL and navigate to it",
        "4. **Expected Result:** JavaScript alert box appears OR payload executes in DOM",
        f"5. Open DevTools Console (F12) to verify payload execution",
        "6. For stored XSS: Navigate to where the payload is stored and verify execution",
        "7. Screenshot the alert/execution as proof"
    ]


# PURE
def _build_ssrf_steps(finding: Dict) -> List[str]:
    """Build reproduction steps for SSRF vulnerabilities."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")

    return [
        f"1. Set up an out-of-band callback server (Burp Collaborator, interactsh, or webhook.site)",
        f"2. Navigate to: {url}",
        f"3. Locate the `{param}` parameter",
        f"4. Inject your callback URL as the payload",
        "5. Submit the request",
        "6. **Expected Result:** Your callback server receives a request from the target server",
        "7. For internal network access, try: http://169.254.169.254/latest/meta-data/ (AWS metadata)"
    ]


# PURE
def _build_csrf_steps(finding: Dict) -> List[str]:
    """Build reproduction steps for CSRF vulnerabilities."""
    return [
        "1. Save the HTML PoC form to a local file (csrf_poc.html)",
        "2. Log into the target application in your browser",
        "3. Open the csrf_poc.html file in the same browser (file:// or hosted)",
        "4. The form will auto-submit after 1 second",
        "5. **Expected Result:** Action is performed without user consent (e.g., item added to cart)",
        "6. Check the target application to verify the unauthorized action occurred"
    ]


# PURE
def _build_open_redirect_steps(finding: Dict) -> List[str]:
    """Build reproduction steps for Open Redirect vulnerabilities."""
    return [
        f"1. Copy the exploit URL with the redirect parameter",
        "2. Open a new browser window",
        "3. Paste and navigate to the URL",
        "4. **Expected Result:** Browser redirects to the external attacker domain",
        "5. Check the address bar to confirm redirection occurred",
        "6. This can be used for phishing: redirect users to fake login pages"
    ]


# PURE
def _build_generic_steps(finding: Dict) -> List[str]:
    """Build generic reproduction steps for unknown vulnerability types."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    payload = finding.get("payload", "")

    return [
        f"1. Navigate to: {url}",
        f"2. Locate the vulnerable parameter: `{param}`",
        f"3. Inject the payload: `{payload}`",
        "4. Submit the request",
        "5. Observe the application response for vulnerability indicators",
        "6. Document any security-relevant behavior"
    ]


# PURE
def sort_findings_by_cvss(findings: List[Dict]) -> List[Dict]:
    """Sort findings by CVSS score descending."""
    def get_score(x):
        s = x.get("cvss_score")
        if s is not None and isinstance(s, (int, float)):
            return float(s)
        sev = (x.get("severity") or "MEDIUM").upper()
        return SEVERITY_WEIGHTS.get(sev, 5.0)

    return sorted(findings, key=get_score, reverse=True)


# PURE
def generate_finding_markdown(f: Dict, index: int) -> str:
    """Generate the markdown block for a single finding (for copy-paste)."""
    md = []
    md.append(f"### {index}. {f.get('type')}")
    md.append(f"**Severity:** {f.get('severity')}")
    md.append(f"**URL:** `{f.get('url')}`")
    md.append(f"**Parameter:** `{f.get('parameter')}`")
    if f.get("db_type"):
        md.append(f"**DB Type:** {f.get('db_type')}")
    if f.get("tamper_used"):
        md.append(f"**Tamper Script:** {f.get('tamper_used')}")
    md.append("")
    md.append("#### Steps to Reproduce")
    for step in generate_reproduction_steps(f):
        md.append(step)
    md.append("")
    if "SQL" in f.get("type", "").upper() and not generate_curl(f).startswith("#"):
        md.append("#### Proof of Concept")
        md.append("```bash")
        md.append(generate_curl(f))
        md.append("```")
    return "\\n".join(md)


# PURE
def display_name(raw: str) -> str:
    """Get display name for a technology, applying known mappings."""
    return DISPLAY_NAMES.get(raw.lower(), raw.capitalize())


# PURE
def parse_nuclei_tech_for_report(tech_profile: Dict) -> Dict:
    """Parse raw Nuclei findings into a structured tech summary for the report.

    Extracts actual version numbers, EOL status, and product names from
    raw_tech_findings and raw_vuln_findings instead of showing template names.

    Returns:
        Dict with keys: technologies (list of dicts), waf_details (list), summary (str)
    """
    if not tech_profile:
        return {"technologies": [], "waf_details": [], "summary": ""}

    raw_findings = (
        tech_profile.get("raw_tech_findings", [])
        + tech_profile.get("raw_vuln_findings", [])
    )

    tech_map: Dict[str, Dict] = {}
    waf_details_set: set = set()
    waf_details = []

    for finding in raw_findings:
        template_id = finding.get("template-id", "")
        info = finding.get("info", {})
        name = info.get("name", "")
        metadata = info.get("metadata", {})
        extracted = finding.get("extracted-results", [])
        matcher_name = finding.get("matcher-name", "")

        # WAF detection
        if template_id == "waf-detect":
            if not tech_profile.get("waf"):
                continue
            waf_type = matcher_name.replace("generic", "").strip() if matcher_name else "Unknown"
            if waf_type and waf_type.lower() not in waf_details_set:
                waf_details_set.add(waf_type.lower())
                waf_details.append(display_name(waf_type))
            continue

        # Wappalyzer tech-detect
        if template_id == "tech-detect":
            product = display_name(matcher_name) if matcher_name else ""
            if not product:
                continue
            key = matcher_name.lower() if matcher_name else ""
            if key not in tech_map:
                tech_map[key] = {
                    "name": product,
                    "version": None,
                    "eol": False,
                    "category": "Technology",
                }
            continue

        # Skip security misconfig findings
        if any(template_id.startswith(p) for p in MISCONFIG_PREFIXES):
            continue

        # Version/EOL detections
        raw_product = metadata.get("product", "")
        product = display_name(raw_product) if raw_product else ""
        if not product:
            raw_product = template_id.split("-")[0] if template_id else ""
            product = display_name(raw_product) if raw_product else ""
        if not product:
            continue

        key = product.lower()
        is_eol = "eol" in template_id

        version = None
        if extracted:
            raw_ver = extracted[0]
            if "/" in raw_ver:
                version = raw_ver.split("/", 1)[1]
            else:
                version = raw_ver

        category = "Technology"
        if any(x in key for x in ["nginx", "apache", "iis", "tomcat", "lighttpd"]):
            category = "Web Server"
        elif any(x in key for x in ["php", "python", "node", "ruby", "java", "asp", "perl"]):
            category = "Language / Runtime"
        elif any(x in key for x in ["angular", "react", "vue", "jquery", "bootstrap"]):
            category = "Framework"
        elif any(x in key for x in ["wordpress", "drupal", "joomla", "magento"]):
            category = "CMS"
        elif any(x in key for x in ["aws", "azure", "gcp", "cloudfront"]):
            category = "Infrastructure"
        elif any(x in key for x in ["cloudflare", "akamai", "fastly"]):
            category = "CDN"

        if key in tech_map:
            if version and not tech_map[key]["version"]:
                tech_map[key]["version"] = version
            if is_eol:
                tech_map[key]["eol"] = True
            if category != "Technology":
                tech_map[key]["category"] = category
        else:
            tech_map[key] = {
                "name": product,
                "version": version,
                "eol": is_eol,
                "category": category,
            }

    technologies = sorted(tech_map.values(), key=lambda t: t["name"])
    return {
        "technologies": technologies,
        "waf_details": waf_details,
        "summary": ", ".join(
            f"{t['name']} {t['version'] or ''}".strip()
            for t in technologies if t["version"]
        ),
    }
