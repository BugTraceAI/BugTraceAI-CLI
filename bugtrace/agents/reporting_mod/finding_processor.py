"""
Finding processing: normalization, deduplication, categorization, enrichment data prep.

All functions are PURE unless marked otherwise.
"""

from collections import defaultdict
from typing import Dict, List, Optional

from bugtrace.agents.reporting_mod.types import (
    STATIC_ANALYSIS_PATTERNS,
    XSS_UNCONFIRMED_LEVELS,
    INFORMATIONAL_TYPES,
    HEADER_TEMPLATES,
    API_DOCS_TEMPLATES,
    HEADER_READABLE_MAP,
)
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.finding_processor")


def _safe_evidence_get(finding: Dict, key: str, default: str = "") -> str:
    """Safely extract a key from finding['evidence'], handling string evidence."""
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        return evidence.get(key, default)
    return default


# PURE
def categorize_findings(all_findings: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Categorize findings by validation status.

    Handles both:
    - VALIDATED_CONFIRMED: Specialist self-validated (no CDP needed)
    - VALIDATED: CDP-validated findings from AgenticValidator
    """
    validated_statuses = {
        "VALIDATED_CONFIRMED",
        "VALIDATED",
        ValidationStatus.VALIDATED_CONFIRMED.value,
        ValidationStatus.FINDING_VALIDATED.value if hasattr(ValidationStatus, 'FINDING_VALIDATED') else "FINDING_VALIDATED",
    }

    return {
        "raw": [f for f in all_findings],
        "validated": [
            f for f in all_findings
            if f.get("status") in validated_statuses
            and has_minimum_evidence(f)
            and meets_report_quality(f)
        ],
        "manual_review": [
            f for f in all_findings
            if f.get("status") == "MANUAL_REVIEW_RECOMMENDED"
            or (f.get("status") in validated_statuses
                and (not has_minimum_evidence(f)
                     or not meets_report_quality(f)))
        ],
        "false_positives": [f for f in all_findings if f.get("status") == "VALIDATED_FALSE_POSITIVE"],
        "pending": [f for f in all_findings if f.get("status") == "PENDING_VALIDATION"]
    }


# PURE
def has_minimum_evidence(finding: Dict) -> bool:
    """
    Safety net: check if a finding has minimum evidence quality to be
    included in validated findings. Findings that claim VALIDATED_CONFIRMED
    but have zero evidence are re-routed to manual_review instead.
    """
    # Non-empty payload = sufficient
    if (finding.get("payload") or "").strip():
        return True
    # Non-trivial evidence dict = sufficient
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict) and evidence and any(v for v in evidence.values() if v):
        return True
    elif isinstance(evidence, str) and evidence.strip():
        return True
    # Positive confidence or evidence score = sufficient
    if finding.get("evidence_score", 0) > 0 or finding.get("confidence", 0) > 0.5:
        return True
    # Screenshot = sufficient
    if finding.get("screenshot_path"):
        return True
    logger.warning(
        f"[ReportingAgent] Quality gate: {finding.get('type')}/{finding.get('parameter')} "
        f"lacks minimum evidence, routing to manual_review"
    )
    return False


# PURE
def meets_report_quality(finding: Dict) -> bool:
    """
    Quality gate for the final report. Ensures findings meet pentest-grade
    standards. Weak findings are routed to manual_review instead.

    Filters:
    - XSS/DOM-XSS with static-analysis payloads (no real exploit)
    - XSS validated only via HTTP response analysis (no browser execution)
    """
    vuln_type = (finding.get("type") or "").upper()
    payload = (finding.get("payload") or "").lower()
    evidence = finding.get("evidence") or {}
    level = ""
    if isinstance(evidence, dict):
        level = evidence.get("level", "") or ""
    validation_method = (finding.get("validation_method") or "").lower()

    # --- Filter 1: Static analysis payloads are not real exploits ---
    for pattern in STATIC_ANALYSIS_PATTERNS:
        if pattern in payload:
            logger.info(
                f"[ReportingAgent] Report quality gate: {vuln_type}/{finding.get('parameter')} "
                f"has static-analysis payload, routing to manual_review"
            )
            return False

    # --- Filter 2: XSS without browser-confirmed execution ---
    if vuln_type == "XSS" and level in XSS_UNCONFIRMED_LEVELS:
        logger.info(
            f"[ReportingAgent] Report quality gate: XSS/{finding.get('parameter')} "
            f"validated at {level} (HTTP-only), routing to manual_review"
        )
        return False

    return True


# PURE
def deduplicate_exact(findings: List[Dict]) -> List[Dict]:
    """Deduplicate findings by exact (url, parameter, payload) key."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("url"), f.get("parameter"), f.get("payload"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# PURE
def normalize_type_for_dedup(vuln_type: str) -> str:
    """
    Normalize vulnerability type for deduplication grouping.

    Strips technique suffixes so variants group together:
    - "SQL Injection (Error-Based)" -> "SQL INJECTION"
    - "XSS" -> "XSS"
    - "CSTI (AngularJS)" -> "CSTI"
    """
    normalized = vuln_type.upper().strip()
    paren_idx = normalized.find("(")
    if paren_idx > -1:
        normalized = normalized[:paren_idx].strip()
    return normalized


# PURE
def normalize_parameter_for_dedup(param: str) -> str:
    """
    Normalize parameter for deduplication grouping.

    Handles variations like:
    - "Cookie: TrackingId" / "cookie: trackingid" / "TrackingId (cookie)"
    - "Header: X-Forwarded-For" / "x-forwarded-for header"

    Returns lowercase normalized key for grouping.
    """
    param_lower = param.lower().strip()

    # Cookie normalization: extract just the cookie name
    if "cookie" in param_lower:
        clean = param_lower.replace("cookie:", "").replace("cookie", "").strip()
        clean = clean.split()[0] if clean else "unknown"
        clean = clean.strip(":").strip()
        return f"cookie:{clean}" if clean else "cookie:unknown"

    # Header normalization
    if "header" in param_lower:
        clean = param_lower.replace("header:", "").replace("header", "").strip()
        clean = clean.split()[0] if clean else "unknown"
        clean = clean.strip(":").strip()
        return f"header:{clean}" if clean else "header:unknown"

    return param_lower


# PURE
def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Deduplicate findings by (type, normalized_parameter).

    For example, if we have 4 SQLi findings on Cookie: TrackingId across
    different URLs, we'll return 1 representative finding.

    Returns: List of deduplicated findings with 'affected_urls' metadata.
    """
    groups = defaultdict(list)
    for f in findings:
        param_raw = f.get("parameter", "")
        param_normalized = normalize_parameter_for_dedup(param_raw)
        vuln_type = normalize_type_for_dedup(f.get("type", "Unknown"))
        key = (vuln_type, param_normalized)
        groups[key].append(f)

    deduplicated = []
    for (vuln_type, param_key), group in groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
        else:
            # Multiple findings - pick the best one as representative
            sorted_group = sorted(
                group,
                key=lambda x: (
                    x.get("status") == "VALIDATED_CONFIRMED",
                    {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                        (x.get("severity") or "medium").lower(), 2
                    )
                ),
                reverse=True
            )
            representative = sorted_group[0].copy()

            # Collect all affected URLs (deduplicated)
            affected_urls = list(set(f.get("url", "") for f in group if f.get("url")))
            representative["affected_urls"] = affected_urls
            representative["affected_count"] = len(affected_urls)

            original_param = representative.get("parameter", param_key)

            original_desc = representative.get("description", "")
            if len(affected_urls) > 1:
                dedup_note = f"\n\n**Note:** This vulnerability affects {len(affected_urls)} endpoints with parameter `{original_param}`."
                representative["description"] = original_desc + dedup_note

            deduplicated.append(representative)

            logger.info(f"[ReportingAgent] Deduplicated {len(group)} {vuln_type} findings on '{param_key}' -> 1 finding")

    return deduplicated


# PURE
def count_by_severity(validated: List[Dict]) -> Dict[str, int]:
    """Count findings by severity level."""
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in validated:
        sev = (f.get("severity") or "medium").lower()
        if sev in by_severity:
            by_severity[sev] += 1
    return by_severity


# PURE
def event_finding_to_db_format(event_finding: Dict) -> Dict:
    """
    Convert event finding structure to DB-compatible structure.

    Args:
        event_finding: Finding from event bus accumulator

    Returns:
        Dictionary with DB-compatible field names
    """
    evidence = event_finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    return {
        "id": None,
        "type": event_finding.get("type") or event_finding.get("vuln_type", "Unknown"),
        "severity": event_finding.get("severity", "HIGH"),
        "url": event_finding.get("url", ""),
        "parameter": event_finding.get("parameter", ""),
        "payload": event_finding.get("payload", ""),
        "description": event_finding.get("description") or evidence.get("description", ""),
        "status": event_finding.get("status", "VALIDATED_CONFIRMED"),
        "validator_notes": event_finding.get("cdp_reasoning") or event_finding.get("reasoning", ""),
        "screenshot_path": event_finding.get("screenshot_path"),
        "validation_method": event_finding.get("validation_method", "event_bus"),
        "source": "event_bus",
        "specialist": event_finding.get("specialist"),
        "scan_context": event_finding.get("scan_context"),
        "cdp_validated": event_finding.get("cdp_validated", False),
        "cdp_confidence": event_finding.get("cdp_confidence"),
    }


# PURE
def merge_event_findings(
    db_findings: List[Dict],
    event_findings: List[Dict],
) -> List[Dict]:
    """
    Merge event-sourced validated findings with database findings.

    Deduplicates based on (url, parameter, payload) to prevent duplicates.
    Event findings are marked with source='event_bus'.

    Args:
        db_findings: Findings from database and Nuclei
        event_findings: Findings from event bus accumulator

    Returns:
        Merged list with event findings appended (no duplicates)
    """
    if not event_findings:
        return db_findings

    def dedup_key(f: Dict) -> tuple:
        return (f.get("url"), f.get("parameter"), f.get("payload"))

    seen_keys = set(dedup_key(f) for f in db_findings)

    for f in db_findings:
        if "source" not in f:
            f["source"] = "database"

    merged = list(db_findings)
    added_count = 0

    for ef in event_findings:
        key = dedup_key(ef)
        if key not in seen_keys:
            formatted = event_finding_to_db_format(ef)
            merged.append(formatted)
            seen_keys.add(key)
            added_count += 1

    logger.info(f"[ReportingAgent] Merged {added_count} event findings with {len(db_findings)} DB findings")
    return merged


# PURE
def consolidate_informational(findings: List[Dict]) -> List[Dict]:
    """
    Consolidate informational findings into grouped entries.

    - All missing security header findings -> 1 consolidated finding
    - All API documentation exposure findings -> 1 consolidated finding
    - Other informational types pass through unchanged
    """
    header_findings = []
    api_docs_findings = []
    other_findings = []

    for f in findings:
        tmpl = _safe_evidence_get(f, "nuclei_template", f.get("parameter", "")).lower()
        ftype = f.get("type", "").upper()

        if ftype == "MISSING_SECURITY_HEADER" and tmpl in HEADER_TEMPLATES:
            header_findings.append(f)
        elif ftype in ("API DOCUMENTATION EXPOSURE", "MISSING_SECURITY_HEADER") and tmpl in API_DOCS_TEMPLATES:
            api_docs_findings.append(f)
        else:
            other_findings.append(f)

    result = list(other_findings)

    if header_findings:
        result.append(build_consolidated_header_finding(header_findings))

    if api_docs_findings:
        result.append(build_consolidated_api_docs_finding(api_docs_findings))

    consolidated_count = len(header_findings) + len(api_docs_findings)
    if consolidated_count > 0:
        logger.info(
            f"[ReportingAgent] Consolidated {consolidated_count} informational findings -> "
            f"{int(bool(header_findings)) + int(bool(api_docs_findings))} grouped entries"
        )

    return result


# PURE
def build_consolidated_header_finding(findings: List[Dict]) -> Dict:
    """Build a single consolidated finding from multiple missing header findings."""
    headers_detail = []
    urls_seen = set()
    for f in findings:
        tmpl = _safe_evidence_get(f, "nuclei_template", f.get("parameter", ""))
        desc = f.get("description", "").strip()
        url = f.get("url", "")
        if url:
            urls_seen.add(url)
        name = tmpl.replace("security-headers-", "").replace("http-missing-security-headers", "Multiple Headers").upper()
        readable = HEADER_READABLE_MAP.get(name, name)
        one_liner = desc.split("\n")[0][:120] if desc else ""
        headers_detail.append({"header": readable, "template": tmpl, "description": one_liner})

    header_lines = []
    for h in headers_detail:
        header_lines.append(f"| {h['header']} | {h['description']} |")

    description = (
        f"The target is missing {len(headers_detail)} recommended security headers. "
        "These are defense-in-depth measures and best practices — not directly exploitable vulnerabilities. "
        "In bug bounty programs, missing headers are typically classified as **Informational**.\n\n"
        "| Missing Header | Details |\n"
        "|---|---|\n"
        + "\n".join(header_lines) + "\n\n"
        "**Recommendation:** Configure the web server or application to include all standard "
        "security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)."
    )

    base = dict(findings[0])
    base["type"] = "MISSING_SECURITY_HEADER"
    base["parameter"] = "security-headers-consolidated"
    base["title"] = f"Missing Security Headers ({len(headers_detail)} headers)"
    base["description"] = description
    base["severity"] = "INFO"
    base["cvss_score"] = 0.0
    base["cvss_vector"] = "N/A"
    base["cvss_rationale"] = "Informational — defense-in-depth headers, not directly exploitable."
    base["enriched"] = True
    base["evidence"] = {
        "nuclei_template": "security-headers-consolidated",
        "missing_headers": [h["header"] for h in headers_detail],
        "original_count": len(findings),
    }
    base["exploitation_details"] = description
    base["url"] = sorted(urls_seen)[0] if urls_seen else base.get("url", "")
    base.pop("cwe", None)
    base.pop("cve", None)
    return base


# PURE
def build_consolidated_api_docs_finding(findings: List[Dict]) -> Dict:
    """Build a single consolidated finding from multiple API documentation exposure findings."""
    endpoints = []
    urls_seen = set()
    for f in findings:
        tmpl = _safe_evidence_get(f, "nuclei_template", f.get("parameter", ""))
        url = f.get("url", "")
        desc = f.get("description", "").strip().split("\n")[0][:120]
        if url:
            urls_seen.add(url)
        endpoints.append({"template": tmpl, "url": url, "description": desc})

    endpoint_lines = []
    for ep in endpoints:
        endpoint_lines.append(f"| {ep['url']} | {ep['description']} |")

    description = (
        f"The application exposes {len(endpoints)} API documentation endpoint(s) without authentication. "
        "While this aids development, in production it reveals internal API structure to potential attackers. "
        "In bug bounty programs, API documentation exposure is typically classified as **Informational**.\n\n"
        "| Endpoint | Details |\n"
        "|---|---|\n"
        + "\n".join(endpoint_lines) + "\n\n"
        "**Recommendation:** Restrict API documentation endpoints to authenticated users or internal networks only."
    )

    base = dict(findings[0])
    base["type"] = "API DOCUMENTATION EXPOSURE"
    base["parameter"] = "api-docs-consolidated"
    base["title"] = f"API Documentation Exposure ({len(endpoints)} endpoints)"
    base["description"] = description
    base["severity"] = "INFO"
    base["cvss_score"] = 0.0
    base["cvss_vector"] = "N/A"
    base["cvss_rationale"] = "Informational — API documentation exposure aids reconnaissance but is not directly exploitable."
    base["enriched"] = True
    base["evidence"] = {
        "nuclei_template": "api-docs-consolidated",
        "exposed_endpoints": [ep["url"] for ep in endpoints],
        "original_count": len(findings),
    }
    base["exploitation_details"] = description
    base["url"] = sorted(urls_seen)[0] if urls_seen else base.get("url", "")
    base.pop("cwe", None)
    base.pop("cve", None)
    return base


# PURE
def db_build_finding_dict(f) -> Dict:
    """Build finding dictionary from database record."""
    return {
        "id": f.id,
        "type": str(f.type.value if hasattr(f.type, 'value') else f.type),
        "severity": f.severity,
        "url": f.attack_url,
        "parameter": f.vuln_parameter,
        "payload": f.payload_used,
        "description": f.details,
        "status": f.status,
        "validator_notes": f.validator_notes,
        "screenshot_path": f.proof_screenshot_path,
        "reproduction": getattr(f, 'reproduction_command', None),
        "created_at": None
    }


# PURE
def db_enrich_sqli_metadata(finding: Dict, f) -> None:
    """Parse and enrich SQLMap metadata from details JSON."""
    import json

    if finding["type"] not in ["SQLI", "SQLi"]:
        return
    if not f.details:
        return

    try:
        details_json = json.loads(f.details)
        finding["db_type"] = details_json.get("db_type")
        finding["tamper_used"] = details_json.get("tamper_used")
        finding["confidence"] = details_json.get("confidence")
        finding["evidence"] = details_json.get("evidence")
        finding["description"] = details_json.get("description", f.details)
        if details_json.get("reproduction_command"):
            finding["reproduction"] = details_json.get("reproduction_command")
    except (json.JSONDecodeError, TypeError):
        pass


# PURE
def nuclei_map_severity(nuclei_sev: Optional[str]) -> str:
    """Map Nuclei severity to our severity scale."""
    nuclei_sev = (nuclei_sev or "info").upper()
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO"
    }
    return severity_map.get(nuclei_sev, "INFO")


# PURE
def nuclei_parse_findings(tech_profile: Dict) -> List[Dict]:
    """Parse Nuclei findings from tech profile."""
    nuclei_findings = []
    for finding in (tech_profile.get("raw_tech_findings") or []) + (tech_profile.get("raw_vuln_findings") or []):
        info = finding.get("info", {})
        severity = nuclei_map_severity(info.get("severity"))
        status = "VALIDATED_CONFIRMED" if severity in ["CRITICAL", "HIGH"] else "PENDING_VALIDATION"

        nuclei_findings.append({
            "id": None,
            "type": f"NUCLEI:{info.get('name', 'Unknown')}",
            "severity": severity,
            "url": finding.get("matched-at", finding.get("matched_at", "")),
            "parameter": info.get("name", ""),
            "payload": finding.get("template_id", ""),
            "description": info.get("description", f"Detected by Nuclei template: {finding.get('template_id', 'unknown')}"),
            "status": status,
            "validator_notes": f"Nuclei detection (template: {finding.get('template_id', 'unknown')})",
            "screenshot_path": None,
            "reproduction": None,
            "source": "nuclei",
            "nuclei_template": finding.get("template_id"),
            "nuclei_tags": info.get("tags", [])
        })
    return nuclei_findings


# PURE
def nuclei_extract_tech_stack(tech_profile: Dict) -> Dict:
    """Extract full tech stack info from tech profile."""
    return {
        "frameworks": tech_profile.get("frameworks", []),
        "languages": tech_profile.get("languages", []),
        "servers": tech_profile.get("servers", []),
        "waf": tech_profile.get("waf", []),
        "infrastructure": tech_profile.get("infrastructure", []),
        "cdn": tech_profile.get("cdn", []),
        "cms": tech_profile.get("cms", []),
        "tech_tags": tech_profile.get("tech_tags", []),
    }


# PURE
def group_findings_by_type(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by normalized vulnerability type for batch PoC enrichment."""
    groups: Dict[str, List[Dict]] = {}
    for f in findings:
        vtype = normalize_type_for_dedup(f.get("type", "UNKNOWN"))
        groups.setdefault(vtype, []).append(f)
    return groups
