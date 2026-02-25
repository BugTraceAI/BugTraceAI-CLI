"""
Report structure building, section assembly, engagement data construction.

All functions are PURE (no self, no I/O, data in -> data out).
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from bugtrace.agents.reporting_mod.types import (
    SEVERITY_ORDER,
    SEVERITY_BADGES,
    CATEGORY_MAP,
)
from bugtrace.agents.reporting_mod.formatters import (
    extract_validation_method,
    get_validation_method,
    get_validation_notes,
    generate_curl,
    generate_reproduction_steps,
    get_impact_for_type,
    get_remediation_for_type,
    generate_finding_markdown,
    sort_findings_by_cvss,
    parse_nuclei_tech_for_report,
)
from bugtrace.agents.reporting_mod.finding_processor import (
    deduplicate_findings,
    count_by_severity,
)
from bugtrace.core.config import settings
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_reference_cve,
    format_cve,
)
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.report_builder")


# PURE
def build_finding_entry(f: Dict, finding_id: str, status: str, confidence: str) -> Dict:
    """Build a single finding entry with all required fields."""
    source = f.get("source", "database")
    validation_source = "event_bus" if source == "event_bus" else "database"

    # Sanitize FUZZ template markers from gospider URLs
    url = f.get("url", "")
    if "FUZZ" in url:
        url = url.replace("=FUZZ", "").replace("FUZZ", "")
        f["url"] = url

    # Fallback description when specialists don't provide one
    description = f.get("description", "")
    if not description:
        vuln_type = f.get("type", "Unknown")
        param = f.get("parameter", "")
        description = f"{vuln_type} vulnerability detected on {url}"
        if param:
            description += f" via parameter '{param}'"
        description += "."

    entry = {
        "id": finding_id,
        "type": f.get("type", "Unknown"),
        "severity": f.get("severity", "MEDIUM" if status == "VALIDATED_CONFIRMED" else "HIGH"),
        "confidence": confidence,
        "status": status,
        "url": url,
        "parameter": f.get("parameter", ""),
        "payload": f.get("payload", ""),
        "validation": build_validation_section(f, status),
        "reproduction": build_reproduction_section(f),
        "description": description,
        "impact": get_impact_for_type(f.get("type", "")),
        "remediation": get_remediation_for_type(f.get("type", "")),
        "cvss_score": f.get("cvss_score"),
        "cvss_vector": f.get("cvss_vector"),
        "cvss_rationale": f.get("cvss_rationale"),
        "cve": f.get("cve"),
        "markdown_block": generate_finding_markdown(f, int(finding_id.split("-")[1])),
        "source": source,
        "validation_source": validation_source,
    }

    # Add SQLi-specific fields
    if f.get("db_type"):
        entry["db_type"] = f.get("db_type")
    if f.get("tamper_used"):
        entry["tamper_used"] = f.get("tamper_used")

    # Add exploitation details if present
    if f.get("exploitation_details"):
        entry["exploitation_details"] = f.get("exploitation_details")

    # Add screenshot path if available
    if f.get("screenshot_path"):
        entry["screenshot_path"] = f"captures/{Path(f.get('screenshot_path', '')).name}"

    # Add CDP validation metadata if present
    if f.get("cdp_validated"):
        entry["cdp_validated"] = f.get("cdp_validated")
    if f.get("cdp_confidence"):
        entry["cdp_confidence"] = f.get("cdp_confidence")
    if f.get("specialist"):
        entry["specialist"] = f.get("specialist")

    # Add validation method label for report display
    entry["validation_method_label"] = extract_validation_method(f)

    # Enrichment status per finding
    entry["enriched"] = f.get("enriched", True)

    # Add alternative payloads if available
    if f.get("successful_payloads") and len(f["successful_payloads"]) > 1:
        entry["successful_payloads"] = f["successful_payloads"]

    return entry


# PURE
def build_validation_section(f: Dict, status: str) -> Dict:
    """Build validation section for a finding."""
    if status == "MANUAL_REVIEW_RECOMMENDED":
        return {
            "method": "Manual Review Required",
            "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
            "notes": f.get("validator_notes", "") or "Automated validation inconclusive. Manual verification required."
        }
    return {
        "method": get_validation_method(f),
        "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
        "notes": get_validation_notes(f)
    }


# PURE
def build_reproduction_section(f: Dict) -> Dict:
    """Build reproduction section for a finding."""
    return {
        "steps": generate_reproduction_steps(f),
        "poc": generate_curl(f)
    }


# PURE
def build_triager_findings(
    validated: List[Dict],
    manual_review: List[Dict],
    i_param: int = 1
) -> Tuple[List[Dict], List[Dict]]:
    """Build triager-ready findings from validated and manual review lists."""
    triager_findings = []

    for i, f in enumerate(validated, i_param):
        finding_entry = build_finding_entry(f, f"F-{i:03d}", "VALIDATED_CONFIRMED", "CERTAIN")
        triager_findings.append(finding_entry)

    for i, f in enumerate(manual_review, len(validated) + i_param):
        finding_entry = build_finding_entry(f, f"M-{i:03d}", "MANUAL_REVIEW_RECOMMENDED", "POTENTIAL")
        triager_findings.append(finding_entry)

    nuclei_infra = [f for f in triager_findings if f.get("type", "").startswith("NUCLEI:")]
    vuln_findings = [f for f in triager_findings if not f.get("type", "").startswith("NUCLEI:")]

    return vuln_findings, nuclei_infra


# PURE
def build_engagement_data(
    all_findings: List[Dict],
    validated: List[Dict],
    false_positives: List[Dict],
    manual_review: List[Dict],
    stats: Dict,
    tech_stack: Dict,
    scan_id: int,
    target_url: str,
    tech_profile: Dict,
    enrichment_total: int,
    enrichment_failures: int,
) -> Dict:
    """Build engagement data structure (shared between JSON and JS outputs)."""
    stats = stats or {"urls_scanned": 0, "duration": "0s"}
    tech_stack = tech_stack or {}

    # Deduplicate and process findings
    validated = deduplicate_findings(validated)
    manual_review = deduplicate_findings(manual_review)
    by_severity = count_by_severity(validated)

    # Build and sort findings
    vuln_findings, nuclei_infra = build_triager_findings(validated, manual_review)
    vuln_findings = sort_findings_by_cvss(vuln_findings)
    nuclei_infra = sort_findings_by_cvss(nuclei_infra)

    return {
        "meta": _engagement_build_meta(scan_id, target_url, enrichment_total, enrichment_failures),
        "stats": _engagement_build_stats(stats, tech_profile),
        "summary": _engagement_build_summary(all_findings, validated, false_positives, manual_review, by_severity),
        "findings": vuln_findings,
        "infrastructure": {
            "tech_stack": tech_stack,
            "nuclei_findings": nuclei_infra
        }
    }


# PURE
def _engagement_build_meta(
    scan_id: int,
    target_url: str,
    enrichment_total: int,
    enrichment_failures: int,
) -> Dict:
    """Build engagement metadata section."""
    enrichment_status = compute_enrichment_status(enrichment_total, enrichment_failures)
    return {
        "scan_id": scan_id,
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "tool_version": settings.VERSION,
        "validation_engine": "AgenticValidator + CDP + Vision AI",
        "report_signature": "BUGTRACE_AI_REPORT_V5",
        "enrichment_status": enrichment_status,
        "enrichment_stats": {
            "total": enrichment_total,
            "enriched": enrichment_total - enrichment_failures,
            "failed": enrichment_failures,
        },
    }


# PURE
def _engagement_build_stats(stats: Dict, tech_profile: Dict) -> Dict:
    """Build engagement statistics section."""
    result = {
        "urls_scanned": stats.get("urls_scanned", 0),
        "duration": stats.get("duration", "N/A"),
        "duration_seconds": stats.get("duration_seconds", 0),
        "validation_coverage": "100%",
        "total_tokens": stats.get("total_tokens", 0),
        "estimated_cost": stats.get("estimated_cost", 0.0),
    }

    tech_data = parse_nuclei_tech_for_report(tech_profile)
    technologies = list(tech_data["technologies"])

    # Merge frameworks/servers/cms/cdn from tech_profile (HTML parsing fallback)
    if tech_profile:
        existing = {t["name"].lower() for t in technologies}
        for field, category in CATEGORY_MAP.items():
            for name in tech_profile.get(field, []):
                if name.lower() not in existing:
                    existing.add(name.lower())
                    technologies.append({
                        "name": name,
                        "version": None,
                        "eol": False,
                        "category": category,
                    })

    if technologies or tech_data["waf_details"]:
        result["tech_stack"] = {
            "technologies": technologies,
            "waf": tech_data["waf_details"],
        }
    return result


# PURE
def _engagement_build_summary(
    all_findings: List[Dict],
    validated: List[Dict],
    false_positives: List[Dict],
    manual_review: List[Dict],
    by_severity: Dict
) -> Dict:
    """Build engagement summary section with source tracking."""
    event_sourced = sum(1 for f in all_findings if f.get("source") == "event_bus")
    db_sourced = sum(1 for f in all_findings if f.get("source") in ("database", None))
    nuclei_sourced = sum(1 for f in all_findings if f.get("source") == "nuclei")

    return {
        "total_findings": len(all_findings),
        "validated": len(validated),
        "false_positives": len(false_positives),
        "manual_review": len(manual_review),
        "by_severity": by_severity,
        "event_sourced": event_sourced,
        "db_sourced": db_sourced,
        "nuclei_sourced": nuclei_sourced,
    }


# PURE
def compute_enrichment_status(enrichment_total: int, enrichment_failures: int) -> str:
    """Compute overall enrichment status for the scan."""
    if enrichment_total == 0:
        return "full"
    if enrichment_failures == 0:
        return "full"
    if enrichment_failures == enrichment_total:
        return "none"
    return "partial"


# PURE
def generate_standardized_finding(finding: Dict, index: int, template_path: Path) -> str:
    """
    Generate a standardized finding entry using the finding template.

    Args:
        finding: Finding dictionary with all data
        index: Finding number (1-based)
        template_path: Path to the finding_template.md

    Returns:
        Formatted markdown string for the finding
    """
    # Load template
    try:
        with open(template_path, "r") as f:
            template = f.read()
    except FileNotFoundError:
        logger.warning(f"[ReportingAgent] Template not found, falling back to inline format")
        return md_build_finding_entry_inline(finding, index)

    vuln_type = finding.get("type", "Unknown")
    severity = finding.get("severity", "MEDIUM")
    url = finding.get("url", "")
    parameter = finding.get("parameter", "")
    payload = finding.get("payload", "")
    description = finding.get("description", "")

    # Get CWE reference
    cwe_id = finding.get("cwe") or get_cwe_for_vuln(vuln_type) or "N/A"
    cwe_num = cwe_id.replace("CWE-", "") if cwe_id != "N/A" else "0"

    # Format CVE reference
    cve_raw = finding.get("cve")
    if not cve_raw:
        cve_raw = get_reference_cve(vuln_type, finding)
    if cve_raw:
        try:
            cve_reference = f"[{format_cve(cve_raw)}](https://nvd.nist.gov/vuln/detail/{format_cve(cve_raw)})"
        except ValueError:
            cve_reference = "N/A"
    else:
        cve_reference = "N/A"

    remediation = finding.get("remediation") or get_remediation_for_vuln(vuln_type)
    impact = get_impact_for_type(vuln_type)

    cvss_score = finding.get("cvss_score")
    cvss_score_str = f"{cvss_score:.1f}" if cvss_score else "N/A"

    severity_badge = SEVERITY_BADGES.get(severity, severity)
    status_badge = "✅ CONFIRMED"

    http_request = generate_curl(finding)

    validator_notes = finding.get("validator_notes", "")
    http_response_excerpt = validator_notes[:500] if validator_notes else description[:500]

    screenshot_section = ""
    if finding.get("screenshot_path"):
        img_name = Path(finding.get("screenshot_path")).name
        screenshot_section = f"**Screenshot:**\n\n![Evidence](captures/{img_name})"

    reproduction_steps_list = generate_reproduction_steps(finding)
    reproduction_steps = "\n".join(reproduction_steps_list)

    validation_method = extract_validation_method(finding)

    alt_payloads = finding.get("successful_payloads") or []
    if len(alt_payloads) > 1:
        lines = ["\n**Alternative Payloads:**\n"]
        for i, p in enumerate(alt_payloads, 1):
            lines.append(f"{i}. `{p}`")
        alternative_payloads_section = "\n".join(lines) + "\n"
    else:
        alternative_payloads_section = ""

    filled = template.format(
        index=index,
        title=vuln_type,
        severity_badge=severity_badge,
        cwe_id=cwe_id,
        cwe_num=cwe_num,
        cve_reference=cve_reference,
        status_badge=status_badge,
        cvss_score=cvss_score_str,
        validation_method=validation_method,
        url=url,
        parameter=parameter,
        payload=payload,
        description=description,
        impact=impact,
        remediation=remediation,
        http_request=http_request,
        http_response_excerpt=http_response_excerpt,
        screenshot_section=screenshot_section,
        reproduction_steps=reproduction_steps,
        alternative_payloads_section=alternative_payloads_section
    )

    return filled


# PURE
def md_build_finding_entry_inline(finding: Dict, index: int) -> str:
    """
    Fallback method to build finding entry inline (used when template not found).
    Returns markdown string instead of appending to lines list.
    """
    lines = []
    lines.append(f"### {index}. {finding.get('type', 'Unknown Vulnerability')}\n")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| **Severity** | {finding.get('severity', 'MEDIUM')} |")
    lines.append(f"| **Status** | ✅ CONFIRMED |")
    lines.append(f"| **Validation Method** | {extract_validation_method(finding)} |")
    lines.append(f"| **URL** | `{finding.get('url', '')}` |")
    lines.append(f"| **Parameter** | `{finding.get('parameter', '')}` |")
    if finding.get("db_type"):
        lines.append(f"| **DB Type** | {finding.get('db_type')} |")
    if finding.get("tamper_used"):
        lines.append(f"| **Tamper Script** | {finding.get('tamper_used')} |")
    lines.append("")

    lines.append("#### Steps to Reproduce\n")
    for step in generate_reproduction_steps(finding):
        lines.append(step)
    lines.append("")

    if "SQL" in finding.get("type", "").upper() and not generate_curl(finding).startswith("#"):
        lines.append("#### Proof of Concept\n")
        lines.append("```bash")
        lines.append(generate_curl(finding))
        lines.append("```\n")

    if finding.get("validator_notes"):
        lines.append("#### Validation Notes\n")
        lines.append(f"> {finding.get('validator_notes')}\n")

    if finding.get("screenshot_path"):
        img_name = Path(finding.get("screenshot_path")).name
        lines.append(f"#### Screenshot\n")
        lines.append(f"![Evidence](captures/{img_name})\n")

    lines.append("---\n")
    return "\n".join(lines)


# PURE
def build_html_template() -> str:
    """
    Build HTML template string for dynamic report viewer.
    Note: HTML template strings >50 lines are acceptable per 08-03 decision.
    """
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugTraceAI Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: system-ui, sans-serif; background: #f8fafc; }
        .severity-critical { background: #991b1b; color: white; }
        .severity-high { background: #dc2626; color: white; }
        .severity-medium { background: #d97706; color: white; }
        .severity-low { background: #2563eb; color: white; }
        .severity-info { background: #059669; color: white; }
        pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
    </style>
</head>
<body class="p-8">
    <div id="app" class="max-w-6xl mx-auto">
        <div class="text-center py-8">
            <p class="text-gray-500">Loading report...</p>
        </div>
    </div>

    <script>
        async function loadReport() {
            try {
                const response = await fetch('./engagement_data.json');
                const data = await response.json();
                renderReport(data);
            } catch (e) {
                document.getElementById('app').innerHTML =
                    '<p class="text-red-500">Error loading report: ' + e.message + '</p>';
            }
        }

        function renderReport(data) {
            const app = document.getElementById('app');

            let html = `
                <header class="mb-8">
                    <h1 class="text-3xl font-bold text-gray-900">Security Assessment Report</h1>
                    <p class="text-gray-600 mt-2">Target: ${data.meta.target}</p>
                    <p class="text-gray-500 text-sm">Scan ID: ${data.meta.scan_id} | Date: ${data.meta.scan_date}</p>
                </header>

                <section class="grid grid-cols-4 gap-4 mb-8">
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-green-600">${data.summary.validated}</p>
                        <p class="text-gray-600">Confirmed</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-yellow-600">${data.summary.manual_review}</p>
                        <p class="text-gray-600">Manual Review</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-red-600">${data.summary.false_positives}</p>
                        <p class="text-gray-600">False Positives</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-gray-600">${data.summary.total_findings}</p>
                        <p class="text-gray-600">Total</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-2xl font-bold mb-4">Confirmed Vulnerabilities</h2>
            `;

            if (data.findings.length === 0) {
                html += '<p class="text-gray-500">No confirmed vulnerabilities found.</p>';
            } else {
                data.findings.forEach((f, i) => {
                    const sevClass = 'severity-' + f.severity.toLowerCase();
                    html += `
                        <div class="bg-white rounded-lg shadow mb-4 overflow-hidden">
                            <div class="flex items-center justify-between p-4 border-b">
                                <h3 class="text-xl font-bold">${f.id}. ${f.type}</h3>
                                <span class="px-3 py-1 rounded text-sm font-bold ${sevClass}">${f.severity}</span>
                            </div>
                            <div class="p-4">
                                <p class="mb-2"><strong>URL:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.url}</code></p>
                                <p class="mb-2"><strong>Parameter:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.parameter}</code></p>
                                <p class="mb-4"><strong>Payload:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.payload}</code></p>
                                ${f.db_type ? `<p class="mb-2"><strong>DB Type:</strong> <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded">${f.db_type}</span></p>` : ''}
                                ${f.tamper_used ? `<p class="mb-2"><strong>Tamper Script:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.tamper_used}</code></p>` : ''}

                                <h4 class="font-bold mt-4 mb-2">Steps to Reproduce</h4>
                                <ol class="list-decimal list-inside mb-4">
                                    ${(f.reproduction && f.reproduction.steps) ? f.reproduction.steps.map(s => '<li>' + s + '</li>').join('') : '<li>No specific reproduction steps provided.</li>'}
                                </ol>

                                ${(f.reproduction && f.reproduction.poc && !f.reproduction.poc.trim().startsWith('#')) ?
                                `<h4 class="font-bold mt-4 mb-2">Proof of Concept</h4>
                                <pre class="whitespace-pre-wrap">${f.reproduction.poc}</pre>` : ''}

                                ${f.exploitation_details ? '<div class="mt-4 p-4 bg-red-50 border-l-4 border-red-500 rounded"><h4 class="font-bold text-red-700 mb-2">🎯 Exploitation Details</h4><pre class="whitespace-pre-wrap text-sm text-gray-800">' + f.exploitation_details + '</pre></div>' : ''}
                                ${f.validation.notes ? '<p class="mt-4 text-gray-600"><strong>Validator Notes:</strong> ' + f.validation.notes + '</p>' : ''}
                                ${f.validation.screenshot ? '<img src="' + f.validation.screenshot + '" class="mt-4 rounded border" />' : ''}
                            </div>
                        </div>
                    `;
                });
            }

            html += '</section>';
            app.innerHTML = html;
        }

        loadReport();
    </script>
</body>
</html>'''
