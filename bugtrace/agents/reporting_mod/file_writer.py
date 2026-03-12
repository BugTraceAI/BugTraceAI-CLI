"""
Write report files to disk (JSON, MD, HTML).

All functions are I/O (filesystem writes).
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from bugtrace.agents.reporting_mod.types import SEVERITY_BADGES
from bugtrace.agents.reporting_mod.formatters import (
    generate_curl,
    extract_validation_method,
    parse_nuclei_tech_for_report,
    normalize_severity,
)
from bugtrace.agents.reporting_mod.finding_processor import (
    deduplicate_findings,
    count_by_severity,
)
from bugtrace.agents.reporting_mod.report_builder import (
    generate_standardized_finding,
    build_html_template,
    compute_enrichment_status,
)
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.file_writer")


# I/O
def write_json(
    findings: List[Dict],
    filename: str,
    description: str,
    output_dir: Path,
    scan_id: int,
    target_url: str,
) -> Path:
    """Write findings to a JSON file."""
    path = output_dir / filename

    output = {
        "meta": {
            "scan_id": scan_id,
            "target": target_url,
            "generated_at": datetime.now().isoformat(),
            "description": description,
            "count": len(findings)
        },
        "findings": findings
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    logger.info(f"[ReportingAgent] Wrote {filename} ({len(findings)} findings)")
    return path


# I/O
def write_validated_json(
    validated: List[Dict],
    manual_review: List[Dict],
    output_dir: Path,
    scan_id: int,
    target_url: str,
) -> Path:
    """Write validated_findings.json with both confirmed and manual_review."""
    path = output_dir / "validated_findings.json"

    output = {
        "meta": {
            "scan_id": scan_id,
            "target": target_url,
            "generated_at": datetime.now().isoformat(),
            "description": "VALIDATED_CONFIRMED + manual_review findings (deduplicated)",
            "count": len(validated),
            "manual_review_count": len(manual_review),
        },
        "findings": validated,
        "manual_review": manual_review,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    logger.info(
        f"[ReportingAgent] Wrote validated_findings.json "
        f"({len(validated)} validated, {len(manual_review)} manual_review)"
    )
    return path


# I/O
def write_engagement_json(
    engagement_data: Dict,
    output_dir: Path,
) -> Path:
    """Write the structured engagement_data.json for HTML viewer."""
    path = output_dir / "engagement_data.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(engagement_data, f, indent=2, default=str)

    logger.info(f"[ReportingAgent] Wrote engagement_data.json ({len(engagement_data['findings'])} vuln findings, {len(engagement_data['infrastructure']['nuclei_findings'])} nuclei findings)")
    return path


# I/O
def write_engagement_js(
    engagement_data: Dict,
    output_dir: Path,
) -> Path:
    """Write the structured engagement_data.js for HTML viewer (JSONP style).

    Raises:
        RuntimeError: If JSON serialization fails or file cannot be written.
    """
    path = output_dir / "engagement_data.js"

    # Validate JSON serialization BEFORE writing
    try:
        json_str = json.dumps(engagement_data, indent=2, default=str)
    except (TypeError, ValueError) as e:
        logger.error(f"[ReportingAgent] CRITICAL: Failed to serialize engagement data to JSON: {e}")
        raise RuntimeError(f"engagement_data.js generation failed: JSON serialization error: {e}")

    # Validate minimum required fields
    if "report_signature" not in engagement_data.get("meta", {}):
        logger.error(f"[ReportingAgent] CRITICAL: engagement_data missing report_signature")
        raise RuntimeError("engagement_data.js generation failed: missing report_signature")

    # Write as JS assignment
    js_content = f"window.BUGTRACE_REPORT_DATA = {json_str};"

    with open(path, "w", encoding="utf-8") as f:
        f.write(js_content)

    # Validate file was written correctly
    if not path.exists() or path.stat().st_size < 100:
        logger.error(f"[ReportingAgent] CRITICAL: engagement_data.js was not written correctly (size={path.stat().st_size if path.exists() else 0})")
        raise RuntimeError("engagement_data.js generation failed: file not written correctly")

    logger.info(f"[ReportingAgent] Wrote engagement_data.js ({len(engagement_data['findings'])} vuln findings, {len(engagement_data['infrastructure']['nuclei_findings'])} nuclei findings)")
    return path


# I/O
def write_markdown_report(
    validated: List[Dict],
    manual_review: List[Dict],
    pending: List[Dict],
    output_dir: Path,
    scan_id: int,
    target_url: str,
    tech_profile: Dict,
) -> Path:
    """Write the triager-ready markdown report."""
    path = output_dir / "final_report.md"

    validated = deduplicate_findings(validated)
    manual_review = deduplicate_findings(manual_review)
    pending = deduplicate_findings(pending)

    lines = []
    _md_build_header(lines, validated, manual_review, pending, scan_id, target_url, tech_profile, output_dir)
    _md_build_validated_findings(lines, validated, output_dir)
    _md_build_manual_review(lines, manual_review)
    _md_build_pending_findings(lines, pending)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info(f"[ReportingAgent] Wrote final_report.md ({len(validated)} validated, deduplicated)")
    return path


# I/O (reads template from disk, but is a helper for write_markdown_report)
def _md_build_header(
    lines: List[str],
    validated: List[Dict],
    manual_review: List[Dict],
    pending: List[Dict],
    scan_id: int,
    target_url: str,
    tech_profile: Dict,
    output_dir: Path,
) -> None:
    """Build markdown report header and summary with standardized structure."""
    stats = _calculate_scan_stats_for_md(validated + manual_review + pending, output_dir)
    by_severity = count_by_severity(validated + pending)

    lines.append("# Security Assessment Report\n")

    lines.append("## Scan Metadata\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| **Target** | {target_url} |")
    lines.append(f"| **Scan ID** | {scan_id} |")
    lines.append(f"| **Date** | {datetime.now().strftime('%d %b %Y %H:%M')} |")
    lines.append(f"| **Tool Version** | BugTraceAI v{settings.VERSION} |")
    lines.append(f"| **Duration** | {stats.get('duration', 'N/A')} |")
    lines.append(f"| **URLs Scanned** | {stats.get('urls_scanned', 0)} |")
    if stats.get('total_tokens', 0) > 0:
        lines.append(f"| **LLM Tokens Used** | {stats.get('total_tokens', 0):,} ({stats.get('input_tokens', 0):,} in / {stats.get('output_tokens', 0):,} out) |")
        lines.append(f"| **Estimated API Cost** | ${stats.get('estimated_cost', 0.0):.4f} |")
    lines.append("")

    if tech_profile:
        tech_data = parse_nuclei_tech_for_report(tech_profile)
        techs = tech_data["technologies"]
        waf_details = tech_data["waf_details"]

        if techs or waf_details:
            lines.append("## Technology Stack\n")
            lines.append("| Component | Version | Category | Notes |")
            lines.append("|-----------|---------|----------|-------|")
            for t in techs:
                version = t["version"] or "-"
                notes = "End-of-Life" if t["eol"] else ""
                lines.append(f"| **{t['name']}** | {version} | {t['category']} | {notes} |")
            lines.append("")

            if waf_details:
                lines.append(f"**Security Controls:** WAF detected ({', '.join(waf_details)})\n")

        lines.append("---\n")

    lines.append("## Executive Summary\n")

    lines.append("### Findings by Severity\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| Critical | {by_severity.get('critical', 0)} |")
    lines.append(f"| High | {by_severity.get('high', 0)} |")
    lines.append(f"| Medium | {by_severity.get('medium', 0)} |")
    lines.append(f"| Low | {by_severity.get('low', 0)} |")
    lines.append(f"| Info | {by_severity.get('info', 0)} |")
    total_count = sum(by_severity.values())
    lines.append(f"| **Total** | **{total_count}** |")
    lines.append("")

    lines.append("### Validation Summary\n")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| Confirmed | {len(validated)} |")
    lines.append(f"| Manual Review | {len(manual_review)} |")
    false_positive_count = 0
    lines.append(f"| False Positives | {false_positive_count} |")
    lines.append(f"| Pending | {len(pending)} |")
    lines.append("")


# I/O (reads urls file from disk)
def _calculate_scan_stats_for_md(all_findings: List[Dict], output_dir: Path) -> Dict:
    """Calculate scan statistics for markdown report header."""
    stats = {"urls_scanned": 0, "duration": "Unknown"}
    try:
        if output_dir and output_dir.exists():
            import os
            dir_stat = os.stat(output_dir)
            start_time = datetime.fromtimestamp(dir_stat.st_ctime)
            duration = datetime.now() - start_time
            hours, remainder = divmod(int(duration.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            stats["duration"] = f"{hours}h {minutes}m {seconds}s"
            stats["duration_seconds"] = int(duration.total_seconds())
    except Exception:
        pass

    # Count URLs scanned from file
    urls_file = output_dir / "recon" / "urls.txt"
    if urls_file.exists():
        with open(urls_file, "r") as f:
            stats["urls_scanned"] = len([line.strip() for line in f if line.strip()])
    else:
        unique_urls = set(f.get("url") for f in all_findings if f.get("url"))
        stats["urls_scanned"] = len(unique_urls)

    try:
        from bugtrace.core.llm_client import llm_client
        token_summary = llm_client.token_tracker.get_summary()
        stats["total_tokens"] = token_summary.get("total", 0)
        stats["input_tokens"] = token_summary.get("total_input", 0)
        stats["output_tokens"] = token_summary.get("total_output", 0)
        stats["estimated_cost"] = token_summary.get("estimated_cost", 0.0)
    except Exception:
        pass

    return stats


# PURE (operates on list, no filesystem)
def _md_build_validated_findings(lines: List[str], validated: List[Dict], output_dir: Path) -> None:
    """Build validated findings section of markdown report."""
    lines.append("---\n")
    lines.append("## Confirmed Vulnerabilities (Triager Ready)\n")

    if not validated:
        lines.append("*No confirmed vulnerabilities found.*\n")
        return

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    validated_sorted = sorted(validated, key=lambda x: severity_order.get(normalize_severity(x.get("severity") or "MEDIUM").upper(), 5))

    template_path = Path(__file__).parent.parent.parent / "reporting" / "templates" / "finding_template.md"

    for i, f in enumerate(validated_sorted, 1):
        finding_md = generate_standardized_finding(f, i, template_path)
        lines.append(finding_md)


# PURE
def _md_build_manual_review(lines: List[str], manual_review: List[Dict]) -> None:
    """Build manual review section of markdown report."""
    if not manual_review:
        return

    lines.append("## Needs Manual Review\n")
    lines.append("> These findings have high AI confidence but could not be confirmed via browser automation.\n")

    for i, f in enumerate(manual_review, 1):
        severity = f.get('severity', 'HIGH').upper()
        severity_badge = SEVERITY_BADGES.get(severity, severity)
        cvss_score = f.get("cvss_score")
        cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
        lines.append(f"### MR-{i}. {f.get('type', 'Unknown')}\n")
        lines.append(f"- **Severity:** {severity_badge}")
        lines.append(f"- **CVSS Score:** {cvss_str}")
        lines.append(f"- **URL:** `{f.get('url', '')}`")
        lines.append(f"- **Parameter:** `{f.get('parameter', '')}`")
        lines.append(f"- **Payload:** `{f.get('payload', '')}`")
        if f.get("validator_notes"):
            lines.append(f"- **AI Notes:** {f.get('validator_notes')}")
        lines.append("")


# PURE
def _md_build_pending_findings(lines: List[str], pending: List[Dict]) -> None:
    """Build pending findings section of markdown report."""
    if not pending:
        return

    lines.append("---\n")
    lines.append("## Pending Validation (High Confidence)\n")
    lines.append("> ⚠️ These findings were detected by specialist agents but could not be confirmed via browser automation.")
    lines.append("> They likely represent valid vulnerabilities. Manual verification recommended.\n")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    pending_sorted = sorted(pending, key=lambda x: severity_order.get(normalize_severity(x.get("severity") or "HIGH").upper(), 5))

    for i, f in enumerate(pending_sorted, 1):
        vuln_type = f.get('type', 'Unknown')
        severity = f.get('severity', 'HIGH').upper()
        severity_badge = SEVERITY_BADGES.get(severity, severity)

        lines.append(f"### P-{i}. {vuln_type}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | {severity_badge} |")
        cvss_score = f.get("cvss_score")
        cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
        lines.append(f"| **CVSS Score** | {cvss_str} |")
        lines.append(f"| **Status** | ⏳ PENDING |")
        lines.append("")
        lines.append(f"**URL:** `{f.get('url', '')}`")
        lines.append(f"**Parameter:** `{f.get('parameter', '')}`")
        lines.append(f"**Payload:** `{f.get('payload', '')}`")
        lines.append("")

        if f.get("description"):
            lines.append("#### Description\n")
            lines.append(f"{f.get('description')}")
            lines.append("")

        if f.get("validator_notes"):
            lines.append("#### Validator Notes\n")
            lines.append(f"{f.get('validator_notes')}")
            lines.append("")

        lines.append("---\n")


# I/O
def write_raw_markdown(
    findings: List[Dict],
    output_dir: Path,
    scan_id: int,
    target_url: str,
) -> Path:
    """Write raw findings to a markdown file (Pre-Audit)."""
    path = output_dir / "raw_findings.md"

    lines = []
    lines.append(f"# Raw Findings (Pre-Audit): {target_url}\n")
    lines.append(f"**Scan ID:** {scan_id}")
    lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
    lines.append(f"**Total Findings:** {len(findings)}\n")
    lines.append("---\n")

    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {f.get('type')} on {f.get('parameter', 'unknown')}\n")
        lines.append(f"- **URL:** `{f.get('url')}`")
        lines.append(f"- **Payload:** `{f.get('payload')}`")
        lines.append(f"- **Description:** {f.get('description')}\n")
        lines.append("---\n")

    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    logger.info(f"[ReportingAgent] Wrote raw_findings.md")
    return path


# I/O
def write_validated_markdown(
    validated: List[Dict],
    manual_review: List[Dict],
    output_dir: Path,
    scan_id: int,
    target_url: str,
) -> Path:
    """Write validated findings to a markdown file (Post-Audit)."""
    path = output_dir / "validated_findings.md"

    lines = []
    lines.append(f"# Validated Findings (Post-Audit): {target_url}\n")
    lines.append(f"**Scan ID:** {scan_id}")
    lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
    lines.append(f"**Confirmed:** {len(validated)} | **Manual Review:** {len(manual_review)}\n")
    lines.append("---\n")

    if validated:
        lines.append("## ✅ Confirmed Vulnerabilities\n")
        for i, f in enumerate(validated, 1):
            lines.append(f"### C-{i}. {f.get('type')}\n")
            lines.append(f"**Severity:** {f.get('severity')}\n")
            lines.append(f"**URL:** `{f.get('url')}`\n")
            lines.append(f"**Parameter:** `{f.get('parameter')}`\n")
            lines.append(f"**PoC:**\n```bash\n{generate_curl(f)}\n```\n")
            if f.get("validator_notes"):
                lines.append(f"**Validation Notes:**\n> {f.get('validator_notes')}\n")
            lines.append("---\n")

    if manual_review:
        lines.append("## ⚠️ Needs Manual Review\n")
        for i, f in enumerate(manual_review, 1):
            lines.append(f"### M-{i}. {f.get('type')}\n")
            lines.append(f"**URL:** `{f.get('url')}`\n")
            lines.append(f"**Parameter:** `{f.get('parameter')}`\n")
            lines.append(f"**Payload:** `{f.get('payload')}`\n")
            lines.append(f"**Why Review:** {f.get('validator_notes')}\n")
            lines.append("---\n")

    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    logger.info(f"[ReportingAgent] Wrote validated_findings.md")
    return path


# I/O
def copy_html_template(output_dir: Path) -> Path:
    """Copy the static HTML template that loads engagement_data.json."""
    template_src = Path(__file__).parent.parent.parent / "reporting" / "templates" / "report_dynamic.html"
    dest = output_dir / "report.html"

    if template_src.exists():
        shutil.copy(template_src, dest)
    else:
        create_minimal_html(dest)

    logger.info(f"[ReportingAgent] Copied report.html")
    return dest


# I/O
def create_minimal_html(path: Path) -> None:
    """Create minimal HTML that loads JSON dynamically."""
    html = build_html_template()
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
