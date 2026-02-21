"""MCP Tools - Scan and report tools for AI assistants.

This module registers MCP tools on the FastMCP server instance from server.py.
Each tool wraps ScanService and ReportService methods for AI assistant use.

Tools:
- start_scan: Create and start a new security scan
- get_scan_status: Check scan progress and status
- query_findings: Retrieve vulnerability findings from a scan
- stop_scan: Stop a running scan gracefully
- export_report: Export final report for download/sharing

Author: BugtraceAI Team
Date: 2026-01-27
Version: 1.1.0
"""

from pathlib import Path
from typing import Optional, Dict, Any

from bugtrace.mcp.server import mcp_server
from bugtrace.api.deps import get_scan_service
from bugtrace.services.scan_context import ScanOptions


@mcp_server.tool()
async def start_scan(
    target_url: str,
    scan_type: str = "full",
    max_depth: int = 2,
    max_urls: int = 20
) -> Dict[str, Any]:
    """Start a new security scan on a target URL.

    Creates a new scan with specified options and returns the scan ID for tracking.
    The scan runs in the background - use get_scan_status to monitor progress.

    Args:
        target_url: The URL to scan (must be valid HTTP/HTTPS URL)
        scan_type: Type of scan - "full" (default), "hunter", "manager", or specific agent name
        max_depth: Maximum crawl depth (default: 2, range: 1-5)
        max_urls: Maximum URLs to scan (default: 20, range: 1-100)

    Returns:
        Dictionary with scan_id, status, and message
        Example: {"scan_id": 1, "status": "created", "message": "Scan started successfully"}

    Raises:
        RuntimeError: If concurrent scan limit exceeded or scan creation fails
    """
    try:
        # Create scan options
        options = ScanOptions(
            target_url=target_url,
            scan_type=scan_type,
            max_depth=max_depth,
            max_urls=max_urls
        )

        # Get scan service and create scan
        scan_service = get_scan_service()
        scan_id = await scan_service.create_scan(options)

        return {
            "scan_id": scan_id,
            "status": "created",
            "message": f"Scan {scan_id} started successfully for {target_url}"
        }
    except RuntimeError as e:
        return {
            "error": str(e),
            "status": "failed",
            "message": "Failed to start scan"
        }


@mcp_server.tool()
async def get_scan_status(scan_id: int) -> Dict[str, Any]:
    """Get the current status and progress of a scan.

    Retrieves detailed status information including progress, findings count,
    active agent, and phase. Works for both running and completed scans.

    Args:
        scan_id: The ID of the scan to check

    Returns:
        Dictionary with scan status details including:
        - scan_id: The scan ID
        - target: Target URL being scanned
        - status: Current status (initializing, running, completed, failed, stopped)
        - progress: Completion percentage (0-100)
        - findings_count: Number of vulnerabilities found
        - active_agent: Currently executing agent
        - phase: Current scan phase
        - uptime_seconds: Time elapsed since scan start

    Raises:
        ValueError: If scan ID does not exist
    """
    try:
        scan_service = get_scan_service()
        status = await scan_service.get_scan_status(scan_id)
        return status
    except ValueError:
        return {
            "error": "Scan not found",
            "scan_id": scan_id
        }


@mcp_server.tool()
async def query_findings(
    scan_id: int,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 20
) -> Dict[str, Any]:
    """Query vulnerability findings from a completed or running scan.

    Retrieves paginated list of security findings with optional filtering by
    severity level and vulnerability type.

    Args:
        scan_id: The ID of the scan to query
        severity: Filter by severity - "critical", "high", "medium", "low", "info" (optional)
        vuln_type: Filter by vulnerability type - "xss", "sqli", "csrf", etc. (optional)
        page: Page number for pagination (default: 1, min: 1)
        per_page: Results per page (default: 20, range: 1-100)

    Returns:
        Dictionary with findings data including:
        - scan_id: The scan ID
        - findings: List of vulnerability objects with details
        - total: Total number of findings matching filters
        - page: Current page number
        - per_page: Results per page
        - total_pages: Total pages available

    Raises:
        ValueError: If scan ID does not exist or parameters are invalid
    """
    try:
        scan_service = get_scan_service()
        findings = await scan_service.get_findings(
            scan_id=scan_id,
            severity=severity,
            vuln_type=vuln_type,
            page=page,
            per_page=per_page
        )
        return findings
    except ValueError as e:
        return {
            "error": str(e),
            "scan_id": scan_id
        }


@mcp_server.tool()
async def stop_scan(scan_id: int) -> Dict[str, Any]:
    """Stop a running scan gracefully.

    Sends a stop signal to the scan, allowing it to complete current tasks
    and save progress. The scan status will change to "stopping" then "stopped".

    Args:
        scan_id: The ID of the scan to stop

    Returns:
        Dictionary with stop operation result:
        - scan_id: The scan ID
        - status: New status after stop signal
        - message: Human-readable result message

    Raises:
        ValueError: If scan ID does not exist or scan is not running
    """
    try:
        scan_service = get_scan_service()
        result = await scan_service.stop_scan(scan_id)
        return result
    except ValueError as e:
        return {
            "error": str(e),
            "scan_id": scan_id,
            "status": "failed",
            "message": "Failed to stop scan"
        }


@mcp_server.tool()
async def export_report(scan_id: int, section: str = "summary") -> Dict[str, Any]:
    """Export a scan report summary or specific section.

    Returns a concise report for a completed scan. Use section parameter to
    control how much detail is returned.

    IMPORTANT: The default "summary" section returns a brief overview suitable
    for messaging apps. Use "critical" to see only critical/high findings.
    Use "full" only if you need the entire report (may be very large).

    Args:
        scan_id: The ID of the scan to export
        section: What to return:
            - "summary" (default): Executive summary with severity counts and top findings
            - "critical": Only critical and high severity findings with details
            - "full": Complete markdown report (WARNING: can be 40KB+, may timeout)

    Returns:
        Dictionary with scan_id, target, report text, and findings summary
    """
    try:
        from bugtrace.api.routes.reports import _find_report_dir
        from bugtrace.core.database import get_db_manager

        db = get_db_manager()
        with db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                return {"error": f"Scan {scan_id} not found", "scan_id": scan_id}
            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else "unknown"
            scan_status = scan.status

        if scan_status in ("initializing", "running"):
            return {
                "error": f"Scan {scan_id} is still {scan_status}. Wait for completion.",
                "scan_id": scan_id,
                "status": scan_status,
            }

        report_dir = _find_report_dir(scan_id)
        if not report_dir:
            return {
                "error": f"No report found for scan {scan_id}.",
                "scan_id": scan_id,
            }

        findings_summary = _build_findings_summary(report_dir)
        section = section.lower()

        if section == "full":
            md_file = report_dir / "final_report.md"
            if not md_file.is_file():
                md_file = report_dir / "technical_report.md"
            if not md_file.is_file():
                return {"error": "No report file found", "scan_id": scan_id}
            content = md_file.read_text(encoding="utf-8")
            # Truncate to 8000 chars to avoid LLM context overflow
            if len(content) > 8000:
                content = content[:8000] + "\n\n... [TRUNCATED — report is too large for chat. Full report has " + str(len(md_file.read_text(encoding="utf-8"))) + " characters] ..."

        elif section == "critical":
            content = _extract_critical_findings(report_dir, target_url)

        else:  # summary (default)
            content = _build_executive_summary(report_dir, target_url, scan_id, findings_summary)

        return {
            "scan_id": scan_id,
            "target": target_url,
            "section": section,
            "report": content,
            "findings_summary": findings_summary,
        }

    except Exception as e:
        return {"error": str(e), "scan_id": scan_id}


def _build_findings_summary(report_dir: Path) -> Dict[str, Any]:
    """Build a quick severity summary from validated_findings.json."""
    import json

    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vf = report_dir / "validated_findings.json"
    if not vf.is_file():
        vf = report_dir / "raw_findings.json"
    if not vf.is_file():
        return summary

    try:
        data = json.loads(vf.read_text(encoding="utf-8"))
        findings = data if isinstance(data, list) else data.get("findings", [])
        summary["total"] = len(findings)
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev in summary:
                summary[sev] += 1
    except Exception:
        pass

    return summary


def _build_executive_summary(
    report_dir: Path, target_url: str, scan_id: int, summary: Dict[str, Any]
) -> str:
    """Build a concise executive summary from the report files."""
    import json

    lines = [
        f"# BugTraceAI Scan Report — Scan #{scan_id}",
        f"**Target:** {target_url}",
        "",
        "## Findings Overview",
        f"- **Total findings:** {summary['total']}",
        f"- **Critical:** {summary['critical']}",
        f"- **High:** {summary['high']}",
        f"- **Medium:** {summary['medium']}",
        f"- **Low:** {summary['low']}",
        f"- **Info:** {summary['info']}",
        "",
    ]

    # Extract top findings (critical + high)
    vf = report_dir / "validated_findings.json"
    if not vf.is_file():
        vf = report_dir / "raw_findings.json"

    if vf.is_file():
        try:
            data = json.loads(vf.read_text(encoding="utf-8"))
            findings = data if isinstance(data, list) else data.get("findings", [])

            top = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")]
            if top:
                lines.append("## Critical & High Findings")
                for i, f in enumerate(top[:10], 1):
                    ftype = f.get("type", "Unknown")
                    sev = f.get("severity", "?").upper()
                    url = f.get("url") or f.get("attack_url") or "N/A"
                    param = f.get("parameter") or f.get("vuln_parameter") or ""
                    desc = f.get("description") or f.get("details") or ""
                    # Truncate description
                    if len(desc) > 150:
                        desc = desc[:150] + "..."
                    lines.append(f"### {i}. [{sev}] {ftype}")
                    lines.append(f"- **URL:** {url}")
                    if param:
                        lines.append(f"- **Parameter:** {param}")
                    if desc:
                        lines.append(f"- **Details:** {desc}")
                    lines.append("")

            # Vuln type breakdown
            type_counts: Dict[str, int] = {}
            for f in findings:
                ft = str(f.get("type", "unknown"))
                type_counts[ft] = type_counts.get(ft, 0) + 1
            if type_counts:
                lines.append("## Vulnerability Types")
                for vtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                    lines.append(f"- {vtype}: {count}")
                lines.append("")

        except Exception:
            pass

    lines.append("*Use `export_report` with `section=\"critical\"` for more details on critical findings.*")

    return "\n".join(lines)


def _extract_critical_findings(report_dir: Path, target_url: str) -> str:
    """Extract detailed critical and high findings."""
    import json

    vf = report_dir / "validated_findings.json"
    if not vf.is_file():
        vf = report_dir / "raw_findings.json"
    if not vf.is_file():
        return "No findings data available."

    try:
        data = json.loads(vf.read_text(encoding="utf-8"))
        findings = data if isinstance(data, list) else data.get("findings", [])
    except Exception:
        return "Error reading findings data."

    critical = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")]
    if not critical:
        return "No critical or high severity findings."

    lines = [f"# Critical & High Findings — {target_url}", ""]
    for i, f in enumerate(critical[:15], 1):
        ftype = f.get("type", "Unknown")
        sev = f.get("severity", "?").upper()
        url = f.get("url") or f.get("attack_url") or "N/A"
        param = f.get("parameter") or f.get("vuln_parameter") or ""
        desc = f.get("description") or f.get("details") or ""
        payload = f.get("payload") or f.get("payload_used") or ""
        repro = f.get("reproduction_command") or ""

        lines.append(f"## {i}. [{sev}] {ftype}")
        lines.append(f"**URL:** {url}")
        if param:
            lines.append(f"**Parameter:** {param}")
        if desc:
            if len(desc) > 500:
                desc = desc[:500] + "..."
            lines.append(f"**Description:** {desc}")
        if payload:
            if len(payload) > 300:
                payload = payload[:300] + "..."
            lines.append(f"**Payload:** `{payload}`")
        if repro:
            if len(repro) > 300:
                repro = repro[:300] + "..."
            lines.append(f"**Reproduce:** `{repro}`")
        lines.append("")

    return "\n".join(lines)
