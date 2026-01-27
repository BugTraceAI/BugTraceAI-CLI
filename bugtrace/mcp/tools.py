"""MCP Tools - Scan and report tools for AI assistants.

This module registers MCP tools on the FastMCP server instance from server.py.
Each tool wraps ScanService and ReportService methods for AI assistant use.

Tools:
- start_scan: Create and start a new security scan
- get_scan_status: Check scan progress and status
- query_findings: Retrieve vulnerability findings from a scan
- stop_scan: Stop a running scan gracefully

Author: BugtraceAI Team
Date: 2026-01-27
Version: 1.0.0
"""

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
