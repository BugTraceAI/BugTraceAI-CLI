"""
Report Download Endpoints - Serve generated reports in multiple formats.

Provides GET /scans/{scan_id}/report/{format} endpoint for HTML, JSON, and Markdown reports.

Solves:
- API-06: Report download endpoint

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import Response

from bugtrace.api.deps import get_report_service
from bugtrace.services.report_service import ReportService
from bugtrace.utils.logger import get_logger

logger = get_logger("api.routes.reports")

router = APIRouter(tags=["reports"])


@router.get("/scans/{scan_id}/report/{format}")
async def get_report(
    scan_id: int,
    format: str = Path(..., description="Report format: html, json, markdown"),
    report_service: ReportService = Depends(get_report_service)
):
    """
    Download generated report in specified format.

    Args:
        scan_id: Scan ID
        format: Report format (html, json, markdown)

    Returns:
        Report file with appropriate content type and download headers

    Raises:
        400: Invalid format
        404: Scan or report not found
        500: Report generation failed

    Solves API-06: Report download endpoint
    """
    format = format.lower()

    # Validate format
    if format not in ("html", "json", "markdown"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {format}. Use html, json, or markdown"
        )

    try:
        # Get or generate report
        report_bytes = await report_service.get_report(scan_id, format)

        if report_bytes is None:
            raise HTTPException(
                status_code=404,
                detail=f"Report not found for scan {scan_id}"
            )

        # Determine content type and filename
        content_types = {
            "html": "text/html",
            "json": "application/json",
            "markdown": "text/markdown",
        }
        extensions = {
            "html": "html",
            "json": "json",
            "markdown": "md",
        }

        content_type = content_types[format]
        filename = f"bugtrace_report_{scan_id}.{extensions[format]}"

        logger.info(f"Serving {format} report for scan {scan_id}: {len(report_bytes)} bytes")

        return Response(
            content=report_bytes,
            media_type=content_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )

    except ValueError as e:
        logger.error(f"Report not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {str(e)}"
        )
