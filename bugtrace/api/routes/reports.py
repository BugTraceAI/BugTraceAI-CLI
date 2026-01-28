"""
Report Download Endpoints - Serve generated reports in multiple formats.

Provides:
- GET /scans/{scan_id}/report/{format} - Download report in HTML/JSON/Markdown
- GET /scans/{scan_id}/files/{filename} - Serve individual report files

Solves:
- API-06: Report download endpoint

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import mimetypes
from pathlib import Path as FilePath

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import Response, FileResponse

from bugtrace.api.deps import get_report_service
from bugtrace.core.config import settings
from bugtrace.core.database import get_db_manager
from bugtrace.services.report_service import ReportService
from bugtrace.utils.logger import get_logger

logger = get_logger("api.routes.reports")

router = APIRouter(tags=["reports"])


def _validate_report_format(format: str) -> None:
    """Validate report format parameter."""
    if format not in ("html", "json", "markdown"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {format}. Use html, json, or markdown"
        )


def _get_content_type_and_extension(format: str) -> tuple[str, str]:
    """Get content type and file extension for report format."""
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
    return content_types[format], extensions[format]


def _build_report_response(
    report_bytes: bytes,
    format: str,
    scan_id: int
) -> Response:
    """Build HTTP response for report download."""
    content_type, extension = _get_content_type_and_extension(format)
    filename = f"bugtrace_report_{scan_id}.{extension}"

    logger.info(f"Serving {format} report for scan {scan_id}: {len(report_bytes)} bytes")

    return Response(
        content=report_bytes,
        media_type=content_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


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
    _validate_report_format(format)

    try:
        report_bytes = await report_service.get_report(scan_id, format)

        if report_bytes is None:
            raise HTTPException(
                status_code=404,
                detail=f"Report not found for scan {scan_id}"
            )

        return _build_report_response(report_bytes, format, scan_id)

    except ValueError as e:
        logger.error(f"Report not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {str(e)}"
        )


def _find_report_dir(scan_id: int) -> FilePath | None:
    """
    Find the report directory for a scan_id.

    Searches two patterns:
    1. scan_{id}/ (created by ReportService API)
    2. {domain}_{timestamp}/ (created by scan pipeline)

    For pattern 2, resolves scan_id -> target URL -> domain, then finds
    the most recent matching directory.
    """
    report_base = settings.REPORT_DIR

    # Pattern 1: API-generated reports
    api_dir = report_base / f"scan_{scan_id}"
    if api_dir.is_dir():
        return api_dir

    # Pattern 2: Pipeline-generated reports ({domain}_{timestamp})
    try:
        db = get_db_manager()
        with db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                return None
            target = session.get(TargetTable, scan.target_id)
            if not target:
                return None

            # Extract domain from URL
            from urllib.parse import urlparse
            domain = urlparse(target.url).hostname or ""

            # Find matching report directories, sorted newest first
            matches = sorted(
                report_base.glob(f"{domain}_*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if matches:
                return matches[0]
    except Exception as e:
        logger.warning(f"Error resolving report dir for scan {scan_id}: {e}")

    return None


@router.get("/scans/{scan_id}/files/{filename:path}")
async def get_report_file(
    scan_id: int,
    filename: str = Path(..., description="Report filename (e.g. final_report.md)"),
):
    """
    Serve an individual file from a scan's report directory.

    Used by the WEB frontend to load report markdown, validated findings JSON,
    and other report deliverables.

    Args:
        scan_id: Scan ID
        filename: File path relative to the report directory

    Returns:
        File contents with appropriate content type

    Raises:
        404: Report directory or file not found
    """
    report_dir = _find_report_dir(scan_id)
    if not report_dir:
        raise HTTPException(status_code=404, detail=f"No report directory found for scan {scan_id}")

    # Resolve and validate the file path (prevent path traversal)
    file_path = (report_dir / filename).resolve()
    if not str(file_path).startswith(str(report_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    # Determine content type
    content_type, _ = mimetypes.guess_type(str(file_path))
    if not content_type:
        content_type = "application/octet-stream"

    logger.info(f"Serving report file: scan={scan_id} file={filename}")

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=file_path.name,
    )
