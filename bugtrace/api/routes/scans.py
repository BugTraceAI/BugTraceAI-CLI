"""
Scan Routes - REST endpoints for scan lifecycle management.

Provides 6 core endpoints:
- POST /api/scans - Create and start a new scan
- GET /api/scans/{scan_id}/status - Get scan status and progress
- GET /api/scans/{scan_id}/findings - Get scan findings with filtering
- GET /api/scans - List scan history with pagination
- POST /api/scans/{scan_id}/stop - Stop a running scan
- DELETE /api/scans/{scan_id} - Delete a scan and its findings

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status

from bugtrace.api.deps import ScanServiceDep
from bugtrace.api.schemas import (
    CreateScanRequest,
    ScanStatusResponse,
    FindingsResponse,
    FindingItem,
    ScanListResponse,
    ScanSummary,
    StopScanResponse,
    DeleteScanResponse,
)
from bugtrace.services.scan_context import ScanOptions
from bugtrace.utils.logger import get_logger

logger = get_logger("api.routes.scans")

router = APIRouter()


@router.post("/scans", status_code=status.HTTP_201_CREATED, response_model=ScanStatusResponse)
async def create_scan(
    request: CreateScanRequest,
    scan_service: ScanServiceDep,
):
    """
    Create and start a new scan.

    Returns immediately with scan_id and initial status.
    Scan runs in background task.

    Args:
        request: Scan configuration
        scan_service: Injected ScanService

    Returns:
        ScanStatusResponse with scan_id and initial status

    Raises:
        429: Too many concurrent scans (limit reached)
        400: Invalid request parameters
    """
    try:
        options = _build_scan_options(request)
        scan_id = await scan_service.create_scan(options, origin="web")
        status_dict = await scan_service.get_scan_status(scan_id)
        logger.info(f"Created scan {scan_id} for target: {request.target_url}")
        return ScanStatusResponse(**status_dict)
    except RuntimeError as e:
        logger.warning(f"Concurrent scan limit reached: {e}")
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except ValueError as e:
        logger.error(f"Invalid scan request: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def _build_scan_options(request: CreateScanRequest) -> ScanOptions:
    """Convert API request to ScanOptions."""
    return ScanOptions(
        target_url=request.target_url,
        scan_type=request.scan_type,
        safe_mode=request.safe_mode,
        max_depth=request.max_depth,
        max_urls=request.max_urls,
        resume=request.resume,
        use_vertical=request.use_vertical,
        focused_agents=request.focused_agents,
        param=request.param,
    )


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: int,
    scan_service: ScanServiceDep,
):
    """
    Get current status for a scan.

    Works for both active and completed scans.

    Args:
        scan_id: Scan ID to query
        scan_service: Injected ScanService

    Returns:
        ScanStatusResponse with current status and progress

    Raises:
        404: Scan not found
    """
    try:
        status_dict = await scan_service.get_scan_status(scan_id)
        return ScanStatusResponse(**status_dict)

    except ValueError as e:
        logger.error(f"Scan {scan_id} not found: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )


@router.get("/scans/{scan_id}/findings", response_model=FindingsResponse)
async def get_scan_findings(
    scan_id: int,
    scan_service: ScanServiceDep,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
):
    """
    Get findings for a scan with filtering and pagination.

    Args:
        scan_id: Scan ID to get findings for
        scan_service: Injected ScanService
        severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        vuln_type: Filter by vulnerability type (XSS, SQLi, etc.)
        page: Page number (1-indexed)
        per_page: Results per page (max 100)

    Returns:
        FindingsResponse with paginated findings list

    Raises:
        404: Scan not found
        400: Invalid filter parameters
    """
    _validate_findings_pagination(page, per_page)

    try:
        findings_dict = await scan_service.get_findings(
            scan_id=scan_id,
            severity=severity,
            vuln_type=vuln_type,
            page=page,
            per_page=per_page,
        )
        finding_items = [FindingItem(**f) for f in findings_dict["findings"]]
        return FindingsResponse(
            findings=finding_items,
            total=findings_dict["total"],
            page=findings_dict["page"],
            per_page=findings_dict["per_page"],
            scan_id=scan_id,
        )
    except ValueError as e:
        logger.error(f"Error getting findings for scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


def _validate_findings_pagination(page: int, per_page: int):
    """Validate pagination parameters."""
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page must be >= 1",
        )
    if per_page < 1 or per_page > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Per page must be between 1 and 100",
        )


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    scan_service: ScanServiceDep,
    page: int = 1,
    per_page: int = 20,
    status_filter: Optional[str] = None,
):
    """
    List scan history with pagination.

    Args:
        scan_service: Injected ScanService
        page: Page number (1-indexed)
        per_page: Results per page (max 100)
        status_filter: Filter by status (RUNNING, COMPLETED, STOPPED, FAILED)

    Returns:
        ScanListResponse with paginated scan list

    Raises:
        400: Invalid pagination parameters
    """
    # Validate pagination
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page must be >= 1",
        )
    if per_page < 1 or per_page > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Per page must be between 1 and 100",
        )

    scans_dict = await scan_service.list_scans(
        page=page,
        per_page=per_page,
        status_filter=status_filter,
    )

    # Convert scans to ScanSummary models
    scan_summaries = [ScanSummary(**s) for s in scans_dict["scans"]]

    return ScanListResponse(
        scans=scan_summaries,
        total=scans_dict["total"],
        page=scans_dict["page"],
        per_page=scans_dict["per_page"],
    )


@router.post("/scans/{scan_id}/stop", response_model=StopScanResponse)
async def stop_scan(
    scan_id: int,
    scan_service: ScanServiceDep,
):
    """
    Stop a running scan gracefully.

    Args:
        scan_id: Scan ID to stop
        scan_service: Injected ScanService

    Returns:
        StopScanResponse with status message

    Raises:
        404: Scan not found or not running
    """
    try:
        result = await scan_service.stop_scan(scan_id)
        logger.info(f"Scan {scan_id} stop requested")
        return StopScanResponse(**result)

    except ValueError as e:
        logger.error(f"Cannot stop scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.delete("/scans/{scan_id}", response_model=DeleteScanResponse)
async def delete_scan(
    scan_id: int,
    scan_service: ScanServiceDep,
):
    """
    Delete a scan and its associated findings.

    Cannot delete a scan that is currently running.

    Args:
        scan_id: Scan ID to delete
        scan_service: Injected ScanService

    Returns:
        DeleteScanResponse with confirmation message

    Raises:
        404: Scan not found
        409: Scan is currently running
    """
    try:
        result = await scan_service.delete_scan(scan_id)
        logger.info(f"Deleted scan {scan_id}")
        return DeleteScanResponse(**result)

    except ValueError as e:
        error_msg = str(e)
        if "still running" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=error_msg,
        )
