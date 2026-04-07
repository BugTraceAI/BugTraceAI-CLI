"""
Dependency Injection - FastAPI dependencies for services.

Provides singleton instances of ScanService, ReportService, and ServiceEventBus
via dependency injection pattern.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Annotated
from fastapi import Depends

from bugtrace.services.scan_service import ScanService
from bugtrace.services.report_service import ReportService
from bugtrace.services.event_bus import service_event_bus, ServiceEventBus

# Singleton instances
_scan_service: ScanService | None = None
_report_service: ReportService | None = None


def get_scan_service() -> ScanService:
    """
    Get or create ScanService singleton.

    Returns:
        ScanService instance for scan lifecycle management
    """
    global _scan_service
    if _scan_service is None:
        _scan_service = ScanService()
    return _scan_service


def get_report_service() -> ReportService:
    """
    Get or create ReportService singleton.

    Returns:
        ReportService instance for report generation
    """
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service


def get_event_bus() -> ServiceEventBus:
    """
    Get ServiceEventBus singleton.

    Returns:
        ServiceEventBus instance for event streaming
    """
    return service_event_bus


# Type aliases for FastAPI dependency injection
ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]
ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]
EventBusDep = Annotated[ServiceEventBus, Depends(get_event_bus)]
