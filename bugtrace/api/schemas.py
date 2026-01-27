"""
API Schemas - Pydantic request/response models for REST API.

Provides type-safe request/response models for all API endpoints.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field


# Scan Request/Response Models

class CreateScanRequest(BaseModel):
    """
    Request body for POST /api/scans.

    Maps to ScanOptions from scan_context.py.
    """
    target_url: str = Field(..., description="Target URL to scan")
    scan_type: str = Field(default="full", description="Scan type: full, hunter, manager, or focused agent names")
    safe_mode: Optional[bool] = Field(default=None, description="Override global safe mode setting")
    max_depth: int = Field(default=2, description="Maximum crawl depth")
    max_urls: int = Field(default=20, description="Maximum URLs to crawl")
    resume: bool = Field(default=False, description="Resume a previous scan")
    use_vertical: bool = Field(default=True, description="Use vertical specialized agents")
    focused_agents: List[str] = Field(default_factory=list, description="List of focused agent names")
    param: Optional[str] = Field(default=None, description="Specific parameter to target")


class ScanStatusResponse(BaseModel):
    """
    Response for GET /api/scans/{scan_id}/status and POST /api/scans.

    Provides current scan state and progress information.
    """
    scan_id: int
    target: str
    status: str  # initializing, running, completed, stopped, failed
    progress: int  # 0-100
    uptime_seconds: Optional[float] = None  # None if not running
    findings_count: int
    active_agent: Optional[str] = None
    phase: Optional[str] = None
    origin: str = "cli"  # "cli" or "web" — where scan was launched


class FindingItem(BaseModel):
    """
    Single finding item for findings list response.
    """
    finding_id: int
    type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    details: str
    payload: Optional[str] = None
    url: str
    parameter: Optional[str] = None
    validated: bool
    status: str
    confidence: Optional[float] = None


class FindingsResponse(BaseModel):
    """
    Response for GET /api/scans/{scan_id}/findings.

    Paginated findings list with filtering support.
    """
    findings: List[FindingItem]
    total: int
    page: int
    per_page: int
    scan_id: int


class ScanSummary(BaseModel):
    """
    Summary information for a scan in list view.
    """
    scan_id: int
    target: str
    status: str
    progress: int
    timestamp: str  # ISO format
    origin: str = "cli"  # "cli" or "web"


class ScanListResponse(BaseModel):
    """
    Response for GET /api/scans.

    Paginated scan list.
    """
    scans: List[ScanSummary]
    total: int
    page: int
    per_page: int


class StopScanResponse(BaseModel):
    """
    Response for POST /api/scans/{scan_id}/stop.
    """
    scan_id: int
    status: str
    message: str


class DeleteScanResponse(BaseModel):
    """
    Response for DELETE /api/scans/{scan_id}.
    """
    scan_id: int
    message: str


class ErrorResponse(BaseModel):
    """
    Error response model for all endpoints.
    """
    detail: str
    error_code: Optional[str] = None
