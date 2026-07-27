"""
API Schemas - Pydantic request/response models for REST API.

Provides type-safe request/response models for all API endpoints.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, field_validator

from bugtrace.schemas.db_models import ScanStatus, FindingStatus


# Scan Request/Response Models

class CreateScanRequest(BaseModel):
    """
    Request body for POST /api/scans.

    Maps to ScanOptions from scan_context.py.
    """
    target_url: str = Field(..., description="Target URL to scan")
    scan_type: str = Field(default="full", description="Scan type: full, hunter, manager, or focused agent names")
    scan_depth: str = Field(default="", description="Exploitation depth: quick, standard, thorough. Empty = use config default.")
    safe_mode: Optional[bool] = Field(default=None, description="Override global safe mode setting")
    max_depth: int = Field(default=2, description="Maximum crawl depth")
    max_urls: int = Field(default=20, description="Maximum URLs to crawl")
    resume: bool = Field(default=False, description="Resume a previous scan")
    use_vertical: bool = Field(default=True, description="Use vertical specialized agents")
    focused_agents: List[str] = Field(default_factory=list, description="List of focused agent names")
    param: Optional[str] = Field(default=None, description="Specific parameter to target")
    auth_token: Optional[str] = Field(default=None, description="Pre-authenticated Bearer token (Level 1)")
    auth: Optional[Dict[str, Any]] = Field(default=None, description="Auto-login credentials: {login_url, credentials: {email, password, totp_secret?}, login_flow?: [...]} (Level 2/3)")
    url_list: Optional[List[str]] = Field(default=None, description="Pre-defined URL list (from URL list file or Swagger import)")

    @field_validator("target_url")
    @classmethod
    def _strip_target_url(cls, v: str) -> str:
        # A pasted leading/trailing space must never reach recon (it yields 0 URLs and
        # fails the scan). Sanitize at the boundary so logs/DB store the clean URL too.
        return v.strip() if isinstance(v, str) else v

    @field_validator("url_list")
    @classmethod
    def _strip_url_list(cls, v):
        if not v:
            return v
        return [u.strip() for u in v if isinstance(u, str) and u.strip()]


class ScanStatusResponse(BaseModel):
    """
    Response for GET /api/scans/{scan_id}/status and POST /api/scans.

    Provides current scan state and progress information.
    """
    scan_id: int
    target: str
    status: ScanStatus  # Type-safe enum: PENDING, RUNNING, COMPLETED, STOPPED, FAILED
    progress: int  # 0-100
    uptime_seconds: Optional[float] = None  # None if not running
    findings_count: int
    active_agent: Optional[str] = None
    phase: Optional[str] = None
    origin: str = "unknown"  # "cli", "web", or "unknown" — where scan was launched
    enrichment_status: Optional[str] = None  # "full", "partial", "none", "pending"
    scan_type: Optional[str] = None
    max_depth: Optional[int] = None
    max_urls: Optional[int] = None
    provider: Optional[str] = None  # LLM provider used: "openrouter", "zai", etc.


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
    status: FindingStatus  # Type-safe enum for validation status
    confidence: Optional[float] = None
    # Seed enrichment: real request(s) that confirmed the finding (auth masked at
    # capture time). `repro` is the structured object; `http_request` is the raw
    # HTTP string. Consumed by the WEB AI Repeater ("Send to Repeater").
    repro: Optional[Dict[str, Any]] = None
    http_request: Optional[str] = None


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
    status: ScanStatus  # Type-safe enum
    progress: int
    timestamp: str  # ISO format
    origin: str = "unknown"  # "cli", "web", or "unknown"
    enrichment_status: Optional[str] = None  # "full", "partial", "none", "pending"
    has_report: bool = True  # Whether report files exist on disk
    recovery_available: bool = False  # Whether partial or full scan artifacts exist on disk
    scan_type: Optional[str] = None
    max_depth: Optional[int] = None
    max_urls: Optional[int] = None
    provider: Optional[str] = None  # LLM provider used
    findings_count: int = 0  # Total findings for this scan


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
    files_cleaned: bool = False


class ErrorResponse(BaseModel):
    """
    Error response model for all endpoints.
    """
    detail: str
    error_code: Optional[str] = None


# OOB Collaborator Models

class OobStartRequest(BaseModel):
    """Request body for POST /api/oob/start (all fields optional)."""
    server: Optional[str] = Field(default=None, description="interactsh server (default: configured INTERACTSH_SERVER, e.g. oast.fun)")


class OobInteractionItem(BaseModel):
    """A single captured OOB interaction."""
    protocol: str = Field(..., description="dns | http | smtp | ...")
    full_id: str = Field(..., description="Full subdomain id that received the callback")
    remote_address: str = Field(..., description="Source IP of the interaction")
    raw_request: str = Field(default="", description="Raw request captured by the server")
    timestamp: str = Field(..., description="ISO timestamp of the interaction")


class OobSessionResponse(BaseModel):
    """Response for POST /api/oob/start — the collaborator domain to use."""
    session_id: str = Field(..., description="OOB session id")
    domain: str = Field(..., description="Unique callback domain to embed in payloads")
    server: str = Field(..., description="interactsh server backing this session")
    interaction_count: int = Field(default=0, description="Interactions captured so far")


class OobInteractionsResponse(BaseModel):
    """Response for GET /api/oob/{session_id} — captured interactions."""
    session_id: str
    domain: str
    interaction_count: int
    interactions: List[OobInteractionItem]
