"""
API Schemas - Pydantic request/response models for REST API.

Provides type-safe request/response models for all API endpoints.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Optional, List, Any, Dict, Literal
from pydantic import BaseModel, Field, field_validator, model_validator

from bugtrace.schemas.db_models import ScanStatus, FindingStatus


# Repeater persistence

class RepeaterFindingCreate(BaseModel):
    """Request body for POST /api/scans/{scan_id}/findings — AI Repeater persists a confirmed finding."""
    type: str = Field(..., min_length=1, max_length=100, description="Vulnerability type (e.g. XSS, SQLi, GRAPHQL_IDOR)")
    severity: str = Field(default="MEDIUM", description="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    url: str = Field(..., min_length=1, max_length=4096, description="Target URL of the finding")
    parameter: Optional[str] = Field(default=None, max_length=500, description="Injection parameter name")
    summary: str = Field(..., min_length=1, max_length=10000, description="Human-readable summary of the finding")
    request: str = Field(..., min_length=1, max_length=100000, description="Raw HTTP request that proved the finding")
    response_status: int = Field(..., ge=100, le=599, description="HTTP response status code")
    response_excerpt: Optional[str] = Field(default=None, max_length=4000, description="Bounded excerpt of the response body")
    source_finding_id: Optional[int] = Field(default=None, description="Original finding id if this extends one from the scan")
    confidence: Optional[float] = Field(default=0.95, ge=0.0, le=1.0, description="Confidence score 0-1")
    request_ok: Literal[True] = Field(..., description="Whether the curl-backed transport completed successfully")

    @model_validator(mode="after")
    def _require_evidence(self):
        if not self.request or not self.request.strip():
            raise ValueError("request is required and must not be empty")
        return self


class RepeaterFindingResponse(BaseModel):
    """Response for POST /api/scans/{scan_id}/findings."""
    finding_id: int
    created: bool
    success: bool = True
    message: str
    report_refresh: Optional[str] = None


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
    auth: Optional[Dict[str, Any]] = Field(default=None, description="Auto-login credentials: {login_url, login_type?: form|api, request_format?: form|json, credentials: {email, password, totp_secret?}, login_flow?: [...]} (Level 2/3)")
    url_list: Optional[List[str]] = Field(default=None, description="Pre-defined URL list (from URL list file or Swagger import)")
    custom_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description=(
            "Per-scan HTTP headers. Precedence (low -> high): DEFAULT_HEADERS_JSON "
            "< auth discovery < these. Authorization/Cookie may be set here to "
            "override auto-discovered values. Reserved names (Host, Content-Length, "
            "Transfer-Encoding, Connection, Upgrade) are rejected."
        ),
    )

    @field_validator("custom_headers")
    @classmethod
    def _validate_custom_headers(cls, v):
        if v is None:
            return v
        if not isinstance(v, dict):
            raise ValueError("custom_headers must be a JSON object (dict)")
        from bugtrace.utils.headers import (
            merge_headers,
            validate_header_name,
            validate_header_value,
        )
        # validate every name + value BEFORE merge_headers (which only strips
        # reserved names as a safety net). This closes the API-side header
        # injection path where {"X-Test": "v\r\nX-Injected: evil"} would
        # otherwise be accepted and reach Nuclei -H / aiohttp verbatim.
        validated: dict = {}
        for raw_name, raw_value in v.items():
            name = validate_header_name(raw_name)
            value = validate_header_value(name, raw_value)
            if not value:
                # Treat empty values at the API boundary the same as a
                # malformed header: refuse the request rather than silently
                # dropping the user's intent.
                raise ValueError(
                    f"value for header {name!r} is empty; omit the key or "
                    f"send a non-empty string"
                )
            validated[name] = value
        merged = merge_headers(validated)
        if not merged:
            raise ValueError(
                "custom_headers contains only reserved/empty entries and cannot "
                "be used; reserved names (Host, Content-Length, Transfer-Encoding, "
                "Connection, Upgrade) are not permitted"
            )
        return merged

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
    findings_count: int = 0  # Compatibility alias for detections_count
    detections_count: int = 0
    confirmed_count: int = 0
    manual_review_count: int = 0
    reportable_count: int = 0


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
