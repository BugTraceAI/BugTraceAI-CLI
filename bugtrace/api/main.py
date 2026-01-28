"""
FastAPI Application - Main application with CORS, health check, and routing.

Provides REST API for BugtraceAI scan and report management.

Solves:
- API-09: CORS with explicit origins (not wildcard with credentials)
- API-10: Serve command integration
- INF-04: Health check endpoint

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from bugtrace.core.config import settings
from bugtrace.api.deps import ScanServiceDep, ReportServiceDep, EventBusDep, get_scan_service
from bugtrace.api.exceptions import register_exception_handlers
from bugtrace.services.event_bus import service_event_bus
from bugtrace.utils.logger import get_logger, set_correlation_id

logger = get_logger("api.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown.

    Startup:
        - Log API server initialization
        - Verify service dependencies

    Shutdown:
        - Log graceful shutdown
        - Services handle their own cleanup
    """
    # Startup
    logger.info("FastAPI application starting up...")
    logger.info(f"API Version: {settings.VERSION}")
    logger.info(f"Environment: {settings.ENV}")
    logger.info(f"CORS Origins: {_get_cors_origins()}")

    # Clean up orphaned scans (RUNNING/PENDING in DB but no process behind them)
    scan_service = get_scan_service()
    orphaned = scan_service.cleanup_orphaned_scans()
    if orphaned:
        logger.info(f"Marked {orphaned} orphaned scan(s) as FAILED on startup")

    yield

    # Shutdown
    logger.info("FastAPI application shutting down...")


# OpenAPI tag metadata for Swagger documentation
openapi_tags = [
    {
        "name": "scans",
        "description": "Security scan lifecycle management - create, monitor, stop scans",
    },
    {
        "name": "reports",
        "description": "Scan report retrieval in HTML, JSON, and Markdown formats",
    },
    {
        "name": "config",
        "description": "Runtime configuration viewing and updating",
    },
    {
        "name": "health",
        "description": "Server health and readiness monitoring",
    },
]

# Create FastAPI app
app = FastAPI(
    title="BugTraceAI API",
    description="REST API for security scanning and report management",
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_tags=openapi_tags,
    docs_url="/docs",
    redoc_url="/redoc",
    contact={"name": "BugTraceAI", "url": "https://github.com/BugTraceAI"},
    license_info={"name": "MIT"},
)


def _get_cors_origins() -> list[str]:
    """
    Get CORS allowed origins from environment.

    Returns:
        List of allowed origin strings

    Environment variable:
        BUGTRACE_CORS_ORIGINS: Comma-separated list of origins
        Example: "http://localhost:3000,http://localhost:5173"

    Default (if not set):
        Development: localhost:3000 and localhost:5173
        Production: Empty list (must be explicitly configured)
    """
    env_origins = os.getenv("BUGTRACE_CORS_ORIGINS", "")

    if env_origins:
        # Parse from environment
        origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
        logger.info(f"CORS origins from environment: {origins}")
        return origins

    # Default to common development origins
    if settings.DEBUG or settings.ENV == "development":
        default_origins = [
            "http://localhost:3000",  # React default
            "http://localhost:5173",  # Vite default
        ]
        logger.info(f"Using default development CORS origins: {default_origins}")
        return default_origins

    # Production: require explicit configuration
    logger.warning("No CORS origins configured for production - CORS will block all cross-origin requests")
    return []


# Configure CORS middleware
# CRITICAL: Uses explicit origin list, NOT wildcard ["*"] with credentials
# This fixes Pitfall 4 from PITFALLS.md (CORS preflight cache invalidation)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_cors_origins(),  # Explicit origins from environment
    allow_credentials=True,  # Allow cookies/authentication
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Scan-ID"],
    expose_headers=["X-Scan-Progress"],
    max_age=3600,  # Cache preflight for 1 hour
)

# Register global exception handlers
# Must be registered AFTER middleware to ensure proper error handling
register_exception_handlers(app)


# Correlation ID middleware — sets correlation_id per request for structured log tracing
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """
    Assign a correlation_id for every request.

    Priority:
        1. scan_id from URL path (e.g. /api/scans/42 -> "scan-42")
        2. X-Correlation-ID or X-Request-ID request header
        3. Auto-generated short UUID
    """
    correlation_id = ""

    # 1. Extract scan_id from path if present
    parts = request.url.path.split("/")
    for i, part in enumerate(parts):
        if part == "scans" and i + 1 < len(parts) and parts[i + 1].isdigit():
            correlation_id = f"scan-{parts[i + 1]}"
            break

    # 2. Check request headers
    if not correlation_id:
        correlation_id = (
            request.headers.get("x-correlation-id")
            or request.headers.get("x-request-id")
            or ""
        )

    # 3. Fallback to generated UUID
    if not correlation_id:
        correlation_id = uuid.uuid4().hex[:8]

    set_correlation_id(correlation_id)
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response


# Root endpoint
@app.get("/")
async def root() -> Dict[str, Any]:
    """
    API information endpoint.

    Returns:
        Dictionary with API name, version, and documentation link
    """
    return {
        "name": "BugTraceAI API",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
        "ready": "/ready",
    }


# Health check endpoint
@app.get("/health", tags=["health"])
async def health_check(
    scan_service: ScanServiceDep,
    event_bus: EventBusDep,
) -> Dict[str, Any]:
    """
    Health check endpoint for monitoring and deployment orchestration.

    Returns:
        status: Server health status (healthy/degraded)
        version: API version
        docker_available: Whether Docker is available for tool execution
        active_scans: Number of currently running scans
        event_bus_stats: Event bus statistics

    Solves INF-04: Health check for container readiness probes
    """
    # Check Docker availability
    docker_available = False
    try:
        from bugtrace.tools.external import docker_cmd
        docker_available = docker_cmd is not None
    except Exception as e:
        logger.warning(f"Docker check failed: {e}")

    # Get active scan count
    active_scans = scan_service.active_scan_count

    # Get event bus stats
    event_stats = event_bus.get_stats()

    # Determine overall status
    status = "healthy"
    if not docker_available:
        status = "degraded"  # Can run API but can't execute scans

    return {
        "status": status,
        "version": settings.VERSION,
        "docker_available": docker_available,
        "active_scans": active_scans,
        "event_bus_stats": event_stats,
    }


# Readiness check endpoint
@app.get("/ready", tags=["health"])
async def readiness_check() -> Dict[str, Any]:
    """
    Readiness check endpoint for deployment orchestration.

    Unlike /health (liveness probe) which indicates the server process is running,
    /ready (readiness probe) verifies that the application can serve requests by
    checking external dependencies like database connectivity.

    Returns:
        ready: Overall readiness status (true only if database is reachable)
        checks:
            database: Whether SQLite database is accessible
            docker_available: Whether Docker is available for scan execution

    Use /health for liveness probes (is the process alive?).
    Use /ready for readiness probes (can it handle requests?).
    """
    # Check database connectivity
    database_ok = False
    try:
        conn = sqlite3.connect("bugtrace.db")
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        database_ok = True
    except Exception as e:
        logger.warning(f"Database readiness check failed: {e}")

    # Check Docker availability
    docker_available = False
    try:
        from bugtrace.tools.external import docker_cmd
        docker_available = docker_cmd is not None
    except Exception as e:
        logger.warning(f"Docker readiness check failed: {e}")

    # Overall readiness: database must be reachable (Docker is optional)
    ready = database_ok

    return {
        "ready": ready,
        "checks": {
            "database": database_ok,
            "docker_available": docker_available,
        },
    }


# Router includes
from bugtrace.api.routes.scans import router as scans_router
from bugtrace.api.routes.reports import router as reports_router
from bugtrace.api.routes.config import router as config_router

app.include_router(scans_router, prefix="/api", tags=["scans"])
app.include_router(reports_router, prefix="/api", tags=["reports"])
app.include_router(config_router, prefix="/api", tags=["config"])


# WebSocket endpoint for real-time scan event streaming
@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_stream(
    websocket: WebSocket,
    scan_id: int,
    last_seq: int = Query(default=0, description="Last received sequence number for reconnection"),
):
    """
    WebSocket endpoint for streaming real-time scan events.

    Args:
        websocket: WebSocket connection
        scan_id: Scan ID to stream events for
        last_seq: Last received sequence number (for reconnection, default 0)

    Behavior:
        1. Accept WebSocket connection
        2. Validate scan_id exists
        3. If last_seq > 0 (reconnection): Send missed events first
        4. Stream live events using ServiceEventBus.stream()
        5. Handle WebSocketDisconnect gracefully
        6. Close cleanly on scan completion (scan_complete or error events)

    Reconnection support:
        Client can reconnect with ?last_seq=N to receive only missed events
        since sequence number N.

    Solves WS-02: Real-time event streaming with reconnection support
    """
    await websocket.accept()
    logger.info(f"WebSocket client connected to scan {scan_id} (last_seq={last_seq})")

    try:
        if not await _ws_validate_scan(websocket, scan_id):
            return
        highest_sent = await _ws_send_missed_events(websocket, scan_id, last_seq)
        await _ws_stream_live_events(websocket, scan_id, highest_sent)
        await websocket.close(code=1000, reason="Scan complete")
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from scan {scan_id}")
    except Exception as e:
        await _ws_handle_error(websocket, scan_id, e)


async def _ws_validate_scan(websocket: WebSocket, scan_id: int) -> bool:
    """Validate scan exists before streaming."""
    scan_service = get_scan_service()
    try:
        scan_service.get_scan_status(scan_id)
        return True
    except Exception as e:
        logger.warning(f"Invalid scan_id {scan_id}: {e}")
        await websocket.close(code=1008, reason=f"Invalid scan_id: {scan_id}")
        return False


async def _ws_send_missed_events(websocket: WebSocket, scan_id: int, last_seq: int) -> int:
    """Send missed events for reconnection."""
    if last_seq == 0:
        return 0

    logger.info(f"Reconnection detected for scan {scan_id}, replaying events since seq {last_seq}")
    missed = service_event_bus.get_history(scan_id, since_seq=last_seq)
    for event in missed:
        await websocket.send_json(event)
    return missed[-1]["seq"] if missed else last_seq


async def _ws_stream_live_events(websocket: WebSocket, scan_id: int, highest_sent: int):
    """Stream live events with deduplication."""
    async for event in service_event_bus.stream(scan_id):
        if event.get("seq", 0) <= highest_sent:
            continue

        await websocket.send_json(event)
        highest_sent = event.get("seq", highest_sent)

        if event.get("event_type") in ("scan_complete", "error"):
            logger.info(f"Scan {scan_id} completed with event_type={event.get('event_type')}, closing WebSocket")
            break


async def _ws_handle_error(websocket: WebSocket, scan_id: int, error: Exception):
    """Handle WebSocket errors gracefully."""
    logger.error(f"WebSocket error for scan {scan_id}: {error}", exc_info=True)
    try:
        await websocket.close(code=1011, reason="Internal server error")
    except Exception:
        # WebSocket already closed or connection lost - ignore
        pass
