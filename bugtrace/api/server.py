"""
API Server - Uvicorn wrapper for FastAPI application.

Provides start_api_server() function for CLI integration.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import uvicorn
from bugtrace.utils.logger import get_logger

logger = get_logger("api.server")


def start_api_server(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """
    Start the FastAPI server with Uvicorn.

    Args:
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 8000)
        reload: Enable auto-reload on code changes (default: False)

    Notes:
        - Uses string import path for compatibility with uvicorn reload
        - Logs server startup information
        - Blocks until server is stopped (Ctrl+C)
    """
    logger.info(f"Starting BugTraceAI API server on {host}:{port}")
    logger.info(f"Auto-reload: {'enabled' if reload else 'disabled'}")
    logger.info("Press Ctrl+C to stop")

    # Use string import path (not direct app object) for reload compatibility
    uvicorn.run(
        "bugtrace.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )
