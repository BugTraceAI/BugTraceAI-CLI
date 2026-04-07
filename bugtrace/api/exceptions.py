"""
Global Exception Handlers - Standardized error response format for FastAPI.

Provides centralized exception handling that ensures all API errors
(HTTPException, ValidationError, ValueError, generic Exception) return
a consistent JSON structure:

{
    "error": {
        "code": "ERROR_CODE",
        "message": "Human-readable message",
        "timestamp": "2026-01-28T12:34:56.789Z",
        "path": "/api/endpoint"
    }
}

Usage:
    In main.py:
    ```python
    from bugtrace.api.exceptions import register_exception_handlers

    app = FastAPI()
    register_exception_handlers(app)
    ```

Solves PC-02: Standardized error response format across all CLI API endpoints.

Author: BugtraceAI Team
Date: 2026-01-28
Version: 2.0.0
"""

from datetime import datetime
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from bugtrace.utils.logger import get_logger

logger = get_logger("api.exceptions")


def _error_response(
    status_code: int,
    error_code: str,
    message: str,
    request: Request,
    details: Any = None,
) -> JSONResponse:
    """
    Create standardized error response.

    Args:
        status_code: HTTP status code
        error_code: Error code identifier (e.g., "HTTP_404", "VALIDATION_ERROR")
        message: Human-readable error message
        request: FastAPI request object
        details: Optional additional error details (e.g., validation errors)

    Returns:
        JSONResponse with standardized error structure
    """
    error_body: Dict[str, Any] = {
        "error": {
            "code": error_code,
            "message": message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "path": str(request.url),
        }
    }

    # Include details if provided (e.g., validation errors)
    if details is not None:
        error_body["error"]["details"] = details

    return JSONResponse(
        status_code=status_code,
        content=error_body,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register global exception handlers on a FastAPI application.

    Handlers registered:
        - HTTPException (Starlette/FastAPI)
        - RequestValidationError (Pydantic validation)
        - ValueError (input validation)
        - Exception (catch-all for unhandled errors)

    Args:
        app: FastAPI application instance
    """
    app.exception_handler(StarletteHTTPException)(_create_http_exception_handler())
    app.exception_handler(RequestValidationError)(_create_validation_exception_handler())
    app.exception_handler(ValueError)(_create_value_error_handler())
    app.exception_handler(Exception)(_create_generic_exception_handler())

    logger.info("Global exception handlers registered")


def _create_http_exception_handler():
    """Create handler for HTTPException."""
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Handle HTTPException with standardized response."""
        logger.warning(
            f"HTTPException in {request.url.path}: status={exc.status_code} detail={exc.detail}"
        )
        return _error_response(
            status_code=exc.status_code,
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            request=request,
        )
    return http_exception_handler


def _create_validation_exception_handler():
    """Create handler for Pydantic validation errors."""
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle validation errors with details."""
        logger.warning(
            f"Request validation error in {request.url.path}: {exc.errors()}"
        )
        return _error_response(
            status_code=422,
            error_code="VALIDATION_ERROR",
            message="Request validation failed",
            request=request,
            details=exc.errors(),
        )
    return validation_exception_handler


def _create_value_error_handler():
    """Create handler for ValueError exceptions."""
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        """Handle ValueError as 400 Bad Request."""
        logger.warning(f"ValueError in {request.url.path}: {exc}")
        return _error_response(
            status_code=400,
            error_code="VALIDATION_ERROR",
            message=str(exc),
            request=request,
        )
    return value_error_handler


def _create_generic_exception_handler():
    """Create catch-all handler for unhandled exceptions."""
    async def generic_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unhandled exceptions as 500 errors."""
        logger.error(
            f"Unhandled exception in {request.url.path}: {exc}", exc_info=True)
        return _error_response(
            status_code=500,
            error_code="INTERNAL_ERROR",
            message="An internal server error occurred",
            request=request,
        )
    return generic_exception_handler
