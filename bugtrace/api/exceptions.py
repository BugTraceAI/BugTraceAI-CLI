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

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """
        Handle HTTPException raised by FastAPI routes.

        Maps HTTPException to standardized error response with code "HTTP_{status_code}".

        Example:
            raise HTTPException(status_code=404, detail="Scan not found")
            ->
            {
                "error": {
                    "code": "HTTP_404",
                    "message": "Scan not found",
                    "timestamp": "2026-01-28T12:34:56.789Z",
                    "path": "/api/scans/123"
                }
            }
        """
        logger.warning(
            f"HTTPException in {request.url.path}: status={exc.status_code} detail={exc.detail}"
        )

        return _error_response(
            status_code=exc.status_code,
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            request=request,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """
        Handle Pydantic validation errors from request models.

        Returns 422 Unprocessable Entity with validation error details.

        Example:
            POST /api/scans with invalid JSON
            ->
            {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "timestamp": "2026-01-28T12:34:56.789Z",
                    "path": "/api/scans",
                    "details": [{"loc": ["body", "target_url"], "msg": "field required"}]
                }
            }
        """
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

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        """
        Handle ValueError exceptions from business logic.

        Maps ValueError to 400 Bad Request with code "VALIDATION_ERROR".

        Example:
            raise ValueError("Scan ID must be positive")
            ->
            {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Scan ID must be positive",
                    "timestamp": "2026-01-28T12:34:56.789Z",
                    "path": "/api/scans/status"
                }
            }
        """
        logger.warning(f"ValueError in {request.url.path}: {exc}")

        return _error_response(
            status_code=400,
            error_code="VALIDATION_ERROR",
            message=str(exc),
            request=request,
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all handler for unhandled exceptions.

        Returns 500 Internal Server Error and logs full traceback.

        Example:
            Any unhandled exception
            ->
            {
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An internal server error occurred",
                    "timestamp": "2026-01-28T12:34:56.789Z",
                    "path": "/api/endpoint"
                }
            }
        """
        logger.error(
            f"Unhandled exception in {request.url.path}: {exc}", exc_info=True
        )

        return _error_response(
            status_code=500,
            error_code="INTERNAL_ERROR",
            message="An internal server error occurred",
            request=request,
        )

    logger.info("Global exception handlers registered")
