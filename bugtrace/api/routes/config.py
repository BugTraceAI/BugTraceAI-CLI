"""
Configuration Management Endpoints - View and update CLI configuration.

Provides GET /config and PATCH /config endpoints for runtime configuration management.

Solves:
- API-07: GET /config (view configuration)
- API-08: PATCH /config (update configuration with validation)

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional

from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("api.routes.config")

router = APIRouter(tags=["config"])


class ConfigResponse(BaseModel):
    """Response model for GET /config."""
    config: Dict[str, Any]
    version: str


class ConfigUpdateRequest(BaseModel):
    """
    Request model for PATCH /config.
    Only includes fields that are safe to update at runtime.
    """
    SAFE_MODE: Optional[bool] = None
    MAX_DEPTH: Optional[int] = None
    MAX_URLS: Optional[int] = None
    MAX_CONCURRENT_URL_AGENTS: Optional[int] = None
    MAX_CONCURRENT_REQUESTS: Optional[int] = None
    DEFAULT_MODEL: Optional[str] = None
    CODE_MODEL: Optional[str] = None
    ANALYSIS_MODEL: Optional[str] = None
    MUTATION_MODEL: Optional[str] = None
    SKEPTICAL_MODEL: Optional[str] = None
    HEADLESS_BROWSER: Optional[bool] = None
    EARLY_EXIT_ON_FINDING: Optional[bool] = None
    STOP_ON_CRITICAL: Optional[bool] = None
    REPORT_ONLY_VALIDATED: Optional[bool] = None


class ConfigUpdateResponse(BaseModel):
    """Response model for PATCH /config."""
    updated: Dict[str, Any]
    message: str


@router.get("/config", response_model=ConfigResponse)
async def get_config():
    """
    Get current CLI configuration with secrets masked.

    Returns:
        ConfigResponse with masked configuration and version

    Excludes:
        - Internal fields (starting with _)
        - Path fields (BASE_DIR, LOG_DIR_PATH, etc.)
        - API keys (masked in output)
        - Database URLs

    Solves API-07: GET /config endpoint
    """
    # Get masked configuration
    masked = settings.mask_secrets()

    # Remove internal/path fields not useful via API
    excluded_keys = {
        "model_config",
        "BASE_DIR",
        "LOG_DIR_PATH",
        "REPORT_DIR_PATH",
        "VECTOR_DB_PATH",
        "DATABASE_URL",
        "_config_history",
        "database",
        "global_config",
    }

    # Filter out excluded keys and private fields
    filtered = {
        k: v for k, v in masked.items()
        if k not in excluded_keys and not k.startswith("_")
    }

    logger.info("Configuration retrieved via API (secrets masked)")

    return ConfigResponse(
        config=filtered,
        version=settings.VERSION
    )


@router.patch("/config", response_model=ConfigUpdateResponse)
async def update_config(request: ConfigUpdateRequest):
    """
    Update CLI configuration with validation.

    Args:
        request: ConfigUpdateRequest with fields to update

    Returns:
        ConfigUpdateResponse with changes applied

    Validation rules:
        - MAX_DEPTH, MAX_URLS, MAX_CONCURRENT_URL_AGENTS, MAX_CONCURRENT_REQUESTS: Must be positive integers
        - DEFAULT_MODEL, CODE_MODEL, etc.: Must contain "/" separator (provider/model format)

    Raises:
        400: No fields provided
        422: Validation errors

    Solves API-08: PATCH /config with validation
    """
    # Extract non-None fields
    updates = request.model_dump(exclude_none=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No fields to update"
        )

    # Validate individual fields
    errors = []

    # Validate positive integers
    for key in ["MAX_DEPTH", "MAX_URLS", "MAX_CONCURRENT_URL_AGENTS", "MAX_CONCURRENT_REQUESTS"]:
        if key in updates:
            value = updates[key]
            if not isinstance(value, int) or value < 1:
                errors.append(f"{key} must be a positive integer (got: {value})")

    # Validate model format (must contain provider/model separator)
    for key in ["DEFAULT_MODEL", "CODE_MODEL", "ANALYSIS_MODEL", "MUTATION_MODEL", "SKEPTICAL_MODEL"]:
        if key in updates:
            value = updates[key]
            if value and "/" not in value:
                errors.append(
                    f"{key} must be in provider/model format (e.g., 'google/gemini-3-flash-preview'), got: {value}"
                )

    if errors:
        logger.warning(f"Configuration update validation failed: {errors}")
        raise HTTPException(
            status_code=422,
            detail={"errors": errors}
        )

    # Apply updates to settings singleton
    # CRITICAL: Use object.__setattr__ for Pydantic Settings objects (same pattern as restore_snapshot())
    applied = {}
    for key, value in updates.items():
        if hasattr(settings, key):
            old_value = getattr(settings, key)
            object.__setattr__(settings, key, value)
            applied[key] = {"from": old_value, "to": value}
            logger.info(f"Config updated: {key} = {old_value} -> {value}")

    logger.info(f"Configuration updated: {len(applied)} field(s) changed")

    return ConfigUpdateResponse(
        updated=applied,
        message=f"Updated {len(applied)} configuration field(s)"
    )
