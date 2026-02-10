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
    updates = _extract_updates(request)
    errors = _validate_config_updates(updates)

    if errors:
        logger.warning(f"Configuration update validation failed: {errors}")
        raise HTTPException(status_code=422, detail={"errors": errors})

    applied = _apply_config_updates(updates)
    logger.info(f"Configuration updated: {len(applied)} field(s) changed")

    return ConfigUpdateResponse(
        updated=applied,
        message=f"Updated {len(applied)} configuration field(s)"
    )


def _extract_updates(request: ConfigUpdateRequest) -> dict:
    """Extract non-None fields from update request."""
    updates = request.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    return updates


def _validate_config_updates(updates: dict) -> list:
    """Validate configuration update values."""
    errors = []
    errors.extend(_validate_positive_integers(updates))
    errors.extend(_validate_model_formats(updates))
    return errors


def _validate_positive_integers(updates: dict) -> list:
    """Validate positive integer fields."""
    errors = []
    int_fields = ["MAX_DEPTH", "MAX_URLS", "MAX_CONCURRENT_URL_AGENTS", "MAX_CONCURRENT_REQUESTS"]
    for key in int_fields:
        if key in updates:
            value = updates[key]
            if not isinstance(value, int) or value < 1:
                errors.append(f"{key} must be a positive integer (got: {value})")
    return errors


def _validate_model_formats(updates: dict) -> list:
    """Validate model format fields."""
    errors = []
    model_fields = ["DEFAULT_MODEL", "CODE_MODEL", "ANALYSIS_MODEL", "MUTATION_MODEL", "SKEPTICAL_MODEL"]
    for key in model_fields:
        if key in updates:
            value = updates[key]
            if value and "/" not in value:
                errors.append(
                    f"{key} must be in provider/model format (e.g., 'moonshotai/kimi-k2-thinking'), got: {value}"
                )
    return errors


def _apply_config_updates(updates: dict) -> dict:
    """Apply validated updates to settings singleton."""
    applied = {}
    for key, value in updates.items():
        if hasattr(settings, key):
            old_value = getattr(settings, key)
            object.__setattr__(settings, key, value)
            applied[key] = {"from": old_value, "to": value}
            logger.info(f"Config updated: {key} = {old_value} -> {value}")
    return applied
