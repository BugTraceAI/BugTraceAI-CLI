"""
Provider Management Endpoints — View and switch LLM providers.

Provides GET /providers, GET /provider, PUT /provider, PATCH /provider/models
for runtime provider management and API key configuration.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.utils.env_writer import update_env_var

logger = get_logger("api.routes.providers")

router = APIRouter(tags=["providers"])

PROVIDERS_DIR = settings.BASE_DIR / "bugtrace" / "data" / "providers"


# ──── Response/Request Models ────


class ProviderSummary(BaseModel):
    id: str
    name: str
    recommended: bool = False
    api_key_configured: bool
    api_key_hint: str


class ProviderDetail(BaseModel):
    provider: str
    name: str
    base_url: str
    api_key_configured: bool
    api_key_hint: str
    features: Dict[str, Any]
    models: Dict[str, str]
    pricing: Dict[str, Any]


class TestProviderRequest(BaseModel):
    provider: str
    api_key: Optional[str] = None


class SwitchProviderRequest(BaseModel):
    provider: str
    api_key: Optional[str] = None


class ModelOverrideRequest(BaseModel):
    """Override individual model assignments at runtime."""
    DEFAULT_MODEL: Optional[str] = None
    CODE_MODEL: Optional[str] = None
    ANALYSIS_MODEL: Optional[str] = None
    PRIMARY_MODELS: Optional[str] = None
    VISION_MODEL: Optional[str] = None
    WAF_DETECTION_MODELS: Optional[str] = None
    MUTATION_MODEL: Optional[str] = None
    SKEPTICAL_MODEL: Optional[str] = None
    REPORTING_MODEL: Optional[str] = None


# ──── Helpers ────


def _load_preset(provider_id: str) -> Dict[str, Any]:
    """Load a provider preset JSON file."""
    path = PROVIDERS_DIR / f"{provider_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    return json.loads(path.read_text())


def _mask_api_key(key: Optional[str]) -> str:
    """Mask API key for display: show first 8 + last 4 chars."""
    if not key:
        return ""
    if len(key) > 12:
        return key[:8] + "..." + key[-4:]
    return "***"


def _check_api_key(preset: Dict[str, Any]) -> tuple:
    """Check if provider's API key is configured. Returns (configured, masked_hint)."""
    key_env = preset.get("api_key_env", "")
    key_value = os.environ.get(key_env) or getattr(settings, key_env, None)
    return bool(key_value), _mask_api_key(key_value)


# ──── Endpoints ────


@router.get("/providers", response_model=List[ProviderSummary])
async def list_providers():
    """List all available LLM providers with API key status."""
    providers = []
    if not PROVIDERS_DIR.exists():
        return providers

    for path in sorted(PROVIDERS_DIR.glob("*.json")):
        try:
            preset = json.loads(path.read_text())
            configured, hint = _check_api_key(preset)
            providers.append(ProviderSummary(
                id=preset["id"],
                name=preset["name"],
                recommended=preset.get("recommended", False),
                api_key_configured=configured,
                api_key_hint=hint if configured else preset.get("api_key_hint", ""),
            ))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Skipping invalid provider preset {path.name}: {e}")

    return providers


@router.get("/provider", response_model=ProviderDetail)
async def get_current_provider():
    """Get the currently active provider configuration."""
    provider_cfg = getattr(settings, '_provider_config', {})
    if not provider_cfg:
        # Fallback: load from file
        try:
            provider_cfg = _load_preset(settings.PROVIDER)
        except HTTPException:
            raise HTTPException(status_code=404, detail=f"Active provider '{settings.PROVIDER}' preset not found")

    configured, hint = _check_api_key(provider_cfg)

    # Return current runtime model assignments (may differ from preset defaults)
    current_models = {}
    for field in ["DEFAULT_MODEL", "CODE_MODEL", "ANALYSIS_MODEL", "PRIMARY_MODELS",
                  "VISION_MODEL", "WAF_DETECTION_MODELS", "MUTATION_MODEL",
                  "SKEPTICAL_MODEL", "REPORTING_MODEL"]:
        current_models[field] = getattr(settings, field, "")

    return ProviderDetail(
        provider=settings.PROVIDER,
        name=provider_cfg.get("name", settings.PROVIDER),
        base_url=provider_cfg.get("base_url", ""),
        api_key_configured=configured,
        api_key_hint=hint if configured else provider_cfg.get("api_key_hint", ""),
        features=provider_cfg.get("features", {}),
        models=current_models,
        pricing=provider_cfg.get("pricing", {}),
    )


@router.get("/providers/{provider_id}", response_model=ProviderDetail)
async def get_provider_detail(provider_id: str):
    """Get the full preset configuration for any provider by ID."""
    preset = _load_preset(provider_id)
    configured, hint = _check_api_key(preset)
    return ProviderDetail(
        provider=preset["id"],
        name=preset["name"],
        base_url=preset.get("base_url", ""),
        api_key_configured=configured,
        api_key_hint=hint if configured else preset.get("api_key_hint", ""),
        features=preset.get("features", {}),
        models=preset.get("models", {}),
        pricing=preset.get("pricing", {}),
    )


@router.put("/provider")
async def switch_provider(req: SwitchProviderRequest):
    """Switch the active LLM provider and optionally set its API key.

    This updates the runtime configuration. The change persists until
    the server restarts (use bugtraceaicli.conf for permanent changes).
    """
    # Validate provider exists
    preset = _load_preset(req.provider)

    # If API key provided, write to .env
    if req.api_key:
        key_env = preset.get("api_key_env", "")
        if not key_env:
            raise HTTPException(status_code=400, detail="Provider has no api_key_env defined")
        if not update_env_var(key_env, req.api_key):
            raise HTTPException(status_code=500, detail="Failed to write API key to .env")
        # Also set on settings object for immediate use
        if hasattr(settings, key_env):
            object.__setattr__(settings, key_env, req.api_key)
        os.environ[key_env] = req.api_key

    # Switch provider
    object.__setattr__(settings, 'PROVIDER', req.provider)

    # Reload preset (applies model defaults)
    settings._load_provider_preset()

    # Reinitialize LLM client with new provider
    try:
        from bugtrace.core.llm_client import llm_client
        provider_cfg = getattr(settings, '_provider_config', {})
        api_key_env = provider_cfg.get('api_key_env', 'OPENROUTER_API_KEY')
        llm_client.api_key = os.environ.get(api_key_env) or getattr(settings, api_key_env, None)
        llm_client.base_url = provider_cfg.get('base_url', "https://openrouter.ai/api/v1/chat/completions")
        llm_client.provider_id = req.provider
        llm_client.models = [m.strip() for m in settings.PRIMARY_MODELS.split(",")]
        logger.info(f"LLM client reinitialized for provider: {req.provider}")
    except ImportError:
        logger.warning("Could not reimport llm_client for hot-reload")

    configured, hint = _check_api_key(preset)
    return {
        "message": f"Switched to provider: {preset['name']}",
        "provider": req.provider,
        "api_key_configured": configured,
        "api_key_hint": hint,
        "models": {k: getattr(settings, k, "") for k in preset.get("models", {}).keys()},
    }


@router.post("/provider/test")
async def test_provider_key(req: TestProviderRequest):
    """Test an API key against a provider by making a real LLM call."""
    import httpx

    preset = _load_preset(req.provider)
    base_url = preset.get("base_url", "")
    if not base_url:
        raise HTTPException(status_code=400, detail="Provider has no base_url configured")

    # Use provided key, or fall back to configured key
    api_key = req.api_key
    if not api_key:
        key_env = preset.get("api_key_env", "")
        api_key = os.environ.get(key_env) or getattr(settings, key_env, None)
    if not api_key:
        return {"success": False, "message": "No API key provided and none configured."}

    # Pick the fastest/cheapest model from preset for testing
    models = preset.get("models", {})
    test_model = models.get("ANALYSIS_MODEL") or models.get("DEFAULT_MODEL") or ""
    if not test_model:
        return {"success": False, "message": "No model configured for this provider."}

    headers: Dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept-Language": "en-US,en",
    }
    # Apply provider-specific headers
    for k, v in preset.get("headers", {}).items():
        headers[k] = v

    body = {
        "model": test_model,
        "messages": [{"role": "user", "content": "Are you alive? Answer only yes."}],
        "max_tokens": 5,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(base_url, json=body, headers=headers)
        if resp.status_code == 200:
            return {"success": True, "message": "API Key Valid Response"}
        elif resp.status_code == 401:
            return {"success": False, "message": "Invalid API key. Please check and try again."}
        elif resp.status_code == 403:
            return {"success": False, "message": "API key rejected — insufficient permissions or account issue."}
        elif resp.status_code == 429:
            return {"success": False, "message": "Rate limited — key is valid but too many requests. Try again later."}
        else:
            detail = ""
            try:
                data = resp.json()
                detail = data.get("error", {}).get("message", "") if isinstance(data.get("error"), dict) else str(data.get("error", ""))
            except Exception:
                pass
            return {"success": False, "message": f"Provider returned HTTP {resp.status_code}. {detail}".strip()}
    except httpx.TimeoutException:
        return {"success": False, "message": "Connection timed out. Check the provider URL."}
    except Exception as e:
        return {"success": False, "message": f"Connection failed: {str(e)}"}


@router.patch("/provider/models")
async def override_models(req: ModelOverrideRequest):
    """Override individual model assignments at runtime."""
    updated = {}
    for field, value in req.model_dump(exclude_none=True).items():
        if hasattr(settings, field):
            old = getattr(settings, field)
            object.__setattr__(settings, field, value)
            updated[field] = {"from": old, "to": value}
            logger.info(f"Model override: {field} = {value}")

    if not updated:
        raise HTTPException(status_code=400, detail="No valid model fields provided")

    # Update LLM client model list if PRIMARY_MODELS changed
    if "PRIMARY_MODELS" in updated:
        try:
            from bugtrace.core.llm_client import llm_client
            llm_client.models = [m.strip() for m in settings.PRIMARY_MODELS.split(",")]
        except ImportError:
            pass

    return {"updated": updated, "message": f"Updated {len(updated)} model assignment(s)"}
