"""
Anthropic OAuth Token Management.

Reads tokens saved by tools/anthropic_login.sh and handles auto-refresh.
No login flow here — that's the bash wizard's job.
"""
import json
import time
import os
import aiohttp
from pathlib import Path
from typing import Optional, Dict
from bugtrace.utils.logger import get_logger

logger = get_logger("core.anthropic_auth")

# OAuth constants (must match anthropic_login.sh)
TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
CLIENT_ID = os.environ.get("BUGTRACE_ANTHROPIC_CLIENT_ID", "")
DEFAULT_TOKEN_FILE = Path("~/.bugtrace/auth.json")


def _get_token_path() -> Path:
    """Get token file path from config or default."""
    try:
        from bugtrace.core.config import settings
        return Path(settings.ANTHROPIC_TOKEN_FILE).expanduser()
    except Exception:
        return DEFAULT_TOKEN_FILE.expanduser()


def load_tokens() -> Optional[Dict]:
    """Read tokens from disk. Returns dict with 'access', 'refresh', 'expires' or None."""
    path = _get_token_path()
    if not path.exists():
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        if "access" not in data or "refresh" not in data:
            logger.warning("Anthropic token file missing required fields")
            return None
        return data
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to read Anthropic token file: {e}")
        return None


def save_tokens(tokens: Dict) -> None:
    """Write tokens to disk with restrictive permissions."""
    path = _get_token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(tokens, f, indent=2)
    os.chmod(path, 0o600)


async def refresh_access_token(refresh_token: str) -> Optional[Dict]:
    """Exchange refresh_token for new access + refresh tokens."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": CLIENT_ID,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error(f"Anthropic token refresh failed ({resp.status}): {body}")
                    return None
                data = await resp.json()
                if "access_token" not in data:
                    logger.error(f"Anthropic token refresh: no access_token in response")
                    return None
                expires_in = data.get("expires_in", 3600)
                return {
                    "access": data["access_token"],
                    "refresh": data.get("refresh_token", refresh_token),
                    "expires": int((time.time() + expires_in) * 1000),
                }
    except Exception as e:
        logger.error(f"Anthropic token refresh exception: {e}")
        return None


async def get_valid_token() -> Optional[str]:
    """
    Load tokens, refresh if expired, return valid access_token or None.

    This is the main entry point called by llm_client.
    """
    tokens = load_tokens()
    if not tokens:
        return None

    # Check expiry (tokens.expires is in milliseconds)
    now_ms = int(time.time() * 1000)
    expires_ms = tokens.get("expires", 0)

    # Refresh if expired or expiring within 60 seconds
    if now_ms >= (expires_ms - 60_000):
        logger.info("Anthropic token expired, refreshing...")
        new_tokens = await refresh_access_token(tokens["refresh"])
        if not new_tokens:
            logger.error("Anthropic token refresh failed. Run: bash tools/anthropic_login.sh")
            return None
        save_tokens(new_tokens)
        return new_tokens["access"]

    return tokens["access"]
