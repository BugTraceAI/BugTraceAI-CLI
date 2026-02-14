"""
Version check utility for BugTraceAI CLI.

Checks GitHub Releases API for newer versions with 24h file-based cache.
All errors are silenced — never blocks or breaks the tool.
"""

import json
import time
from pathlib import Path
from typing import Optional, TypedDict

GITHUB_API_URL = "https://api.github.com/repos/BugTraceAI/{repo}/releases/latest"
CACHE_DIR = Path.home() / ".bugtrace"
CACHE_FILE = CACHE_DIR / "version_cache.json"
CACHE_TTL = 86400  # 24 hours in seconds
REQUEST_TIMEOUT = 5.0


class UpdateInfo(TypedDict):
    update_available: bool
    latest_version: str
    release_url: str


def compare_versions(current: str, latest: str) -> bool:
    """Return True if latest > current (semver)."""
    try:
        # Strip leading 'v' and pre-release suffixes (-beta, -alpha, -rc.N)
        c = tuple(int(x) for x in current.lstrip("v").split("-")[0].split("."))
        l = tuple(int(x) for x in latest.lstrip("v").split("-")[0].split("."))
        return l > c
    except (ValueError, AttributeError):
        return False


def _read_cache(repo: str) -> Optional[dict]:
    """Read cached version data if fresh (< CACHE_TTL)."""
    try:
        if not CACHE_FILE.exists():
            return None
        data = json.loads(CACHE_FILE.read_text())
        entry = data.get(repo)
        if entry and (time.time() - entry.get("checked_at", 0)) < CACHE_TTL:
            return entry
    except Exception:
        pass
    return None


def _write_cache(repo: str, version: str, release_url: str) -> None:
    """Write version data to cache file."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data = {}
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text())
        data[repo] = {
            "checked_at": time.time(),
            "latest_version": version,
            "release_url": release_url,
        }
        CACHE_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def _fetch_latest(repo: str) -> Optional[dict]:
    """Fetch latest release from GitHub API (sync, httpx)."""
    try:
        import httpx
        from bugtrace.core.config import settings

        url = GITHUB_API_URL.format(repo=repo)
        headers = {"User-Agent": f"BugTraceAI-CLI/{settings.VERSION}"}

        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.get(url, headers=headers, follow_redirects=True)
            if resp.status_code != 200:
                return None
            data = resp.json()
            tag = data.get("tag_name", "").lstrip("v")
            html_url = data.get("html_url", "")
            if tag:
                return {"latest_version": tag, "release_url": html_url}
    except Exception:
        pass
    return None


async def _fetch_latest_async(repo: str) -> Optional[dict]:
    """Fetch latest release from GitHub API (async, httpx)."""
    try:
        import httpx
        from bugtrace.core.config import settings

        url = GITHUB_API_URL.format(repo=repo)
        headers = {"User-Agent": f"BugTraceAI-CLI/{settings.VERSION}"}

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, follow_redirects=True)
            if resp.status_code != 200:
                return None
            data = resp.json()
            tag = data.get("tag_name", "").lstrip("v")
            html_url = data.get("html_url", "")
            if tag:
                return {"latest_version": tag, "release_url": html_url}
    except Exception:
        pass
    return None


def check_for_update_sync(current_version: str, repo: str = "BugTraceAI-CLI") -> Optional[UpdateInfo]:
    """Check for updates synchronously. Returns UpdateInfo or None on error/no update."""
    try:
        cached = _read_cache(repo)
        if cached:
            latest = cached["latest_version"]
            return UpdateInfo(
                update_available=compare_versions(current_version, latest),
                latest_version=latest,
                release_url=cached.get("release_url", ""),
            )

        result = _fetch_latest(repo)
        if result:
            _write_cache(repo, result["latest_version"], result["release_url"])
            return UpdateInfo(
                update_available=compare_versions(current_version, result["latest_version"]),
                latest_version=result["latest_version"],
                release_url=result["release_url"],
            )
    except Exception:
        pass
    return None


async def check_for_update_async(current_version: str, repo: str = "BugTraceAI-CLI") -> Optional[UpdateInfo]:
    """Check for updates asynchronously. Returns UpdateInfo or None on error/no update."""
    try:
        cached = _read_cache(repo)
        if cached:
            latest = cached["latest_version"]
            return UpdateInfo(
                update_available=compare_versions(current_version, latest),
                latest_version=latest,
                release_url=cached.get("release_url", ""),
            )

        result = await _fetch_latest_async(repo)
        if result:
            _write_cache(repo, result["latest_version"], result["release_url"])
            return UpdateInfo(
                update_available=compare_versions(current_version, result["latest_version"]),
                latest_version=result["latest_version"],
                release_url=result["release_url"],
            )
    except Exception:
        pass
    return None
