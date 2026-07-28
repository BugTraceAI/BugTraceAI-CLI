import shutil
import asyncio
import os
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("core.diagnostics")

# Used only when no provider preset could be loaded at all. Mirrors the defaults in
# llm_client._apply_provider_config so this gate and the client it gates can never
# disagree about which provider they are talking about.
_FALLBACK_KEY_ENV = "OPENROUTER_API_KEY"
_FALLBACK_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"


def _active_preset() -> Dict[str, Any]:
    """The ACTIVE provider's preset dict, or {} when none was loaded."""
    return getattr(settings, "_provider_config", {}) or {}


def _provider_label(preset: Dict[str, Any]) -> str:
    """Human-readable name of the active provider, for logs."""
    return preset.get("name") or settings.PROVIDER


def _resolve_api_key(preset: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """(env var name, key value) for the ACTIVE provider.

    Same resolution order as llm_client._apply_provider_config — env var first,
    then the settings attribute — so this gate can never reject a key the LLM
    client would happily use.
    """
    key_env = preset.get("api_key_env", _FALLBACK_KEY_ENV)
    return key_env, (os.environ.get(key_env) or getattr(settings, key_env, None))


def _api_origin(preset: Dict[str, Any]) -> str:
    """scheme://host of the ACTIVE provider's API, for a reachability probe."""
    parsed = urlparse(preset.get("base_url") or _FALLBACK_BASE_URL)
    return f"{parsed.scheme}://{parsed.netloc}"


class DiagnosticSystem:
    def __init__(self):
        self.results = {}  # {check_name: (success_bool, error_message)}

    async def run_all(self):
        """Runs a suite of health checks on the environment."""
        dashboard.set_phase("⚡ SYSTEMS CHECK")
        dashboard.log("Running system health check...", "INFO")

        self._log_debug_paths()

        # Critical checks (scan cannot run without these)
        await self._check_docker()
        await self._check_api_key()
        await self._check_connectivity()
        await self._check_credits()

        # Non-critical check (scan can run in headless/degraded mode)
        await self._check_browser()

        critical_checks = ["api_key", "connectivity"]
        all_passed = True

        for check in critical_checks:
            success, error = self.results.get(check, (False, "Check not run"))
            if not success:
                dashboard.log(f"❌ CRITICAL FAILURE: {check} - {error}", "CRITICAL")
                all_passed = False

        if all_passed:
            dashboard.log("Diagnostics complete. System ready.", "SUCCESS")
        else:
            dashboard.log("Diagnostics failed - critical components offline.", "ERROR")

        return all_passed

    def _log_debug_paths(self):
        """Log debug configuration paths."""
        logger.info(f"BASE_DIR: {settings.BASE_DIR}")
        logger.info(f"LOG_DIR: {settings.LOG_DIR}")
        dashboard.log(f"Config: {settings.LOG_DIR}", "DEBUG")

    async def _check_docker(self):
        """Check Docker availability."""
        docker_path = shutil.which("docker")
        success = docker_path is not None
        self.results["docker"] = (success, "" if success else "Docker binary not found in PATH")
        if success:
            dashboard.log("Docker detected (External tools enabled)", "SUCCESS")
        else:
            dashboard.log("Docker NOT found (Nuclei/SQLMap will be disabled)", "WARN")

    async def _check_api_key(self):
        """Check the ACTIVE provider's API key.

        Reading OPENROUTER_API_KEY unconditionally made this CRITICAL gate reject
        every non-OpenRouter provider: with PROVIDER=anthropic the key lives in
        ANTHROPIC_API_KEY, so a fully configured scan aborted at "Diagnostics
        failed" while /health simultaneously reported api_key_configured=true.
        The preset's api_key_env is the same source llm_client resolves from.
        """
        preset = _active_preset()
        key_env, api_key = _resolve_api_key(preset)
        label = _provider_label(preset)

        success = bool(api_key) and len(api_key) > 10
        self.results["api_key"] = (
            success,
            "" if success else f"{key_env} missing or too short (active provider: {label})",
        )
        if success:
            dashboard.log(f"{label} API Key detected (Brain Online)", "SUCCESS")
        else:
            # This check is critical — the scan aborts. Say so instead of implying
            # a degraded-but-working mode that does not exist.
            dashboard.log(f"No {label} API Key: {key_env} is unset", "ERROR")

    async def _check_browser(self):
        """Check Playwright browser availability."""
        try:
            from bugtrace.tools.visual.browser import browser_manager
            # Use a short timeout for diagnostic start
            await asyncio.wait_for(browser_manager.start(), timeout=20.0)
            self.results["browser"] = (True, "")
            dashboard.log("Visual Intelligence Engine: READY", "SUCCESS")
            # Don't stop it here, keep it ready for the scan
        except Exception as e:
            self.results["browser"] = (False, str(e))
            dashboard.log(f"Visual Intelligence (Browser) Failure: {e}", "WARN")
            logger.warning(f"Browser check failed: {e}")

    async def _check_connectivity(self):
        """Check that the ACTIVE provider's API host is reachable.

        Probes the ORIGIN and accepts ANY HTTP response as proof of reachability.
        This gate aborts the entire scan, so only a genuine network-level failure
        (DNS, TCP, TLS, timeout) may block it: demanding HTTP 200 from one
        OpenRouter endpoint meant a provider-side 5xx — or an Anthropic user on a
        network that cannot reach openrouter.ai — killed a scan that would have
        run fine. A bare GET to api.anthropic.com answers 404, which is still
        proof the host is up and routable.
        """
        preset = _active_preset()
        origin = _api_origin(preset)
        label = _provider_label(preset)
        try:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(origin) as resp:
                    self.results["connectivity"] = (True, "")
                    dashboard.log(f"Network Connectivity to {label}: OK (HTTP {resp.status})", "SUCCESS")
        except Exception as e:
            self.results["connectivity"] = (False, f"{origin} unreachable: {type(e).__name__}: {e}")
            logger.warning(f"Connectivity check failed for {origin}: {e}")
            dashboard.log(f"Connectivity to {label}: FAILED ({type(e).__name__})", "ERROR")

    async def _check_credits(self):
        """Check remaining balance — only for providers that expose one.

        features.balance_check in the preset declares whether the provider has a
        balance API at all. Anthropic and Z.ai do not, and probing OpenRouter's
        endpoint with their key returns 401 — a scary, false "Credit check failed"
        on a perfectly healthy scan.
        """
        preset = _active_preset()
        label = _provider_label(preset)

        if not preset.get("features", {}).get("balance_check", False):
            logger.info(f"Balance check skipped: provider '{label}' exposes no balance API")
            self.results["credits"] = (True, "Not applicable for this provider")
            return

        success_key, _ = self.results.get("api_key", (False, ""))
        success_conn, _ = self.results.get("connectivity", (False, ""))

        if not (success_key and success_conn):
            return

        _, api_key = _resolve_api_key(preset)
        # OpenRouter-shaped endpoint. Only presets that declare balance_check reach
        # this line, and those are the ones that speak this API.
        balance_url = f"{_api_origin(preset)}/api/v1/auth/key"

        logger.info(f"Initiating {label} credit check...")
        try:
            headers = {"Authorization": f"Bearer {api_key}"}
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(balance_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        key_data = data.get('data', {})
                        limit = key_data.get('limit')
                        usage = key_data.get('usage', 0)

                        if limit is not None:
                            balance = limit - usage
                            dashboard.credits = balance
                            if balance < settings.MIN_CREDITS:
                                msg = f"⛔ INSUFFICIENT FUNDS: ${balance:.2f} (Required: ${settings.MIN_CREDITS:.2f})"
                                dashboard.log(msg, "CRITICAL")
                                self.results["credits"] = (False, "Insufficient balance")
                            else:
                                dashboard.log(f"{label} Balance: ${balance:.2f}", "SUCCESS")
                                self.results["credits"] = (True, "")
                        else:
                            dashboard.credits = 999.00
                            dashboard.log(f"{label} Key: Unlimited/Free Tier", "SUCCESS")
                            self.results["credits"] = (True, "")
                    else:
                        dashboard.log(f"Credit check failed (Status {resp.status})", "WARN")
                        self.results["credits"] = (False, f"HTTP {resp.status}")
        except Exception as e:
            logger.error(f"Credit check failed: {e}", exc_info=True)
            dashboard.log("Could not verify credits", "DEBUG")
            self.results["credits"] = (True, "Verification error (ignored)")

diagnostics = DiagnosticSystem()
