import shutil
import asyncio
import os
import aiohttp
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("core.diagnostics")

class DiagnosticSystem:
    def __init__(self):
        self.results = {}

    async def run_all(self):
        """Runs a suite of health checks on the environment."""
        dashboard.set_phase("⚡ SYSTEMS CHECK")
        dashboard.log("Running system health check...", "INFO")

        self._log_debug_paths()
        await self._check_docker()
        await self._check_api_key()
        # IMPORTANT: Check connectivity BEFORE browser
        # Playwright's stop() can interfere with the event loop
        await self._check_connectivity()
        await self._check_credits()
        await self._check_browser()

        dashboard.log("Diagnostics complete.", "INFO")
        return all(self.results.values())

    def _log_debug_paths(self):
        """Log debug configuration paths."""
        logger.info(f"BASE_DIR: {settings.BASE_DIR}")
        logger.info(f"LOG_DIR: {settings.LOG_DIR}")
        dashboard.log(f"Config: {settings.LOG_DIR}", "DEBUG")

    async def _check_docker(self):
        """Check Docker availability."""
        docker_path = shutil.which("docker")
        self.results["docker"] = docker_path is not None
        if self.results["docker"]:
            dashboard.log("Docker detected (External tools enabled)", "SUCCESS")
        else:
            dashboard.log("Docker NOT found (Nuclei/SQLMap will be disabled)", "WARN")

    async def _check_api_key(self):
        """Check OpenRouter API key."""
        self.results["api_key"] = settings.OPENROUTER_API_KEY is not None
        if self.results["api_key"]:
            dashboard.log("OpenRouter API Key detected (Brain Online)", "SUCCESS")
        else:
            dashboard.log("No OpenRouter Key (Using limited local intelligence)", "WARN")

    async def _check_browser(self):
        """Check Playwright browser availability."""
        try:
            from bugtrace.tools.visual.browser import browser_manager
            await browser_manager.start()
            self.results["browser"] = True
            dashboard.log("Visual Intelligence Engine: READY", "SUCCESS")
            await browser_manager.stop()
        except Exception as e:
            self.results["browser"] = False
            dashboard.log(f"Browser Failure: {e}", "ERROR")

    async def _check_connectivity(self):
        """Check internet connectivity to OpenRouter."""
        # Use a fresh isolated session to avoid event loop issues
        # The orchestrator.session() can fail if boot.py left the loop in a bad state
        try:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get("https://openrouter.ai/api/v1/models") as resp:
                    self.results["connectivity"] = resp.status == 200
                    dashboard.log("Network Connectivity to AI: OK", "SUCCESS")
        except Exception as e:
            self.results["connectivity"] = False
            logger.warning(f"Connectivity check failed: {e}")
            dashboard.log("Connectivity to AI: FAILED", "ERROR")

    async def _check_credits(self):
        """Check OpenRouter credits."""
        if not (self.results.get("api_key") and self.results.get("connectivity")):
            return

        logger.info("Initiating OpenRouter credit check...")
        try:
            headers = {"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"}
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get("https://openrouter.ai/api/v1/auth/key") as resp:
                    await self._handle_credit_response(resp)
        except Exception as e:
            logger.error(f"Credit check failed: {e}", exc_info=True)
            dashboard.log("Could not verify credits", "DEBUG")

    async def _handle_credit_response(self, resp):
        """Handle credit check response."""
        if resp.status == 200:
            await self._process_credit_response(resp)
        else:
            dashboard.log(f"Credit check failed (Status {resp.status})", "WARN")

    async def _process_credit_response(self, resp):
        """Process credit check API response."""
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
                self.results["credits"] = False
            else:
                dashboard.log(f"OpenRouter Balance: ${balance:.2f}", "SUCCESS")
                self.results["credits"] = True
        else:
            dashboard.credits = 999.00
            dashboard.log("OpenRouter Key: Unlimited/Free Tier", "SUCCESS")

diagnostics = DiagnosticSystem()
