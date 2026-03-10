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
        """Check OpenRouter API key."""
        success = settings.OPENROUTER_API_KEY is not None and len(settings.OPENROUTER_API_KEY) > 10
        self.results["api_key"] = (success, "" if success else "OpenRouter API Key missing or too short")
        if success:
            dashboard.log("OpenRouter API Key detected (Brain Online)", "SUCCESS")
        else:
            dashboard.log("No OpenRouter Key (Using limited local intelligence)", "WARN")

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
        """Check internet connectivity to OpenRouter."""
        try:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get("https://openrouter.ai/api/v1/models") as resp:
                    success = resp.status == 200
                    self.results["connectivity"] = (success, "" if success else f"OpenRouter API returned {resp.status}")
                    if success:
                        dashboard.log("Network Connectivity to AI: OK", "SUCCESS")
                    else:
                        dashboard.log(f"Network Connectivity to AI: DEGRADED (Status {resp.status})", "WARN")
        except Exception as e:
            self.results["connectivity"] = (False, str(e))
            logger.warning(f"Connectivity check failed: {e}")
            dashboard.log(f"Connectivity to AI: FAILED ({type(e).__name__})", "ERROR")

    async def _check_credits(self):
        """Check OpenRouter credits."""
        success_key, _ = self.results.get("api_key", (False, ""))
        success_conn, _ = self.results.get("connectivity", (False, ""))
        
        if not (success_key and success_conn):
            return

        logger.info("Initiating OpenRouter credit check...")
        try:
            headers = {"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"}
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get("https://openrouter.ai/api/v1/auth/key") as resp:
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
                                dashboard.log(f"OpenRouter Balance: ${balance:.2f}", "SUCCESS")
                                self.results["credits"] = (True, "")
                        else:
                            dashboard.credits = 999.00
                            dashboard.log("OpenRouter Key: Unlimited/Free Tier", "SUCCESS")
                            self.results["credits"] = (True, "")
                    else:
                        dashboard.log(f"Credit check failed (Status {resp.status})", "WARN")
                        self.results["credits"] = (False, f"HTTP {resp.status}")
        except Exception as e:
            logger.error(f"Credit check failed: {e}", exc_info=True)
            dashboard.log("Could not verify credits", "DEBUG")
            self.results["credits"] = (True, "Verification error (ignored)")

diagnostics = DiagnosticSystem()

diagnostics = DiagnosticSystem()
