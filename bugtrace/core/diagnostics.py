import shutil
import asyncio
import os
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("core.diagnostics")

class DiagnosticSystem:
    def __init__(self):
        self.results = {}

    async def run_all(self):
        """Runs a suite of health checks on the environment."""
        dashboard.set_phase("DIAGNOSTICS")
        dashboard.log("Running system health check...", "INFO")
        
        # DEBUG PATHS
        logger.info(f"BASE_DIR: {settings.BASE_DIR}")
        logger.info(f"LOG_DIR: {settings.LOG_DIR}")
        dashboard.log(f"Config: {settings.LOG_DIR}", "DEBUG")
        docker_path = shutil.which("docker")
        self.results["docker"] = docker_path is not None
        if self.results["docker"]:
            dashboard.log("Docker detected (External tools enabled)", "SUCCESS")
        else:
            dashboard.log("Docker NOT found (Nuclei/SQLMap will be disabled)", "WARN")

        # 2. Check OpenRouter API Key
        self.results["api_key"] = settings.OPENROUTER_API_KEY is not None
        if self.results["api_key"]:
            dashboard.log("OpenRouter API Key detected (Brain Online)", "SUCCESS")
        else:
            dashboard.log("No OpenRouter Key (Using limited local intelligence)", "WARN")

        # 3. Check Playwright Browser
        try:
            from bugtrace.tools.visual.browser import browser_manager
            await browser_manager.start()
            self.results["browser"] = True
            dashboard.log("Visual Intelligence Engine: READY", "SUCCESS")
            await browser_manager.stop()
        except Exception as e:
            self.results["browser"] = False
            dashboard.log(f"Browser Failure: {e}", "ERROR")

        # 4. Check Internet Connectivity (OpenRouter)
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://openrouter.ai/api/v1/models", timeout=5) as resp:
                    self.results["connectivity"] = resp.status == 200
                    dashboard.log("Network Connectivity to AI: OK", "SUCCESS")
        except:
            self.results["connectivity"] = False
            dashboard.log("Connectivity to AI: FAILED", "ERROR")

        # 5. Check OpenRouter Credits
        if self.results.get("api_key") and self.results.get("connectivity"):
            logger.info("Initiating OpenRouter credit check...")
            try:
                headers = {"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"}
                async with aiohttp.ClientSession() as session:
                    async with session.get("https://openrouter.ai/api/v1/auth/key", headers=headers, timeout=5) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            key_data = data.get('data', {})
                            
                            limit = key_data.get('limit')
                            usage = key_data.get('usage', 0)
                            
                            # Note: limit might be None for unlimited keys or specific types
                            if limit is not None:
                                balance = limit - usage
                                # Update Dashboard State
                                dashboard.credits = balance
                                
                                if balance < settings.MIN_CREDITS:
                                    msg = f"⛔ INSUFFICIENT FUNDS: ${balance:.2f} (Required: ${settings.MIN_CREDITS:.2f})"
                                    dashboard.log(msg, "CRITICAL")
                                    self.results["credits"] = False
                                else:
                                    dashboard.log(f"OpenRouter Balance: ${balance:.2f}", "SUCCESS")
                                    self.results["credits"] = True
                            else:
                                # Unlimited key
                                dashboard.credits = 999.00 # Indicator for unlimited
                                dashboard.log("OpenRouter Key: Unlimited/Free Tier", "SUCCESS")
                                
                        else:
                            dashboard.log(f"Credit check failed (Status {resp.status})", "WARN")
            except Exception as e:
                logger.error(f"Credit check failed: {e}")
                dashboard.log("Could not verify credits", "DEBUG")

        dashboard.log("Diagnostics complete.", "INFO")
        return all(self.results.values())

diagnostics = DiagnosticSystem()
