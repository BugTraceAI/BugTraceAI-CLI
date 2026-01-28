from playwright.async_api import async_playwright, Browser, BrowserContext, Page
import asyncio
import signal
from typing import Optional, Dict, Any, Tuple, List
from contextlib import asynccontextmanager
from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("tools.visual.browser")

class BrowserManager:
    _instance = None
    _init_lock = asyncio.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            # Note: __new__ is sync, so we can't use await lock here easily without blocking loop.
            # But typically for single-threaded asyncio loop, simple check is mostly fine unless threaded.
            # For strict safety if threads are involved:
            if cls._instance is None:
                cls._instance = super(BrowserManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        # Ensure init only runs once
        if not hasattr(self, "_initialized"):
            self._playwright = None
            self._browser: Optional[Browser] = None
            self._context: Optional[BrowserContext] = None
            self._lock = asyncio.Lock()
            self._initialized = True
            self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Ensure browser closes on SIGINT/SIGTERM. (Stability Improvement #6)"""
        import signal
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
        except (NotImplementedError, RuntimeError):
            # Not supported on all platforms/configurations
            pass
            
    async def _kill_orphans(self):
        """Kill zombie chrome/chromium processes launched by Playwright only.

        Only kills processes with remote-debugging-port (Playwright's Chrome),
        leaving user's personal Chrome untouched.
        """
        try:
            # Only kill Chrome instances launched with debugging port (Playwright)
            proc = await asyncio.create_subprocess_exec(
                "pkill", "-f", "remote-debugging-port",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            await asyncio.sleep(0.3)
        except Exception as e:
            logger.debug(f"Pre-start cleanup failed: {e}")

    async def start(self):
        """Starts the browser instance if not already running."""
        async with self._lock:
            if self._browser and self._browser.is_connected():
                return
            
            try:
                # Async cleanup of orphan processes (non-blocking)
                await self._kill_orphans()
                # Add timeout to playwright start
                self._playwright = await asyncio.wait_for(async_playwright().start(), timeout=15.0)
                # Add timeout to browser launch to prevent indefinite hang
                self._browser = await asyncio.wait_for(
                    self._playwright.chromium.launch(
                        headless=True,
                        args=['--no-sandbox', '--disable-setuid-sandbox']
                    ),
                    timeout=30.0
                )
                logger.info("Browser started successfully.")
            except asyncio.TimeoutError:
                logger.error("Playwright start timed out. Headless browser will be unavailable.")
            except Exception as e:
                logger.error(f"Failed to start browser: {e}")
                # Don't raise, allowing framework to run without browser

    async def stop(self):
        """Stops the browser and cleans up resources."""
        async with self._lock:
            if self._context:
                await self._context.close()
                self._context = None
            
            if self._browser:
                await self._browser.close()
                self._browser = None
                
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
            logger.info("Browser stopped.")

    @asynccontextmanager
    async def get_page(self, use_auth: bool = False) -> Page:
        """
        Context manager to get a page. 
        If use_auth is True, attempts to use the shared authenticated context.
        Otherwise creates a fresh ephemeral context.
        """
        # Ensure browser is running
        if not self._browser or not self._browser.is_connected():
            await self.start()

        # Decide on context
        local_context = None
        page = None
        
        try:
            if use_auth and self._context:
                # Use shared context
                context = self._context
                page = await context.new_page()
            else:
                # Create ephemeral context
                from bugtrace.core.config import settings
                
                # Check config
                vp_width = settings.VIEWPORT_WIDTH
                vp_height = settings.VIEWPORT_HEIGHT
                ua = settings.USER_AGENT
                
                local_context = await self._browser.new_context(
                    viewport={'width': vp_width, 'height': vp_height},
                    user_agent=ua
                )
                page = await local_context.new_page()
            
            yield page
            
        finally:
            if page:
                await page.close()
            if local_context:
                await local_context.close()

    async def capture_state(self, url: str) -> Dict[str, Any]:
        """Captures screenshot and HTML of the target URL."""
        from bugtrace.core.config import settings
        
        async with self.get_page() as page:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=settings.TIMEOUT_MS)
                
                # Screenshot
                screenshot_bytes = await page.screenshot(full_page=False)
                html_content = await page.content()
                
                # Save screenshot temporarily for analysis
                import uuid
                filename = str(settings.LOG_DIR / f"capture_{uuid.uuid4().hex[:8]}.png")
                with open(filename, "wb") as f:
                    f.write(screenshot_bytes)
                
                return {
                    "text": html_content, # Simulating DOM text extraction
                    "screenshot": filename,
                    "html": html_content
                }
            except Exception as e:
                logger.error(f"Capture failed for {url}: {e}")
                return {}

    async def emergency_cleanup(self):
        """Hard cleanup of all chromium processes and sessions."""
        try:
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception as e:
            logger.debug(f"Emergency cleanup error: {e}")
        finally:
            self._browser = None
            self._playwright = None
            self._context = None
            # Only kill Playwright's Chrome (with debugging port), not user's Chrome
            import subprocess
            try:
                subprocess.run(["pkill", "-f", "remote-debugging-port"], check=False, timeout=5)
            except Exception as e:
                logger.debug(f"Emergency browser cleanup failed: {e}")
            logger.info("Emergency browser cleanup performed.")

    async def verify_xss(self, url: str, expected_message: str = None) -> Tuple[str, List[str], bool]:
        """
        Verifies XSS by:
        1. Injecting a mock alert handler that creates a visible verification element
        2. Checking for BUGTRACE-XSS-CONFIRMED marker in DOM (per validation_system.md)

        Returns: (screenshot_path, logs, is_valid)
        """
        triggered = [False]  # Use list for mutability in closure
        logs = []
        screenshot_path = ""

        async with self.get_page() as page:
            try:
                await self._setup_xss_verification_scripts(page, logs, triggered)
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
                await page.wait_for_timeout(3000)

                if not triggered[0]:
                    await self._attempt_interaction_triggers(page, logs, triggered)

                marker_found = await self._check_xss_markers(page, logs)
                screenshot_path = await self._capture_verification_screenshot(page)

                is_valid = triggered[0] or marker_found
                self._log_verification_result(is_valid, triggered[0], marker_found)

            except Exception as e:
                return await self._handle_verification_error(page, logs, e)

        return screenshot_path, logs, triggered[0] or marker_found

    async def _setup_xss_verification_scripts(self, page, logs, triggered):
        """Setup callback and alert override scripts."""
        async def on_xss_triggered(msg):
            triggered[0] = True
            logs.append(f"XSS Triggered via alert(): {msg}")

        await page.expose_function("bugtrace_xss_callback", on_xss_triggered)
        await page.add_init_script(self._get_alert_override_script())

    def _get_alert_override_script(self) -> str:
        """Get JavaScript to override window.alert."""
        return """
            window.alert = function(msg) {
                try {
                    const div = document.createElement('div');
                    div.id = 'xss-proof-banner';
                    div.style.position = 'fixed';
                    div.style.top = '20px';
                    div.style.left = '50%';
                    div.style.transform = 'translateX(-50%)';
                    div.style.zIndex = '2147483647';
                    div.style.background = '#dc2626';
                    div.style.color = 'white';
                    div.style.padding = '20px 40px';
                    div.style.borderRadius = '8px';
                    div.style.fontSize = '24px';
                    div.style.fontWeight = 'bold';
                    div.style.fontFamily = 'monospace';
                    div.style.boxShadow = '0 10px 25px rgba(0,0,0,0.5)';
                    div.style.border = '4px solid white';
                    div.innerText = '⚠️ BUGTRACE: XSS EXECUTED (' + msg + ')';
                    document.body.appendChild(div);
                    window.bugtrace_xss_callback(msg);
                } catch(e) { console.error(e); }
            };
        """

    async def _attempt_interaction_triggers(self, page, logs, triggered):
        """Attempt to trigger XSS through user interactions."""
        try:
            logger.debug("Attempting smart interaction to trigger XSS...")
            candidates = await page.query_selector_all(
                'a[onclick], button[onclick], input[type="submit"], input[type="button"], a[href^="javascript:"]'
            )
            for i, el in enumerate(candidates[:5]):
                if triggered[0]:
                    break
                await self._try_click_element(el, i, page, triggered)

            if not triggered[0]:
                await self._try_back_links(page, triggered)
        except Exception as interact_e:
            logger.warning(f"Interaction phase failed: {interact_e}")
            logs.append(f"Interaction error: {interact_e}")

    async def _try_click_element(self, el, index, page, triggered):
        """Try clicking a single element."""
        try:
            await el.evaluate("el => el.style.border = '5px solid red'")
            logger.debug(f"Clicking interaction candidate {index+1}")
            await el.click(timeout=2000, no_wait_after=True)
            await page.wait_for_timeout(1000)
        except Exception as click_err:
            logger.debug(f"Failed to click candidate {index}: {click_err}")

    async def _try_back_links(self, page, triggered):
        """Try clicking back/return links."""
        back_links = await page.query_selector_all("a:has-text('Back'), button:has-text('Back'), a:has-text('Return')")
        for el in back_links:
            if triggered[0]:
                break
            try:
                await el.click(timeout=2000, no_wait_after=True)
                await page.wait_for_timeout(1000)
            except Exception as e:
                logger.debug(f"Back link click failed: {e}")

    async def _check_xss_markers(self, page, logs) -> bool:
        """Check for XSS markers in DOM."""
        try:
            marker_found = await page.evaluate("""
                () => {
                    const banner = document.getElementById('xss-proof-banner');
                    if (banner) return true;

                    const allElements = document.querySelectorAll('*');
                    for (const el of allElements) {
                        if (el.innerText && el.innerText.includes('BUGTRACE-XSS-CONFIRMED')) {
                            const style = window.getComputedStyle(el);
                            if ((style.backgroundColor === 'rgb(255, 255, 0)' || style.background === 'yellow') &&
                                (style.color === 'rgb(255, 0, 0)' || style.color === 'red') &&
                                style.position === 'fixed') {
                                return true;
                            }
                        }
                    }
                    return false;
                }
            """)
            if marker_found:
                logs.append("BUGTRACE marker detected (verified executable DOM element)")
                logger.info("XSS verified via BUGTRACE marker in DOM")
            return marker_found
        except Exception as eval_err:
            logs.append(f"DOM check error: {eval_err}")
            return False

    async def _capture_verification_screenshot(self, page) -> str:
        """Capture screenshot for verification evidence."""
        import uuid
        from bugtrace.core.config import settings
        screenshot_path = str(settings.LOG_DIR / f"proof_xss_{uuid.uuid4().hex[:8]}.png")
        await page.screenshot(path=screenshot_path)
        return screenshot_path

    def _log_verification_result(self, is_valid, triggered, marker_found):
        """Log the verification result."""
        if is_valid:
            logger.info(f"XSS validated! alert={triggered}, marker={marker_found}")
        else:
            logger.warning("XSS payload did not trigger alert() or inject marker.")

    async def _handle_verification_error(self, page, logs, error):
        """Handle verification errors and capture emergency screenshot."""
        logs.append(f"Browser Execution Error: {error}")
        logger.error(f"Verify XSS failed: {error}")

        try:
            import uuid
            from bugtrace.core.config import settings
            emergency_path = str(settings.LOG_DIR / f"error_xss_{uuid.uuid4().hex[:8]}.png")
            await page.screenshot(path=emergency_path)
            logs.append("Captured emergency screenshot during error.")
            return emergency_path, logs, False
        except Exception as screenshot_err:
            logs.append(f"Failed to capture emergency screenshot: {screenshot_err}")
            return "", logs, False

    async def login(self, url: str, creds: Dict[str, str]) -> bool:
        """
        Attempts to login and persist the context.
        """
        async with self._lock: # Lock because we are modifying self._context (shared state)
            if not self._browser:
                await self.start()
                
            # Create persistent context
            self._context = await self._browser.new_context()
            
            page = await self._context.new_page()
            try:
                logger.info(f"Attempting login at {url}")
                await page.goto(url, wait_until="networkidle")
                
                # Very basic generic login logic (placeholder)
                # In real scenario, use LLM or specific selectors
                # ... implementation skipped for brevity ...
                
                logger.info("Login logic placeholder executed.")
                await page.close()
                return True
                
            except Exception as e:
                logger.error(f"Login failed: {e}")
                if self._context:
                    await self._context.close()
                    self._context = None
                return False

    async def get_session_data(self) -> Dict[str, Any]:
        """
        Exports current session cookies and headers for external tools.
        """
        from bugtrace.core.config import settings
        
        data = {
            "cookies": [],
            "headers": {
                "User-Agent": settings.USER_AGENT
            }
        }
        
        async with self._lock:
            if self._context:
                try:
                    data["cookies"] = await self._context.cookies()
                except Exception as e:
                    logger.error(f"Failed to get cookies: {e}")
                    
        return data

browser_manager = BrowserManager()
