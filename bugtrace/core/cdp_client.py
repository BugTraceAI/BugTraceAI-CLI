"""
Chrome DevTools Protocol (CDP) Client for XSS Validation.

This module provides direct access to Chrome's DevTools Protocol,
enabling more reliable XSS detection through console log monitoring
and JavaScript execution.

Key advantages over Playwright for XSS validation:
1. Direct console.log access - see all JS output
2. Runtime.evaluate with proper error handling
3. Network interception for SSRF detection
4. No dialog event race conditions

Author: BugtraceAI Team
Date: 2026-01-08
"""

import asyncio
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
import aiohttp

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("core.cdp_client")


@dataclass
class CDPResult:
    """Result from CDP operation."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    console_logs: List[Dict] = field(default_factory=list)
    screenshot_path: Optional[str] = None
    marker_found: bool = False


class CDPClient:
    """
    Chrome DevTools Protocol Client.
    
    Provides direct CDP access for more reliable XSS validation than Playwright.
    
    Features:
    - Console log monitoring (catches all console.log, console.error, etc.)
    - JavaScript execution with proper return values
    - Screenshot capture
    - Network request monitoring
    
    Usage:
        async with CDPClient() as cdp:
            result = await cdp.validate_xss("http://example.com/vuln?q=<script>alert(1)</script>")
            if result.success:
                print("XSS confirmed!")
    """
    
    def __init__(self, headless: bool = True, port: int = 9222):
        self.headless = headless
        self.port = port
        self.chrome_process: Optional[subprocess.Popen] = None
        self.ws_url: Optional[str] = None
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self._message_id = 0
        self._console_logs: List[Dict] = []
        self._network_requests: List[Dict] = []
        self._listeners: Dict[str, List[Callable]] = {}
        self._pending_responses: Dict[int, asyncio.Future] = {}
        self._receive_task: Optional[asyncio.Task] = None
        self._temp_dir: Optional[Path] = None
        self._alert_detected = False
        self._last_alert_message = None

    def _find_free_port(self) -> int:
        """Find a random free port on localhost."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]
        
    async def __aenter__(self):
        # Dynamically find a free port if default is likely busy or for robustness
        # But respect the passed port if it was explicit (though here we default to 9222)
        # Strategy: Try default, if busy/fails, use random
        await self.start()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Reuse logic: don't close unless error
        if exc_type is not None: 
            logger.warning(f"CDP exit with error: {exc_val}, cleaning up...")
            await self.stop()
        
    async def start(self):
        """Start Chrome and connect via CDP. Reuses existing connection if available."""
        # 1. Check if already connected and healthy
        if self.ws and not self.ws.closed and self.session and not self.session.closed:
            try:
                await self._send("Runtime.enable")
                return
            except Exception:
                logger.warning("CDP connection stale, restarting...")
                await self.stop()

        # 2. Dynamic Port Selection Logic
        # If we failed to connect or are starting fresh, ensure we pick a clean port
        # if the default 9222 is having issues.
        # For this fix, let's always try to find a free port if we are creating a NEW process.
        # This completely avoids the "Address already in use" or "Connect failed" loops.
        
        # NOTE: If we want to reuse, we have to store the port we used. 
        # Since self.port is set in __init__, we update it here for the new process.
        if self.port == 9222: # If using default, feel free to rotate
             self.port = self._find_free_port()
             logger.info(f"CDP: Switched to dynamic free port: {self.port}")
        
        # Create temp directory for Chrome user data
        if not self._temp_dir:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="bugtrace_cdp_"))
        
        # CLEANUP: Ensure no zombie Chrome processes are blocking our port
        # TASK-51/RCE-FIX: Use subprocess list args instead of shell=True to prevent command injection
        if self.port:
            import shlex
            try:
                # Kill any process listening on our port (safe - port is validated as int)
                port_str = str(int(self.port))  # Ensure port is numeric
                subprocess.run(["fuser", "-k", f"{port_str}/tcp"], stderr=subprocess.DEVNULL)
                # General cleanup of zombies (safer to do this only on start)
                subprocess.run(["pkill", "-f", "chrome --remote-debugging-port"], stderr=subprocess.DEVNULL)
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.debug(f"Port cleanup failed: {e}")
        
        # Find Chrome executable
        chrome_path = self._find_chrome()
        if not chrome_path:
            raise RuntimeError("Chrome/Chromium not found. Please install Chrome.")
        
        # Start Chrome with remote debugging
        chrome_args = [
            chrome_path,
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self._temp_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-hang-monitor",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-sync",
            "--disable-translate",
            "--metrics-recording-only",
            "--safebrowsing-disable-auto-update",
            "--enable-features=NetworkService,NetworkServiceInProcess",
            "--disable-features=TranslateUI",
            "--no-sandbox", # CRITICAL FIX for many environments
            "--disable-dev-shm-usage", # Fix for low shm memory in containers
            "about:blank",  # Open a blank page initially
        ]
        
        if self.headless:
            chrome_args.append("--headless=new")
            
        # SAFETY: Wrap in system 'timeout' to prevent infinite zombies if Python crashes
        # 180s (3m) hard limit per session. -k 5 ensures SIGKILL if SIGTERM fails.
        chrome_args = ["timeout", "-k", "5", "180s"] + chrome_args
        
        logger.info(f"Starting Chrome on port {self.port}...")
        # Capture output for debugging crashes
        self.chrome_process = subprocess.Popen(
            chrome_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True 
        )
        
        # Wait for Chrome to start (increased for reliability)
        await asyncio.sleep(4.0)
        
        self.session = aiohttp.ClientSession()
        
        # Get list of pages/targets and connect to the first page
        page_ws_url = None
        last_error = None
        for attempt in range(20):  # Increased attempts
            try:
                # Use 127.0.0.1 to avoid localhost resolution issues
                async with self.session.get(f"http://127.0.0.1:{self.port}/json/list", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    targets = await resp.json()
                    # Find a page target (not background page, not devtools)
                    for target in targets:
                        if target.get("type") == "page":
                            page_ws_url = target.get("webSocketDebuggerUrl")
                            if page_ws_url:
                                logger.info(f"CDP connected to page: {page_ws_url[:60]}...")
                                break
                    if page_ws_url:
                        break
            except Exception as e:
                last_error = e
                # Check if process is still alive
                if self.chrome_process.poll() is not None:
                     logger.error(f"Chrome process died early. Return code: {self.chrome_process.returncode}")
                     break
                
                logger.debug(f"Waiting for Chrome... attempt {attempt+1}: {e}")
                await asyncio.sleep(0.5)
        
        if not page_ws_url:
            # Try creating a new target
            try:
                async with self.session.put(f"http://127.0.0.1:{self.port}/json/new?about:blank", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    target = await resp.json()
                    page_ws_url = target.get("webSocketDebuggerUrl")
            except Exception as e:
                logger.error(f"Failed to create new page: {e}")
        
        if not page_ws_url:
            # Capture stderr for debugging
            stderr_output = ""
            if self.chrome_process and self.chrome_process.stderr:
                 stderr_output = self.chrome_process.stderr.read()
            
            logger.error(f"Chrome Start Failed. Stderr: {stderr_output}")

            # Cleanup on failure
            await self.stop()
            raise RuntimeError(f"Failed to connect to Chrome CDP page on port {self.port}. Last error: {last_error}")
        
        self.ws_url = page_ws_url
        
        # Connect WebSocket to the PAGE target (not browser)
        self.ws = await self.session.ws_connect(self.ws_url)
        
        # Start message receiver
        self._receive_task = asyncio.create_task(self._receive_messages())
        
        # Enable domains
        await self._send("Page.enable")
        await self._send("Runtime.enable")
        await self._send("DOM.enable")
        await self._send("Network.enable")
        
        # -----------------------------------------------------------
        # VISUAL XSS POLYFILL
        # Overrides window.alert to render a visible element instead of blocking
        # This allows screenshots to capture the "alert" for Vision verification
        # -----------------------------------------------------------
        polyfill_script = """
        window.alert = function(msg) {
            // 1. Log for internal detection (replacing dialog event)
            console.log("BUGTRACE_ALERT_HIT::" + msg);
            
            // 2. Render Visual Proof (High Z-Index Overlay)
            // Use a unique ID to avoid duplicates if called multiple times
            if (document.getElementById('bugtrace-alert-box')) return;
            
            var d = document.createElement("div");
            d.id = "bugtrace-alert-box";
            d.style.cssText = "position:fixed;top:10%;left:50%;transform:translate(-50%,0);z-index:2147483647;background:#fff;border:4px solid #ef4444;padding:20px;font-family:system-ui,sans-serif;box-shadow:0 10px 25px rgba(0,0,0,0.5);border-radius:8px;text-align:center;min-width:300px;";
            d.innerHTML = "<div style='font-size:48px;margin-bottom:10px'>⚠️</div><div style='font-size:24px;font-weight:bold;color:#1f2937;margin-bottom:10px'>XSS EXECUTED</div><div style='font-size:16px;color:#4b5563;background:#f3f4f6;padding:10px;border-radius:4px;word-break:break-all'>alert('" + msg + "')</div>";
            document.body.appendChild(d);
            return true;
        };
        """
        
        await self._send("Page.addScriptToEvaluateOnNewDocument", {
            "source": polyfill_script
        })
        
        logger.info("CDP Client ready (Visual Polyfill Injected)")
        
        # Set up console log handler
        self._add_listener("Console.messageAdded", self._on_console_message)
        self._add_listener("Runtime.consoleAPICalled", self._on_runtime_console)
        
        logger.info("CDP Client ready")
        
    async def stop(self):
        """Stop Chrome and cleanup."""
        logger.info("Stopping CDP Client (Releasing port)...")

        # TASK-51: Clear pending responses to prevent memory leaks
        for future in self._pending_responses.values():
            if not future.done():
                future.cancel()
        self._pending_responses.clear()

        # TASK-51: Clear listeners to prevent callback leaks
        self._listeners.clear()

        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        if self.ws:
            await self.ws.close()

        if self.session:
            await self.session.close()

        if self.chrome_process:
            self.chrome_process.terminate()
            try:
                self.chrome_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.chrome_process.kill()

        # Cleanup temp directory
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp dir: {e}")

        # Clear internal state
        self._console_logs.clear()
        self._network_requests.clear()
        self._alert_detected = False
        self._last_alert_message = None

        logger.info("CDP Client stopped")
    
    def _find_chrome(self) -> Optional[str]:
        """Find Chrome/Chromium executable."""
        candidates = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/snap/bin/chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ]
        
        for path in candidates:
            if Path(path).exists():
                return path
        
        # Try 'which'
        result = subprocess.run(["which", "google-chrome"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
            
        return None
    
    async def _send(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Send CDP command and wait for response."""
        self._message_id += 1
        msg_id = self._message_id
        
        message = {
            "id": msg_id,
            "method": method,
            "params": params or {}
        }
        
        # Create future for response
        future = asyncio.get_event_loop().create_future()
        self._pending_responses[msg_id] = future
        
        await self.ws.send_json(message)
        
        try:
            response = await asyncio.wait_for(future, timeout=30.0)
            return response
        except asyncio.TimeoutError:
            del self._pending_responses[msg_id]
            raise RuntimeError(f"CDP command timed out: {method}")
    
    async def _receive_messages(self):
        """Background task to receive and dispatch CDP messages."""
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    
                    # Handle response to our command
                    if "id" in data:
                        msg_id = data["id"]
                        if msg_id in self._pending_responses:
                            self._pending_responses[msg_id].set_result(data)
                            del self._pending_responses[msg_id]
                    
                    # Handle events
                    elif "method" in data:
                        method = data["method"]
                        if method in self._listeners:
                            for listener in self._listeners[method]:
                                try:
                                    listener(data.get("params", {}))
                                except Exception as e:
                                    logger.error(f"Listener error: {e}")
                                    
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {msg.data}")
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"CDP receive error: {e}")
    
    def _add_listener(self, event: str, callback: Callable):
        """Add event listener."""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)
    
    def _on_console_message(self, params: Dict):
        """Handle Console.messageAdded events."""
        message = params.get("message", {})
        self._console_logs.append({
            "type": message.get("level", "log"),
            "text": message.get("text", ""),
            "source": "console",
            "timestamp": message.get("timestamp")
        })
    
    def _on_runtime_console(self, params: Dict):
        """Handle Runtime.consoleAPICalled events."""
        args = params.get("args", [])
        if not args:
            return
            
        text_parts = []
        for arg in args:
            val = arg.get("value")
            if val is not None:
                text_parts.append(str(val))
            elif "description" in arg:
                text_parts.append(arg["description"])
                
        msg = " ".join(text_parts)
        
        # Detect Visual Polyfill Alert
        if "BUGTRACE_ALERT_HIT::" in msg:
            self._alert_detected = True
            clean_msg = msg.split("BUGTRACE_ALERT_HIT::")[1]
            self._last_alert_message = clean_msg
            logger.info(f"CDP: JS Dialog detected (Visual Polyfill): {clean_msg}")
        
        # Original logging of runtime console messages
        log_type = params.get("type", "log")
        self._console_logs.append({
            "type": log_type,
            "text": msg,
            "source": "runtime",
            "timestamp": params.get("timestamp")
        })

    
    # Deprecated: Native dialog handling removed in favor of Visual Polyfill
    # def _on_dialog_opening(self, params: Dict):
    #     pass
    
    async def navigate(self, url: str) -> bool:
        """Navigate to URL and wait for page load."""
        self._console_logs.clear()  # Clear logs for new page
        
        try:
            result = await self._send("Page.navigate", {"url": url})
            
            if "error" in result:
                logger.error(f"Navigation error: {result['error']}")
                return False
            
            # Wait for page load
            await self._send("Page.loadEventFired")
            await asyncio.sleep(1.0)  # Extra time for JS execution
            
            return True
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return False
    
    async def execute_js(self, expression: str) -> Any:
        """Execute JavaScript and return result."""
        result = await self._send("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True
        })
        
        if "result" in result and "result" in result["result"]:
            return result["result"]["result"].get("value")
        return None
    
    async def screenshot(self, path: str) -> str:
        """Take screenshot and save to path."""
        try:
            # Use shorter timeout for screenshot
            self._message_id += 1
            msg_id = self._message_id
            
            message = {
                "id": msg_id,
                "method": "Page.captureScreenshot",
                "params": {"format": "png"}
            }
            
            future = asyncio.get_event_loop().create_future()
            self._pending_responses[msg_id] = future
            
            await self.ws.send_json(message)
            
            # Shorter timeout for screenshot
            result = await asyncio.wait_for(future, timeout=10.0)
            
            if "result" in result and "data" in result["result"]:
                import base64
                image_data = base64.b64decode(result["result"]["data"])
                
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                with open(path, "wb") as f:
                    f.write(image_data)
                
                return path
        except asyncio.TimeoutError:
            if msg_id in self._pending_responses:
                del self._pending_responses[msg_id]
            logger.warning("Screenshot timed out (10s)")
        except Exception as e:
            logger.warning(f"Screenshot error: {e}")
        
        raise RuntimeError("Screenshot failed")
    
    async def validate_xss(
        self,
        url: str,
        xss_marker: str = "BUGTRACE-XSS-CONFIRMED",
        timeout: float = 5.0,
        screenshot_dir: Optional[str] = None,
        expected_marker: Optional[str] = None
    ) -> CDPResult:
        """
        Validate XSS by navigating to URL and checking for markers.
        
        This method:
        1. Navigates to the potentially vulnerable URL
        2. Monitors console for XSS marker (logged via injected payload)
        3. Checks DOM for marker element
        4. Takes screenshot as evidence
        
        Args:
            url: URL to test (with XSS payload in params)
            xss_marker: Marker to look for in console/DOM
            timeout: Time to wait for XSS execution
            screenshot_dir: Directory to save screenshot
            
        Returns:
            CDPResult with validation outcome
        """
        logger.info(f"CDP: Validating XSS at {url[:80]}...")
        
        # Reset state for new validation
        self._console_logs.clear()
        self._alert_detected = False
        self._last_alert_message = None
        
        # Navigate to URL
        nav_success = await self.navigate(url)
        if not nav_success:
            return CDPResult(
                success=False,
                error="Navigation failed",
                console_logs=self._console_logs.copy()
            )
        
        # Wait for potential XSS execution
        await asyncio.sleep(timeout)
        
        # Check 1: Look for marker in console logs (STRONGEST PROOF - script executed)
        xss_in_console = any(
            xss_marker in log.get("text", "") 
            for log in self._console_logs
        )
        
        # Check 2: Look for marker in DOM - but verify it's NOT just escaped text
        # We need to check if a script actually executed, not just reflected text
        xss_in_dom_raw = await self.execute_js(
            f'document.body.innerHTML.includes("{xss_marker}")'
        )
        
        # Check if marker appears in a real executed script context
        # by looking for a dynamically created element with our marker
        xss_in_dom_executed = await self.execute_js('''
            (() => {
                // Multiple checks for JavaScript execution proof
                const marker = "BUGTRACE-XSS-CONFIRMED";
                
                // 1. Check for visible text that matches marker (real XSS creates visible elements)
                const bodyText = document.body.innerText || "";
                const hasVisibleMarker = bodyText.includes(marker);
                
                // 2. Check if marker is in a style attribute (common XSS pattern)
                const styledElements = document.querySelectorAll('[style*="color"], [style*="background"]');
                const hasStyledMarker = Array.from(styledElements).some(el => 
                    el.textContent && el.textContent.includes(marker)
                );
                
                // 3. Check for dynamically created elements with IDs starting with "BTPOE_" (PoE markers)
                const poeElements = document.querySelectorAll('[id^="BTPOE_"]');
                const hasPoeMarker = poeElements.length > 0;
                
                // 4. Check if document structure was modified by script (scripts create new nodes)
                const scriptCreatedDivs = document.querySelectorAll('div[id], span[id]');
                const hasScriptCreatedElement = Array.from(scriptCreatedDivs).some(el => {
                    // Check if element looks like it was created by our PoE script
                    return el.id.startsWith('BTPOE_') || (el.textContent && el.textContent.includes(marker));
                });
                
                // True XSS execution: styled markers OR PoE markers OR script-created elements
                return hasStyledMarker || hasPoeMarker || hasScriptCreatedElement;
            })()
        ''')
        
        # Check 4: Explicit expected marker (STRONG PoE)
        marker_found = False
        if expected_marker:
            try:
                res = await self.execute_js(f'document.getElementById("{expected_marker}") !== null')
                marker_found = bool(res)
            except Exception as e:
                logger.debug(f"Marker check failed: {e}")

        # STRICT XSS VALIDATION:
        # XSS requires JavaScript EXECUTION, not just HTML injection
        # Priority: alert_detected > expected_marker > console logs > DOM execution proof
        if self._alert_detected:
            xss_confirmed = True
        elif expected_marker:
            # If we have an expected marker, require either the marker or console proof
            xss_confirmed = marker_found or xss_in_console
        else:
            # Without expected marker, accept console OR DOM execution proof
            # This prevents false negatives when XSS executes but doesn't log to console
            xss_confirmed = xss_in_console or xss_in_dom_executed
        
        # Log the distinction
        if xss_in_dom_raw and not xss_confirmed:
            logger.info("NOTE: Marker found in DOM but no JS execution - may be HTML injection, not XSS")
        
        # Take screenshot
        screenshot_path = None
        if screenshot_dir:
            import time
            screenshot_path = f"{screenshot_dir}/cdp_xss_{int(time.time())}.png"
            try:
                await self.screenshot(screenshot_path)
            except Exception as e:
                logger.warning(f"Screenshot failed: {e}")
        
        logger.info(f"CDP XSS Result: alert={self._alert_detected}, console={xss_in_console}, dom_raw={xss_in_dom_raw}, dom_executed={xss_in_dom_executed}, marker_found={marker_found}")
        
        return CDPResult(
            success=xss_confirmed,
            data={
                "alert_detected": self._alert_detected,
                "xss_in_console": xss_in_console,
                "xss_in_dom_raw": xss_in_dom_raw,
                "xss_in_dom_executed": xss_in_dom_executed,
                "marker_found": marker_found,
                "url": url
            },
            console_logs=self._console_logs.copy(),
            screenshot_path=screenshot_path,
            marker_found=marker_found
        )
    
    async def get_console_logs(self) -> List[Dict]:
        """Get all console logs captured since last navigation."""
        return self._console_logs.copy()
    
    async def inject_xss_payload(self, payload: str) -> bool:
        """
        Inject XSS payload directly into page.
        
        Useful for testing if context allows XSS execution.
        """
        try:
            # Attempt to inject via document.write
            await self.execute_js(f'document.write({json.dumps(payload)})')
            return True
        except Exception as e:
            logger.error(f"Payload injection failed: {e}")
            return False


# Singleton instance
_cdp_client: Optional[CDPClient] = None


async def get_cdp_client(headless: bool = True) -> CDPClient:
    """Get or create CDP client instance."""
    global _cdp_client
    
    if _cdp_client is None:
        _cdp_client = CDPClient(headless=headless)
        await _cdp_client.start()
    
    return _cdp_client


async def close_cdp_client():
    """Close the CDP client if open."""
    global _cdp_client
    
    if _cdp_client is not None:
        await _cdp_client.stop()
        _cdp_client = None
