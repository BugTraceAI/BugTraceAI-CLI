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
    alert_message: Optional[str] = None


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
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logger.warning(f"CDP exit with error: {exc_val}, cleaning up...")
            await self.stop()

    async def _check_existing_connection(self) -> bool:
        """Check if existing connection is still healthy."""
        if not (self.ws and not self.ws.closed and self.session and not self.session.closed):
            return False

        try:
            await self._send("Runtime.enable")
            return True
        except Exception:
            logger.warning("CDP connection stale, restarting...")
            await self.stop()
            return False

    def _select_port(self):
        """Select an available port for Chrome."""
        if self.port == 9222:
            self.port = self._find_free_port()
            logger.info(f"CDP: Switched to dynamic free port: {self.port}")

    async def _cleanup_zombie_processes(self):
        """Cleanup zombie Chrome processes blocking the port."""
        if not self.port:
            return

        try:
            port_str = str(int(self.port))
            subprocess.run(["fuser", "-k", f"{port_str}/tcp"], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "chrome --remote-debugging-port"], stderr=subprocess.DEVNULL)
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Port cleanup failed: {e}")

    def _build_chrome_args(self, chrome_path: str) -> list:
        """Build Chrome command line arguments."""
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
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "about:blank",
        ]

        if self.headless:
            chrome_args.append("--headless=new")

        return ["timeout", "-k", "5", "180s"] + chrome_args

    async def _connect_to_chrome_page(self) -> str:
        """Connect to Chrome page and return WebSocket URL."""
        page_ws_url = await self._try_connect_to_existing_page()

        if not page_ws_url:
            page_ws_url = await self._create_new_chrome_page()

        if not page_ws_url:
            self._handle_connection_failure()

        return page_ws_url

    async def _try_connect_to_existing_page(self) -> Optional[str]:
        """Try to connect to an existing Chrome page."""
        for attempt in range(20):
            page_ws_url = await self._attempt_chrome_connection(attempt)
            if page_ws_url:
                return page_ws_url
        return None

    async def _attempt_chrome_connection(self, attempt: int) -> Optional[str]:
        """Attempt single Chrome connection try."""
        try:
            async with self.session.get(
                f"http://127.0.0.1:{self.port}/json/list",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                targets = await resp.json()
                return self._find_page_websocket_url(targets)
        except Exception as e:
            return await self._handle_connection_error(e, attempt)

    def _find_page_websocket_url(self, targets: list) -> Optional[str]:
        """Find WebSocket URL for a page target."""
        for target in targets:
            if target.get("type") != "page":
                continue

            page_ws_url = target.get("webSocketDebuggerUrl")
            if not page_ws_url:
                continue

            logger.info(f"CDP connected to page: {page_ws_url[:60]}...")
            return page_ws_url
        return None

    async def _handle_connection_error(self, error: Exception, attempt: int) -> Optional[str]:
        """Handle Chrome connection error."""
        if self.chrome_process.poll() is not None:
            logger.error(f"Chrome process died early. Return code: {self.chrome_process.returncode}")
            return None

        logger.debug(f"Waiting for Chrome... attempt {attempt+1}: {error}")
        await asyncio.sleep(0.5)
        return None

    async def _create_new_chrome_page(self) -> Optional[str]:
        """Create a new Chrome page."""
        try:
            async with self.session.put(
                f"http://127.0.0.1:{self.port}/json/new?about:blank",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                target = await resp.json()
                return target.get("webSocketDebuggerUrl")
        except Exception as e:
            logger.error(f"Failed to create new page: {e}", exc_info=True)
            return None

    def _handle_connection_failure(self):
        """Handle Chrome connection failure."""
        stderr_output = ""
        if self.chrome_process and self.chrome_process.stderr:
            stderr_output = self.chrome_process.stderr.read()
        logger.error(f"Chrome Start Failed. Stderr: {stderr_output}")
        raise RuntimeError(f"Failed to connect to Chrome CDP page on port {self.port}")

    async def _inject_xss_polyfill(self):
        """Inject Visual XSS polyfill for alert() detection."""
        polyfill_script = """
        window.alert = function(msg) {
            console.log("BUGTRACE_ALERT_HIT::" + msg);
            if (document.getElementById('bugtrace-alert-box')) return;
            var d = document.createElement("div");
            d.id = "bugtrace-alert-box";
            d.style.cssText = "position:fixed;top:10%;left:50%;transform:translate(-50%,0);z-index:2147483647;background:#fff;border:4px solid #ef4444;padding:20px;font-family:system-ui,sans-serif;box-shadow:0 10px 25px rgba(0,0,0,0.5);border-radius:8px;text-align:center;min-width:300px;";
            d.innerHTML = "<div style='font-size:48px;margin-bottom:10px'>⚠️</div><div style='font-size:24px;font-weight:bold;color:#1f2937;margin-bottom:10px'>XSS EXECUTED</div><div style='font-size:16px;color:#4b5563;background:#f3f4f6;padding:10px;border-radius:4px;word-break:break-all'>alert('" + msg + "')</div>";
            document.body.appendChild(d);
            return true;
        };
        """
        await self._send("Page.addScriptToEvaluateOnNewDocument", {"source": polyfill_script})

    async def start(self):
        """Start Chrome and connect via CDP. Reuses existing connection if available."""
        # Guard: Check existing connection
        if await self._check_existing_connection():
            return

        # Setup
        self._select_port()

        if not self._temp_dir:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="bugtrace_cdp_"))

        await self._cleanup_zombie_processes()

        # Find Chrome
        chrome_path = self._find_chrome()
        if not chrome_path:
            raise RuntimeError("Chrome/Chromium not found. Please install Chrome.")

        # Launch Chrome
        await self._launch_chrome(chrome_path)

        # Connect and enable domains
        await self._connect_and_enable_domains()

        logger.info("CDP Client ready")

    async def _launch_chrome(self, chrome_path: str):
        """Launch Chrome browser process."""
        chrome_args = self._build_chrome_args(chrome_path)
        logger.info(f"Starting Chrome on port {self.port}...")
        self.chrome_process = subprocess.Popen(
            chrome_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        await asyncio.sleep(4.0)

    async def _connect_and_enable_domains(self):
        """Connect to Chrome and enable CDP domains."""
        self.session = aiohttp.ClientSession()

        # Connect to page
        self.ws_url = await self._connect_to_chrome_page()
        self.ws = await self.session.ws_connect(self.ws_url)

        # Start receiver and enable domains
        self._receive_task = asyncio.create_task(self._receive_messages())
        await self._send("Page.enable")
        await self._send("Runtime.enable")
        await self._send("DOM.enable")
        await self._send("Network.enable")

        # Inject polyfill
        await self._inject_xss_polyfill()

        # Setup listeners
        self._add_listener("Console.messageAdded", self._on_console_message)
        self._add_listener("Runtime.consoleAPICalled", self._on_runtime_console)

    async def stop(self):
        """Stop Chrome and cleanup."""
        logger.info("Stopping CDP Client (Releasing port)...")

        # Clear pending responses and listeners
        self._clear_pending_resources()

        # Cancel receiver task
        await self._cancel_receiver_task()

        # Close connections
        await self._close_connections()

        # Stop Chrome process
        self._stop_chrome_process()

        # Cleanup temp directory
        self._cleanup_temp_directory()

        # Clear internal state
        self._clear_internal_state()

        logger.info("CDP Client stopped")

    def _clear_pending_resources(self):
        """Clear pending responses and listeners to prevent memory leaks."""
        for future in self._pending_responses.values():
            if not future.done():
                future.cancel()
        self._pending_responses.clear()
        self._listeners.clear()

    async def _cancel_receiver_task(self):
        """Cancel the message receiver task."""
        if not self._receive_task:
            return

        self._receive_task.cancel()
        try:
            await self._receive_task
        except asyncio.CancelledError:
            pass

    async def _close_connections(self):
        """Close WebSocket and HTTP session connections."""
        if self.ws:
            await self.ws.close()

        if self.session:
            await self.session.close()

    def _stop_chrome_process(self):
        """Stop the Chrome browser process."""
        if not self.chrome_process:
            return

        self.chrome_process.terminate()
        try:
            self.chrome_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.chrome_process.kill()

    def _cleanup_temp_directory(self):
        """Cleanup temporary directory."""
        if not (self._temp_dir and self._temp_dir.exists()):
            return

        try:
            shutil.rmtree(self._temp_dir)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir: {e}")

    def _clear_internal_state(self):
        """Clear internal tracking state."""
        self._console_logs.clear()
        self._network_requests.clear()
        self._alert_detected = False
        self._last_alert_message = None

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
                await self._process_websocket_message(msg)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"CDP receive error: {e}", exc_info=True)

    async def _process_websocket_message(self, msg):
        """Process a single WebSocket message."""
        if msg.type == aiohttp.WSMsgType.TEXT:
            data = json.loads(msg.data)
            self._handle_cdp_message(data)
            return

        if msg.type == aiohttp.WSMsgType.ERROR:
            logger.error(f"WebSocket error: {msg.data}")
            raise RuntimeError("WebSocket error occurred")

    def _handle_cdp_message(self, data: dict):
        """Handle received CDP message."""
        # Handle response to our command
        if "id" in data:
            self._handle_cdp_response(data)
            return

        # Handle events
        if "method" in data:
            self._handle_cdp_event(data)

    def _handle_cdp_response(self, data: dict):
        """Handle CDP command response."""
        msg_id = data["id"]
        if msg_id not in self._pending_responses:
            return

        self._pending_responses[msg_id].set_result(data)
        del self._pending_responses[msg_id]

    def _handle_cdp_event(self, data: dict):
        """Handle CDP event."""
        method = data["method"]
        if method not in self._listeners:
            return

        params = data.get("params", {})
        for listener in self._listeners[method]:
            try:
                listener(params)
            except Exception as e:
                logger.error(f"Listener error: {e}", exc_info=True)

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
        msg = self._extract_console_message(params)

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

    def _extract_console_message(self, params: Dict) -> str:
        """Extract message text from console API params."""
        args = params.get("args", [])
        if not args:
            return ""

        text_parts = []
        for arg in args:
            val = arg.get("value")
            if val is not None:
                text_parts.append(str(val))
            elif "description" in arg:
                text_parts.append(arg["description"])

        return " ".join(text_parts)

    async def navigate(self, url: str) -> bool:
        """Navigate to URL and wait for page load."""
        self._console_logs.clear()

        try:
            result = await self._send("Page.navigate", {"url": url})

            if "error" in result:
                logger.error(f"Navigation error: {result['error']}")
                return False

            # Wait for page load (simple sleep since we can't await events via _send)
            await asyncio.sleep(2.0)

            return True
        except Exception as e:
            logger.error(f"Navigation failed: {e}", exc_info=True)
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
            result = await self._send_screenshot_command()

            if "result" in result and "data" in result["result"]:
                self._save_screenshot_data(result["result"]["data"], path)
                return path
        except asyncio.TimeoutError:
            logger.warning("Screenshot timed out (10s)")
        except Exception as e:
            logger.warning(f"Screenshot error: {e}")

        raise RuntimeError("Screenshot failed")

    async def _send_screenshot_command(self) -> dict:
        """Send screenshot capture command with shorter timeout."""
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
        try:
            return await asyncio.wait_for(future, timeout=10.0)
        except asyncio.TimeoutError:
            if msg_id in self._pending_responses:
                del self._pending_responses[msg_id]
            raise

    def _save_screenshot_data(self, data: str, path: str):
        """Save base64 screenshot data to file."""
        import base64
        image_data = base64.b64decode(data)

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(image_data)

    async def _check_xss_in_console(self, xss_marker: str) -> bool:
        """Check if XSS marker appears in console logs."""
        return any(xss_marker in log.get("text", "") for log in self._console_logs)

    async def _check_xss_in_dom_executed(self) -> bool:
        """Check if XSS was executed (not just reflected) in DOM."""
        return await self.execute_js('''
            (() => {
                const markers = ["BUGTRACE-XSS-CONFIRMED", "HACKED BY BUGTRACEAI"];
                const bodyText = document.body.innerText || "";
                
                // Check visible text for any marker
                const hasVisibleMarker = markers.some(m => bodyText.includes(m));

                const styledElements = document.querySelectorAll('[style*="color"], [style*="background"]');
                const hasStyledMarker = Array.from(styledElements).some(el =>
                    el.textContent && markers.some(m => el.textContent.includes(m))
                );

                // Check for both legacy POE ID and new XSSAgent bt-pwn ID
                const poeElements = document.querySelectorAll('[id^="BTPOE_"], [id="bt-pwn"]');
                const hasPoeMarker = poeElements.length > 0;

                const scriptCreatedDivs = document.querySelectorAll('div[id], span[id]');
                const hasScriptCreatedElement = Array.from(scriptCreatedDivs).some(el => {
                    const idMatch = el.id.startsWith('BTPOE_') || el.id === 'bt-pwn';
                    const textMatch = el.textContent && markers.some(m => el.textContent.includes(m));
                    return idMatch || textMatch;
                });

                return hasStyledMarker || hasPoeMarker || hasScriptCreatedElement;
            })()
        ''')

    async def _check_expected_marker(self, expected_marker: str) -> bool:
        """Check if expected marker element exists in DOM."""
        try:
            res = await self.execute_js(f'document.getElementById("{expected_marker}") !== null')
            return bool(res)
        except Exception as e:
            logger.debug(f"Marker check failed: {e}")
            return False

    def _determine_xss_confirmed(
        self,
        xss_in_console: bool,
        xss_in_dom_raw: bool,
        xss_in_dom_executed: bool,
        marker_found: bool,
        expected_marker: Optional[str]
    ) -> bool:
        """Determine if XSS is confirmed based on multiple checks."""
        # Priority: alert > expected_marker > console > DOM execution
        if self._alert_detected:
            return True
        if expected_marker:
            return marker_found or xss_in_console
        return xss_in_console or xss_in_dom_executed

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
        """
        logger.info(f"CDP: Validating XSS at {url[:80]}...")

        # Reset state
        self._reset_validation_state()

        # Navigate
        nav_success = await self.navigate(url)
        if not nav_success:
            return CDPResult(
                success=False,
                error="Navigation failed",
                console_logs=self._console_logs.copy()
            )

        # Wait for XSS execution
        await asyncio.sleep(timeout)

        # Perform checks
        check_results = await self._perform_xss_checks(xss_marker, expected_marker)

        # Take screenshot
        screenshot_path = await self._capture_validation_screenshot(screenshot_dir)

        # Log results
        self._log_validation_results(check_results)

        return self._build_validation_result(check_results, screenshot_path, url)

    def _reset_validation_state(self):
        """Reset validation state before new check."""
        self._console_logs.clear()
        self._alert_detected = False
        self._last_alert_message = None

    async def _perform_xss_checks(self, xss_marker: str, expected_marker: Optional[str]) -> dict:
        """Perform all XSS validation checks."""
        xss_in_console = await self._check_xss_in_console(xss_marker)
        xss_in_dom_raw = await self.execute_js(f'document.body.innerHTML.includes("{xss_marker}")')
        xss_in_dom_executed = await self._check_xss_in_dom_executed()

        marker_found = False
        if expected_marker:
            marker_found = await self._check_expected_marker(expected_marker)

        xss_confirmed = self._determine_xss_confirmed(
            xss_in_console, xss_in_dom_raw, xss_in_dom_executed, marker_found, expected_marker
        )

        if xss_in_dom_raw and not xss_confirmed:
            logger.info("NOTE: Marker found in DOM but no JS execution - may be HTML injection, not XSS")

        return {
            "xss_in_console": xss_in_console,
            "xss_in_dom_raw": xss_in_dom_raw,
            "xss_in_dom_executed": xss_in_dom_executed,
            "marker_found": marker_found,
            "xss_confirmed": xss_confirmed
        }

    async def _capture_validation_screenshot(self, screenshot_dir: Optional[str]) -> Optional[str]:
        """Capture screenshot if directory specified."""
        if not screenshot_dir:
            return None

        import time
        screenshot_path = f"{screenshot_dir}/cdp_xss_{int(time.time())}.png"
        try:
            await self.screenshot(screenshot_path)
            return screenshot_path
        except Exception as e:
            logger.warning(f"Screenshot failed: {e}")
            return None

    def _log_validation_results(self, check_results: dict):
        """Log XSS validation results."""
        logger.info(
            f"CDP XSS Result: alert={self._alert_detected}, "
            f"console={check_results['xss_in_console']}, "
            f"dom_raw={check_results['xss_in_dom_raw']}, "
            f"dom_executed={check_results['xss_in_dom_executed']}, "
            f"marker_found={check_results['marker_found']}"
        )

    def _build_validation_result(self, check_results: dict, screenshot_path: Optional[str], url: str) -> CDPResult:
        """Build CDPResult from validation checks."""
        return CDPResult(
            success=check_results["xss_confirmed"],
            data={
                "alert_detected": self._alert_detected,
                "xss_in_console": check_results["xss_in_console"],
                "xss_in_dom_raw": check_results["xss_in_dom_raw"],
                "xss_in_dom_executed": check_results["xss_in_dom_executed"],
                "marker_found": check_results["marker_found"],
                "url": url
            },
            console_logs=self._console_logs.copy(),
            screenshot_path=screenshot_path,
            marker_found=check_results.get("marker_found", False),
            alert_message=self._last_alert_message
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
            logger.error(f"Payload injection failed: {e}", exc_info=True)
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
