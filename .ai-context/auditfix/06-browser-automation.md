# Browser Automation - Audit Fix Tasks

## Feature Overview
Browser automation for visual validation and JavaScript testing using:
- **Playwright**: Cross-browser automation (Chromium, Firefox, WebKit)
- **Chrome DevTools Protocol (CDP)**: Direct browser control
- **Screenshot Capture**: Visual proof of exploitation
- **Console Event Monitoring**: JavaScript execution detection

---

## 🔴 CRITICAL Tasks (2)

### TASK-90: Fix Unsafe Subprocess Shell Execution
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/visual/browser.py:49-58,193`
**Issue**: Uses `create_subprocess_shell()` and `os.system()` for Chrome launch
**Impact**: Shell injection risk, arbitrary command execution

**Current Code**:
```python
# Lines 49-58
command = f"google-chrome --remote-debugging-port={port} --headless"
process = await asyncio.create_subprocess_shell(
    command,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE
)

# Line 193
os.system(f"pkill -f 'chrome.*--remote-debugging-port={port}'")
```

**Proposed Fix**:
```python
# Use create_subprocess_exec with argument array
async def launch_chrome(self, port, headless=True):
    # Build argument array (no shell interpretation)
    args = [
        "google-chrome",
        f"--remote-debugging-port={port}",
        "--no-sandbox",  # Required for Docker
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-setuid-sandbox"
    ]

    if headless:
        args.append("--headless=new")

    # Use exec instead of shell
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    return process

# Replace os.system with subprocess
async def kill_chrome(self, port):
    try:
        # Use subprocess.run with argument array
        subprocess.run(
            ["pkill", "-f", f"chrome.*--remote-debugging-port={port}"],
            timeout=5,
            check=False
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"Chrome kill timeout for port {port}")
```

**Verification**:
1. Test with malicious port: `port = "9222; rm -rf /tmp/test"`
2. Verify command is not executed
3. Run security scanner (Bandit)

**Priority**: P0 - Fix immediately (RCE risk)

**Related Fix**: ✅ Also fixed RCE in `bugtrace/core/cdp_client.py:134-136` (2026-01-26)
- Changed `subprocess.run(f"fuser -k {self.port}/tcp", shell=True)` to list args
- Changed `subprocess.run("pkill -f 'chrome...'", shell=True)` to list args
- Added port validation with `str(int(self.port))`

---

### TASK-91: Add Browser Process Cleanup
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/visual/browser.py`
**Issue**: Browser processes not cleaned up on error/crash
**Impact**: Zombie processes, port exhaustion

**Proposed Fix**:
```python
class BrowserManager:
    def __init__(self):
        self.active_browsers = {}
        self.active_pages = {}
        atexit.register(self.cleanup_all)

    async def cleanup_all(self):
        """Clean up all browser resources."""
        logger.info("Cleaning up all browser resources...")

        # Close all pages
        for page_id, page in list(self.active_pages.items()):
            try:
                await page.close()
            except Exception as e:
                logger.error(f"Failed to close page {page_id}: {e}")

        # Close all browsers
        for browser_id, browser in list(self.active_browsers.items()):
            try:
                await browser.close()
            except Exception as e:
                logger.error(f"Failed to close browser {browser_id}: {e}")

        # Kill any remaining Chrome processes
        await self._kill_orphaned_chrome_processes()

    async def _kill_orphaned_chrome_processes(self):
        """Kill any Chrome processes that weren't properly closed."""
        try:
            # Find Chrome processes started by this app
            result = subprocess.run(
                ["pgrep", "-f", "chrome.*--remote-debugging-port"],
                capture_output=True,
                text=True
            )

            if result.stdout:
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                        logger.info(f"Killed orphaned Chrome process: {pid}")
                    except ProcessLookupError:
                        pass
        except Exception as e:
            logger.error(f"Failed to kill orphaned processes: {e}")

    async def get_page(self):
        """Get a page with guaranteed cleanup."""
        page = await self._create_page()
        page_id = id(page)
        self.active_pages[page_id] = page

        # Wrap with cleanup handler
        original_close = page.close

        async def close_with_cleanup():
            try:
                await original_close()
            finally:
                self.active_pages.pop(page_id, None)

        page.close = close_with_cleanup
        return page
```

**Priority**: P0 - Fix immediately

---

## 🟠 HIGH Priority Tasks (4)

### TASK-92: Add Browser Launch Timeout
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/visual/browser.py`
**Issue**: Browser launch can hang indefinitely

**Proposed Fix**:
```python
async def launch_browser_with_timeout(self, timeout=30):
    """Launch browser with timeout."""
    try:
        async with asyncio.timeout(timeout):
            browser = await playwright.chromium.launch(
                headless=settings.HEADLESS_BROWSER,
                args=[
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-dev-shm-usage'
                ]
            )
            return browser
    except asyncio.TimeoutError:
        logger.error(f"Browser launch timeout after {timeout}s")
        raise BrowserLaunchError("Browser launch timeout")
```

**Priority**: P1 - Fix within 1 week

---

### TASK-93: Add Page Navigation Timeout Handling
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/visual/browser.py`
**Issue**: Page navigation errors not handled gracefully

**Proposed Fix**:
```python
async def navigate_with_retry(self, page, url, max_retries=3):
    """Navigate to URL with retry logic."""
    for attempt in range(max_retries):
        try:
            await page.goto(
                url,
                wait_until='networkidle',
                timeout=settings.TIMEOUT_MS
            )
            return True

        except playwright.async_api.TimeoutError:
            if attempt == max_retries - 1:
                logger.error(f"Navigation timeout after {max_retries} attempts")
                return False
            logger.warning(f"Navigation timeout, retry {attempt + 1}/{max_retries}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff

        except playwright.async_api.Error as e:
            if "net::ERR_CONNECTION_REFUSED" in str(e):
                logger.error(f"Connection refused: {url}")
                return False
            raise
```

**Priority**: P1 - Fix within 1 week

---

### TASK-94: Add Browser Context Isolation
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/visual/browser.py`
**Issue**: All pages share same browser context (cookies, storage)

**Proposed Fix**:
```python
async def create_isolated_context(self):
    """Create isolated browser context for each test."""
    context = await self.browser.new_context(
        viewport={'width': 1280, 'height': 720},
        user_agent=settings.USER_AGENT,
        ignore_https_errors=False,  # Enforce HTTPS validation
        java_script_enabled=True
    )

    # Clear storage
    await context.clear_cookies()
    await context.clear_permissions()

    return context

async def test_with_isolation(self, url, payload):
    """Test XSS with isolated context."""
    context = await self.create_isolated_context()
    try:
        page = await context.new_page()
        # ... test
    finally:
        await context.close()  # Clean up context
```

**Priority**: P1 - Fix within 1 week

---

### TASK-95: Add Screenshot Error Handling
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/visual/browser.py`
**Issue**: Screenshot failures cause test to fail entirely

**Proposed Fix**:
```python
async def capture_screenshot_safe(self, page, path):
    """Capture screenshot with error handling."""
    try:
        await page.screenshot(path=path, full_page=True)
        return path

    except playwright.async_api.TimeoutError:
        logger.warning("Screenshot timeout, trying viewport only")
        try:
            await page.screenshot(path=path, full_page=False)
            return path
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return None

    except Exception as e:
        logger.error(f"Screenshot error: {e}")
        return None
```

**Priority**: P1 - Fix within 2 weeks

---

## 🟡 MEDIUM Priority Tasks (5)

### TASK-96: Add Browser Resource Limits
**Severity**: 🟡 MEDIUM
**Issue**: No limits on memory/CPU usage

**Proposed Fix**:
```python
# Launch with resource limits
browser = await playwright.chromium.launch(
    args=[
        '--no-sandbox',
        '--disable-gpu',
        '--max-old-space-size=512',  # 512MB heap
        '--js-flags="--max-old-space-size=512"'
    ]
)
```

**Priority**: P2 - Fix before release

---

### TASK-97: Add CDP Event Listener Cleanup
**Severity**: 🟡 MEDIUM
**Issue**: CDP event listeners not removed after use

**Priority**: P2 - Fix before release

---

### TASK-98: Add Browser Logging
**Severity**: 🟡 MEDIUM
**Issue**: Browser console logs not captured

**Proposed Fix**:
```python
page.on("console", lambda msg: logger.debug(f"Browser: {msg.text}"))
page.on("pageerror", lambda exc: logger.error(f"Page error: {exc}"))
```

**Priority**: P2 - Fix before release

---

### TASK-99: Add Browser Cache Management
**Severity**: 🟡 MEDIUM
**Issue**: Cache can interfere with testing

**Priority**: P2 - Fix before release

---

### TASK-100: Add Multi-Browser Support
**Severity**: 🟡 MEDIUM
**Issue**: Only Chromium supported

**Priority**: P3 - Next release

---

## 🟢 LOW Priority Tasks (3)

### TASK-101: Add Browser Profile Management
**Severity**: 🟢 LOW
**Issue**: Can't use custom browser profiles

**Priority**: P4 - Technical debt

---

### TASK-102: Add Browser Extension Support
**Severity**: 🟢 LOW
**Issue**: Can't load browser extensions for testing

**Priority**: P4 - Technical debt

---

### TASK-103: Add Unit Tests for Browser Manager
**Severity**: 🟢 LOW
**Issue**: Limited test coverage

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 14
- 🔴 Critical: 2 (Shell injection, resource leak)
- 🟠 High: 4 (Timeouts, isolation, error handling)
- 🟡 Medium: 5 (Resource limits, logging)
- 🟢 Low: 3 (Technical debt)

**Estimated Effort**: 1-2 weeks for P0-P1 tasks

**Security Note**: TASK-90 (Shell injection) is an RCE vulnerability and must be fixed immediately.
