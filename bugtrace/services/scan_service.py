"""
Scan Service - Scan lifecycle management with asyncio-based concurrency.

Wraps TeamOrchestrator with concurrent scan management, enforces scan limits,
and provides status/stop/list operations. This is the core service that CLI,
API, and MCP will all invoke.

Solves:
- SVC-01: Shared ScanService for all interfaces
- INF-02: SQLite pooling via existing DatabaseManager
- INF-03: Concurrent scan limit enforcement

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import asyncio
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse

from bugtrace.services.scan_context import ScanContext, ScanOptions
from bugtrace.services.event_bus import service_event_bus
from bugtrace.core.database import get_db_manager
from bugtrace.schemas.db_models import ScanStatus, FindingStatus
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("services.scan_service")


class ScanService:
    """
    Manages scan lifecycle with asyncio-based concurrent execution.

    Key responsibilities:
    - Create and start scans with create_scan()
    - Enforce concurrent scan limit (default 1)
    - Track active scans in memory
    - Provide status queries for active and completed scans
    - Stop running scans gracefully
    - List paginated scan history

    CRITICAL: Uses asyncio.create_task (NOT threading.Thread) to avoid event loop conflicts.
    """

    EVENT_HISTORY_CLEANUP_GRACE_SECONDS = 3600.0
    REPEATER_REFRESH_MARKER = ".repeater-refresh-pending.json"

    def __init__(self, max_concurrent: int = 1):
        """
        Initialize ScanService.

        Args:
            max_concurrent: Maximum number of concurrent scans (default 1)
        """
        self.db = get_db_manager()
        self.event_bus = service_event_bus
        self.max_concurrent = max_concurrent

        # Active scans: {scan_id: ScanContext}
        self._active_scans: Dict[int, ScanContext] = {}

        # Concurrency control primitives
        self._lock = asyncio.Lock()  # Protects _active_scans dict
        self._semaphore = asyncio.Semaphore(max_concurrent)  # Limits concurrent executions
        self._repeater_persistence_lock = asyncio.Lock()
        self._repeater_report_refresh_tasks: Dict[str, asyncio.Task] = {}

        logger.info(f"ScanService initialized (max_concurrent={max_concurrent})")

    async def create_scan(self, options: ScanOptions, origin: str = "unknown") -> int:
        """
        Create and start a new scan.

        Args:
            options: Scan configuration (target_url, scan_type, etc.)
            origin: Where the scan was launched from ('cli' or 'web')

        Returns:
            scan_id: Database ID for tracking this scan

        Process:
            1. Check if at concurrent limit (raise error if so)
            2. Create database scan record
            3. Create ScanContext with frozen settings
            4. Launch background task via asyncio.create_task
            5. Emit scan.created event

        Raises:
            RuntimeError: If max concurrent scans already running
        """
        async with self._lock:
            self._check_concurrent_limit()

            try:
                scan_id = self._create_scan_record(options, origin)
            except Exception as e:
                logger.error(f"Failed to create scan record: {e}", exc_info=True)
                raise RuntimeError(f"Failed to create scan in database: {e}")

            try:
                ctx = self._build_scan_context(scan_id, options)
                self._active_scans[scan_id] = ctx

                await self._emit_scan_created_event(scan_id, options)
                ctx._task = asyncio.create_task(self._run_scan(ctx))
                logger.info(f"Scan {scan_id} task started (active: {len(self._active_scans)})")
            except Exception as e:
                logger.error(f"Scan {scan_id} created in DB but failed to start: {e}", exc_info=True)
                self._active_scans.pop(scan_id, None)
                self.db.update_scan_progress(scan_id, 0, ScanStatus.FAILED)
                raise

            return scan_id

    def _check_concurrent_limit(self):
        """Check if at concurrent scan limit."""
        if len(self._active_scans) >= self.max_concurrent:
            raise RuntimeError(
                f"Maximum concurrent scans ({self.max_concurrent}) already running. "
                f"Wait for a scan to complete or stop one."
            )

    def _create_scan_record(self, options: ScanOptions, origin: str) -> int:
        """Create database scan record with config."""
        from bugtrace.core.config import settings as _settings
        scan_id = self.db.create_new_scan(
            options.target_url,
            origin=origin,
            scan_type=options.scan_type,
            max_depth=options.max_depth,
            max_urls=options.max_urls,
            provider=getattr(_settings, 'PROVIDER', None),
        )
        logger.info(f"Created scan {scan_id} for target: {options.target_url} (origin={origin})")
        return scan_id

    def _build_scan_context(self, scan_id: int, options: ScanOptions) -> ScanContext:
        """Build scan context for in-memory lifecycle state."""
        return ScanContext(scan_id, options, self.event_bus)

    async def _emit_scan_created_event(self, scan_id: int, options: ScanOptions):
        """Emit scan.created event."""
        await self.event_bus.emit("scan.created", {
            "scan_id": scan_id,
            "target": options.target_url,
            "scan_type": options.scan_type,
        })

    async def _run_scan(self, ctx: ScanContext):
        """
        Background task to execute a scan.

        Args:
            ctx: ScanContext for this scan

        Process:
            1. Acquire semaphore (enforces concurrent limit)
            2. Update status to RUNNING
            3. Compute output_dir from settings.REPORT_DIR
            4. Create TeamOrchestrator with ctx settings
            5. Monkey-patch orchestrator._stop_event to ctx.stop_event
            6. Execute orchestrator.start()
            7. Handle completion/errors
            8. Cleanup: release semaphore, remove from active_scans

        CRITICAL: Uses asyncio.Semaphore to enforce max_concurrent limit.
        CRITICAL: Does NOT mutate global settings singleton.
        """
        scan_id = ctx.scan_id

        try:
            async with self._semaphore:
                await self._execute_scan(ctx)
        except asyncio.CancelledError:
            await self._handle_scan_cancellation(ctx)
            raise
        except Exception as e:
            await self._handle_scan_failure(ctx, e)
        finally:
            await self._cleanup_scan(scan_id)

    async def _execute_scan(self, ctx: ScanContext):
        """Execute scan with orchestrator."""
        scan_id = ctx.scan_id
        logger.info(f"Scan {scan_id} acquired semaphore, starting execution")

        # Update status
        ctx.status = "running"
        ctx.phase = "INIT"
        self.db.update_scan_status(scan_id, ScanStatus.RUNNING)

        await self.event_bus.emit("scan.started", {
            "scan_id": scan_id,
            "target": ctx.options.target_url,
        })

        # Resumed scans continue in the parent's directory so specialist state,
        # sidecars, and the canonical report remain one coherent artifact set.
        output_dir = getattr(ctx, "_output_dir", None)
        if output_dir is None:
            output_dir = self._compute_output_dir(ctx.options.target_url)

        # Create and configure orchestrator
        orchestrator = self._create_orchestrator(ctx, output_dir)

        # Setup auth tokens (Level 1: pass-through, Level 2: auto-login)
        # Store the orchestrator's scan_context key on ctx so cleanup uses the same key
        ctx._auth_token_key = orchestrator.scan_context
        await self._setup_auth_tokens(ctx.options, orchestrator.scan_context)

        # Execute scan
        logger.info(f"Scan {scan_id} starting TeamOrchestrator")
        await orchestrator.start()

        # Mark as completed
        await self._mark_scan_completed(ctx)

    def _compute_output_dir(self, target_url: str) -> Path:
        """Compute output directory for scan reports."""
        domain = urlparse(target_url).netloc.replace(":", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _create_orchestrator(self, ctx: ScanContext, output_dir: Path):
        """Create and configure TeamOrchestrator."""
        from bugtrace.core.team import TeamOrchestrator

        orchestrator = TeamOrchestrator(
            target=ctx.options.target_url,
            resume=ctx.options.resume,
            max_depth=ctx.options.max_depth,
            max_urls=ctx.options.max_urls,
            use_vertical_agents=ctx.options.use_vertical,
            output_dir=output_dir,
            scan_id=ctx.scan_id,  # Pass existing scan_id to avoid duplicate creation
            scan_depth=ctx.options.scan_depth or settings.SCAN_DEPTH,
            url_list=ctx.options.url_list,  # Pre-defined URL list from file upload or Swagger
            auth=ctx.options.auth,  # Pass auth config for browser-based TOTP login
        )

        # CRITICAL: Monkey-patch stop_event for graceful shutdown
        orchestrator._stop_event = ctx.stop_event
        # Pause support: orchestrator checks this at phase boundaries
        orchestrator._scan_context = ctx

        return orchestrator

    async def _setup_auth_tokens(self, options: ScanOptions, scan_ctx_id: str):
        """
        Setup authentication tokens before scan starts.

        Level 1: auth_token provided directly → store as-is.
        Level 2: auth.login_url + auth.credentials → POST to login, extract JWT.
        Level 3: auth.login_flow + totp_secret → Browser-based login with TOTP support.
        """
        from bugtrace.services.scan_context import store_auth_token

        # Level 1: Direct token pass-through
        if options.auth_token:
            store_auth_token(scan_ctx_id, "api_provided", options.auth_token)
            logger.info(f"Auth Level 1: Stored provided Bearer token for scan")
            return

        # Level 2/3: Auto-login with credentials
        if options.auth and isinstance(options.auth, dict):
            login_url = options.auth.get("login_url", "")
            credentials = options.auth.get("credentials", {})
            login_flow = options.auth.get("login_flow", [])

            if not login_url or not credentials:
                logger.warning("Auth Level 2/3: Missing login_url or credentials, skipping")
                return

            # Resolve relative login_url against target
            if login_url.startswith("/"):
                login_url = options.target_url.rstrip("/") + login_url

            # Check if we need browser-based login (Level 3)
            totp_secret = credentials.get("totp_secret", "")
            has_login_flow = bool(login_flow)

            if has_login_flow:
                # Level 3: Browser-based login with custom multi-step flow
                # Only use browser when a custom login_flow is explicitly defined
                logger.info(f"Auth Level 3: Will be handled by TeamOrchestrator (login_flow steps: {len(login_flow)})")
                return
            else:
                # Level 2: Simple POST login (supports TOTP via code generation)
                # Works for both plain credentials and TOTP-enabled APIs
                logger.info(f"Auth Level 2: Attempting login at {login_url} (TOTP: {bool(totp_secret)})")
                await self._simple_post_login(scan_ctx_id, login_url, credentials)

    async def _simple_post_login(self, scan_ctx_id: str, login_url: str, credentials: dict):
        """
        Level 2: POST request login with optional TOTP support.

        Builds the payload by:
        1. Copying username/password from credentials
        2. If totp_secret present: generates current TOTP code and tries common
           field names (totp_code, totp, code, otp, mfa_code) — sends all of them
           so the API can pick whichever it expects.
        """
        from bugtrace.services.scan_context import store_auth_token

        try:
            import httpx

            # Build login payload — exclude totp_secret (never sent as-is)
            payload = {
                k: v for k, v in credentials.items()
                if k not in ("totp_secret",)
            }

            # Generate TOTP code if secret provided and inject with all common field names
            totp_secret = credentials.get("totp_secret", "")
            if totp_secret:
                from bugtrace.utils.totp import get_totp_code
                totp_code = get_totp_code(totp_secret)
                if not totp_code:
                    logger.error("Auth Level 2: Failed to generate TOTP code")
                    return
                # Inject with multiple common field names — server will use whichever matches
                for field_name in ("totp_code", "totp", "code", "otp", "mfa_code", "verification_code"):
                    payload[field_name] = totp_code
                logger.info(f"Auth Level 2: Generated TOTP code and added to payload")

            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.post(login_url, json=payload)

                if resp.status_code not in (200, 201):
                    logger.warning(
                        f"Auth Level 2: Login failed (HTTP {resp.status_code}): {resp.text[:200]}"
                    )
                    return

                # Extract JWT from response
                token = self._extract_jwt_from_response(resp)
                if token:
                    store_auth_token(scan_ctx_id, "auto_login", token)
                    logger.info("Auth Level 2: JWT extracted and stored from login response")
                else:
                    # Fallback: store session cookies if no JWT
                    if resp.cookies:
                        cookie_str = "; ".join([f"{k}={v}" for k, v in resp.cookies.items()])
                        store_auth_token(scan_ctx_id, "auto_login_cookies", cookie_str)
                        logger.info(f"Auth Level 2: No JWT found, stored {len(resp.cookies)} cookies")
                    else:
                        logger.warning("Auth Level 2: Login succeeded but no JWT or cookies found in response")

        except Exception as e:
            logger.error(f"Auth Level 2: Login request failed: {e}")

    async def _browser_login_with_totp(
        self,
        scan_ctx_id: str,
        login_url: str,
        credentials: dict,
        login_flow: list,
        auth_config: dict
    ):
        """
        Level 3: Browser-based login with TOTP support.

        Supports custom login flows defined in YAML config with variable substitution:
        - $username, $email → credentials.username or credentials.email
        - $password → credentials.password
        - $totp → Generated TOTP code from credentials.totp_secret
        """
        from bugtrace.services.scan_context import store_auth_token
        from bugtrace.tools.visual.browser import browser_manager

        try:
            await browser_manager.start()

            async with browser_manager.get_page() as page:
                # Navigate to login page
                logger.info(f"Auth Level 3: Navigating to {login_url}")
                await page.goto(login_url, wait_until="networkidle", timeout=30000)

                if login_flow:
                    # Execute custom login flow
                    success = await self._execute_login_flow(page, credentials, login_flow)
                else:
                    # Auto-detect login form
                    success = await self._auto_detect_login(page, credentials)

                if not success:
                    logger.warning("Auth Level 3: Login flow did not complete successfully")
                    return

                # Check success condition if provided
                success_condition = auth_config.get("success_condition", {})
                if success_condition:
                    if not await self._check_login_success(page, success_condition):
                        logger.warning("Auth Level 3: Success condition not met")
                        return

                # Extract cookies and tokens
                cookies = await page.context.cookies()
                if cookies:
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                    store_auth_token(scan_ctx_id, "browser_login", cookies=cookie_str)
                    logger.info(f"Auth Level 3: Stored {len(cookies)} cookies from browser login")

                # Try to extract JWT from localStorage/sessionStorage
                token = await page.evaluate("""
                    () => {
                        const keys = ['token', 'access_token', 'jwt', 'authToken', 'auth_token'];
                        for (const key of keys) {
                            let val = localStorage.getItem(key) || sessionStorage.getItem(key);
                            if (val && val.startsWith('eyJ')) return val;
                        }
                        return null;
                    }
                """)
                if token:
                    store_auth_token(scan_ctx_id, "browser_jwt", token)
                    logger.info("Auth Level 3: JWT extracted from browser storage")

        except Exception as e:
            logger.error(f"Auth Level 3: Browser login failed: {e}", exc_info=True)

    async def _execute_login_flow(self, page, credentials: dict, login_flow: list) -> bool:
        """Execute a custom login flow with variable substitution."""
        from bugtrace.utils.totp import get_totp_code

        # Prepare variable substitutions
        username = credentials.get("username", credentials.get("email", ""))
        password = credentials.get("password", "")
        totp_secret = credentials.get("totp_secret", "")

        total_steps = len(login_flow)
        for i, step in enumerate(login_flow, 1):
            try:
                # Substitute variables
                step_resolved = step
                step_resolved = step_resolved.replace("$username", username)
                step_resolved = step_resolved.replace("$email", username)
                step_resolved = step_resolved.replace("$password", password)

                # Generate TOTP if needed
                if "$totp" in step_resolved:
                    if not totp_secret:
                        logger.error("Login flow requires $totp but no totp_secret provided")
                        return False
                    totp_code = get_totp_code(totp_secret)
                    if not totp_code:
                        logger.error("Failed to generate TOTP code")
                        return False
                    step_resolved = step_resolved.replace("$totp", totp_code)
                    logger.info(f"Auth Level 3: Generated TOTP code: {totp_code}")

                # Log step (mask password)
                log_step = step_resolved.replace(password, "***") if password else step_resolved
                logger.info(f"Auth Level 3: Step {i}/{total_steps}: {log_step[:60]}")

                # Parse and execute step
                await self._execute_login_step(page, step_resolved)
                await page.wait_for_timeout(500)  # Small delay between steps

            except Exception as e:
                logger.error(f"Auth Level 3: Login step failed: {step} -> {e}")
                return False

        return True

    async def _execute_login_step(self, page, step: str):
        """Execute a single login step instruction with Microsoft SSO support."""
        step_lower = step.lower()

        # Type into field: "Type <value> into the <field> field"
        if step_lower.startswith("type "):
            import re
            match = re.match(r"type ['\"]?(.+?)['\"]? into (?:the )?(.+?)(?:\s+field)?$", step, re.IGNORECASE)
            if match:
                value, field_desc = match.groups()
                # Find input by various selectors (including Microsoft SSO)
                selectors = [
                    f"input[name='{field_desc}']",  # Exact match (loginfmt, passwd)
                    f"input[name*='{field_desc}' i]",
                    f"input[id*='{field_desc}' i]",
                    f"input[placeholder*='{field_desc}' i]",
                    f"input[type='{field_desc}']",
                    f"[aria-label*='{field_desc}' i]",
                ]
                for selector in selectors:
                    try:
                        el = await page.query_selector(selector)
                        if el:
                            await el.fill(value)
                            logger.debug(f"Typed into {selector}")
                            return
                    except Exception:
                        continue
                # Fallback: try label text
                label = await page.query_selector(f"label:has-text('{field_desc}')")
                if label:
                    for_id = await label.get_attribute("for")
                    if for_id:
                        await page.fill(f"#{for_id}", value)
                        return
                raise Exception(f"Could not find input field: {field_desc}")

        # Click button: "Click the '<text>' button" or "Click '<text>'"
        elif step_lower.startswith("click "):
            import re
            match = re.search(r"['\"](.+?)['\"]", step)
            if match:
                button_text = match.group(1)

                # Microsoft SSO specific button IDs
                ms_buttons = {
                    "next": "input#idSIButton9",
                    "sign in": "input#idSIButton9",
                    "signin": "input#idSIButton9",
                    "verify": "input#idSubmit_SAOTCC_Continue",
                    "no": "input#idBtn_Back",
                    "yes": "input#idSIButton9",
                }

                # Try Microsoft-specific selector first
                ms_sel = ms_buttons.get(button_text.lower())
                if ms_sel:
                    try:
                        el = await page.query_selector(ms_sel)
                        if el:
                            await el.click()
                            try:
                                await page.wait_for_load_state("networkidle", timeout=10000)
                            except Exception:
                                pass
                            logger.debug(f"Clicked MS button: {ms_sel}")
                            return
                    except Exception:
                        pass

                # Try various generic selectors
                selectors = [
                    f"button:has-text('{button_text}')",
                    f"input[type='submit'][value*='{button_text}' i]",
                    f"input[type='submit']",  # Fallback to any submit
                    f"a:has-text('{button_text}')",
                    f"[role='button']:has-text('{button_text}')",
                ]
                for selector in selectors:
                    try:
                        el = await page.query_selector(selector)
                        if el:
                            await el.click()
                            try:
                                await page.wait_for_load_state("networkidle", timeout=10000)
                            except Exception:
                                pass
                            logger.debug(f"Clicked {selector}")
                            return
                    except Exception:
                        continue
                raise Exception(f"Could not find button: {button_text}")

        # Enter/fill: "Enter <value> in the <field> field"
        elif step_lower.startswith("enter "):
            # Treat same as "type"
            modified_step = "Type " + step[6:]
            await self._execute_login_step(page, modified_step)

        # Wait: "Wait for <seconds> seconds"
        elif "wait" in step_lower:
            import re
            match = re.search(r"(\d+)", step)
            if match:
                seconds = int(match.group(1))
                await page.wait_for_timeout(seconds * 1000)

        else:
            logger.warning(f"Auth Level 3: Unknown login step: {step}")

    async def _auto_detect_login(self, page, credentials: dict) -> bool:
        """Auto-detect and fill login form without explicit flow."""
        from bugtrace.utils.totp import get_totp_code

        username = credentials.get("username", credentials.get("email", ""))
        password = credentials.get("password", "")
        totp_secret = credentials.get("totp_secret", "")

        try:
            # Find and fill username/email field
            username_selectors = [
                "input[type='email']", "input[name*='email' i]", "input[name*='user' i]",
                "input[id*='email' i]", "input[id*='user' i]", "input[autocomplete='username']"
            ]
            for sel in username_selectors:
                el = await page.query_selector(sel)
                if el:
                    await el.fill(username)
                    break

            # Find and fill password field
            password_el = await page.query_selector("input[type='password']")
            if password_el:
                await password_el.fill(password)

            # Submit form
            submit_selectors = [
                "button[type='submit']", "input[type='submit']",
                "button:has-text('Sign in')", "button:has-text('Login')",
                "button:has-text('Log in')"
            ]
            for sel in submit_selectors:
                el = await page.query_selector(sel)
                if el:
                    await el.click()
                    break

            await page.wait_for_load_state("networkidle", timeout=15000)

            # Check if TOTP is required (look for OTP input)
            if totp_secret:
                totp_selectors = [
                    "input[name*='otp' i]", "input[name*='totp' i]", "input[name*='code' i]",
                    "input[name*='2fa' i]", "input[autocomplete='one-time-code']",
                    "input[maxlength='6']"
                ]
                for sel in totp_selectors:
                    el = await page.query_selector(sel)
                    if el:
                        totp_code = get_totp_code(totp_secret)
                        if totp_code:
                            await el.fill(totp_code)
                            logger.info("Auth Level 3: Entered TOTP code")
                            # Submit TOTP
                            for submit_sel in submit_selectors:
                                submit_el = await page.query_selector(submit_sel)
                                if submit_el:
                                    await submit_el.click()
                                    break
                            await page.wait_for_load_state("networkidle", timeout=10000)
                        break

            return True

        except Exception as e:
            logger.error(f"Auth Level 3: Auto-detect login failed: {e}")
            return False

    async def _check_login_success(self, page, condition: dict) -> bool:
        """Check if login success condition is met."""
        condition_type = condition.get("type", "")
        value = condition.get("value", "")

        try:
            current_url = page.url

            if condition_type == "url_contains":
                return value in current_url
            elif condition_type == "url_equals_exactly":
                return current_url == value
            elif condition_type == "element_present":
                el = await page.query_selector(value)
                return el is not None
            elif condition_type == "text_contains":
                content = await page.content()
                return value in content
            else:
                logger.warning(f"Unknown success condition type: {condition_type}")
                return True  # Assume success if unknown

        except Exception as e:
            logger.error(f"Auth Level 3: Success condition check failed: {e}")
            return False

    @staticmethod
    def _extract_jwt_from_response(resp) -> Optional[str]:
        """Extract JWT token from an HTTP login response."""
        import re
        jwt_pattern = re.compile(
            r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)'
        )

        # Try JSON body first
        try:
            body = resp.json()
            if isinstance(body, dict):
                for key in ("access_token", "token", "jwt", "auth_token", "id_token",
                            "accessToken", "authToken", "idToken"):
                    val = body.get(key, "")
                    if val and jwt_pattern.match(val):
                        return val
                # Check nested: body.data.token, body.user.token, etc.
                for outer_key in ("data", "user", "result", "response"):
                    nested = body.get(outer_key, {})
                    if isinstance(nested, dict):
                        for key in ("access_token", "token", "jwt"):
                            val = nested.get(key, "")
                            if val and jwt_pattern.match(val):
                                return val
        except Exception:
            pass

        # Fallback: regex scan on raw text
        text = resp.text
        match = jwt_pattern.search(text)
        if match:
            return match.group(1)

        # Check Authorization header in response (some APIs echo it)
        auth_header = resp.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if jwt_pattern.match(token):
                return token

        return None

    async def _mark_scan_completed(self, ctx: ScanContext):
        """Mark scan as completed with success event."""
        ctx.status = "completed"
        ctx.progress = 100
        self.db.update_scan_status(ctx.scan_id, ScanStatus.COMPLETED)

        # Clean up auth tokens stored during this scan
        from bugtrace.services.scan_context import clear_scan_tokens
        clear_scan_tokens(getattr(ctx, '_auth_token_key', str(ctx.scan_id)))

        await self.event_bus.emit("scan.completed", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
            "findings_count": ctx.findings_count,
        })
        self._schedule_event_history_cleanup(ctx.scan_id)

        logger.info(f"Scan {ctx.scan_id} completed successfully")

    async def _handle_scan_cancellation(self, ctx: ScanContext):
        """Handle scan cancellation."""
        ctx.status = "stopped"
        self.db.update_scan_status(ctx.scan_id, ScanStatus.STOPPED)

        from bugtrace.services.scan_context import clear_scan_tokens
        clear_scan_tokens(getattr(ctx, '_auth_token_key', str(ctx.scan_id)))

        await self.event_bus.emit("scan.stopped", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
        })
        self._schedule_event_history_cleanup(ctx.scan_id)

        logger.warning(f"Scan {ctx.scan_id} was cancelled")

    async def _handle_scan_failure(self, ctx: ScanContext, error: Exception):
        """Handle scan failure."""
        ctx.status = "failed"
        self.db.update_scan_status(ctx.scan_id, ScanStatus.FAILED)

        from bugtrace.services.scan_context import clear_scan_tokens
        clear_scan_tokens(getattr(ctx, '_auth_token_key', str(ctx.scan_id)))

        await self.event_bus.emit("scan.failed", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
            "error": str(error),
        })
        self._schedule_event_history_cleanup(ctx.scan_id)

        logger.error(f"Scan {ctx.scan_id} failed: {error}")

    def _schedule_event_history_cleanup(self, scan_id: int) -> None:
        """Schedule delayed event-bus cleanup after terminal scan states."""
        asyncio.create_task(self._clear_event_history_after_grace(scan_id))

    async def _clear_event_history_after_grace(self, scan_id: int) -> None:
        await asyncio.sleep(self.EVENT_HISTORY_CLEANUP_GRACE_SECONDS)
        self.event_bus.clear_scan(scan_id)

    async def _cleanup_scan(self, scan_id: int):
        """Remove scan from active scans."""
        async with self._lock:
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]
                logger.info(f"Scan {scan_id} removed from active scans (remaining: {len(self._active_scans)})")

    @staticmethod
    def _exposed_progress(status: ScanStatus, progress: int) -> int:
        """Repair legacy completed rows without changing partial-state semantics."""
        if status == ScanStatus.COMPLETED and progress == 0:
            return 100
        return progress

    async def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """
        Get status for a scan (active or completed).

        Args:
            scan_id: Scan ID to query

        Returns:
            Dictionary with scan_id, target, status, progress, findings_count, etc.

        Process:
            - If scan is active: return from ScanContext
            - If scan is completed: query database
        """
        # Check if scan is active
        async with self._lock:
            if scan_id in self._active_scans:
                ctx = self._active_scans[scan_id]
                return ctx.to_status_dict()

        # Query database for completed/stopped/failed scans
        with self.db.get_session() as session:
            from sqlmodel import select
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            statement = select(ScanTable).where(ScanTable.id == scan_id)
            scan = session.exec(statement).first()

            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            # Get target info
            target = session.get(TargetTable, scan.target_id)

            # Count findings
            from bugtrace.schemas.db_models import FindingTable
            findings_statement = select(FindingTable).where(FindingTable.scan_id == scan_id)
            findings = session.exec(findings_statement).all()
            report_counts = self._load_report_counts(scan_id)
            detections_count = report_counts.get("detections_count", len(findings))

            return {
                "scan_id": scan_id,
                "target": target.url if target else "unknown",
                "status": scan.status.value,
                "progress": self._exposed_progress(scan.status, scan.progress_percent),
                "uptime_seconds": None,  # No longer running
                "findings_count": detections_count,
                "active_agent": None,
                "phase": None,
                "origin": getattr(scan, "origin", None) or "unknown",
                "enrichment_status": getattr(scan, "enrichment_status", None),
                "scan_type": scan.scan_type,
                "max_depth": scan.max_depth,
                "max_urls": scan.max_urls,
                "provider": getattr(scan, "provider", None),
            }

    async def stop_scan(self, scan_id: int) -> Dict[str, Any]:
        """Stop a running or paused scan gracefully."""
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]
            ctx.request_stop()

            if ctx._task and not ctx._task.done():
                ctx._task.cancel()

            logger.info(f"Scan {scan_id} stop requested")

            return {
                "scan_id": scan_id,
                "status": "stopping",
                "message": "Stop signal sent to scan",
            }

    async def pause_scan(self, scan_id: int) -> Dict[str, Any]:
        """Pause a running scan. Pipeline blocks at next checkpoint."""
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]
            if ctx.status != "running":
                raise ValueError(f"Scan {scan_id} is not running (status: {ctx.status})")

            ctx.request_pause()
            self.db.update_scan_status(scan_id, ScanStatus.PAUSED)

            await self.event_bus.emit("scan.paused", {
                "scan_id": scan_id,
                "target": ctx.options.target_url,
            })

            logger.info(f"Scan {scan_id} paused")

            return {
                "scan_id": scan_id,
                "status": "paused",
                "message": "Scan paused",
            }

    async def _resume_paused_scan(self, scan_id: int) -> Dict[str, Any]:
        """Resume an in-memory paused scan."""
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not active")

            ctx = self._active_scans[scan_id]
            if ctx.status != "paused":
                raise ValueError(f"Scan {scan_id} is not paused (status: {ctx.status})")

            ctx.request_resume()
            self.db.update_scan_status(scan_id, ScanStatus.RUNNING)

            await self.event_bus.emit("scan.resumed", {
                "scan_id": scan_id,
                "target": ctx.options.target_url,
            })

            logger.info(f"Scan {scan_id} resumed")

            return {
                "scan_id": scan_id,
                "status": "running",
                "message": "Scan resumed",
            }

    async def resume_scan(self, scan_id: int) -> Dict[str, Any]:
        """Resume either a paused in-memory scan or recreate a recoverable failed scan."""
        async with self._lock:
            ctx = self._active_scans.get(scan_id)

        if ctx is not None:
            return await self._resume_paused_scan(scan_id)

        return await self._resume_recoverable_scan(scan_id)

    async def list_scans(
        self,
        page: int = 1,
        per_page: int = 20,
        status_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List scans with pagination.

        Args:
            page: Page number (1-indexed)
            per_page: Results per page
            status_filter: Optional status filter (RUNNING, COMPLETED, STOPPED, FAILED)

        Returns:
            Dictionary with scans, total, page, per_page
        """
        offset = (page - 1) * per_page

        with self.db.get_session() as session:
            from sqlmodel import select, func
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            statement = self._build_scans_query(status_filter)
            total = self._count_scans(session, status_filter, func)
            scans = session.exec(statement.offset(offset).limit(per_page)).all()
            results = self._format_scan_results(session, scans)

            return {
                "scans": results,
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    def _build_scans_query(self, status_filter: Optional[str]):
        """Build scans query with optional status filter and eager-loaded target."""
        from sqlmodel import select
        from sqlalchemy.orm import selectinload
        from bugtrace.schemas.db_models import ScanTable

        # Use selectinload to prevent N+1 queries when accessing scan.target and scan.findings
        statement = (
            select(ScanTable)
            .options(selectinload(ScanTable.target), selectinload(ScanTable.findings))
            .order_by(ScanTable.id.desc())
        )
        if status_filter:
            statement = statement.where(ScanTable.status == ScanStatus[status_filter.upper()])
        return statement

    def _count_scans(self, session, status_filter: Optional[str], func) -> int:
        """Count total scans matching filter."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanTable

        count_statement = select(func.count()).select_from(ScanTable)
        if status_filter:
            count_statement = count_statement.where(ScanTable.status == ScanStatus[status_filter.upper()])
        return session.exec(count_statement).one()

    def _format_scan_results(self, session, scans) -> List[Dict[str, Any]]:
        """Format scan results with report status.

        Note: Assumes scans were loaded with selectinload(ScanTable.target)
        to prevent N+1 queries.
        """
        report_base = settings.REPORT_DIR
        results = []
        for scan in scans:
            # Use already-loaded relationship (no extra query due to selectinload)
            target_url = scan.target.url if scan.target else None
            report_dir = getattr(scan, "report_dir", None)
            has_report = self._has_report_dir(report_base, scan.id, target_url, scan.timestamp, report_dir)
            recovery_available = self._has_recovery_artifacts(
                report_base,
                scan.id,
                target_url,
                scan.timestamp,
                report_dir,
            )
            report_counts = self._load_report_counts(scan.id) if has_report else {}
            detections_count = report_counts.get(
                "detections_count",
                len(scan.findings) if scan.findings else 0,
            )

            results.append({
                "scan_id": scan.id,
                "target": target_url or "unknown",
                "status": scan.status.value,
                "progress": self._exposed_progress(scan.status, scan.progress_percent),
                "timestamp": scan.timestamp.isoformat(),
                "origin": getattr(scan, "origin", None) or "unknown",
                "enrichment_status": getattr(scan, "enrichment_status", None),
                "has_report": has_report,
                "recovery_available": recovery_available,
                "scan_type": scan.scan_type,
                "max_depth": scan.max_depth,
                "max_urls": scan.max_urls,
                "provider": getattr(scan, "provider", None),
                # Compatibility alias: this is the deduplicated detection count,
                # never the number of physical persistence rows.
                "findings_count": detections_count,
                "detections_count": detections_count,
                "confirmed_count": report_counts.get("confirmed_count", 0),
                "manual_review_count": report_counts.get("manual_review_count", 0),
                "reportable_count": report_counts.get("reportable_count", 0),
            })
        return results

    async def persist_repeater_finding(
        self, scan_id: int, finding_data: dict
    ) -> dict:
        """Persist a confirmed AI Repeater finding to SQLite and canonical artifacts.

        Transactional compensation: under a lock, validates input, resolves paths,
        captures artifact byte snapshots, writes temp files + fsyncs, commits DB,
        replaces artifacts. On any exception: rolls back DB AND restores artifact bytes.
        Never returns 2xx with success=false.

        Returns dict with finding_id, created, success, message.
        """
        import json, tempfile, os

        target_url = finding_data.get("target_url") or finding_data.get("scan_target")
        vuln_url = finding_data.get("url", "")
        vuln_type = finding_data.get("type", "").upper()
        severity = finding_data.get("severity", "MEDIUM").upper()
        summary = finding_data.get("summary", "")
        parameter = finding_data.get("parameter", "")
        confidence = finding_data.get("confidence", 0.95)
        request_raw = finding_data.get("request", "")
        response_status = finding_data.get("response_status")
        response_excerpt = finding_data.get("response_excerpt", "")
        request_ok = finding_data.get("request_ok")

        if not vuln_type or not summary:
            raise ValueError("type and summary are required")
        if not request_raw or not request_raw.strip():
            raise ValueError("request is required and must not be empty")
        if response_status is None or response_status < 100 or response_status > 599:
            raise ValueError("response_status must be between 100 and 599")
        if request_ok is not True:
            raise ValueError("request_ok must be true")

        with self.db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED}:
                raise ValueError("Repeater findings cannot be persisted while the scan is active")
            target = session.get(TargetTable, scan.target_id)
            if not target:
                raise ValueError(f"Target for scan {scan_id} not found")
            actual_target_url = target.url
            self._assert_report_not_shared_with_active_scan(session, scan)

        if target_url and target_url != actual_target_url:
            raise ValueError("Scan target mismatch")

        self._validate_repeater_exchange(actual_target_url, vuln_url, request_raw)

        report_dir = self._find_or_create_report_dir_for_scan(
            scan_id, actual_target_url, finding_data,
        )
        async with self._repeater_persistence_lock:
            async with self._async_repeater_artifact_lock(report_dir):
                result = await self._persist_repeater_finding_locked(
                    scan_id, actual_target_url, vuln_url, vuln_type, severity,
                    parameter, summary, confidence, request_raw, response_status,
                    response_excerpt, finding_data, report_dir,
                )
        report_dir = result.pop("_report_dir")
        try:
            self._queue_repeater_report_refresh(
                scan_id, actual_target_url, report_dir, write_marker=False,
            )
            result["report_refresh"] = "queued"
        except Exception as exc:
            logger.error(f"Could not queue report refresh for scan {scan_id}: {exc}", exc_info=True)
            result["report_refresh"] = "failed"
        return result

    def _queue_repeater_report_refresh(
        self, scan_id: int, target_url: str, report_dir: Path,
        *, write_marker: bool = True,
    ) -> None:
        """Coalesce post-Repeater report regeneration per scan."""
        key = self._report_refresh_key(report_dir)
        current = self._repeater_report_refresh_tasks.get(key)
        if current and not current.done():
            marker = report_dir / self.REPEATER_REFRESH_MARKER
            try:
                import json
                marker_scan_id = int(json.loads(marker.read_text(encoding="utf-8"))["scan_id"])
            except Exception:
                marker_scan_id = scan_id
            if marker_scan_id != scan_id:
                raise RuntimeError(
                    f"Report refresh already belongs to scan {marker_scan_id}"
                )
            try:
                self.db.update_scan_enrichment_status(scan_id, "pending")
            except Exception as exc:
                logger.warning(f"Could not mark scan {scan_id} enrichment pending: {exc}")
            return
        if write_marker:
            self._write_repeater_refresh_marker(scan_id, target_url, report_dir)
        try:
            self.db.update_scan_enrichment_status(scan_id, "pending")
        except Exception as exc:
            logger.warning(f"Could not mark scan {scan_id} enrichment pending: {exc}")
        task = asyncio.create_task(
            self._run_queued_repeater_report_refresh(report_dir)
        )
        self._repeater_report_refresh_tasks[key] = task

    async def _run_queued_repeater_report_refresh(
        self, report_dir: Path,
    ) -> None:
        """Regenerate all products until the report directory's marker is consumed."""
        import json

        key = self._report_refresh_key(report_dir)
        marker = report_dir / self.REPEATER_REFRESH_MARKER
        refresh_succeeded = False
        try:
            while marker.is_file():
                # Brief debounce lets rapid Repeater saves share one regeneration.
                await asyncio.sleep(0.5)
                if not marker.is_file():
                    break
                async with self._async_repeater_artifact_lock(report_dir):
                    if not marker.is_file():
                        break
                    marker_token = marker.read_text(encoding="utf-8")
                    marker_data = json.loads(marker_token)
                    marker_scan_id = int(marker_data["scan_id"])
                    marker_target_url = str(marker_data["target_url"])
                    refresh_succeeded = await self._run_re_enrichment(
                        marker_scan_id, marker_target_url, report_dir,
                        acquire_artifact_lock=False,
                    )
                    if (
                        refresh_succeeded
                        and marker.is_file()
                        and marker.read_text(encoding="utf-8") == marker_token
                    ):
                        marker.unlink(missing_ok=True)
                        self._fsync_directory(report_dir)
                if not refresh_succeeded or not marker.is_file():
                    break
        finally:
            current = self._repeater_report_refresh_tasks.get(key)
            if current is asyncio.current_task():
                self._repeater_report_refresh_tasks.pop(key, None)

    def _write_repeater_refresh_marker(
        self, scan_id: int, target_url: str, report_dir: Path,
    ) -> None:
        """Persist refresh intent so an API restart cannot lose queued work."""
        import os
        import uuid

        marker = report_dir / self.REPEATER_REFRESH_MARKER
        temp = self._stage_artifact(marker, {
            "scan_id": scan_id,
            "target_url": target_url,
            "token": uuid.uuid4().hex,
        })
        os.replace(temp, marker)
        self._fsync_directory(report_dir)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        import os

        directory = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _report_refresh_key(report_dir: Path) -> str:
        return str(report_dir.resolve())

    def _start_recovered_repeater_refresh(
        self, scan_id: int, target_url: str, report_dir: Path,
    ) -> None:
        key = self._report_refresh_key(report_dir)
        current = self._repeater_report_refresh_tasks.get(key)
        if current and not current.done():
            return
        task = asyncio.create_task(
            self._run_queued_repeater_report_refresh(report_dir)
        )
        self._repeater_report_refresh_tasks[key] = task

    def recover_pending_repeater_refreshes(self) -> int:
        """Resume durable post-Repeater refresh markers after an API restart."""
        import json

        recovered = 0
        if not settings.REPORT_DIR.is_dir():
            return recovered
        for marker in settings.REPORT_DIR.glob(f"*/{self.REPEATER_REFRESH_MARKER}"):
            try:
                data = json.loads(marker.read_text(encoding="utf-8"))
                scan_id = int(data["scan_id"])
                target_url = str(data["target_url"])
                with self.db.get_session() as session:
                    from sqlmodel import select
                    from bugtrace.schemas.db_models import ScanTable, TargetTable

                    marked_scan = session.get(ScanTable, scan_id)
                    if not marked_scan:
                        raise ValueError(f"Marker references missing scan {scan_id}")
                    owner = marked_scan
                    if marked_scan.report_dir and (
                        Path(marked_scan.report_dir).resolve() == marker.parent.resolve()
                    ):
                        owner = session.exec(
                            select(ScanTable).where(
                                ScanTable.report_dir == marked_scan.report_dir,
                            ).order_by(ScanTable.id.desc())
                        ).first() or marked_scan
                    if owner.id != scan_id:
                        target = session.get(TargetTable, owner.target_id)
                        scan_id = owner.id
                        target_url = target.url if target else target_url
                        self._write_repeater_refresh_marker(
                            scan_id, target_url, marker.parent,
                        )
                        logger.info(
                            f"Migrated stale report refresh marker to canonical scan {scan_id}"
                        )
                try:
                    self.db.update_scan_enrichment_status(scan_id, "pending")
                except Exception as exc:
                    logger.warning(f"Could not mark recovered scan {scan_id} pending: {exc}")
                self._start_recovered_repeater_refresh(scan_id, target_url, marker.parent)
                recovered += 1
            except Exception as exc:
                logger.error(f"Could not recover Repeater refresh marker {marker}: {exc}")
        return recovered

    @staticmethod
    def _async_repeater_artifact_lock(report_dir: Path):
        """Acquire the cross-process report lock without blocking the event loop."""
        import fcntl
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def lock():
            report_dir.mkdir(parents=True, exist_ok=True)
            handle = (report_dir / ".report-artifacts.lock").open("a+b")
            await asyncio.to_thread(fcntl.flock, handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                await asyncio.to_thread(fcntl.flock, handle.fileno(), fcntl.LOCK_UN)
                handle.close()

        return lock()

    @staticmethod
    def _repeater_artifact_lock(report_dir: Path):
        """Serialize Repeater artifact transactions across API worker processes."""
        import fcntl
        from contextlib import contextmanager

        @contextmanager
        def lock():
            report_dir.mkdir(parents=True, exist_ok=True)
            with (report_dir / ".report-artifacts.lock").open("a+b") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

        return lock()

    async def _persist_repeater_finding_locked(
        self, scan_id, actual_target_url, vuln_url, vuln_type, severity,
        parameter, summary, confidence, request_raw, response_status,
        response_excerpt, finding_data, report_dir,
    ):
        """Transactional persistence under lock. Never returns success=false on 2xx."""
        import os
        import uuid

        finding_payload = {
            "type": vuln_type,
            "severity": severity,
            "url": vuln_url or actual_target_url,
            "parameter": parameter or "",
            "summary": summary,
            "details": summary,
            "confidence": confidence,
            "validated": True,
            "status": FindingStatus.VALIDATED_CONFIRMED.value,
            "source": "ai_repeater",
            "validator_notes": f"Confirmed by AI Repeater. {summary}",
            "reproduction": request_raw,
            "response_status": response_status,
            "response_excerpt": response_excerpt or "",
            "source_finding_id": finding_data.get("source_finding_id"),
        }

        if not report_dir:
            raise RuntimeError(f"No report directory available for scan {scan_id}")
        raw_path = report_dir / "raw_findings.json"
        validated_path = report_dir / "validated_findings.json"
        marker_path = report_dir / self.REPEATER_REFRESH_MARKER

        raw_snapshot = raw_path.read_bytes() if raw_path.is_file() else None
        validated_snapshot = validated_path.read_bytes() if validated_path.is_file() else None
        marker_snapshot = marker_path.read_bytes() if marker_path.is_file() else None
        raw_tmp = None
        validated_tmp = None
        marker_tmp = None
        raw_replaced = False
        validated_replaced = False
        marker_replaced = False
        raw_staged_bytes = None
        validated_staged_bytes = None
        marker_staged_bytes = None

        with self.db.get_session() as session:
            try:
                from bugtrace.schemas.models import normalize_vuln_type
                vuln_type_enum = normalize_vuln_type(vuln_type)
            except Exception:
                from bugtrace.schemas.db_models import VulnType
                vuln_type_enum = VulnType.MISCONFIG
            finding_payload["reported_type"] = finding_payload["type"]
            finding_payload["type"] = vuln_type_enum.value

            existing = self.db._find_existing_finding(
                session, scan_id, vuln_type_enum,
                {"url": vuln_url or actual_target_url, "parameter": parameter},
                actual_target_url,
            )
            created = existing is None

            try:
                raw_doc = self._load_artifact_document(raw_path)
                val_doc = self._load_artifact_document(validated_path)
                canonical = self._build_canonical_finding(finding_payload, scan_id)
                self._upsert_finding_in_list(
                    raw_doc["findings"], canonical, vuln_type, parameter,
                    vuln_url or actual_target_url,
                )
                self._upsert_finding_in_list(
                    val_doc["findings"], canonical, vuln_type, parameter,
                    vuln_url or actual_target_url,
                )
                raw_doc.setdefault("scan_id", str(scan_id))
                val_doc.setdefault("scan_id", str(scan_id))
                raw_tmp = self._stage_artifact(raw_path, raw_doc)
                validated_tmp = self._stage_artifact(validated_path, val_doc)
                marker_tmp = self._stage_artifact(marker_path, {
                    "scan_id": scan_id,
                    "target_url": actual_target_url,
                    "token": uuid.uuid4().hex,
                })
                raw_staged_bytes = raw_tmp.read_bytes()
                validated_staged_bytes = validated_tmp.read_bytes()
                marker_staged_bytes = marker_tmp.read_bytes()

                if existing:
                    # Repeater is authoritative for its own canonical record;
                    # corrections may lower severity/confidence or shorten text.
                    existing.severity = severity
                    existing.details = summary
                    existing.confidence_score = confidence
                    existing.visual_validated = True
                    existing.status = FindingStatus.VALIDATED_CONFIRMED
                    existing.attack_url = vuln_url or actual_target_url
                    existing.vuln_parameter = parameter or ""
                    existing.reproduction_command = request_raw
                    existing.validator_notes = finding_payload["validator_notes"]
                    session.add(existing)
                else:
                    new_finding = self.db._create_new_finding(scan_id, vuln_type_enum, finding_payload, actual_target_url)
                    new_finding.validator_notes = finding_payload["validator_notes"]
                    session.add(new_finding)

                session.flush()
                finding_id = existing.id if existing else new_finding.id

                if not self._artifact_matches_snapshot(raw_path, raw_snapshot):
                    raise RuntimeError(f"{raw_path.name} changed concurrently")
                os.replace(raw_tmp, raw_path)
                raw_replaced = True
                raw_tmp = None
                if not self._artifact_matches_snapshot(validated_path, validated_snapshot):
                    raise RuntimeError(f"{validated_path.name} changed concurrently")
                os.replace(validated_tmp, validated_path)
                validated_replaced = True
                validated_tmp = None
                if not self._artifact_matches_snapshot(marker_path, marker_snapshot):
                    raise RuntimeError(f"{marker_path.name} changed concurrently")
                os.replace(marker_tmp, marker_path)
                marker_replaced = True
                marker_tmp = None
                self._fsync_directory(report_dir)
                session.commit()

            except Exception as exc:
                session.rollback()
                restore_errors = []
                for path, snapshot, replaced, staged_bytes in (
                    (raw_path, raw_snapshot, raw_replaced, raw_staged_bytes),
                    (validated_path, validated_snapshot, validated_replaced, validated_staged_bytes),
                    (marker_path, marker_snapshot, marker_replaced, marker_staged_bytes),
                ):
                    if not replaced:
                        continue
                    try:
                        if path.read_bytes() != staged_bytes:
                            raise RuntimeError("artifact changed after replacement")
                        self._restore_artifact(path, snapshot)
                    except Exception as restore_exc:
                        restore_errors.append(f"{path.name}: {restore_exc}")
                if restore_errors:
                    logger.critical(
                        "Repeater persistence compensation failed: "
                        + "; ".join(restore_errors)
                    )
                detail = f"Repeater persistence rolled back: {exc}"
                if restore_errors:
                    detail += "; artifact restore errors: " + "; ".join(restore_errors)
                raise RuntimeError(detail) from exc
            finally:
                for tmp in (raw_tmp, validated_tmp, marker_tmp):
                    if tmp and tmp.exists():
                        try:
                            tmp.unlink(missing_ok=True)
                        except Exception:
                            pass

        logger.info(
            f"{'Created' if created else 'Updated'} Repeater finding id={finding_id} in scan {scan_id}"
        )
        return {
            "finding_id": finding_id,
            "created": created,
            "success": True,
            "message": f"{'Created' if created else 'Updated'} finding {finding_id} in scan {scan_id}",
            "_report_dir": report_dir,
        }

    @staticmethod
    def _normalized_origin(url: str) -> tuple:
        """Return a strict (scheme, hostname, effective-port) origin."""
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL must be absolute HTTP(S)")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid URL origin: {url}") from exc
        return parsed.scheme.lower(), parsed.hostname.lower(), port

    @classmethod
    def _validate_repeater_exchange(
        cls, target_url: str, finding_url: str, raw_request: str,
    ) -> None:
        """Ensure target, declared URL and raw request describe one exchange."""
        from urllib.parse import parse_qsl, urlsplit

        if cls._normalized_origin(target_url) != cls._normalized_origin(finding_url):
            raise ValueError("Finding URL origin does not match scan target origin")

        lines = raw_request.replace("\r\n", "\n").split("\n")
        request_line = lines[0].strip().split()
        if len(request_line) < 2:
            raise ValueError("Raw request has an invalid request line")
        request_target = request_line[1]
        declared = urlsplit(finding_url)
        hosts = []
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                hosts.append(line.split(":", 1)[1].strip())
        if len(hosts) != 1 or not hosts[0]:
            raise ValueError("Raw request must contain exactly one Host header")
        host = hosts[0]
        if cls._normalized_origin(f"{declared.scheme}://{host}") != cls._normalized_origin(finding_url):
            raise ValueError("Raw request Host does not match finding URL")
        if request_target.startswith(("http://", "https://")):
            raw_url = request_target
        else:
            path = request_target if request_target.startswith("/") else f"/{request_target}"
            raw_url = f"{declared.scheme}://{host}{path}"

        raw = urlsplit(raw_url)
        if cls._normalized_origin(raw_url) != cls._normalized_origin(finding_url):
            raise ValueError("Raw request origin does not match finding URL")
        if raw.path != declared.path or sorted(parse_qsl(raw.query, keep_blank_values=True)) != sorted(
            parse_qsl(declared.query, keep_blank_values=True)
        ):
            raise ValueError("Raw request path/query does not match finding URL")

    @staticmethod
    def _load_artifact_document(path: Path) -> dict:
        """Load a canonical artifact without silently discarding invalid data."""
        import json

        if not path.is_file():
            return {"findings": []}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Cannot read valid JSON from {path.name}") from exc
        if isinstance(data, list):
            return {"findings": list(data)}
        if not isinstance(data, dict):
            raise RuntimeError(f"Unsupported JSON structure in {path.name}")
        result = dict(data)
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            raise RuntimeError(f"Invalid findings collection in {path.name}")
        result["findings"] = list(findings)
        return result

    @staticmethod
    def _stage_artifact(path: Path, document: dict) -> Path:
        """Write and fsync a unique temporary artifact beside its destination."""
        import json
        import os
        import tempfile

        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
            return Path(handle.name)

    @classmethod
    def _restore_artifact(cls, path: Path, snapshot: Optional[bytes]) -> None:
        """Restore exact prior bytes, or remove a file that did not exist."""
        import os
        import tempfile

        if snapshot is None:
            path.unlink(missing_ok=True)
            return
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.restore.",
            suffix=".tmp", delete=False,
        ) as handle:
            handle.write(snapshot)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, path)

    @staticmethod
    def _artifact_matches_snapshot(path: Path, snapshot: Optional[bytes]) -> bool:
        """Detect report changes made outside this service before replacement."""
        if snapshot is None:
            return not path.exists()
        return path.is_file() and path.read_bytes() == snapshot

    def _build_canonical_finding(self, finding_payload: dict, scan_id: int) -> dict:
        import hashlib

        proof = "\0".join(str(finding_payload.get(field, "")) for field in (
            "url", "reproduction", "response_status", "response_excerpt",
        ))
        canonical = {
            "type": finding_payload.get("type", ""),
            "reported_type": finding_payload.get("reported_type", finding_payload.get("type", "")),
            "severity": finding_payload.get("severity", "MEDIUM"),
            "url": finding_payload.get("url", ""),
            "parameter": finding_payload.get("parameter", ""),
            "status": "VALIDATED_CONFIRMED",
            "confidence": finding_payload.get("confidence", 0.95),
            "source": "ai_repeater",
            "summary": finding_payload.get("summary", ""),
            "description": finding_payload.get("summary", ""),
            "reproduction": finding_payload.get("reproduction", ""),
            "http_request": finding_payload.get("reproduction", ""),
            "http_response": finding_payload.get("response_excerpt", "")[:4000],
            "response_status": finding_payload.get("response_status"),
            "response_excerpt": finding_payload.get("response_excerpt", "")[:4000],
            "evidence": {
                "response_status": finding_payload.get("response_status"),
                "response_excerpt": finding_payload.get("response_excerpt", "")[:4000],
                "source": "ai_repeater",
            },
            "source_finding_id": finding_payload.get("source_finding_id"),
            "validator_notes": finding_payload.get("validator_notes", ""),
            "scan_id": str(scan_id),
            "evidence_fingerprint": hashlib.sha256(proof.encode("utf-8")).hexdigest(),
        }
        from bugtrace.agents.reporting_mod.finding_processor import apply_deterministic_baseline
        return apply_deterministic_baseline([canonical])[0]

    @staticmethod
    def _upsert_finding_in_list(findings: list, canonical: dict, vuln_type: str, parameter: str, url: str):
        for i, f in enumerate(findings):
            existing_reported_type = str(f.get("reported_type") or f.get("type") or "").upper()
            if (
                (f.get("type") == canonical["type"] or existing_reported_type == vuln_type.upper())
                and f.get("url") == canonical["url"]
                and f.get("parameter", "") == canonical.get("parameter", "")
            ):
                merged = {**f, **canonical}
                old_fingerprint = f.get("evidence_fingerprint")
                if not old_fingerprint:
                    import hashlib
                    old_proof = "\0".join(str(value) for value in (
                        f.get("url", ""),
                        f.get("http_request") or f.get("reproduction") or "",
                        f.get("response_status", ""),
                        f.get("http_response") or f.get("response_excerpt") or "",
                    ))
                    old_fingerprint = hashlib.sha256(old_proof.encode("utf-8")).hexdigest()
                new_fingerprint = canonical.get("evidence_fingerprint")
                enrichment_inputs_changed = (
                    old_fingerprint != new_fingerprint
                    or str(f.get("severity", "")).upper() != str(canonical.get("severity", "")).upper()
                    or (f.get("summary") or f.get("description") or "") != canonical.get("summary", "")
                    or f.get("confidence") != canonical.get("confidence")
                )
                if enrichment_inputs_changed:
                    for field in (
                        "cvss_score", "cvss_vector", "cvss_rationale", "cve",
                        "exploitation_details", "llm_reproduction_steps", "enriched",
                    ):
                        merged.pop(field, None)
                findings[i] = merged
                return
        findings.append(canonical)

    async def _find_existing_repeater_finding(
        self, scan_id: int, vuln_type: str, parameter: str, url: str
    ):
        """Find an existing AI Repeater finding matching type+url+parameter."""
        from bugtrace.schemas.db_models import FindingTable, VulnType
        from sqlmodel import select

        try:
            from bugtrace.schemas.models import normalize_vuln_type
            vuln_type_enum = normalize_vuln_type(vuln_type)
        except Exception:
            vuln_type_enum = VulnType.MISCONFIG

        with self.db.get_session() as session:
            results = session.exec(
                select(FindingTable).where(
                    FindingTable.scan_id == scan_id,
                    FindingTable.type == vuln_type_enum,
                    FindingTable.attack_url == url,
                )
            ).all()
            for r in results:
                if (r.vuln_parameter or "") == (parameter or ""):
                    return r
            return None

    def _get_last_inserted_finding_id(
        self, scan_id: int, vuln_type: str, parameter: str, url: str
    ) -> int:
        """Get the ID of the most recently inserted matching finding."""
        from bugtrace.schemas.db_models import FindingTable, VulnType
        from sqlmodel import select

        try:
            from bugtrace.schemas.models import normalize_vuln_type
            vuln_type_enum = normalize_vuln_type(vuln_type)
        except Exception:
            vuln_type_enum = VulnType.MISCONFIG

        with self.db.get_session() as session:
            results = session.exec(
                select(FindingTable).where(
                    FindingTable.scan_id == scan_id,
                    FindingTable.type == vuln_type_enum,
                ).order_by(FindingTable.id.desc())
            ).all()
            for r in results:
                if (r.vuln_parameter or "") == (parameter or "") and (r.attack_url or "") == (url or ""):
                    return r.id
            if results:
                return results[0].id
            return 0

    def _find_or_create_report_dir_for_scan(
        self, scan_id: int, target_url: str, finding_data: dict
    ) -> Optional[Path]:
        """Find the scan's report directory or create one."""
        report_dir = self._find_report_dir_for_scan(scan_id)
        if report_dir:
            return report_dir

        domain = urlparse(target_url).netloc.replace(":", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_dir = settings.REPORT_DIR / f"scan_{scan_id}"
        report_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created report directory for scan {scan_id}: {report_dir}")
        return report_dir

    @staticmethod
    def _assert_report_not_shared_with_active_scan(session, scan) -> None:
        """Reject writes unless this is the sole/latest owner of its artifacts."""
        if not scan.report_dir:
            return
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanTable

        active = session.exec(
            select(ScanTable).where(
                ScanTable.id != scan.id,
                ScanTable.report_dir == scan.report_dir,
                ScanTable.status.in_([
                    ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED,
                ]),
            )
        ).first()
        if active:
            raise ValueError(
                f"Report artifacts are in use by active resumed scan {active.id}"
            )
        newer = session.exec(
            select(ScanTable).where(
                ScanTable.id > scan.id,
                ScanTable.report_dir == scan.report_dir,
            ).order_by(ScanTable.id.desc())
        ).first()
        if newer:
            raise ValueError(
                f"Report artifacts belong to newer resumed scan {newer.id}"
            )

    async def _update_canonical_artifacts(
        self,
        report_dir: Path,
        finding_data: dict,
        vuln_type: str,
        parameter: str,
        url: str,
        is_new: bool,
    ):
        """Atomically update raw_findings.json and validated_findings.json."""
        import json, tempfile, os
        from bugtrace.core.payload_format import decode_finding_payloads

        raw_path = report_dir / "raw_findings.json"
        validated_path = report_dir / "validated_findings.json"

        canonical_finding = {
            "type": vuln_type,
            "severity": finding_data.get("severity", "MEDIUM"),
            "url": url,
            "parameter": parameter or "",
            "status": "VALIDATED_CONFIRMED",
            "confidence": finding_data.get("confidence", 0.95),
            "source": "ai_repeater",
            "summary": finding_data.get("summary", ""),
            "scan_id": str(finding_data.get("scan_id", "")),
        }

        if is_new:
            self._append_to_json_file(raw_path, canonical_finding)
            self._append_to_json_file(validated_path, canonical_finding)
        else:
            self._upsert_in_json_file(raw_path, canonical_finding, vuln_type, parameter, url)
            self._upsert_in_json_file(validated_path, canonical_finding, vuln_type, parameter, url)

    def _load_json_file(self, path: Path) -> dict:
        """Load a JSON file preserving all metadata fields, or return empty dict."""
        import json
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return dict(data)
            except Exception:
                pass
        return {}

    def _append_to_json_file(self, path: Path, finding: dict):
        """Append a finding to a JSON findings file atomically, preserving all top-level metadata."""
        import json, os

        data = self._load_json_file(path)
        existing_findings = data.get("findings", [])
        if isinstance(existing_findings, list):
            pass
        elif isinstance(data, list):
            existing_findings = data
            data = {}
        else:
            existing_findings = []

        if any(
            f.get("type") == finding["type"]
            and f.get("url") == finding["url"]
            and f.get("parameter", "") == finding.get("parameter", "")
            for f in existing_findings
        ):
            return

        existing_findings.append(finding)
        data["findings"] = existing_findings
        if "scan_id" not in data:
            data["scan_id"] = finding.get("scan_id", "")

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)

    def _upsert_in_json_file(self, path: Path, finding: dict, vuln_type: str, parameter: str, url: str):
        """Update or insert a finding in a JSON findings file atomically, preserving all top-level metadata."""
        import json, os

        data = self._load_json_file(path)
        existing_findings = data.get("findings", [])
        if isinstance(existing_findings, list):
            pass
        elif isinstance(data, list):
            existing_findings = data
            data = {}
        else:
            existing_findings = []

        found = False
        for i, f in enumerate(existing_findings):
            if (
                f.get("type") == vuln_type
                and f.get("url") == url
                and f.get("parameter", "") == parameter
            ):
                existing_findings[i] = {**f, **finding}
                found = True
                break

        if not found:
            existing_findings.append(finding)

        data["findings"] = existing_findings
        if "scan_id" not in data:
            data["scan_id"] = finding.get("scan_id", "")

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)

    def _load_report_counts(self, scan_id: int) -> Dict[str, int]:
        """Read user-facing counters from canonical report artifacts."""
        import json

        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            return {}

        counts: Dict[str, int] = {}
        try:
            raw = json.loads((report_dir / "raw_findings.json").read_text(encoding="utf-8"))
            raw_findings = raw.get("findings", []) if isinstance(raw, dict) else raw
            counts["detections_count"] = len(raw_findings) if isinstance(raw_findings, list) else 0
        except (OSError, ValueError, TypeError):
            pass

        try:
            validated = json.loads((report_dir / "validated_findings.json").read_text(encoding="utf-8"))
            confirmed = validated.get("findings", []) if isinstance(validated, dict) else []
            manual = validated.get("manual_review", []) if isinstance(validated, dict) else []
            counts["confirmed_count"] = len(confirmed) if isinstance(confirmed, list) else 0
            counts["manual_review_count"] = len(manual) if isinstance(manual, list) else 0
            counts["reportable_count"] = counts["confirmed_count"] + counts["manual_review_count"]
        except (OSError, ValueError, TypeError):
            pass

        return counts

    async def delete_scan(self, scan_id: int, force: bool = False) -> Dict[str, Any]:
        """
        Delete a scan and its associated findings from the database,
        and remove report files from disk.

        Args:
            scan_id: Scan ID to delete
            force: If True, bypass origin check (used by CLI delete command)

        Returns:
            Dictionary with scan_id and message

        Raises:
            ValueError: If scan not found or is currently running
            PermissionError: If scan origin is 'cli' and force=False (web cannot delete CLI scans)
        """
        with self.db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status == ScanStatus.RUNNING:
                raise ValueError(f"Cannot delete scan {scan_id}: scan is still running")

            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else None
            scan_timestamp = scan.timestamp

            findings_count = self._delete_scan_findings(session, scan_id)
            self._delete_scan_states(session, scan_id)

            session.delete(scan)
            session.commit()
            logger.info(f"Deleted scan {scan_id} with {findings_count} findings")

        deleted_dirs = self._delete_report_dirs(scan_id, target_url, scan_timestamp)
        return self._build_delete_response(scan_id, findings_count, deleted_dirs)

    def _delete_scan_findings(self, session, scan_id: int) -> int:
        """Delete all findings associated with a scan."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import FindingTable

        findings = session.exec(select(FindingTable).where(FindingTable.scan_id == scan_id)).all()
        for finding in findings:
            session.delete(finding)
        return len(findings)

    def _delete_scan_states(self, session, scan_id: int):
        """Delete all scan states associated with a scan."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanStateTable

        scan_states = session.exec(select(ScanStateTable).where(ScanStateTable.scan_id == scan_id)).all()
        for state in scan_states:
            session.delete(state)

    def _build_delete_response(self, scan_id: int, findings_count: int, deleted_dirs: List[Path]) -> Dict[str, Any]:
        """Build delete scan response message."""
        parts = [f"Scan {scan_id} deleted ({findings_count} findings removed)"]
        if deleted_dirs:
            parts.append(f"{len(deleted_dirs)} report folder(s) removed")

        return {
            "scan_id": scan_id,
            "message": ", ".join(parts),
            "files_cleaned": len(deleted_dirs) > 0,
        }

    @staticmethod
    def _has_report_dir(
        report_base: Path,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
        report_dir: Optional[str] = None,
    ) -> bool:
        """Check if a report directory with actual report files exists for this scan."""
        report_files = {"final_report.md", "validated_findings.json", "raw_findings.json"}

        def _has_files(d: Path) -> bool:
            """Check if directory contains at least one known report file."""
            return d.is_dir() and any((d / f).is_file() for f in report_files)

        if report_dir and _has_files(Path(report_dir)):
            return True

        # Pattern 1: API-generated (scan_{id}/)
        if _has_files(report_base / f"scan_{scan_id}"):
            return True

        # Pattern 2: Pipeline-generated ({domain}_{timestamp}/)
        return ScanService._check_pipeline_report_dir(
            report_base, target_url, scan_timestamp, _has_files
        )

    @staticmethod
    def _has_recovery_artifacts(
        report_base: Path,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
        report_dir: Optional[str] = None,
    ) -> bool:
        """Check whether a scan has any persisted artifacts, even without final deliverables."""
        candidate_dirs: List[Path] = []

        if report_dir:
            candidate_dirs.append(Path(report_dir))

        candidate_dirs.append(report_base / f"scan_{scan_id}")

        if target_url:
            hostname = urlparse(target_url).hostname or ""
            if hostname:
                if scan_timestamp:
                    ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
                    candidate_dirs.extend(report_base.glob(f"{hostname}_{ts_prefix}*"))
                candidate_dirs.extend(report_base.glob(f"{hostname}_*"))

        seen = set()
        for directory in candidate_dirs:
            if directory in seen:
                continue
            seen.add(directory)

            if not directory.is_dir():
                continue

            try:
                if any(path.is_file() for path in directory.rglob("*")):
                    return True
            except OSError as e:
                logger.debug(f"Error inspecting recovery artifacts in {directory}: {e}")

        return False

    @staticmethod
    def _check_pipeline_report_dir(
        report_base: Path,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime],
        has_files_check
    ) -> bool:
        """Check for pipeline-generated report directories."""
        if not target_url:
            return False

        hostname = urlparse(target_url).hostname or ""
        if not hostname:
            return False

        return ScanService._check_hostname_reports(
            report_base, hostname, scan_timestamp, has_files_check
        )

    @staticmethod
    def _check_hostname_reports(
        report_base: Path,
        hostname: str,
        scan_timestamp: Optional[datetime],
        has_files_check
    ) -> bool:
        """Check for report directories matching hostname."""
        # Precise match using scan timestamp (minute-level)
        if scan_timestamp:
            ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
            for match in report_base.glob(f"{hostname}_{ts_prefix}*"):
                if has_files_check(match):
                    return True

        # Fallback: any dir for this domain that contains report files
        for match in report_base.glob(f"{hostname}_*"):
            if has_files_check(match):
                return True

        return False

    def _delete_report_dirs(
        self,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
    ) -> List[Path]:
        """
        Find and delete report directories associated with a scan.

        Searches two patterns:
        1. scan_{scan_id}/ (created by ReportService API)
        2. {domain}_{YYYYMMDD}_{HHMMSS}/ (created by scan pipeline)

        Uses the scan's timestamp to precisely match the pipeline directory
        and avoid deleting reports from other scans of the same target.

        Args:
            scan_id: Scan ID
            target_url: Target URL for domain extraction
            scan_timestamp: Scan creation timestamp for precise directory matching

        Returns:
            List of deleted directory paths
        """
        report_base = settings.REPORT_DIR
        deleted = []

        self._delete_api_report_dir(report_base, scan_id, deleted)
        if target_url:
            self._delete_pipeline_report_dirs(report_base, target_url, scan_timestamp, deleted)

        return deleted

    def _delete_api_report_dir(self, report_base: Path, scan_id: int, deleted: List[Path]):
        """Delete API-generated report directory (scan_{id}/)."""
        api_dir = report_base / f"scan_{scan_id}"
        if api_dir.is_dir():
            try:
                shutil.rmtree(api_dir)
                deleted.append(api_dir)
                logger.info(f"Deleted report directory: {api_dir}")
            except OSError as e:
                logger.warning(f"Failed to delete report directory {api_dir}: {e}")

    def _delete_pipeline_report_dirs(
        self,
        report_base: Path,
        target_url: str,
        scan_timestamp: Optional[datetime],
        deleted: List[Path]
    ):
        """Delete pipeline-generated report directories ({domain}_{timestamp}/)."""
        try:
            hostname = urlparse(target_url).hostname or ""
            if not hostname:
                return

            if scan_timestamp:
                self._delete_timestamped_reports(report_base, hostname, scan_timestamp, deleted)
            else:
                self._delete_all_domain_reports(report_base, hostname, deleted)
        except Exception as e:
            logger.warning(f"Error finding report dirs for {target_url}: {e}")

    def _delete_timestamped_reports(
        self,
        report_base: Path,
        hostname: str,
        scan_timestamp: datetime,
        deleted: List[Path]
    ):
        """Delete reports matching precise timestamp."""
        ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
        for match in report_base.glob(f"{hostname}_{ts_prefix}*"):
            if match.is_dir():
                self._try_delete_dir(match, deleted)

    def _delete_all_domain_reports(self, report_base: Path, hostname: str, deleted: List[Path]):
        """Delete all reports for a domain (fallback when no timestamp)."""
        for match in report_base.glob(f"{hostname}_*"):
            if match.is_dir():
                self._try_delete_dir(match, deleted)

    def _try_delete_dir(self, path: Path, deleted: List[Path]):
        """Attempt to delete a directory and track success."""
        try:
            shutil.rmtree(path)
            deleted.append(path)
            logger.info(f"Deleted report directory: {path}")
        except OSError as e:
            logger.warning(f"Failed to delete report directory {path}: {e}")

    async def get_findings(
        self,
        scan_id: int,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Dict[str, Any]:
        """
        Get findings for a scan with filtering and pagination.

        V3.2: Reads from FILES (source of truth) instead of database.
        Files: specialists/wet/*.json, specialists/dry/*.json, specialists/results/*.json

        Args:
            scan_id: Scan ID to get findings for
            severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            vuln_type: Optional vulnerability type filter (XSS, SQLi, etc.)
            page: Page number (1-indexed)
            per_page: Results per page

        Returns:
            Dictionary with findings, total, page, per_page
        """
        # Verify scan exists before loading findings
        with self.db.get_session() as session:
            from sqlmodel import select
            from bugtrace.schemas.db_models import ScanTable
            scan = session.exec(select(ScanTable).where(ScanTable.id == scan_id)).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

        # Load all findings from files (source of truth)
        all_findings = self._load_findings_from_files(scan_id)

        # Apply filters
        filtered = self._filter_findings(all_findings, severity, vuln_type)

        # Paginate
        total = len(filtered)
        offset = (page - 1) * per_page
        paginated = filtered[offset:offset + per_page]

        # Format for API response
        results = self._format_file_findings(paginated)

        return {
            "findings": results,
            "total": total,
            "page": page,
            "per_page": per_page,
        }

    @staticmethod
    def _dir_has_report_files(directory: Path) -> bool:
        """Check if a directory contains actual report deliverables."""
        key_files = ("final_report.md", "validated_findings.json", "raw_findings.json")
        return any((directory / f).is_file() for f in key_files)

    @staticmethod
    def _dir_belongs_to_scan(directory: Path, scan_id: int) -> bool:
        """Return True only when report metadata clearly names this scan."""
        import json

        candidates = (
            directory / "validated_findings.json",
            directory / "raw_findings.json",
        )
        for path in candidates:
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue

            if ScanService._json_names_scan(data, scan_id):
                return True

        return False

    @staticmethod
    def _json_names_scan(data: Any, scan_id: int) -> bool:
        """Inspect common report JSON shapes for scan_id."""
        if isinstance(data, dict):
            if str(data.get("scan_id", "")) == str(scan_id):
                return True
            findings = data.get("findings")
            if isinstance(findings, list):
                return any(ScanService._json_names_scan(item, scan_id) for item in findings)
            finding = data.get("finding")
            if isinstance(finding, dict):
                return ScanService._json_names_scan(finding, scan_id)
            return False
        if isinstance(data, list):
            return any(ScanService._json_names_scan(item, scan_id) for item in data)
        return False

    def _find_report_dir_for_scan(self, scan_id: int) -> Optional[Path]:
        """
        Find the report directory for a scan_id.

        Priority order:
        0. scan.report_dir from DB (v5.1 architecture)
        1. scan_{id}/ (created by ReportService API, fallback)
        2. {domain}_{timestamp}/ (created by scan pipeline, verified by scan_id)

        Validates directories contain actual report files before returning.
        """
        report_base = settings.REPORT_DIR

        try:
            with self.db.get_session() as session:
                from bugtrace.schemas.db_models import ScanTable, TargetTable
                scan = session.get(ScanTable, scan_id)
                if not scan:
                    return None
                target = session.get(TargetTable, scan.target_id)
                if not target:
                    return None

                # Pattern 0: Direct DB match (v5.1 architecture)
                if hasattr(scan, 'report_dir') and scan.report_dir:
                    db_dir = Path(scan.report_dir)
                    if db_dir.is_dir() and self._dir_has_report_files(db_dir):
                        return db_dir

                # Pattern 1: API-generated reports (scan-specific fallback)
                api_dir = report_base / f"scan_{scan_id}"
                if api_dir.is_dir() and self._dir_has_report_files(api_dir):
                    return api_dir

                # Pattern 2: Pipeline-generated reports ({domain}_{timestamp})
                # Only accept hostname matches that prove scan_id ownership.
                domain = urlparse(target.url).hostname or ""
                matches = sorted(
                    report_base.glob(f"{domain}_*"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                for match in matches:
                    if (
                        self._dir_has_report_files(match)
                        and self._dir_belongs_to_scan(match, scan_id)
                    ):
                        return match

        except Exception as e:
            logger.warning(f"Error resolving report dir for scan {scan_id}: {e}")

        # Last resort without DB
        api_dir = report_base / f"scan_{scan_id}"
        if api_dir.is_dir() and self._dir_has_report_files(api_dir):
            return api_dir

        return None

    def _load_findings_from_files(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Load all findings from files for a scan.

        Reads from (in priority order):
        1. specialists/results/*.json (validated findings)
        2. specialists/dry/*.json (deduplicated findings)
        3. specialists/wet/*.json (raw findings)

        Returns:
            List of finding dictionaries
        """
        import json
        from bugtrace.core.payload_format import decode_finding_payloads

        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            logger.debug(f"No report directory found for scan {scan_id}")
            return []

        # Completed reports expose the ReportingAgent's canonical, deduplicated
        # detection set. Specialist stage files remain a recovery fallback.
        raw_path = report_dir / "raw_findings.json"
        if raw_path.is_file():
            try:
                raw_findings = self._read_findings_file(raw_path)
                canonical = []
                for finding_id, finding in enumerate(raw_findings, 1):
                    finding = decode_finding_payloads(finding)
                    finding["_source_file"] = str(raw_path)
                    finding["_source_dir"] = "raw"
                    finding["_id"] = finding_id
                    canonical.append(finding)
                logger.debug(f"Loaded {len(canonical)} canonical detections for scan {scan_id}")
                return canonical
            except Exception as e:
                logger.warning(f"Failed to read canonical findings from {raw_path}: {e}")

        specialists_dir = report_dir / "specialists"
        if not specialists_dir.exists():
            logger.debug(f"No specialists dir in {report_dir}")
            return []

        all_findings = []
        finding_id_counter = 1

        # Priority: results > dry > wet
        for subdir in ["results", "dry", "wet"]:
            subdir_path = specialists_dir / subdir
            if not subdir_path.exists():
                continue

            for json_file in subdir_path.glob("*.json"):
                try:
                    findings_from_file = self._read_findings_file(json_file)
                    for finding in findings_from_file:
                        # Decode base64 payloads if present
                        finding = decode_finding_payloads(finding)
                        finding["_source_file"] = str(json_file)
                        finding["_source_dir"] = subdir
                        finding["_id"] = finding_id_counter
                        finding_id_counter += 1
                        all_findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to read {json_file}: {e}")

            # If we found findings in results/, don't look in dry/wet
            if all_findings and subdir == "results":
                break
            # If we found findings in dry/, don't look in wet
            if all_findings and subdir == "dry":
                break

        logger.debug(f"Loaded {len(all_findings)} findings from files for scan {scan_id}")
        return all_findings

    def _read_findings_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Read findings from a JSON or JSON Lines file.

        Supports three formats:
        - Wrapped JSON: {"findings": [...]} (nuclei_misconfig, bac_detection)
        - JSON Lines: One JSON object per line (v3.2 format)
        - JSON Array: Array of finding objects
        """
        import json

        findings = []
        content = file_path.read_text(encoding="utf-8").strip()

        if not content:
            return []

        if content.startswith("{"):
            # Try as single wrapped JSON object first (e.g. nuclei_misconfig_results.json)
            try:
                data = json.loads(content)
                if "findings" in data and isinstance(data["findings"], list):
                    return data["findings"]
                # Single finding object (one JSON object, not wrapped)
                if "finding" in data:
                    return [data["finding"]]
                # Could be a single finding dict itself
                if any(k in data for k in ("vulnerability_type", "vuln_type", "type", "severity")):
                    return [data]
            except json.JSONDecodeError:
                pass

            # Fall through to JSON Lines (one object per line)
            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if "finding" in entry:
                        findings.append(entry["finding"])
                    else:
                        findings.append(entry)
                except json.JSONDecodeError:
                    continue
        # Try JSON Array
        elif content.startswith("["):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    findings = data
            except json.JSONDecodeError:
                pass

        return findings

    def _filter_findings(
        self,
        findings: List[Dict[str, Any]],
        severity: Optional[str],
        vuln_type: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Filter findings by severity and/or vulnerability type."""
        filtered = findings

        if severity:
            sev_upper = severity.upper()
            filtered = [f for f in filtered if f.get("severity", "").upper() == sev_upper]

        if vuln_type:
            type_upper = vuln_type.upper()
            filtered = [
                f for f in filtered
                if type_upper in (f.get("type", "") or "").upper()
            ]

        return filtered

    def _format_file_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format file-based findings for API response."""
        results = []
        for finding in findings:
            # Determine status: respect finding's own status from specialist,
            # only fall back to directory-based inference if no explicit status
            source_dir = finding.get("_source_dir", "wet")
            explicit_status = str(finding.get("status") or "").strip().upper()
            status_aliases = {
                "VALIDATED": "VALIDATED_CONFIRMED",
                "FINDING_VALIDATED": "VALIDATED_CONFIRMED",
                "NEEDS_VALIDATION": "MANUAL_REVIEW_RECOMMENDED",
                "VALIDATION_ERROR": "MANUAL_REVIEW_RECOMMENDED",
                "NEEDS_CDP_VALIDATION": "MANUAL_REVIEW_RECOMMENDED",
            }
            canonical_statuses = {
                "PENDING_VALIDATION", "VALIDATED_CONFIRMED",
                "VALIDATED_FALSE_POSITIVE", "MANUAL_REVIEW_RECOMMENDED",
                "SKIPPED", "ERROR",
            }
            normalized_status = status_aliases.get(explicit_status, explicit_status)
            if normalized_status in canonical_statuses:
                status = normalized_status
            elif source_dir == "results":
                status = "VALIDATED_CONFIRMED"
            elif source_dir == "dry":
                status = "PENDING_VALIDATION"
            else:
                status = "PENDING_VALIDATION"

            results.append({
                "finding_id": finding.get("_id", 0),
                "type": finding.get("type", "Unknown"),
                "severity": finding.get("severity", "MEDIUM"),
                "details": self._normalize_details(finding),
                "payload": finding.get("payload", ""),
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "validated": status == "VALIDATED_CONFIRMED",
                "status": status,
                "confidence": finding.get("confidence", 0.0),
                # Seed enrichment: the real request(s) that confirmed the finding,
                # auth already masked at capture time. Consumed by the WEB AI Repeater.
                "repro": finding.get("repro"),
                "http_request": finding.get("http_request"),
            })
        return results

    @staticmethod
    def _normalize_details(finding: Dict[str, Any]) -> str:
        """Extract details from a finding, converting dicts to JSON strings."""
        value = finding.get("evidence") or finding.get("description") or finding.get("note", "")
        if isinstance(value, dict):
            import json
            return json.dumps(value)
        return str(value) if value else ""

    @property
    def active_scan_count(self) -> int:
        """Get count of currently running scans."""
        return len(self._active_scans)

    def get_active_scan_ids(self) -> List[int]:
        """Get list of active scan IDs."""
        return list(self._active_scans.keys())

    def find_incomplete_scan(self, target_url: str, scan_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Find the most recent FAILED scan with recovery artifacts for resumption.
        
        Args:
            target_url: URL to find incomplete scan for
            scan_type: Optional scan type filter ("full", "hunter", etc)
            
        Returns:
            Dict with scan metadata if incomplete scan found, None otherwise
        """
        from bugtrace.schemas.db_models import ScanTable, TargetTable, ScanStatus
        from sqlmodel import select
        
        with self.db.get_session() as session:
            # Find target first
            target_stmt = select(TargetTable).where(TargetTable.url == target_url)
            target = session.exec(target_stmt).first()
            if not target:
                return None
            
            # Find most recent FAILED scan with recovery artifacts
            query = select(ScanTable).where(
                (ScanTable.target_id == target.id) &
                (ScanTable.status == ScanStatus.FAILED)
            ).order_by(ScanTable.timestamp.desc())
            
            if scan_type:
                query = query.where(ScanTable.scan_type == scan_type)
            
            scan = session.exec(query).first()
            if not scan:
                return None
            
            # Verify it has recovery artifacts
            if not self._has_recovery_artifacts(
                Path(settings.REPORT_DIR),
                scan.id,
                target_url,
                scan.timestamp,
                scan.report_dir
            ):
                return None
            
            return {
                "scan_id": scan.id,
                "target_url": target_url,
                "scan_type": scan.scan_type,
                "last_phase": scan.last_phase_completed,
                "report_dir": scan.report_dir,
                "retry_count": scan.retry_count,
            }

    async def _resume_recoverable_scan(self, original_scan_id: int) -> Dict[str, Any]:
        """Resume a failed scan with preserved recovery artifacts using stored scan config."""
        from bugtrace.schemas.db_models import ScanTable, TargetTable, ScanStatus
        from sqlmodel import select

        with self.db.get_session() as session:
            original = session.exec(
                select(ScanTable).where(ScanTable.id == original_scan_id)
            ).first()
            if not original:
                raise ValueError(f"Scan {original_scan_id} not found")
            if original.status != ScanStatus.FAILED:
                raise ValueError(
                    f"Scan {original_scan_id} is not resumable (status: {original.status.value})"
                )

            target = session.exec(
                select(TargetTable).where(TargetTable.id == original.target_id)
            ).first()
            if not target:
                raise ValueError(f"Target for scan {original_scan_id} not found")

            if not self._has_recovery_artifacts(
                Path(settings.REPORT_DIR),
                original.id,
                target.url,
                original.timestamp,
                original.report_dir,
            ):
                raise ValueError(f"Scan {original_scan_id} has no recovery artifacts to resume")

            options = ScanOptions(
                target_url=target.url,
                scan_type=original.scan_type or "full",
                max_depth=original.max_depth or 2,
                max_urls=original.max_urls or 20,
                resume=True,
            )
            origin = original.origin or "unknown"

        new_scan_id = await self._start_resumed_scan(original_scan_id, options, origin=origin)
        return {
            "scan_id": new_scan_id,
            "status": "running",
            "message": f"Resumed scan {original_scan_id} as new scan {new_scan_id}",
        }

    async def _start_resumed_scan(self, original_scan_id: int, options: ScanOptions, origin: str = "unknown") -> int:
        """
        Create a new scan that resumes from an incomplete previous scan.
        
        Args:
            original_scan_id: ID of the failed scan to resume from
            options: Updated scan configuration
            origin: Where the resume was initiated from
            
        Returns:
            New scan_id for the resumed scan
        """
        from bugtrace.schemas.db_models import ScanTable
        from sqlmodel import select
        
        new_scan_id = None
        original_report_dir = None
        retry_count = 0

        # Get original scan metadata
        with self.db.get_session() as session:
            original = session.exec(
                select(ScanTable).where(ScanTable.id == original_scan_id)
            ).first()
            if not original:
                raise ValueError(f"Original scan {original_scan_id} not found")
            
            # Increment retry count
            original.retry_count += 1
            retry_count = original.retry_count
            original_report_dir = original.report_dir
            session.add(original)
            session.commit()
        
        logger.info(
            f"Resuming scan {original_scan_id} (retry #{retry_count})",
            extra={"scan_id": original_scan_id}
        )
        
        # Create new scan record marked as resumed
        async with self._lock:
            self._check_concurrent_limit()
            new_scan_id = self._create_scan_record(options, origin)
            
        # Update new scan to reference original
        with self.db.get_session() as session:
            new_scan = session.exec(
                select(ScanTable).where(ScanTable.id == new_scan_id)
            ).first()
            new_scan.resumed_from_id = original_scan_id
            new_scan.report_dir = original_report_dir  # Reuse same report dir
            session.add(new_scan)
            session.commit()
        
        # Start the resumed scan
        try:
            ctx = self._build_scan_context(new_scan_id, options)
            ctx._output_dir = (
                Path(original_report_dir)
                if original_report_dir
                else self._compute_output_dir(options.target_url)
            )
            
            async with self._lock:
                self._active_scans[new_scan_id] = ctx

            ctx._task = asyncio.create_task(self._run_scan(ctx))
            await self.event_bus.emit("scan.resumed", {
                "scan_id": new_scan_id,
                "parent_scan_id": original_scan_id,
                "target": options.target_url,
            })
            
            logger.info(f"Resumed scan started: {new_scan_id} (parent: {original_scan_id})")
            return new_scan_id
        except Exception as e:
            logger.error(f"Failed to start resumed scan {new_scan_id}: {e}", exc_info=True)
            if new_scan_id is not None:
                with self.db.get_session() as session:
                    failed_scan = session.exec(
                        select(ScanTable).where(ScanTable.id == new_scan_id)
                    ).first()
                    if failed_scan:
                        failed_scan.status = ScanStatus.FAILED
                        session.add(failed_scan)
                        session.commit()
            raise

    def cleanup_orphaned_scans(self) -> int:
        """Mark any RUNNING/PENDING/PAUSED scans as FAILED on startup.

        When the backend restarts, no scans are actually running in-process.
        Any scan still marked RUNNING/PAUSED in the DB is orphaned (process died).
        """
        from bugtrace.schemas.db_models import ScanTable, ScanStatus
        from sqlmodel import select

        count = 0
        with self.db.get_session() as session:
            stmt = select(ScanTable).where(
                ScanTable.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.PAUSED])
            )
            orphans = session.exec(stmt).all()
            for scan in orphans:
                scan.status = ScanStatus.FAILED
                session.add(scan)
                count += 1
            if count:
                session.commit()
                logger.info(f"Cleaned up {count} orphaned scan(s) → FAILED")
        return count

    async def re_enrich_scan(self, scan_id: int) -> Dict[str, Any]:
        """
        Re-enrich a completed scan whose LLM enrichment failed.

        Reads engagement_data.json, identifies unenriched findings,
        runs LLM enrichment on them, and writes updated files back.

        Args:
            scan_id: Scan ID to re-enrich

        Returns:
            Dictionary with status and message

        Raises:
            ValueError: If scan not found or not completed
            RuntimeError: If LLM unavailable or no report dir found
        """
        from bugtrace.core.llm_client import llm_client

        # 1. Verify LLM health
        health = llm_client.get_health_status() or {}
        if health.get("state") == "CRITICAL":
            raise RuntimeError("LLM unavailable (circuit breaker OPEN). Try again later.")

        # 2. Verify scan exists and is completed
        with self.db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status != ScanStatus.COMPLETED:
                raise RuntimeError(f"Scan {scan_id} is not completed (status: {scan.status.value})")
            self._assert_report_not_shared_with_active_scan(session, scan)

            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else "unknown"

        # 3. Find report directory
        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            raise RuntimeError(f"No report directory found for scan {scan_id}")

        # 4. Coalesce manual and Repeater regeneration by report directory.
        key = self._report_refresh_key(report_dir)
        current = self._repeater_report_refresh_tasks.get(key)
        if current and not current.done():
            marker = report_dir / self.REPEATER_REFRESH_MARKER
            marker_scan_id = None
            try:
                import json
                marker_scan_id = int(json.loads(marker.read_text(encoding="utf-8"))["scan_id"])
            except Exception:
                pass
            if marker_scan_id != scan_id:
                raise RuntimeError(
                    f"Report refresh already belongs to scan {marker_scan_id}"
                )
            return {
                "scan_id": scan_id,
                "status": "re_enriching",
                "message": f"Re-enrichment already running for scan {scan_id}.",
            }

        # 5. Use the same durable marker and queue as post-Repeater refreshes.
        self._queue_repeater_report_refresh(
            scan_id, target_url, report_dir, write_marker=True,
        )

        return {
            "scan_id": scan_id,
            "status": "re_enriching",
            "message": f"Re-enrichment started for scan {scan_id}. Check enrichment_status for progress.",
        }

    async def _run_re_enrichment(
        self,
        scan_id: int,
        target_url: str,
        report_dir: Path,
        *,
        acquire_artifact_lock: bool = True,
    ) -> bool:
        """Background task: fully regenerate a scan's report with fresh LLM enrichment.

        Re-runs the ReportingAgent end-to-end (re-collect from specialist results → enrich →
        render ALL deliverables → truth-based enrichment_status) instead of patching
        engagement_data.json in place. The old in-place patch decided what to re-enrich from
        each finding's `enriched` flag — but that flag can read True while cvss_score is None
        (enrichment interrupted mid-way), so it skipped everything and falsely reported
        "full", and it left final_report.md / report.html / validated_findings.json stale.
        generate_all_deliverables redoes the work from source and rewrites every deliverable
        consistently, and its completeness audit persists the honest status.
        """
        if acquire_artifact_lock:
            async with self._async_repeater_artifact_lock(report_dir):
                return await self._run_re_enrichment(
                    scan_id, target_url, report_dir, acquire_artifact_lock=False,
                )

        from bugtrace.agents.reporting import ReportingAgent

        agent = ReportingAgent(
            scan_id=scan_id,
            target_url=target_url,
            output_dir=report_dir,
        )
        try:
            logger.info(f"Re-enrichment started for scan {scan_id}")
            await agent.generate_all_deliverables()
            # generate_all_deliverables persists the truth-based enrichment_status itself.
            logger.info(f"Re-enrichment completed for scan {scan_id}")
            return True

        except asyncio.CancelledError:
            self._update_enrichment_status_from_artifacts(scan_id, report_dir, agent)
            raise
        except Exception as e:
            logger.error(f"Re-enrichment failed for scan {scan_id}: {e}", exc_info=True)
            self._update_enrichment_status_from_artifacts(scan_id, report_dir, agent)
            return False

    def _update_enrichment_status_from_artifacts(
        self, scan_id: int, report_dir: Path, agent,
    ) -> None:
        status = "none"
        try:
            data = self._load_artifact_document(report_dir / "validated_findings.json")
            confirmed = [
                finding for finding in data.get("findings", [])
                if isinstance(finding, dict)
            ]
            status = agent._audit_enrichment_completeness(confirmed)["status"]
        except Exception:
            pass
        self.db.update_scan_enrichment_status(scan_id, status)
