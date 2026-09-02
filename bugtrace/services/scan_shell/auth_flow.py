"""ScanService shell mixin (auth). Hard max 2000 LOC."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict

from bugtrace.utils.logger import get_logger

if TYPE_CHECKING:
    from bugtrace.services.scan_context import ScanOptions

logger = get_logger(__name__)

class ScanAuthMixin:
    async def _setup_auth_tokens(self, options: ScanOptions, scan_ctx_id: str) -> Dict[str, Any]:
        """
        Setup authentication tokens before scan starts.

        Level 1: auth_token provided directly → store as-is.
        Level 2: auth.login_url + auth.credentials → POST to login, extract JWT.
        Level 3: auth.login_flow + totp_secret → Browser-based login with TOTP support.
        """
        from bugtrace.services.scan_context import store_auth_token

        session_data: Dict[str, Any] = {"cookies": [], "headers": {}}

        # Level 1: Direct token pass-through
        if options.auth_token:
            store_auth_token(scan_ctx_id, "api_provided", options.auth_token)
            session_data["headers"]["Authorization"] = f"Bearer {options.auth_token}"
            logger.info(f"Auth Level 1: Stored provided Bearer token for scan")
            return session_data

        # Level 2/3: Auto-login with credentials
        if options.auth and isinstance(options.auth, dict):
            login_url = options.auth.get("login_url", "")
            credentials = options.auth.get("credentials", {})
            login_flow = options.auth.get("login_flow", [])

            if not login_url or not credentials:
                logger.warning("Auth Level 2/3: Missing login_url or credentials, skipping")
                return session_data

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
                return session_data
            else:
                # Level 2: Simple POST login (supports TOTP via code generation)
                # Works for both plain credentials and TOTP-enabled APIs
                logger.info(f"Auth Level 2: Attempting login at {login_url} (TOTP: {bool(totp_secret)})")
                login_type = str(options.auth.get("login_type", "form")).lower()
                request_format = str(
                    options.auth.get("request_format")
                    or ("json" if login_type == "api" else "form")
                ).lower()
                return await self._simple_post_login(
                    scan_ctx_id,
                    login_url,
                    credentials,
                    request_format=request_format,
                )

        return session_data

    async def _simple_post_login(
        self,
        scan_ctx_id: str,
        login_url: str,
        credentials: dict,
        request_format: str = "form",
    ) -> Dict[str, Any]:
        """
        Level 2: POST request login with optional TOTP support.

        Builds the payload by:
        1. Copying username/password from credentials
        2. If totp_secret present: generates current TOTP code and tries common
           field names (totp_code, totp, code, otp, mfa_code) — sends all of them
           so the API can pick whichever it expects.
        """
        from bugtrace.services.scan_context import store_auth_token

        session_data: Dict[str, Any] = {"cookies": [], "headers": {}}

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
                    return session_data
                # Inject with multiple common field names — server will use whichever matches
                for field_name in ("totp_code", "totp", "code", "otp", "mfa_code", "verification_code"):
                    payload[field_name] = totp_code
                logger.info(f"Auth Level 2: Generated TOTP code and added to payload")

            if request_format not in {"form", "json"}:
                logger.warning(
                    f"Auth Level 2: Unknown request_format={request_format!r}; using form"
                )
                request_format = "form"

            request_kwargs = (
                {"json": payload} if request_format == "json" else {"data": payload}
            )
            async with httpx.AsyncClient(
                verify=False,
                timeout=15,
                follow_redirects=True,
            ) as client:
                resp = await client.post(login_url, **request_kwargs)

                if resp.status_code not in (200, 201, 204):
                    logger.warning(
                        f"Auth Level 2: Login failed (HTTP {resp.status_code}): {resp.text[:200]}"
                    )
                    return session_data

                # Extract JWT from response
                token = self._extract_jwt_from_response(resp)
                if token:
                    store_auth_token(scan_ctx_id, "auto_login", token)
                    session_data["headers"]["Authorization"] = f"Bearer {token}"
                    logger.info("Auth Level 2: JWT extracted and stored from login response")

                # Read the client's jar so cookies set before a redirect are retained.
                cookies = [
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                    }
                    for cookie in client.cookies.jar
                ]
                if cookies:
                    cookie_str = "; ".join(
                        f"{cookie['name']}={cookie['value']}" for cookie in cookies
                    )
                    store_auth_token(
                        scan_ctx_id,
                        "auto_login_cookies",
                        cookies=cookie_str,
                    )
                    session_data["cookies"] = cookies
                    session_data["headers"]["Cookie"] = cookie_str
                    logger.info(f"Auth Level 2: Stored {len(cookies)} session cookies")

                if not token and not cookies:
                    logger.warning(
                        "Auth Level 2: Login succeeded but no JWT or cookies found in response"
                    )

        except Exception as e:
            logger.error(f"Auth Level 2: Login request failed: {e}")

        return session_data

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
