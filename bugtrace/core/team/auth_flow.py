"""Authentication and token shell for TeamOrchestrator.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import re
import signal
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from shutil import move, rmtree
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx
from loguru import logger
from rich.live import Live

from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import event_bus
from bugtrace.core.http_manager import http_manager
from bugtrace.core.state_manager import get_state_manager
from bugtrace.core.pipeline import PipelineLifecycle, PipelinePhase, PipelineState
from bugtrace.core.phase_semaphores import (
    phase_semaphores, ScanPhase,
    get_exploitation_semaphore, get_analysis_semaphore, get_validation_semaphore,
    get_reporting_semaphore,
)
from bugtrace.core.batch_metrics import batch_metrics, reset_batch_metrics

# Agents / tools referenced by orchestrator shell methods
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.nuclei_agent import NucleiAgent
from bugtrace.agents.gospider_agent import GoSpiderAgent
from bugtrace.agents.analysis_agent import DASTySASTAgent
from bugtrace.agents.xss import XSSAgent
from bugtrace.agents.csti_agent import CSTIAgent
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.agents.jwt_agent import JWTAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.agents.asset_discovery_agent import AssetDiscoveryAgent
from bugtrace.agents.api_security_agent import APISecurityAgent
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.reattack import ReAttackAgent
from bugtrace.utils.token_scanner import find_jwts
from bugtrace.core.conductor import conductor
from bugtrace.core.verbose_events import create_emitter, install_ui_bridge
from bugtrace.core.surface import (
    ControlModel, ProbeObservation, build_control_model, differs_from_control,
    drop_insecure_duplicate_origins, names_a_resource,
)


class TeamAuthMixin:
    def set_auth(self, creds: str):
        self.auth_creds = creds

    def get_effective_headers(self) -> Dict[str, str]:
        """Return the merged header set the agents should send.

        Precedence (low -> high; right side wins on conflict):
            1. DEFAULT_HEADERS_JSON from bugtraceaicli.conf [SCAN]
            2. Auth-discovery headers (Authorization, Cookie) from scan_context
            3. Captured session headers from authenticated browser
            4. Per-scan custom_headers (CLI --header / API custom_headers)

        Why the order: per-scan custom headers are an explicit user action
        and must always win over implicit auto-discovered values. The browser
        captured session is auto-discovered (it represents what the
        authenticated page returned), so it sits BELOW per-scan overrides.
        The CLI's `bugtrace audit` and similar commands can therefore override
        Authorization on a per-scan basis even after browser auth.

        Why this lives on the auth mixin: every Mixin that constructs
        an agent eventually calls into here, and a single merge point
        guarantees the four-layer ordering rule the design spec calls for.
        Environment-variable placeholders are expanded at this point so
        secrets sourced from .env never linger in the orchestrator state.

        Returns a fresh dict on every call (callers may mutate freely).
        """
        from bugtrace.utils.headers import (
            merge_headers,
            parse_default_headers_json,
            resolve_env_placeholders,
        )

        # Layer 1: global defaults from the .conf. parse_default_headers_json
        # raises on malformed input; we caught that at Settings init time so it
        # cannot fail here.
        default_layer: Dict[str, str] = {}
        try:
            default_layer = parse_default_headers_json(
                getattr(__import__("bugtrace.core.config", fromlist=["settings"]).settings,
                        "DEFAULT_HEADERS_JSON", "")
            )
        except Exception:
            # Never break an in-flight scan because of a parsing surprise.
            default_layer = {}

        # Layer 2: auth-discovery headers stored in the scan_context. We pull
        # the admin-role defaults; the auth discovery flow already filters
        # tokens by role. Headers stay in-memory only — never logged.
        auth_layer: Dict[str, str] = {}
        try:
            scan_ctx = getattr(self, "scan_context", "")
            if scan_ctx:
                from bugtrace.services.scan_context import get_scan_auth_headers
                auth_layer = get_scan_auth_headers(scan_ctx)
        except Exception:
            auth_layer = {}

        # Layer 3: captured session headers from the authenticated browser.
        # These are auto-discovered (implicit), so per-scan overrides (layer 4)
        # must still take precedence — see docstring ordering above.
        captured: Dict[str, str] = dict(
            (getattr(self, "captured_session", {}) or {}).get("headers", {}) or {}
        )

        # Layer 4: per-scan custom headers (CLI / API). May override
        # Authorization or Cookie (explicit per-scan override is the rule).
        # This is the rightmost layer; merge_headers() lets it win.
        custom_layer: Dict[str, str] = dict(getattr(self, "_custom_headers", {}) or {})

        merged = merge_headers(default_layer, auth_layer, captured, custom_layer)
        # Resolve env placeholders at the boundary so any debug log of the
        # resulting dict (we don't do this — but a future caller might) sees
        # the literal value. Callers that need the raw dict for redaction can
        # still read merge_headers output before this step.
        return resolve_env_placeholders(merged)

    async def _handle_authentication(self):
        """Handle authentication if credentials provided."""
        if not self.auth_creds:
            return

        dashboard.set_phase("🔐 BREACHING GATES")
        dashboard.current_agent = "AuthAgent"
        logger.info(f"Initiating authenticated session for {self.auth_creds.split(':')[0]}...")

        from bugtrace.tools.visual.browser import browser_manager
        login_url = f"{self.target.rstrip('/')}/login"

        try:
            success = await browser_manager.login(login_url, self.auth_creds)
            if success:
                logger.info("Authentication Successful. Session captured.")
                # Capture session data for specialists
                self.captured_session = await browser_manager.get_session_data()
                logger.debug(f"Captured {len(self.captured_session.get('cookies', []))} cookies")
                
                # Store in global scan context for specialists that pull from it
                from bugtrace.services.scan_context import store_auth_token
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.captured_session.get("cookies", [])])
                store_auth_token(str(self.scan_id), "browser_session", cookies=cookie_str)
            else:
                logger.warning("Authentication Failed. Proceeding as guest.")
        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            logger.error(f"Authentication Error: {e}. Proceeding as guest.")
        finally:
            try:
                if hasattr(browser_manager, 'cleanup_auth_session'):
                    await browser_manager.cleanup_auth_session()
            except Exception as cleanup_err:
                logger.debug(f"Auth session cleanup warning: {cleanup_err}")

    async def _perform_authentication(self):
        """
        Perform browser-based authentication using YAML config.

        Supports:
        - Custom login flows with variable substitution ($username, $password, $totp)
        - TOTP-based 2FA authentication
        - Success condition verification
        - Pre-scan verification with detailed logging
        """
        if not self.auth_config:
            return

        dashboard.set_phase("🔐 AUTHENTICATING")
        dashboard.current_agent = "AuthAgent"

        # Create verbose event emitter for auth phase (WebSocket streaming)
        self._auth_emitter = create_emitter("AuthAgent", str(self.scan_id))

        login_url = self.auth_config.get("login_url", "")
        credentials = self.auth_config.get("credentials", {})
        login_flow = self.auth_config.get("login_flow", [])
        success_condition = self.auth_config.get("success_condition", {})

        # Resolve relative login_url (support both relative and absolute URLs)
        # Avoid doubling path if target already includes the login_url path
        from urllib.parse import urlparse
        target_path = urlparse(self.target).path.rstrip("/")
        login_path = login_url.lstrip("/") if login_url.startswith("/") else login_url

        if login_url.startswith("http"):
            # Already absolute URL, use as-is
            pass
        elif target_path and target_path.endswith("/" + login_path.rstrip("/")):
            # Target already includes the login path (e.g., target=/WebPA/UserOverview, login_url=/WebPA/UserOverview)
            login_url = self.target.rstrip("/")
            logger.debug(f"[AUTH] Login path already in target, using: {login_url}")
        elif login_url.startswith("/"):
            # Relative URL starting with /
            base_url = self.target.split(target_path)[0].rstrip("/") if target_path else self.target.rstrip("/")
            login_url = base_url + login_url
        else:
            login_url = self.target.rstrip("/") + "/" + login_url

        # Convert natural language instructions to commands if needed
        from bugtrace.utils.auth_flow_parser import is_natural_language_flow, convert_natural_flow_to_commands
        if login_flow and is_natural_language_flow(login_flow):
            logger.info("[AUTH] Detected natural language flow, converting to commands...")
            login_flow = convert_natural_flow_to_commands(login_flow, credentials, login_url)
            logger.info(f"[AUTH] Converted to {len(login_flow)} executable steps")

        totp_enabled = bool(credentials.get("totp_secret"))
        username = credentials.get("username", credentials.get("email", ""))

        # Log auth start with details (use logger for server logs)
        logger.info("=" * 50)
        logger.info("AUTHENTICATION PHASE STARTING")
        logger.info(f"  Target: {login_url}")
        logger.info(f"  User: {username}")
        logger.info(f"  TOTP: {'Enabled' if totp_enabled else 'Disabled'}")
        logger.info(f"  Flow steps: {len(login_flow)}")
        logger.info("=" * 50)

        # Emit auth phase started for WebSocket
        self._auth_emitter.emit("auth.phase.started", {
            "target": login_url,
            "user": username,
            "totp_enabled": totp_enabled,
            "total_steps": len(login_flow),
        })

        from bugtrace.tools.visual.browser import browser_manager
        from bugtrace.services.scan_context import store_auth_token

        try:
            await browser_manager.start()
            logger.info("[AUTH] Browser started")

            async with browser_manager.get_page() as page:
                # Navigate to login page
                logger.info(f"[AUTH] Navigating to {login_url}...")
                await page.goto(login_url, wait_until="networkidle", timeout=30000)
                logger.info(f"[AUTH] Page loaded: {page.url[:60]}...")

                # Execute login flow with detailed logging
                if login_flow:
                    success = await self._execute_auth_flow(page, credentials, login_flow)
                else:
                    logger.info("[AUTH] No login_flow defined, using auto-detect")
                    success = await self._auto_detect_auth(page, credentials)

                if not success:
                    logger.error("[AUTH] Login flow FAILED - steps did not complete")
                    logger.warning("[AUTH] Scan will proceed WITHOUT authentication")
                    self._auth_emitter.emit("auth.failed", {"reason": "Login flow did not complete"})
                    # Save error screenshot
                    await self._save_auth_screenshot(page, "auth_failed")
                    return

                # Verify success condition
                logger.info("[AUTH] Verifying login success...")
                if success_condition:
                    cond_type = success_condition.get("type", "")
                    cond_value = success_condition.get("value", "")
                    logger.info(f"[AUTH] Checking: {cond_type} = '{cond_value}'")

                    if not await self._check_auth_success(page, success_condition):
                        logger.error(f"[AUTH] VERIFICATION FAILED!")
                        logger.error(f"[AUTH] Current URL: {page.url}")
                        logger.warning("[AUTH] Scan will proceed WITHOUT authentication")
                        self._auth_emitter.emit("auth.failed", {"reason": "Success condition not met", "url": page.url})
                        await self._save_auth_screenshot(page, "auth_verify_failed")
                        return

                    logger.info("[AUTH] Success condition VERIFIED!")
                    self._auth_emitter.emit("auth.verified", {"condition": cond_type, "value": cond_value})
                else:
                    logger.warning("[AUTH] No success_condition defined, assuming success")

                # Extract and store cookies
                cookies = await page.context.cookies()
                if cookies:
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])

                    # Store with BOTH IDs so all agents can find them
                    # scan_id (numeric) - used by some agents
                    # scan_context (string) - used by other agents
                    store_auth_token(str(self.scan_id), "browser_auth", cookies=cookie_str)
                    store_auth_token(self.scan_context, "browser_auth", cookies=cookie_str)
                    self.captured_session["cookies"] = cookies

                    # Mark that this scan requires authenticated session
                    self._auth_required = True

                    # Log important cookies
                    session_cookies = [c for c in cookies if 'session' in c['name'].lower() or c['name'] in ['JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId']]
                    logger.info(f"[AUTH] Captured {len(cookies)} cookies")
                    logger.info(f"[AUTH] Stored for scan_id={self.scan_id} AND scan_context={self.scan_context[:30]}...")
                    for sc in session_cookies[:3]:
                        logger.info(f"[AUTH]   - {sc['name']}: {sc['value'][:20]}...")
                else:
                    logger.warning("[AUTH] WARNING: No cookies captured!")

                # Try to extract JWT from storage
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
                    store_auth_token(str(self.scan_id), "browser_jwt", token)
                    store_auth_token(self.scan_context, "browser_jwt", token)
                    logger.info(f"[AUTH] JWT extracted: {token[:30]}...")

                # Save success screenshot
                await self._save_auth_screenshot(page, "auth_success")

                # Final summary
                logger.info("=" * 50)
                logger.info("AUTHENTICATION SUCCESSFUL")
                logger.info(f"  Session cookies: {len(cookies)}")
                logger.info(f"  JWT token: {'Yes' if token else 'No'}")
                logger.info("  Scan will use authenticated session")
                logger.info("=" * 50)

                # Emit success event for WebSocket
                self._auth_emitter.emit("auth.success", {
                    "cookies_count": len(cookies) if cookies else 0,
                    "jwt_captured": bool(token),
                })

        except Exception as e:
            logger.error(f"YAML auth error: {e}", exc_info=True)
            logger.error(f"[AUTH] EXCEPTION: {e}")
            logger.warning("[AUTH] Scan will proceed WITHOUT authentication")
            if hasattr(self, '_auth_emitter'):
                self._auth_emitter.emit("auth.failed", {"reason": str(e)})

    async def _save_auth_screenshot(self, page, prefix: str):
        """Save authentication screenshot for verification."""
        try:
            import uuid
            screenshot_path = self.report_dir / "logs" / f"{prefix}_{uuid.uuid4().hex[:8]}.png"
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(screenshot_path))
            logger.info(f"[AUTH] Screenshot saved: {screenshot_path.name}")
        except Exception as e:
            logger.debug(f"Failed to save auth screenshot: {e}")

    async def _execute_auth_flow(self, page, credentials: dict, login_flow: list) -> bool:
        """Execute custom login flow with variable substitution and detailed logging."""
        from bugtrace.utils.totp import get_totp_code

        username = credentials.get("username", credentials.get("email", ""))
        password = credentials.get("password", "")
        totp_secret = credentials.get("totp_secret", "")

        total_steps = len(login_flow)
        logger.info(f"[AUTH] Executing {total_steps} login steps...")

        for i, step in enumerate(login_flow, 1):
            try:
                step_resolved = step
                step_resolved = step_resolved.replace("$username", username)
                step_resolved = step_resolved.replace("$email", username)
                step_resolved = step_resolved.replace("$password", "***")  # Don't log password

                totp_code = None
                # Generate TOTP if needed
                if "$totp" in step:
                    if not totp_secret:
                        logger.error(f"[AUTH] Step {i}: FAILED - $totp required but no totp_secret")
                        self._auth_emitter.emit("auth.step.failed", {"step": i, "total": total_steps, "error": "TOTP required but no secret"})
                        return False
                    totp_code = get_totp_code(totp_secret)
                    if not totp_code:
                        logger.error(f"[AUTH] Step {i}: FAILED - Could not generate TOTP")
                        self._auth_emitter.emit("auth.step.failed", {"step": i, "total": total_steps, "error": "Could not generate TOTP"})
                        return False
                    step_resolved = step.replace("$totp", totp_code)
                    step_resolved = step_resolved.replace("$username", username)
                    step_resolved = step_resolved.replace("$password", "***")
                    logger.info(f"[AUTH] Step {i}/{total_steps}: {step_resolved} (TOTP: {totp_code})")
                else:
                    # Log step (mask password)
                    log_step = step_resolved[:60] + "..." if len(step_resolved) > 60 else step_resolved
                    logger.info(f"[AUTH] Step {i}/{total_steps}: {log_step}")

                # Emit step event for WebSocket
                self._auth_emitter.emit("auth.step", {
                    "step": i,
                    "total": total_steps,
                    "action": step_resolved[:80],
                    "totp": totp_code if totp_code else None,
                })

                # Execute the actual step (with real password)
                actual_step = step.replace("$username", username).replace("$email", username).replace("$password", password)
                if "$totp" in actual_step:
                    actual_step = actual_step.replace("$totp", totp_code)

                await self._execute_auth_step(page, actual_step)
                await page.wait_for_timeout(500)

            except Exception as e:
                logger.error(f"[AUTH] Step {i}: FAILED - {e}")
                logger.error(f"Auth step failed: {step} -> {e}")
                self._auth_emitter.emit("auth.step.failed", {"step": i, "total": total_steps, "error": str(e)})
                return False

        logger.info(f"[AUTH] All {total_steps} steps completed")
        self._auth_emitter.emit("auth.steps.complete", {"total": total_steps})
        return True

    async def _execute_auth_step(self, page, step: str):
        """Execute a single login step instruction with Microsoft SSO support."""
        import re
        step_lower = step.lower()

        if step_lower.startswith("type ") or step_lower.startswith("enter "):
            # Parse: "Type <value> into the <field> field"
            match = re.match(r"(?:type|enter)\s+['\"]?(.+?)['\"]?\s+(?:into|in)\s+(?:the\s+)?(.+?)(?:\s+field)?$", step, re.IGNORECASE)
            if match:
                value, field_desc = match.groups()
                field_lower = field_desc.lower()

                # Build selectors - include Microsoft SSO and generic form selectors
                selectors = [
                    f"input[name='{field_desc}']",  # Exact match first (loginfmt, passwd, otc)
                    f"input#idTxtBx_SAOTCC_OTC" if 'otc' in field_lower else None,  # MS TOTP
                    f"input[name*='{field_desc}' i]", f"input[id*='{field_desc}' i]",
                    f"input[placeholder*='{field_desc}' i]", f"input[type='{field_desc}']",
                    f"[aria-label*='{field_desc}' i]",
                ]

                # Add flexible selectors for common field types
                if any(x in field_lower for x in ['user', 'email', 'login', 'loginfmt']):
                    selectors.extend([
                        "input[type='email']", "input[type='text'][name*='user' i]",
                        "input[type='text'][name*='email' i]", "input[type='text'][name*='login' i]",
                        "input[name='username']", "input[name='email']", "input[name='login']",
                        "input[id*='user' i]", "input[id*='email' i]", "input[id*='login' i]",
                        "input[placeholder*='user' i]", "input[placeholder*='email' i]",
                        "input[autocomplete='username']", "input[autocomplete='email']",
                    ])
                elif 'pass' in field_lower or 'pwd' in field_lower:
                    selectors.extend([
                        "input[type='password']", "input[name='password']", "input[name='passwd']",
                        "input[id*='pass' i]", "input[autocomplete='current-password']",
                    ])
                elif any(x in field_lower for x in ['totp', 'otp', 'code', 'otc', 'mfa', '2fa']):
                    selectors.extend([
                        "input[name*='totp' i]", "input[name*='otp' i]", "input[name*='code' i]",
                        "input[maxlength='6']", "input[type='text'][inputmode='numeric']",
                        "input[id*='totp' i]", "input[id*='otp' i]", "input[id*='code' i]",
                    ])

                selectors = [s for s in selectors if s]  # Remove None
                for selector in selectors:
                    try:
                        el = await page.query_selector(selector)
                        if el:
                            await el.fill(value)
                            return
                    except Exception:
                        continue
                raise Exception(f"Could not find input field: {field_desc}")

        elif step_lower.startswith("click "):
            match = re.search(r"['\"](.+?)['\"]", step)
            if match:
                button_text = match.group(1)
                # Microsoft SSO button IDs
                ms_button_ids = {
                    "next": "input#idSIButton9",
                    "sign in": "input#idSIButton9",
                    "signin": "input#idSIButton9",
                    "verify": "input#idSubmit_SAOTCC_Continue",
                    "no": "input#idBtn_Back",
                    "yes": "input#idSIButton9",
                }
                # Check for Microsoft-specific button first
                ms_selector = ms_button_ids.get(button_text.lower())
                if ms_selector:
                    try:
                        el = await page.query_selector(ms_selector)
                        if el:
                            await el.click()
                            await page.wait_for_load_state("networkidle", timeout=10000)
                            return
                    except Exception:
                        pass

                selectors = [
                    f"button:has-text('{button_text}')", f"input[type='submit'][value*='{button_text}' i]",
                    f"a:has-text('{button_text}')", f"[role='button']:has-text('{button_text}')",
                    f"input[type='submit']",  # Fallback to any submit
                ]
                for selector in selectors:
                    try:
                        el = await page.query_selector(selector)
                        if el:
                            await el.click()
                            await page.wait_for_load_state("networkidle", timeout=10000)
                            return
                    except Exception:
                        continue
                raise Exception(f"Could not find button: {button_text}")

        elif "wait" in step_lower:
            match = re.search(r"(\d+)", step)
            if match:
                seconds = int(match.group(1))
                await page.wait_for_timeout(seconds * 1000)

        else:
            logger.warning(f"Unknown auth step: {step}")

    async def _auto_detect_auth(self, page, credentials: dict) -> bool:
        """Auto-detect and fill login form."""
        from bugtrace.utils.totp import get_totp_code

        username = credentials.get("username", credentials.get("email", ""))
        password = credentials.get("password", "")
        totp_secret = credentials.get("totp_secret", "")

        try:
            # Fill username/email
            for sel in ["input[type='email']", "input[name*='email' i]", "input[name*='user' i]"]:
                el = await page.query_selector(sel)
                if el:
                    await el.fill(username)
                    break

            # Fill password
            password_el = await page.query_selector("input[type='password']")
            if password_el:
                await password_el.fill(password)

            # Submit
            for sel in ["button[type='submit']", "input[type='submit']", "button:has-text('Sign in')", "button:has-text('Login')"]:
                el = await page.query_selector(sel)
                if el:
                    await el.click()
                    break

            await page.wait_for_load_state("networkidle", timeout=15000)

            # Handle TOTP if secret provided
            if totp_secret:
                for sel in ["input[name*='otp' i]", "input[name*='totp' i]", "input[name*='code' i]", "input[maxlength='6']"]:
                    el = await page.query_selector(sel)
                    if el:
                        totp_code = get_totp_code(totp_secret)
                        if totp_code:
                            await el.fill(totp_code)
                            logger.info("Entered TOTP code for 2FA")
                            for submit_sel in ["button[type='submit']", "input[type='submit']"]:
                                submit_el = await page.query_selector(submit_sel)
                                if submit_el:
                                    await submit_el.click()
                                    break
                            await page.wait_for_load_state("networkidle", timeout=10000)
                        break

            return True

        except Exception as e:
            logger.error(f"Auto-detect auth failed: {e}")
            return False

    async def _check_auth_success(self, page, condition: dict) -> bool:
        """Check if login success condition is met."""
        cond_type = condition.get("type", "")
        value = condition.get("value", "")

        try:
            current_url = page.url

            if cond_type == "url_contains":
                return value in current_url
            elif cond_type == "url_equals_exactly":
                return current_url == value
            elif cond_type == "element_present":
                el = await page.query_selector(value)
                return el is not None
            elif cond_type == "text_contains":
                content = await page.content()
                return value in content
            else:
                return True

        except Exception as e:
            logger.error(f"Success condition check failed: {e}")
            return False

    async def _run_auth_discovery(self, recon_dir: Path, urls_to_scan: List[str]) -> Dict:
        """Run AuthDiscoveryAgent for JWT/cookie discovery.
        Returns dict with 'jwts' and 'cookies' lists."""
        from bugtrace.agents.auth_discovery_agent import AuthDiscoveryAgent

        auth_discovery_dir = recon_dir / "auth_discovery"
        auth_discovery_dir.mkdir(exist_ok=True)

        self._v.emit("recon.auth.started", {
            "target_url": self.target,
            "urls_count": min(5, len(urls_to_scan)),
        })
        auth_agent = AuthDiscoveryAgent(
            target=self.target,
            report_dir=auth_discovery_dir,
            urls_to_scan=urls_to_scan,
            verbose_emitter=self._v,
        )
        auth_results = await auth_agent.run()

        # Inject pre-loaded auth tokens (from Level 1/2) into results so JWTAgent can test them
        auth_results = self._inject_preloaded_tokens(auth_results, auth_discovery_dir)

        self._v.emit("recon.auth.completed", {
            "jwts_found": len(auth_results['jwts']),
            "cookies_found": len(auth_results['cookies']),
        })
        logger.info(
            f"[AuthDiscovery] Found {len(auth_results['jwts'])} JWTs, "
            f"{len(auth_results['cookies'])} cookies"
        )
        return auth_results

    def _inject_preloaded_tokens(self, auth_results: Dict, auth_discovery_dir: Path) -> Dict:
        """Inject pre-loaded auth tokens (Level 1/2) into AuthDiscovery results.

        If ScanService stored a JWT via _setup_auth_tokens(), inject it here
        so Phase 3 routes it to JWTAgent for secret cracking/algorithm testing.
        """
        from bugtrace.services.scan_context import get_scan_auth_headers

        headers = get_scan_auth_headers(self.scan_context)
        if not headers:
            return auth_results

        token = headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not token or not token.startswith("eyJ"):
            return auth_results

        # Check if this JWT is already in results (avoid duplicates)
        existing_tokens = {j.get("token") for j in auth_results.get("jwts", [])}
        if token in existing_tokens:
            return auth_results

        # Inject as a discovered JWT
        jwt_entry = {
            "token": token,
            "source": "api_provided",
            "url": self.target,
            "context": "scan_config",
        }
        auth_results["jwts"].append(jwt_entry)
        logger.info("[AuthDiscovery] Injected pre-loaded auth token for JWTAgent testing")

        # Update the jwts_discovered.json file so Phase 3 picks it up
        jwt_file = auth_discovery_dir / "jwts_discovered.json"
        try:
            if jwt_file.exists():
                with open(jwt_file, 'r') as f:
                    data = json.load(f)
            else:
                data = {"jwts": [], "timestamp": datetime.now().isoformat()}

            data["jwts"].append(jwt_entry)
            with open(jwt_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to update jwts_discovered.json: {e}")

        return auth_results

    async def _scan_for_tokens(self, urls_to_scan: list):
        """Scan discovered URLs for authentication tokens."""
        logger.info("🔍 Scanning discovery artifacts for authentication tokens...")
        combined_recon_data = " ".join(urls_to_scan) + " " + json.dumps(self.tech_profile)
        found_jwts = find_jwts(combined_recon_data)

        if found_jwts:
            logger.warning(f"🔑 Found {len(found_jwts)} potential JWT(s) in recon data!")
            for token in found_jwts:
                # EventBus exposes `emit` (async), not `publish`; calling the
                # missing method raised AttributeError that aborted the scan
                # (URL-list mode) or silently collapsed urls_to_scan to the root
                # (normal mode) whenever recon surfaced a JWT.
                await self.event_bus.emit("auth_token_found", {
                    "token": token,
                    "url": self.target,
                    "location": "recon_discovery"
                })

    async def _load_auth_discovery_findings(self, auth_discovery_dir: Path) -> List[Dict]:
        """
        Load authentication artifacts from AuthDiscoveryAgent and convert to findings.

        Reads:
        - jwts_discovered.json → JWT_DISCOVERED findings
        - cookies_discovered.json → SESSION_COOKIE_DISCOVERED findings

        Returns:
            List of findings ready for ThinkingAgent processing
        """
        import json
        findings = []

        # Load JWTs
        jwt_file = auth_discovery_dir / "jwts_discovered.json"
        if jwt_file.exists():
            try:
                with open(jwt_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                jwts = data.get("jwts", [])
                logger.info(f"[AuthDiscovery] Loading {len(jwts)} JWTs from {jwt_file.name}")

                for jwt_info in jwts:
                    finding = {
                        "type": "JWT_DISCOVERED",
                        "url": jwt_info.get("url", ""),
                        "token": jwt_info.get("token", ""),
                        "source": jwt_info.get("source", ""),
                        "parameter": jwt_info.get("storage_key", jwt_info.get("cookie_name", "N/A")),
                        "context": jwt_info.get("context", "unknown"),
                        "severity": "INFO",
                        "agent": "AuthDiscoveryAgent",
                        "timestamp": data.get("timestamp", ""),
                        "metadata": jwt_info.get("metadata", {}),
                        "_source_file": str(jwt_file),
                        "_scan_context": self.scan_context,
                        "_report_files": {
                            "json": str(jwt_file),
                            "markdown": str(auth_discovery_dir / "auth_discovery.md")
                        }
                    }
                    findings.append(finding)

            except Exception as e:
                logger.error(f"Failed to load {jwt_file}: {e}")

        # Load session cookies
        cookie_file = auth_discovery_dir / "cookies_discovered.json"
        if cookie_file.exists():
            try:
                with open(cookie_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                cookies = data.get("cookies", [])
                logger.info(f"[AuthDiscovery] Loading {len(cookies)} cookies from {cookie_file.name}")

                for cookie_info in cookies:
                    finding = {
                        "type": "SESSION_COOKIE_DISCOVERED",
                        "url": cookie_info.get("url", ""),
                        "cookie_name": cookie_info.get("name", ""),
                        "cookie_value": cookie_info.get("value", ""),
                        "source": "cookie_jar",
                        "severity": "INFO",
                        "agent": "AuthDiscoveryAgent",
                        "timestamp": data.get("timestamp", ""),
                        "metadata": cookie_info.get("metadata", {}),
                        "_source_file": str(cookie_file),
                        "_scan_context": self.scan_context,
                        "_report_files": {
                            "json": str(cookie_file),
                            "markdown": str(auth_discovery_dir / "auth_discovery.md")
                        }
                    }
                    findings.append(finding)

            except Exception as e:
                logger.error(f"Failed to load {cookie_file}: {e}")

        return findings

