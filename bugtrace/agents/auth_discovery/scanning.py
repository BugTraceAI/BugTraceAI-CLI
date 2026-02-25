"""
Auth Discovery Agent — I/O functions.

All functions in this module perform HTTP I/O, browser interaction, or
file system operations. Dependencies are passed as explicit parameters.

Contents:
    - scan_url: Scan a single URL for authentication artifacts via browser
    - extract_from_cookies: Extract JWT cookies and session cookies from browser
    - extract_from_storage: Extract JWTs from localStorage and sessionStorage
    - extract_from_html: Extract JWTs from HTML content via regex
    - extract_from_javascript: Extract JWTs from loaded JavaScript files
    - attempt_auto_registration: Attempt auto-registration to obtain JWTs
"""

import asyncio
import json
import uuid
import re
from typing import Dict, List, Any, Tuple
from loguru import logger

from bugtrace.core.http_orchestrator import orchestrator, DestinationType

from bugtrace.agents.auth_discovery.core import (
    JWT_PATTERN,
    is_jwt,
    is_session_cookie,
    find_jwt_context_in_html,
    is_duplicate_jwt,
    is_duplicate_cookie,
)


async def extract_from_cookies(
    page,
    url: str,
    discovered_jwts: List[Dict],
    discovered_cookies: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:  # I/O
    """Extract both JWT cookies and session cookies from browser page.

    Args:
        page: Playwright page object.
        url: The current page URL.
        discovered_jwts: Current list of discovered JWTs (for dedup).
        discovered_cookies: Current list of discovered cookies (for dedup).

    Returns:
        Tuple of (new_jwts, new_cookies) to append to the discovery lists.
    """
    new_jwts: List[Dict] = []
    new_cookies: List[Dict] = []

    try:
        cookies = await page.context.cookies()

        for cookie in cookies:
            cookie_value = cookie.get("value", "")
            cookie_name = cookie.get("name", "")

            if is_jwt(cookie_value):
                if not is_duplicate_jwt(cookie_value, discovered_jwts + new_jwts):
                    new_jwts.append({
                        "token": cookie_value,
                        "source": "cookie",
                        "cookie_name": cookie_name,
                        "url": url,
                        "context": "cookie_jar",
                        "metadata": {
                            "domain": cookie.get("domain"),
                            "path": cookie.get("path"),
                            "secure": cookie.get("secure", False),
                            "httpOnly": cookie.get("httpOnly", False),
                            "sameSite": cookie.get("sameSite", "None"),
                        },
                    })
                    logger.info(f"JWT cookie found: {cookie_name}")

            elif is_session_cookie(cookie_name):
                if not is_duplicate_cookie(cookie_name, cookie_value, discovered_cookies + new_cookies):
                    new_cookies.append({
                        "name": cookie_name,
                        "value": cookie_value,
                        "source": "cookie_jar",
                        "url": url,
                        "metadata": {
                            "domain": cookie.get("domain"),
                            "path": cookie.get("path"),
                            "secure": cookie.get("secure", False),
                            "httpOnly": cookie.get("httpOnly", False),
                            "sameSite": cookie.get("sameSite", "None"),
                        },
                    })
                    logger.info(f"Session cookie found: {cookie_name}")

    except Exception as e:
        logger.debug(f"Cookie extraction failed: {e}")

    return new_jwts, new_cookies


async def extract_from_storage(
    page,
    url: str,
    discovered_jwts: List[Dict],
) -> List[Dict]:  # I/O
    """Extract JWTs from localStorage and sessionStorage.

    Args:
        page: Playwright page object.
        url: The current page URL.
        discovered_jwts: Current list of discovered JWTs (for dedup).

    Returns:
        List of new JWT info dicts to append to the discovery list.
    """
    new_jwts: List[Dict] = []

    try:
        storage_data = await page.evaluate("""
            () => {
                const local = {};
                const session = {};

                try {
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        local[key] = localStorage.getItem(key);
                    }
                } catch (e) {}

                try {
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        session[key] = sessionStorage.getItem(key);
                    }
                } catch (e) {}

                return { local, session };
            }
        """)

        all_existing = discovered_jwts + new_jwts

        for key, value in storage_data.get("local", {}).items():
            if value and is_jwt(value):
                if not is_duplicate_jwt(value, all_existing):
                    new_jwts.append({
                        "token": value,
                        "source": "localStorage",
                        "storage_key": key,
                        "url": url,
                        "context": "client_storage",
                    })
                    all_existing = discovered_jwts + new_jwts
                    logger.info(f"JWT in localStorage: {key}")

        for key, value in storage_data.get("session", {}).items():
            if value and is_jwt(value):
                if not is_duplicate_jwt(value, all_existing):
                    new_jwts.append({
                        "token": value,
                        "source": "sessionStorage",
                        "storage_key": key,
                        "url": url,
                        "context": "client_storage",
                    })
                    all_existing = discovered_jwts + new_jwts
                    logger.info(f"JWT in sessionStorage: {key}")

    except Exception as e:
        logger.debug(f"Storage extraction failed: {e}")

    return new_jwts


async def extract_from_html(
    page,
    url: str,
    discovered_jwts: List[Dict],
) -> List[Dict]:  # I/O
    """Extract JWTs from HTML content via regex.

    Args:
        page: Playwright page object.
        url: The current page URL.
        discovered_jwts: Current list of discovered JWTs (for dedup).

    Returns:
        List of new JWT info dicts.
    """
    new_jwts: List[Dict] = []

    try:
        html = await page.content()
        all_existing = discovered_jwts + new_jwts

        for match in JWT_PATTERN.finditer(html):
            token = match.group(1)
            if is_jwt(token) and not is_duplicate_jwt(token, all_existing):
                context = find_jwt_context_in_html(html, token)
                new_jwts.append({
                    "token": token,
                    "source": "html_content",
                    "url": url,
                    "context": context,
                    "extraction_method": "regex_scan",
                })
                all_existing = discovered_jwts + new_jwts
                logger.info(f"JWT in HTML: {context}")

    except Exception as e:
        logger.debug(f"HTML extraction failed: {e}")

    return new_jwts


async def extract_from_javascript(
    page,
    url: str,
    discovered_jwts: List[Dict],
) -> List[Dict]:  # I/O
    """Extract JWTs from loaded JavaScript files.

    Args:
        page: Playwright page object.
        url: The current page URL.
        discovered_jwts: Current list of discovered JWTs (for dedup).

    Returns:
        List of new JWT info dicts.
    """
    new_jwts: List[Dict] = []

    try:
        script_urls = await page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('script[src]'))
                           .map(s => s.src)
                           .filter(src => src && src.startsWith('http'));
            }
        """)

        all_existing = discovered_jwts + new_jwts

        for script_url in script_urls[:10]:
            try:
                async with orchestrator.session(DestinationType.TARGET) as session:
                    async with session.get(script_url, timeout=10) as resp:
                        if resp.status == 200:
                            js_content = await resp.text()

                            for match in JWT_PATTERN.finditer(js_content):
                                token = match.group(1)
                                if is_jwt(token) and not is_duplicate_jwt(token, all_existing):
                                    new_jwts.append({
                                        "token": token,
                                        "source": "javascript_file",
                                        "script_url": script_url,
                                        "page_url": url,
                                        "context": "external_script",
                                    })
                                    all_existing = discovered_jwts + new_jwts
                                    logger.info(f"JWT in JS file: {script_url}")

            except Exception as e:
                logger.debug(f"Failed to scan JS file {script_url}: {e}")

    except Exception as e:
        logger.debug(f"JavaScript extraction failed: {e}")

    return new_jwts


async def scan_url(
    url: str,
    discovered_jwts: List[Dict],
    discovered_cookies: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:  # I/O
    """Scan a single URL for authentication artifacts using browser.

    Sets up request interceptor for headers, navigates to URL, and extracts
    tokens from cookies, storage, HTML, and JavaScript.

    Args:
        url: The URL to scan.
        discovered_jwts: Current list of discovered JWTs (for dedup).
        discovered_cookies: Current list of discovered cookies (for dedup).

    Returns:
        Tuple of (new_jwts, new_cookies) to append to the discovery lists.
    """
    from bugtrace.tools.visual.browser import browser_manager

    all_new_jwts: List[Dict] = []
    all_new_cookies: List[Dict] = []

    async with browser_manager.get_page() as page:
        # Storage for intercepted tokens
        intercepted_tokens: List[Dict] = []

        async def handle_request(request):
            auth_header = request.headers.get("authorization", "")
            if "Bearer " in auth_header:
                token = auth_header.split("Bearer ")[1].strip()
                if is_jwt(token):
                    intercepted_tokens.append({
                        "token": token,
                        "source": "http_header_authorization",
                        "url": url,
                        "context": "request",
                    })

            for header_name in ["x-auth-token", "x-access-token", "token"]:
                header_value = request.headers.get(header_name, "")
                if header_value and is_jwt(header_value):
                    intercepted_tokens.append({
                        "token": header_value,
                        "source": f"http_header_{header_name}",
                        "url": url,
                        "context": "request",
                    })

        page.on("request", handle_request)

        # Navigate to URL
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception as e:
            logger.warning(f"Navigation timeout/error for {url}: {e}")

        # Combine existing + new for dedup across extraction phases
        combined_jwts = list(discovered_jwts)
        combined_cookies = list(discovered_cookies)

        # Extract from all sources
        results = await asyncio.gather(
            extract_from_cookies(page, url, combined_jwts, combined_cookies),
            extract_from_storage(page, url, combined_jwts),
            extract_from_html(page, url, combined_jwts),
            extract_from_javascript(page, url, combined_jwts),
            return_exceptions=True,
        )

        # Process results
        if not isinstance(results[0], Exception):
            cookie_jwts, cookie_cookies = results[0]
            all_new_jwts.extend(cookie_jwts)
            all_new_cookies.extend(cookie_cookies)
            combined_jwts.extend(cookie_jwts)

        if not isinstance(results[1], Exception):
            all_new_jwts.extend(results[1])
            combined_jwts.extend(results[1])

        if not isinstance(results[2], Exception):
            all_new_jwts.extend(results[2])
            combined_jwts.extend(results[2])

        if not isinstance(results[3], Exception):
            all_new_jwts.extend(results[3])
            combined_jwts.extend(results[3])

        # Add intercepted tokens
        for token_info in intercepted_tokens:
            if not is_duplicate_jwt(token_info["token"], combined_jwts):
                all_new_jwts.append(token_info)
                combined_jwts.append(token_info)
                logger.info(f"JWT found in {token_info['source']}")

    return all_new_jwts, all_new_cookies


async def attempt_auto_registration(
    urls_to_scan: List[str],
    discovered_jwts: List[Dict],
) -> List[Dict]:  # I/O
    """Attempt auto-registration on discovered auth endpoints to obtain JWTs.

    Generic approach -- works with any app that has open registration:
    1. Scan recon URLs for registration/signup endpoints
    2. POST with random test credentials
    3. Extract JWT from response body

    Args:
        urls_to_scan: List of recon URLs to search for registration endpoints.
        discovered_jwts: Current list of discovered JWTs (for dedup).

    Returns:
        List of new JWT info dicts obtained via auto-registration.
    """
    new_jwts: List[Dict] = []

    register_patterns = [
        "register", "signup", "sign-up", "sign_up", "create-account",
        "create_account", "join", "enroll",
    ]

    register_urls: List[str] = []
    for url in urls_to_scan:
        url_lower = url.lower()
        if any(p in url_lower for p in register_patterns):
            register_urls.append(url)

    if not register_urls:
        logger.debug("No registration endpoints found in recon URLs")
        return new_jwts

    random_suffix = uuid.uuid4().hex[:8]
    test_credentials = [
        {
            "username": f"btai_test_{random_suffix}",
            "password": f"BtaiTest_{random_suffix}1",
            "email": f"btai_test_{random_suffix}@test.local",
        },
    ]

    jwt_token_keys = [
        "access_token", "token", "jwt", "auth_token", "id_token",
        "accessToken", "authToken", "idToken",
    ]

    all_existing = list(discovered_jwts)

    for reg_url in register_urls:
        for creds in test_credentials:
            try:
                async with orchestrator.session(DestinationType.TARGET) as session:
                    async with session.post(
                        reg_url, json=creds, timeout=15,
                    ) as resp:
                        if resp.status in (200, 201):
                            try:
                                body = await resp.json()
                            except Exception:
                                body_text = await resp.text()
                                for match in JWT_PATTERN.finditer(body_text):
                                    token = match.group(1)
                                    if is_jwt(token) and not is_duplicate_jwt(token, all_existing):
                                        jwt_info = {
                                            "token": token,
                                            "source": "auto_registration",
                                            "url": reg_url,
                                            "context": "registration_response_text",
                                            "credentials": {
                                                "username": creds["username"],
                                                "email": creds["email"],
                                            },
                                        }
                                        new_jwts.append(jwt_info)
                                        all_existing.append(jwt_info)
                                        logger.info(f"JWT from auto-registration (text): {reg_url}")
                                continue

                            if isinstance(body, dict):
                                for key in jwt_token_keys:
                                    token = body.get(key, "")
                                    if token and is_jwt(token) and not is_duplicate_jwt(token, all_existing):
                                        jwt_info = {
                                            "token": token,
                                            "source": "auto_registration",
                                            "url": reg_url,
                                            "context": f"registration_response.{key}",
                                            "credentials": {
                                                "username": creds["username"],
                                                "email": creds["email"],
                                            },
                                        }
                                        new_jwts.append(jwt_info)
                                        all_existing.append(jwt_info)
                                        logger.info(
                                            f"JWT from auto-registration: {reg_url} (field: {key})"
                                        )
                                        return new_jwts  # Got a token, done

                                # Also scan entire response for JWT pattern
                                body_str = json.dumps(body)
                                for match in JWT_PATTERN.finditer(body_str):
                                    token = match.group(1)
                                    if is_jwt(token) and not is_duplicate_jwt(token, all_existing):
                                        jwt_info = {
                                            "token": token,
                                            "source": "auto_registration",
                                            "url": reg_url,
                                            "context": "registration_response_nested",
                                            "credentials": {
                                                "username": creds["username"],
                                                "email": creds["email"],
                                            },
                                        }
                                        new_jwts.append(jwt_info)
                                        all_existing.append(jwt_info)
                                        logger.info(
                                            f"JWT from auto-registration (nested): {reg_url}"
                                        )
                                        return new_jwts

                        else:
                            logger.debug(
                                f"Registration attempt returned {resp.status} on {reg_url}"
                            )

            except Exception as e:
                logger.debug(f"Auto-registration failed on {reg_url}: {e}")

    return new_jwts
