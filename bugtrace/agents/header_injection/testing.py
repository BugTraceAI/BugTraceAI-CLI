"""
Header Injection Agent - I/O functions

All functions here are async and perform network I/O or interact with
external services (HTTP, browser, LLM, filesystem).

Dependencies (http_manager, llm_client, browser) are passed as explicit
first parameters -- never accessed via global state.

Responsibilities:
- HTTP testing for CRLF injection
- Smart probe (single request to detect CRLF survival)
- Full payload testing with response analysis
- Autonomous parameter discovery (browser-based)
- LLM-powered deduplication
- Queue draining
- Report file writing
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

import aiohttp

from bugtrace.agents.header_injection.core import (
    CRLF_PAYLOADS,
    build_test_url,
    check_raw_headers_for_crlf,
    check_markers_in_response,
    check_smart_probe_response,
    create_finding,
    fallback_fingerprint_dedup,
    build_dedup_prompt,
)
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.header_injection")


# ============================================================================
# HTTP TESTING (I/O)
# ============================================================================

# I/O
async def check_injection(
    session: aiohttp.ClientSession,
    test_url: str,
    param: str,
    payload: str,
    url: str,
    headers: Dict[str, str],
    cookies: List[Dict],
    user_agent: str,
    validation_status_value: str,
) -> Optional[Dict]:
    """
    Check if CRLF injection was successful by examining response.

    Detection strategy (priority order):
    1. Raw header inspection: Check response.raw_headers for literal \\r/\\n
       bytes in header values (Burp-style).
    2. Marker-based detection (fallback): Check for known injection markers
       like 'X-Injected' in parsed headers.

    Args:
        session: aiohttp ClientSession
        test_url: URL with payload injected
        param: Parameter being tested
        payload: CRLF payload string
        url: Original target URL
        headers: Additional request headers
        cookies: List of cookie dicts
        user_agent: User-Agent string
        validation_status_value: ValidationStatus.VALIDATED_CONFIRMED.value

    Returns:
        Finding dict or None
    """
    try:
        req_headers = {"User-Agent": user_agent}
        req_headers.update(headers)

        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            req_headers["Cookie"] = cookie_str

        async with session.get(
            test_url,
            headers=req_headers,
            allow_redirects=False,  # Important: Don't follow redirects
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False
        ) as response:
            # Phase 1: Raw header CRLF detection (Burp-style)
            try:
                raw_result = check_raw_headers_for_crlf(
                    list(response.raw_headers), param
                )
                if raw_result:
                    return create_finding(
                        url, param, payload,
                        raw_result["detection_type"],
                        raw_result["location"],
                        raw_result["header_name"],
                        raw_result["evidence"],
                        validation_status_value,
                    )
            except Exception as e:
                logger.debug(f"Raw header inspection error: {e}")

            # Phase 2: Marker-based detection (fallback)
            resp_headers = dict(response.headers)
            body = await response.text()

            marker_result = check_markers_in_response(resp_headers, body, param)
            if marker_result:
                return create_finding(
                    url, param, payload,
                    marker_result["marker"],
                    marker_result["location"],
                    marker_result["header_name"],
                    marker_result["evidence"],
                    validation_status_value,
                )

    except asyncio.TimeoutError:
        logger.debug(f"Timeout testing {param} with payload")
    except Exception as e:
        logger.debug(f"Error testing {param}: {e}")

    return None


# I/O
async def smart_probe_crlf(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    headers: Dict[str, str],
    cookies: List[Dict],
    user_agent: str,
    validation_status_value: str,
) -> Tuple[bool, Optional[Dict]]:
    """
    Smart probe: 1 request to test if CRLF chars survive in response.

    Sends a basic %0d%0a probe with a unique header marker.
    - If marker appears in response headers -> direct confirmation
    - If marker appears in body -> response splitting potential (continue)
    - If neither -> server sanitizes CRLF (skip all 11 payloads)

    Args:
        session: aiohttp ClientSession
        url: Target URL
        param: Parameter to test
        headers: Additional request headers
        cookies: List of cookie dicts
        user_agent: User-Agent string
        validation_status_value: ValidationStatus.VALIDATED_CONFIRMED.value

    Returns:
        Tuple of (should_continue, finding_or_none)
    """
    probe_payload = "%0d%0aBT-Probe:1"
    test_url = build_test_url(url, param, probe_payload)

    try:
        req_headers = {"User-Agent": user_agent}
        req_headers.update(headers)

        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            req_headers["Cookie"] = cookie_str

        async with session.get(
            test_url,
            headers=req_headers,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False
        ) as response:
            resp_headers = dict(response.headers)
            body = await response.text()

            should_continue, probe_detection = check_smart_probe_response(resp_headers, body)

            if probe_detection:
                # Direct confirmation -- build a full finding
                finding = create_finding(
                    url, param, probe_payload,
                    probe_detection["marker"],
                    probe_detection["location"],
                    probe_detection["header_name"],
                    probe_detection["evidence"],
                    validation_status_value,
                )
                return True, finding

            return should_continue, None

    except asyncio.TimeoutError:
        logger.debug(f"Smart probe timeout for {param}")
        return True, None  # On timeout, continue testing
    except Exception as e:
        logger.debug(f"Smart probe error for {param}: {e}")
        return True, None  # On error, continue testing


# I/O
async def test_parameter_from_queue(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    headers: Dict[str, str],
    cookies: List[Dict],
    user_agent: str,
    validation_status_value: str,
    verbose_emitter: Any = None,
) -> Optional[Dict]:
    """
    Test a single parameter from queue for CRLF injection.

    Performs smart probe first, then tests all payloads if probe indicates
    CRLF may survive.

    Args:
        session: aiohttp ClientSession
        url: Target URL
        param: Parameter to test
        headers: Additional request headers
        cookies: List of cookie dicts
        user_agent: User-Agent string
        validation_status_value: ValidationStatus value string
        verbose_emitter: Optional verbose event emitter

    Returns:
        Finding dict or None
    """
    # Smart probe: skip if CRLF is sanitized
    should_continue, direct_finding = await smart_probe_crlf(
        session, url, param, headers, cookies, user_agent, validation_status_value
    )
    if direct_finding:
        return direct_finding
    if not should_continue:
        return None

    for payload in CRLF_PAYLOADS:
        if verbose_emitter:
            verbose_emitter.progress(
                "exploit.specialist.progress",
                {"agent": "HeaderInjection", "param": param, "payload": payload[:60]},
                every=50,
            )

        test_url = build_test_url(url, param, payload)
        finding = await check_injection(
            session, test_url, param, payload, url,
            headers, cookies, user_agent, validation_status_value,
        )

        if finding:
            return finding

    return None


# ============================================================================
# AUTONOMOUS PARAMETER DISCOVERY (I/O)
# ============================================================================

# I/O
async def discover_header_params(url: str) -> Dict[str, str]:
    """
    Header Injection-focused parameter discovery.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)

    Prioritizes parameters that might influence HTTP headers:
    - redirect, language, locale, encoding, charset
    - url, callback, next, return, ref

    Args:
        url: Target URL to discover params on

    Returns:
        Tuple of (params_dict, html_content) where params_dict maps param
        names to default values and html_content is the cached HTML
    """
    from bugtrace.tools.visual.browser import browser_manager
    from urllib.parse import urlparse, parse_qs
    from bs4 import BeautifulSoup

    all_params: Dict[str, str] = {}
    html_content = ""

    # 1. Extract URL query parameters
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"Failed to parse URL params: {e}")

    # 2. Fetch HTML and extract form parameters + link parameters
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if html:
            html_content = html
            soup = BeautifulSoup(html, "html.parser")

            # Extract from <input>, <textarea>, <select>
            for tag in soup.find_all(["input", "textarea", "select"]):
                param_name = tag.get("name")
                if param_name and param_name not in all_params:
                    input_type = tag.get("type", "text").lower()

                    # Skip non-testable input types
                    if input_type not in ["submit", "button", "reset"]:
                        # Include CSRF tokens for header injection (they can trigger headers)
                        default_value = tag.get("value", "")
                        all_params[param_name] = default_value

            # Extract params from <a> href links (same-origin only)
            parsed_base = urlparse(url)
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                try:
                    parsed_href = urlparse(href)
                    # Same-origin or relative links only
                    if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                        continue
                    href_params = parse_qs(parsed_href.query)
                    for p_name, p_vals in href_params.items():
                        if p_name not in all_params:
                            all_params[p_name] = p_vals[0] if p_vals else ""
                except Exception:
                    continue

    except Exception as e:
        logger.error(f"HTML parsing failed: {e}")

    logger.info(f"Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
    return all_params


# ============================================================================
# LLM DEDUPLICATION (I/O)
# ============================================================================

# I/O
async def llm_analyze_and_dedup(
    wet_findings: List[Dict],
    scan_context: str,
    tech_stack: Dict,
    prime_directive: str,
    dedup_context: str,
) -> List[Dict]:
    """
    Use LLM to intelligently deduplicate Header Injection findings.
    Falls back to fingerprint-based dedup if LLM fails.

    CRITICAL: Respects autonomous discovery - same URL + DIFFERENT param = DIFFERENT finding.

    Args:
        wet_findings: List of WET findings to deduplicate
        scan_context: Scan context identifier
        tech_stack: Technology stack context
        prime_directive: Agent-specific prime directive
        dedup_context: Agent-specific dedup context

    Returns:
        Deduplicated list of findings
    """
    from bugtrace.core.llm_client import llm_client

    prompt, system_prompt = build_dedup_prompt(
        wet_findings, tech_stack, prime_directive, dedup_context
    )

    try:
        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="HEADER_INJECTION_DEDUP",
            temperature=0.2
        )

        # Parse LLM response
        result = json.loads(response)
        dry_list = result.get("findings", [])

        if dry_list:
            logger.info(f"LLM deduplication successful: {len(wet_findings)} -> {len(dry_list)}")
            return dry_list
        else:
            logger.warning("LLM returned empty list, using fallback")
            return fallback_fingerprint_dedup(wet_findings)

    except Exception as e:
        logger.warning(f"LLM deduplication failed: {e}, using fallback")
        return fallback_fingerprint_dedup(wet_findings)


# ============================================================================
# QUEUE DRAINING (I/O)
# ============================================================================

# I/O
async def drain_queue(queue: Any, max_wait: float = 300.0) -> List[Dict]:
    """
    Drain all WET findings from a queue.

    Waits for queue to have items, then drains until stable empty
    (10 consecutive empty checks).

    Args:
        queue: Queue object with depth() and dequeue() methods
        max_wait: Maximum wait time in seconds

    Returns:
        List of drained WET findings
    """
    wet_findings: List[Dict] = []

    # Wait for queue to have items
    wait_start = time.monotonic()
    while (time.monotonic() - wait_start) < max_wait:
        if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
            break
        await asyncio.sleep(0.5)

    # Drain all WET findings from queue
    logger.info(f"Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

    stable_empty_count = 0
    drain_start = time.monotonic()

    while stable_empty_count < 10 and (time.monotonic() - drain_start) < max_wait:
        item = await queue.dequeue(timeout=0.5)

        if item is None:
            stable_empty_count += 1
            continue

        stable_empty_count = 0

        finding = item.get("finding", {}) if isinstance(item, dict) else {}
        if finding:
            wet_findings.append({
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "finding": finding,
                "scan_context": item.get("scan_context", ""),
            })

    logger.info(f"Drained {len(wet_findings)} WET findings from queue")
    return wet_findings


# ============================================================================
# REPORT WRITING (I/O)
# ============================================================================

# I/O
async def write_specialist_report(report: Dict, report_path: Path) -> None:
    """
    Write specialist report to disk.

    Args:
        report: Report dict to serialize
        report_path: Path to write the report file
    """
    import aiofiles

    report_path.parent.mkdir(parents=True, exist_ok=True)

    async with aiofiles.open(report_path, "w") as f:
        await f.write(json.dumps(report, indent=2))

    logger.info(f"Specialist report saved: {report_path}")
