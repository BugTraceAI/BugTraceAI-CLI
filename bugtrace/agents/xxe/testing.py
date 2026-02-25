"""
XXE Agent - I/O functions

All functions here are async and perform network I/O or interact with
external services (HTTP, browser, LLM, filesystem).

Dependencies are passed as explicit parameters.

Responsibilities:
- XML payload submission and response testing
- LLM-driven bypass strategy generation
- Autonomous XXE endpoint discovery (browser-based)
- LLM-powered deduplication
- Queue draining
- Report file writing
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

import aiohttp

from bugtrace.agents.xxe.core import (
    INITIAL_XXE_PAYLOADS,
    check_xxe_indicators,
    fallback_fingerprint_dedup,
    build_dedup_prompt,
)
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.xxe")


# ============================================================================
# XML TESTING (I/O)
# ============================================================================

# I/O
async def test_xml(
    session: aiohttp.ClientSession,
    url: str,
    xml_body: str,
) -> bool:
    """
    Test a single XML payload against a target URL.

    Args:
        session: aiohttp ClientSession
        url: Target URL
        xml_body: XML payload to submit

    Returns:
        True if XXE indicators found in response
    """
    try:
        headers = {'Content-Type': 'application/xml'}

        async with session.post(
            url, data=xml_body, headers=headers, timeout=5
        ) as resp:
            text = await resp.text()
            return check_xxe_indicators(text)

    except Exception as e:
        logger.debug(f"XXE Request failed: {e}")
        return False


# I/O
async def test_heuristic_payloads(
    session: aiohttp.ClientSession,
    url: str,
    verbose_emitter: Any = None,
) -> Tuple[List[str], Optional[str]]:
    """
    Test initial payloads and return (successful_payloads, best_payload).

    Args:
        session: aiohttp ClientSession
        url: Target URL
        verbose_emitter: Optional verbose event emitter

    Returns:
        Tuple of (list of successful payloads, best payload string or None)
    """
    successful_payloads: List[str] = []
    best_payload: Optional[str] = None

    for payload_idx, p in enumerate(INITIAL_XXE_PAYLOADS, 1):
        if verbose_emitter:
            verbose_emitter.progress(
                "exploit.specialist.progress",
                {"agent": "XXE", "payload": p[:60]},
                every=50,
            )

        if await test_xml(session, url, p):
            successful_payloads.append(p)
            if verbose_emitter:
                verbose_emitter.emit(
                    "exploit.specialist.signature_match",
                    {"agent": "XXE", "payload": p[:60], "url": url},
                )
            if not best_payload or ("passwd" in p and "passwd" not in best_payload):
                best_payload = p

    return successful_payloads, best_payload


# I/O
async def try_llm_bypass(
    session: aiohttp.ClientSession,
    url: str,
    system_prompt: str,
    previous_response: str,
    max_attempts: int = 5,
) -> Tuple[List[str], Optional[str]]:
    """
    Try LLM-driven bypass. Returns (successful_payloads, best_payload).

    Args:
        session: aiohttp ClientSession
        url: Target URL
        system_prompt: System prompt for LLM
        previous_response: Previous attempt response snippet
        max_attempts: Maximum bypass attempts

    Returns:
        Tuple of (list of successful payloads, best payload or None)
    """
    from bugtrace.core.llm_client import llm_client
    from bugtrace.utils.parsers import XmlParser

    for attempt in range(max_attempts):
        user_prompt = f"Target URL: {url}"
        if previous_response:
            user_prompt += f"\n\nPrevious attempt failed. Response snippet:\n{previous_response[:1000]}"
            user_prompt += "\n\nTry a different bypass (e.g. XInclude, parameter entities, UTF-16 encoding)."

        response = await llm_client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            module_name="XXE_AGENT",
        )

        tags = ["payload", "vulnerable", "context", "confidence"]
        strategy = XmlParser.extract_tags(response, tags)

        if not strategy or not strategy.get('payload'):
            break

        payload = strategy['payload']
        if await test_xml(session, url, payload):
            return [payload], payload

    return [], None


# ============================================================================
# AUTONOMOUS XXE ENDPOINT DISCOVERY (I/O)
# ============================================================================

# I/O
async def discover_xxe_params(url: str) -> List[Dict[str, str]]:
    """
    XXE-focused endpoint discovery.

    Extracts ALL testable XXE endpoints from:
    1. File upload forms with accept=".xml"
    2. Forms with enctype="multipart/form-data"
    3. Endpoints that accept Content-Type: application/xml

    Args:
        url: Target URL

    Returns:
        List of dicts with XXE endpoint info
    """
    from bugtrace.tools.visual.browser import browser_manager
    from urllib.parse import urlparse, urljoin
    from bs4 import BeautifulSoup

    xxe_endpoints: List[Dict[str, str]] = []

    # 1. Fetch HTML
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if not html:
            logger.warning(f"No HTML content for {url}")
            return [{"url": url, "type": "xml_endpoint", "method": "POST"}]

        soup = BeautifulSoup(html, "html.parser")
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 2. Extract file upload forms with .xml acceptance
        for form in soup.find_all("form"):
            file_inputs = form.find_all("input", {"type": "file"})

            for file_input in file_inputs:
                accept_attr = file_input.get("accept", "")

                if ".xml" in accept_attr.lower() or "xml" in accept_attr.lower():
                    action = form.get("action", "")
                    method = form.get("method", "POST").upper()

                    if action:
                        endpoint_url = urljoin(url, action)
                    else:
                        endpoint_url = url

                    xxe_endpoints.append({
                        "url": endpoint_url,
                        "type": "file_upload_xml",
                        "accept": accept_attr,
                        "method": method,
                    })
                    logger.debug(f"Found XML file upload: {endpoint_url} (accept={accept_attr})")

                # Also check multipart forms
                enctype = form.get("enctype", "")
                if "multipart" in enctype and not accept_attr:
                    action = form.get("action", "")
                    method = form.get("method", "POST").upper()

                    if action:
                        endpoint_url = urljoin(url, action)
                    else:
                        endpoint_url = url

                    xxe_endpoints.append({
                        "url": endpoint_url,
                        "type": "multipart_form",
                        "accept": "any",
                        "method": method,
                    })
                    logger.debug(f"Found multipart form: {endpoint_url}")

        # 3. Check if current URL accepts XML
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.options(url, timeout=3) as resp:
                    content_type_header = resp.headers.get("Accept", "")
                    if "xml" in content_type_header.lower():
                        xxe_endpoints.append({
                            "url": url,
                            "type": "xml_api_endpoint",
                            "accept": "application/xml",
                            "method": "POST",
                        })
                        logger.debug(f"Endpoint accepts XML: {url}")
        except Exception as e:
            logger.debug(f"OPTIONS request failed: {e}")

        # 4. Fallback: test URL as generic XML endpoint
        if not xxe_endpoints:
            logger.debug("No specific XXE endpoints found, testing URL as XML endpoint")
            xxe_endpoints.append({
                "url": url,
                "type": "generic_xml_test",
                "accept": "",
                "method": "POST",
            })

    except Exception as e:
        logger.error(f"XXE discovery failed for {url}: {e}")
        xxe_endpoints.append({
            "url": url,
            "type": "fallback",
            "method": "POST",
        })

    logger.info(f"Discovered {len(xxe_endpoints)} XXE endpoints on {url}: {[ep['type'] for ep in xxe_endpoints]}")
    return xxe_endpoints


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
    xml_parser: str,
) -> List[Dict]:
    """
    LLM-powered intelligent deduplication with agent-specific rules.

    Args:
        wet_findings: WET findings to deduplicate
        scan_context: Scan context
        tech_stack: Technology stack
        prime_directive: Agent prime directive
        dedup_context: Agent dedup context
        xml_parser: Inferred XML parser

    Returns:
        Deduplicated list of findings
    """
    from bugtrace.core.llm_client import llm_client

    prompt, system_prompt = build_dedup_prompt(
        wet_findings, tech_stack, prime_directive, dedup_context, xml_parser
    )

    response = await llm_client.generate(
        prompt=prompt,
        system_prompt=system_prompt,
        module_name="XXE_DEDUP",
        temperature=0.2,
    )

    try:
        result = json.loads(response)
        return result.get("findings", wet_findings)
    except json.JSONDecodeError:
        logger.warning("LLM returned invalid JSON, using fallback")
        return fallback_fingerprint_dedup(wet_findings)


# ============================================================================
# QUEUE DRAINING (I/O)
# ============================================================================

# I/O
async def drain_queue(queue: Any, scan_context: str = "", max_wait: float = 300.0) -> List[Dict]:
    """
    Drain all WET findings from a queue.

    Args:
        queue: Queue object with depth() and dequeue() methods
        scan_context: Default scan context
        max_wait: Maximum wait time in seconds

    Returns:
        List of drained WET findings
    """
    wet_findings: List[Dict] = []

    wait_start = time.monotonic()
    while (time.monotonic() - wait_start) < max_wait:
        depth = queue.depth() if hasattr(queue, 'depth') else 0
        if depth > 0:
            logger.info(f"Phase A: Queue has {depth} items, starting drain...")
            break
        await asyncio.sleep(0.5)
    else:
        logger.info("Phase A: Queue timeout - no items appeared")
        return []

    empty_count = 0
    max_empty_checks = 10

    while empty_count < max_empty_checks:
        item = await queue.dequeue(timeout=0.5)
        if item is None:
            empty_count += 1
            await asyncio.sleep(0.5)
            continue

        empty_count = 0

        finding = item.get("finding", {})
        url = finding.get("url", "")

        if url:
            wet_findings.append({
                "url": url,
                "finding": finding,
                "scan_context": item.get("scan_context", scan_context),
            })

    logger.info(f"Phase A: Drained {len(wet_findings)} WET findings from queue")
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

    async with aiofiles.open(report_path, 'w') as f:
        await f.write(json.dumps(report, indent=2))

    logger.info(f"Specialist report saved: {report_path}")
