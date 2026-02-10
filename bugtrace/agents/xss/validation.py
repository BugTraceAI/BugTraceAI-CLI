"""
XSS Agent Validation Module

Multi-level validation pipeline for XSS confirmation:
- Level 1: HTTP Static Reflection (fast, ~70% coverage)
- Level 2: AI-Powered Auditor (smart contextual analysis)
- Level 3: Playwright Browser Execution (DOM/client-side)
- Level 4: CDP Deep Protocol (delegated to AgenticValidator)

Also includes Vision AI validation for visual confirmation.
"""

import asyncio
import re
from typing import Dict, List, Optional, Any, Tuple, Callable, Awaitable
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("agents.xss.validation")


# Vision AI prompt for banner confirmation
VISION_PROMPT = """Look at this screenshot of a web page.

Question: Do you see a red banner or text that says "HACKED BY BUGTRACEAI" anywhere in the image?

Answer with ONLY one word: SI or NO"""

# Positive vision responses
VISION_POSITIVE_RESPONSES = ["SI", "SÍ", "YES", "S", "Y"]


def build_attack_url(base_url: str, param: str, payload: str) -> str:
    """
    Build attack URL with payload injected into parameter.

    Args:
        base_url: Original target URL
        param: Parameter name to inject
        payload: XSS payload

    Returns:
        Complete URL with payload
    """
    parsed = urlparse(base_url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(parsed.query).items()}
    params[param] = payload

    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(params), parsed.fragment
    ))


async def validate_xss_multilevel(
    param: str,
    payload: str,
    response_html: str,
    screenshots_dir: Path,
    interactsh_checker: Optional[Callable[..., Awaitable[Optional[Dict]]]] = None,
    browser_verifier=None,
    ai_analyzer: Optional[Callable[..., Awaitable[Dict]]] = None,
    base_url: str = "",
    agent_name: str = "XSSAgent",
) -> Tuple[bool, Dict[str, Any]]:
    """
    4-Level validation pipeline for XSS confirmation.

    Levels:
    1. L1: HTTP Static Reflection (OOB + context analysis)
    2. L2: AI-Powered Auditor (contextual analysis)
    3. L3: Playwright Browser Execution
    4. L4: Escalation to AgenticValidator (not handled here)

    Args:
        param: Parameter name
        payload: XSS payload tested
        response_html: HTML response from payload test
        screenshots_dir: Directory for screenshots
        interactsh_checker: Function to check for OOB callbacks
        browser_verifier: XSSVerifier instance for browser validation
        ai_analyzer: Function for AI-powered reflection analysis
        base_url: Target URL
        agent_name: Agent name for logging

    Returns:
        Tuple of (success: bool, evidence: Dict)
    """
    evidence = {"payload": payload}

    # Level 1: HTTP Static Reflection Check
    l1_result = await validate_http_reflection(
        param, payload, response_html, evidence,
        interactsh_checker, agent_name
    )
    if l1_result:
        return True, evidence

    # Level 2: AI-Powered Auditor
    if ai_analyzer and response_html:
        l2_result = await validate_with_ai(
            param, payload, response_html, evidence,
            ai_analyzer, agent_name
        )
        if l2_result:
            return True, evidence

    # Level 3: Playwright Browser Execution
    if browser_verifier and _requires_browser_validation(payload, response_html):
        l3_result = await validate_with_playwright(
            param, payload, screenshots_dir, evidence,
            browser_verifier, base_url, agent_name
        )
        if l3_result:
            return True, evidence

    # Level 4: Escalation required
    logger.debug(f"[{agent_name}] L1-L3 inconclusive, escalation to L4 required")
    return False, evidence


async def validate_http_reflection(
    param: str,
    payload: str,
    response_html: str,
    evidence: Dict[str, Any],
    interactsh_checker: Optional[Callable[..., Awaitable[Optional[Dict]]]] = None,
    agent_name: str = "XSSAgent",
) -> bool:
    """
    Level 1: Fast HTTP static reflection and OOB check.

    Checks:
    - Interactsh OOB callback (definitive)
    - Executable reflection in HTML context
    - Executable reflection in event handler
    - Executable reflection in javascript: URI

    Returns:
        True if XSS confirmed at L1
    """
    # L1.1: OOB Interactsh check (definitive proof)
    if interactsh_checker:
        hit_data = await interactsh_checker(param)
        if hit_data:
            evidence["interactsh_hit"] = True
            evidence["interactions"] = [hit_data]
            evidence["method"] = "L1: OOB Interactsh"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            dashboard.log(f"[{agent_name}] OOB INTERACTION DETECTED!", "CRITICAL")
            return True

    if not response_html:
        return False

    # L1.2: Check for executable reflection contexts
    if _is_executable_in_html_context(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "html_tag"
        evidence["method"] = "L1: HTTP Static Reflection"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    if _is_executable_in_event_handler(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "event_handler"
        evidence["method"] = "L1: HTTP Static Reflection"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    if _is_executable_in_javascript_uri(payload, response_html):
        evidence["http_confirmed"] = True
        evidence["execution_context"] = "javascript_uri"
        evidence["method"] = "L1: HTTP Static Reflection"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    return False


async def validate_with_ai(
    param: str,
    payload: str,
    response_html: str,
    evidence: Dict[str, Any],
    ai_analyzer: Callable[..., Awaitable[Dict]],
    agent_name: str = "XSSAgent",
) -> bool:
    """
    Level 2: AI-powered context audit and filter analysis.

    Uses LLM to analyze if the reflection is exploitable.

    Returns:
        True if AI confirms vulnerability
    """
    if not response_html or re.escape(payload) not in response_html:
        return False

    dashboard.log(f"[{agent_name}] L2: AI Auditor analyzing reflection...", "INFO")

    try:
        ai_judgment = await ai_analyzer(payload, response_html)

        if ai_judgment.get("vulnerable"):
            evidence["ai_confirmed"] = True
            evidence["ai_reasoning"] = ai_judgment.get("reasoning")
            evidence["execution_context"] = ai_judgment.get("context")
            evidence["method"] = "L2: AI Auditor"
            evidence["level"] = 2
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True
    except Exception as e:
        logger.warning(f"[{agent_name}] AI validation failed: {e}")

    return False


async def validate_with_playwright(
    param: str,
    payload: str,
    screenshots_dir: Path,
    evidence: Dict[str, Any],
    browser_verifier,
    base_url: str,
    agent_name: str = "XSSAgent",
) -> bool:
    """
    Level 3: Playwright browser execution for DOM/client behavior.

    Executes payload in real browser and checks for XSS execution.

    Returns:
        True if Playwright confirms XSS execution
    """
    attack_url = build_attack_url(base_url, param, payload)

    try:
        result = await browser_verifier.verify_xss(
            url=attack_url,
            screenshot_dir=str(screenshots_dir),
            timeout=8.0,
            max_level=3  # Playwright only, no CDP
        )

        if result.success:
            evidence.update(result.details or {})
            evidence["playwright_confirmed"] = True
            evidence["screenshot_path"] = result.screenshot_path
            evidence["method"] = "L3: Playwright Browser"
            evidence["level"] = 3
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

    except Exception as e:
        logger.debug(f"[{agent_name}] Playwright validation error: {e}")

    return False


async def validate_visual_payload(
    param: str,
    payload: str,
    screenshots_dir: Path,
    browser_verifier,
    base_url: str,
    vision_validator: Optional[Callable[..., Awaitable[str]]] = None,
    agent_name: str = "XSSAgent",
) -> Optional[Dict[str, Any]]:
    """
    Validate a visual payload (with HACKED BY BUGTRACEAI banner).

    This is BULLETPROOF validation:
    1. Playwright navigates to URL with payload
    2. Detects XSS execution (dialog, DOM markers)
    3. Captures screenshot
    4. Vision AI confirms banner is visible

    Args:
        param: Parameter name
        payload: Visual payload with banner injection
        screenshots_dir: Directory for screenshots
        browser_verifier: XSSVerifier instance
        base_url: Target URL
        vision_validator: Function to call Vision AI
        agent_name: Agent name for logging

    Returns:
        Evidence dict with vision_confirmed=True if fully validated
    """
    attack_url = build_attack_url(base_url, param, payload)

    try:
        result = await browser_verifier.verify_xss(
            url=attack_url,
            screenshot_dir=str(screenshots_dir),
            timeout=10.0,
            max_level=3
        )

        if not result.success:
            return None

        evidence = {
            "playwright_confirmed": True,
            "screenshot_path": result.screenshot_path,
            "method": "L3: Playwright + Vision",
            "level": 3,
            "status": "PENDING_VISION"
        }
        evidence.update(result.details or {})

        # Vision AI validation if screenshot available
        if result.screenshot_path and vision_validator:
            vision_confirmed = await run_vision_validation(
                result.screenshot_path,
                attack_url,
                payload,
                evidence,
                vision_validator,
                agent_name
            )

            if vision_confirmed:
                evidence["status"] = "VALIDATED_CONFIRMED"
                evidence["validation_method"] = "visual_playwright_vision"
                return evidence

        return evidence

    except Exception as e:
        logger.debug(f"[{agent_name}] Visual validation error: {e}")
        return None


async def run_vision_validation(
    screenshot_path: str,
    attack_url: str,
    payload: str,
    evidence: Dict[str, Any],
    vision_validator: Callable[..., Awaitable[str]],
    agent_name: str = "XSSAgent",
) -> bool:
    """
    Run Vision AI validation for visual confirmation.

    Playwright already detected XSS. Vision provides VISUAL CONFIRMATION
    that the banner is visible = double evidence.

    Args:
        screenshot_path: Path to screenshot
        attack_url: URL that was tested
        payload: Payload that was used
        evidence: Evidence dict to update
        vision_validator: Function to call Vision AI
        agent_name: Agent name for logging

    Returns:
        True if Vision confirmed banner visible
    """
    dashboard.log(f"[{agent_name}] Calling Vision AI for confirmation...", "INFO")

    try:
        vision_response = await vision_validator(
            prompt=VISION_PROMPT,
            image_path=screenshot_path
        )

        return process_vision_result(vision_response, evidence, agent_name)

    except Exception as e:
        logger.error(f"[{agent_name}] Vision AI validation failed: {e}")
        evidence["vision_error"] = str(e)
        return False


def process_vision_result(
    vision_response: str,
    evidence: Dict[str, Any],
    agent_name: str = "XSSAgent",
) -> bool:
    """
    Process vision AI response - simple SI/NO parsing.

    Returns:
        True if Vision confirmed banner visible
    """
    if not vision_response:
        evidence["vision_confirmed"] = False
        evidence["vision_reason"] = "Empty response"
        return False

    response_upper = vision_response.strip().upper()

    if response_upper in VISION_POSITIVE_RESPONSES:
        evidence["vision_confirmed"] = True
        evidence["vision_response"] = vision_response
        evidence["validation_method"] = "playwright+vision"

        dashboard.log(
            f"[{agent_name}] VISION CONFIRMED: Banner visible",
            "SUCCESS"
        )
        return True

    evidence["vision_confirmed"] = False
    evidence["vision_response"] = vision_response
    dashboard.log(
        f"[{agent_name}] Vision says NO banner: {vision_response}",
        "WARN"
    )
    return False


def _requires_browser_validation(payload: str, response_html: str) -> bool:
    """Check if browser validation is needed for this payload."""
    # DOM-based payloads always need browser
    if "document." in payload or "window." in payload:
        return True

    # Event handlers need browser to fire
    if re.search(r'\bon\w+\s*=', payload, re.IGNORECASE):
        return True

    # Template expressions need evaluation
    if "{{" in payload or "${" in payload:
        return True

    return False


def _is_executable_in_html_context(payload: str, html: str) -> bool:
    """Check if payload reflects as executable HTML tag."""
    # Check for script tag injection
    if "<script" in payload.lower():
        escaped_script = re.escape("<script")
        if re.search(escaped_script, html, re.IGNORECASE):
            # Verify it's not HTML-encoded
            if "&lt;script" not in html.lower():
                return True

    # Check for other executable tags
    for tag in ["<img", "<svg", "<iframe", "<body", "<div"]:
        if tag in payload.lower() and tag in html.lower():
            if f"&lt;{tag[1:]}" not in html.lower():
                return True

    return False


def _is_executable_in_event_handler(payload: str, html: str) -> bool:
    """Check if payload reflects in executable event handler."""
    event_pattern = r'on\w+\s*=\s*["\'][^"\']*' + re.escape(payload[:20])
    return bool(re.search(event_pattern, html, re.IGNORECASE))


def _is_executable_in_javascript_uri(payload: str, html: str) -> bool:
    """Check if payload reflects in javascript: URI."""
    if "javascript:" in payload.lower():
        return "javascript:" in html.lower() and payload[:30] in html
    return False


__all__ = [
    "build_attack_url",
    "validate_xss_multilevel",
    "validate_http_reflection",
    "validate_with_ai",
    "validate_with_playwright",
    "validate_visual_payload",
    "run_vision_validation",
    "process_vision_result",
    "VISION_PROMPT",
    "VISION_POSITIVE_RESPONSES",
]
