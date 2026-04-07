"""
Validation Browser

I/O layer for Playwright/CDP validation execution,
screenshot capture, and vision model calls.

Extracted from agentic_validator.py for modularity.
"""

import asyncio
import uuid
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
from loguru import logger

from bugtrace.agents.validation.core import (
    VerifierPool,
    construct_payload_url,
    check_sql_errors,
)


# Global pool instance
_verifier_pool = VerifierPool(pool_size=3)


async def execute_payload_optimized(  # I/O
    url: str,
    payload: Optional[str],
    vuln_type: str,
    param: Optional[str],
    verifier_pool: VerifierPool = None,
    fast_timeout: float = 20.0,
    verbose_emitter=None,
) -> Tuple[Optional[str], List[str], bool, Optional[str]]:
    """
    Optimized payload execution using pooled verifiers.

    Args:
        url: Target URL
        payload: Payload to inject
        vuln_type: Vulnerability type
        param: Parameter name
        verifier_pool: Optional verifier pool (uses global if None)
        fast_timeout: Timeout for validation
        verbose_emitter: Optional verbose event emitter

    Returns:
        Tuple of (screenshot_path, logs, triggered, alert_message)
    """
    from bugtrace.core.config import settings

    pool = verifier_pool or _verifier_pool

    if vuln_type in ["xss", "csti"]:
        verifier = await pool.get_verifier()
        try:
            target_url = construct_payload_url(url, payload, param)
            if verbose_emitter:
                verbose_emitter.emit("validation.browser.navigating", {
                    "vuln_type": vuln_type, "url": target_url[:100],
                })
            result = await verifier.verify_xss(
                target_url,
                screenshot_dir=str(settings.LOG_DIR),
                timeout=fast_timeout - 5,
                max_level=4,
            )
            if verbose_emitter:
                verbose_emitter.emit("validation.browser.loaded", {
                    "success": result.success,
                    "has_screenshot": bool(result.screenshot_path),
                    "console_events": len(result.console_logs or []),
                    "alert": result.alert_message[:50] if result.alert_message else None,
                })
            return result.screenshot_path, result.console_logs or [], result.success, result.alert_message
        finally:
            pool.release()
    else:
        path, logs, triggered = await generic_capture(url, payload, param)
        return path, logs, triggered, None


async def generic_capture(  # I/O
    url: str,
    payload: Optional[str],
    param: Optional[str] = None,
) -> Tuple[str, List[str], bool]:
    """
    Generic page capture for non-XSS validations.

    Args:
        url: Target URL
        payload: Optional payload
        param: Optional parameter

    Returns:
        Tuple of (screenshot_path, logs, triggered)
    """
    from bugtrace.tools.visual.browser import browser_manager
    from bugtrace.core.config import settings

    logs = []
    screenshot_path = ""

    target_url = construct_payload_url(url, payload, param) if payload else url

    async with browser_manager.get_page() as page:
        try:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)

            screenshot_path = str(settings.LOG_DIR / f"validate_{uuid.uuid4().hex[:8]}.png")
            await page.screenshot(path=screenshot_path)

            content = await page.content()
            sql_error = check_sql_errors(content)
            if sql_error:
                logs.append(f"SQL Error detected: {sql_error}")
                return screenshot_path, logs, True

        except Exception as e:
            logs.append(f"Capture error: {e}")
            logger.error(f"Generic capture failed: {e}", exc_info=True)

    return screenshot_path, logs, False


async def validate_static_xss(  # I/O
    finding: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Check for static XSS reflection to skip browser overhead.

    This is a lightweight check before launching a browser.

    Args:
        finding: Finding dictionary

    Returns:
        Validation result dict if XSS confirmed, None otherwise
    """
    # This is a placeholder for the static XSS validation
    # The original code calls self._validate_static_xss which may
    # not be fully implemented. Return None to fall through to browser.
    return None


async def call_vision_model(  # I/O
    prompt: str,
    screenshot_path: str,
) -> str:
    """
    Call a vision-capable LLM to analyze the screenshot.

    Args:
        prompt: Vision analysis prompt
        screenshot_path: Path to screenshot image

    Returns:
        LLM response text
    """
    from bugtrace.core.llm_client import LLMClient
    from bugtrace.core.config import settings

    llm = LLMClient()

    response = await llm.generate_with_image(
        prompt=prompt,
        image_path=screenshot_path,
        model_override=settings.VISION_MODEL,
        temperature=0.1,
    )

    return response
