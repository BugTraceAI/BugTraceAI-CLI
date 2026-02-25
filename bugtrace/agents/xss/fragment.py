"""
Fragment-based XSS testing (hash-based DOM XSS).

Tests for DOM XSS via location.hash, which bypasses server-side WAFs
because fragments (#payload) are never sent to the server.

Extracted from xss_agent.py (lines 8083-8153).
Note: fragment_build_url already exists in bugtrace.agents.shared.http_attack
and is reused here via import.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.agents.xss.types import XSSFinding
from bugtrace.agents.shared.http_attack import fragment_build_url

logger = get_logger("agents.xss.fragment")


# ---------------------------------------------------------------------------
# PURE FUNCTIONS
# ---------------------------------------------------------------------------

def build_fragment_finding(
    url: str,
    param: str,
    payload: str,
    result,
) -> XSSFinding:
    """
    Build XSS finding from validated fragment injection.

    Args:
        url: Target URL that was tested.
        param: Parameter name that was bypassed via fragment.
        payload: The XSS payload that was confirmed.
        result: Verification result object with attributes:
            - details: Optional[Dict] - evidence details
            - method: str - verification method used
            - screenshot_path: Optional[str] - path to screenshot
            - console_logs: Optional[List] - browser console logs

    Returns:
        XSSFinding with fragment-specific metadata.
    """
    evidence = result.details or {}
    evidence["method"] = result.method
    evidence["screenshot_path"] = result.screenshot_path
    if result.console_logs:
        evidence["console_logs"] = result.console_logs

    return XSSFinding(
        url=url,
        parameter=f"#fragment (bypassed {param})",
        payload=payload,
        context="dom_xss_fragment",
        validation_method=f"vision+{result.method}",
        evidence=evidence,
        confidence=1.0,
        status="VALIDATED_CONFIRMED",
        validated=True,
        screenshot_path=result.screenshot_path,
        reflection_context="location.hash -> innerHTML",
        surviving_chars="N/A (client-side)"
    )


# ---------------------------------------------------------------------------
# I/O FUNCTIONS
# ---------------------------------------------------------------------------

async def test_fragment_xss(
    verifier,
    url: str,
    param: str,
    interactsh_url: str,
    fragment_payloads: List[str],
    agent_name: str = "XSS",
    screenshots_dir: Optional[Path] = None,
) -> Optional[XSSFinding]:
    """
    Test Fragment-based XSS (DOM XSS via location.hash).

    This bypasses WAFs because fragments (#payload) don't reach the server.
    Level 7+ targets often use location.hash in innerHTML/eval, creating DOM XSS.

    Args:
        verifier: XSSVerifier instance with async verify_xss() method.
        url: Target URL to test.
        param: Parameter name being bypassed.
        interactsh_url: OOB callback URL for payload templating.
        fragment_payloads: List of fragment payload templates.
        agent_name: Agent name for logging.
        screenshots_dir: Directory for screenshots.

    Returns:
        XSSFinding if confirmed, None otherwise.
    """
    dashboard.log(f"[{agent_name}] Testing FRAGMENT XSS (bypassing WAF via location.hash)...", "INFO")

    for fragment_template in fragment_payloads:
        payload = fragment_template.replace("{{interactsh_url}}", interactsh_url)
        fragment_url = fragment_build_url(url, payload)

        dashboard.set_current_payload(payload[:60], "Fragment XSS", "Testing")
        logger.info(f"[{agent_name}] Testing Fragment: {fragment_url}")

        try:
            result = await verifier.verify_xss(
                url=fragment_url,
                screenshot_dir=str(screenshots_dir) if screenshots_dir else None,
                timeout=10.0
            )

            if result.success:
                dashboard.log(f"[{agent_name}] FRAGMENT XSS SUCCESS! ({result.method})", "SUCCESS")
                return build_fragment_finding(url, param, payload, result)

        except Exception as e:
            logger.debug(f"Fragment test failed for {payload[:30]}: {e}")
            continue

    logger.info(f"[{agent_name}] No Fragment XSS found after testing {len(fragment_payloads)} payloads")
    return None


__all__ = [
    # Re-export from shared
    "fragment_build_url",
    # Pure
    "build_fragment_finding",
    # I/O
    "test_fragment_xss",
]
