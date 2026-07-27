"""
POST parameter and HTML form XSS testing.

Handles discovery of HTML forms, extraction of form data, sending POST
requests with XSS payloads, and validating reflections.

Extracted from xss_agent.py (lines 8269-8424).
"""

from typing import Dict, List, Optional, Any, Tuple, Callable, Awaitable
from pathlib import Path
from urllib.parse import urljoin

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.agents.xss.types import XSSFinding

logger = get_logger("agents.xss.forms")


# ---------------------------------------------------------------------------
# PURE FUNCTIONS
# ---------------------------------------------------------------------------

def extract_form_data(form, base_url: str) -> Tuple[str, Dict[str, str]]:
    """
    Extract form action URL and parameters from a BeautifulSoup form element.

    Only returns data for POST forms. GET forms return ("", {}).

    Args:
        form: BeautifulSoup Tag element representing an HTML <form>.
        base_url: Base URL to resolve relative action URLs.

    Returns:
        Tuple of (form_action_url, post_params_dict).
        Returns ("", {}) if not a POST form or no inputs found.
    """
    method = (form.get('method') or 'get').lower()
    if method != 'post':
        return "", {}

    action = form.get('action', '')
    form_action = urljoin(base_url, action) if action else base_url

    # Extract form inputs
    post_params: Dict[str, str] = {}
    for inp in form.find_all(['input', 'textarea', 'select']):
        name = inp.get('name')
        if name:
            value = inp.get('value', '')
            post_params[name] = value

    return form_action, post_params


def build_post_finding(
    form_action: str,
    param: str,
    payload: str,
    evidence: Dict,
) -> XSSFinding:
    """
    Build XSS finding from validated POST injection.

    Args:
        form_action: The form action URL that was submitted.
        param: The POST parameter name that was injected.
        payload: The XSS payload that was confirmed.
        evidence: Evidence dict from validation.

    Returns:
        XSSFinding with POST-specific metadata.
    """
    evidence["vector"] = "POST"
    evidence["form_action"] = form_action

    return XSSFinding(
        url=form_action,
        parameter=f"POST:{param}",
        payload=payload,
        context="POST form submission",
        validation_method="post_injection",
        evidence=evidence,
        confidence=0.9,
        status="VALIDATED_CONFIRMED",
        validated=True,
        screenshot_path=evidence.get("screenshot_path"),
        reflection_context="post_body"
    )


# ---------------------------------------------------------------------------
# I/O FUNCTIONS
# ---------------------------------------------------------------------------

async def fetch_page_forms(url: str) -> Optional[str]:
    """
    Fetch page HTML for form discovery.

    Args:
        url: URL to fetch.

    Returns:
        HTML string of the page, or None on failure.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        async with http_manager.session(ConnectionProfile.STANDARD) as session:
            async with session.get(url, headers=headers, ssl=False) as resp:
                return await resp.text()
    except Exception as e:
        logger.warning(f"Failed to fetch page for form discovery: {e}")
        return None


async def send_post_request(
    form_action: str,
    test_data: Dict[str, str],
) -> Optional[str]:
    """
    Send POST request and return response HTML.

    Args:
        form_action: URL to send the POST request to.
        test_data: Form data dict with parameter values.

    Returns:
        Response HTML string, or None on failure.
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        async with http_manager.session(ConnectionProfile.PROBE) as session:
            async with session.post(
                form_action,
                data=test_data,
                headers=headers,
                ssl=False,
                allow_redirects=True
            ) as resp:
                return await resp.text()
    except Exception as e:
        logger.debug(f"POST request failed: {e}")
        return None


async def test_post_params(
    form_action: str,
    post_params: Dict[str, str],
    interactsh_url: str,
    golden_payloads: List[str],
    validate_fn: Callable[..., Awaitable[Tuple[bool, Dict]]],
    agent_name: str = "XSS",
    screenshots_dir: Optional[Path] = None,
    max_impact_check: Optional[Callable[[], bool]] = None,
) -> Optional[XSSFinding]:
    """
    Test POST parameters for XSS.

    Iterates over parameters and payloads, sending each via POST and checking
    for reflection. When reflection is found, calls the validate function.

    Args:
        form_action: Form action URL.
        post_params: Dict of parameter name -> default value.
        interactsh_url: OOB callback URL for payload templating.
        golden_payloads: List of payload templates to test.
        validate_fn: Async callable(param, payload, response_html, screenshots_dir) -> (bool, evidence).
        agent_name: Agent name for logging.
        screenshots_dir: Optional directory for screenshots.
        max_impact_check: Optional callable() -> bool to check early termination.

    Returns:
        XSSFinding if confirmed, None otherwise.
    """
    dashboard.log(f"[{agent_name}] Testing POST form: {form_action}", "INFO")

    for param, original_value in post_params.items():
        if max_impact_check and max_impact_check():
            break

        for payload_template in golden_payloads[:10]:
            payload = payload_template.replace("{{interactsh_url}}", interactsh_url)
            test_data = post_params.copy()
            test_data[param] = payload

            response_html = await send_post_request(form_action, test_data)
            if not response_html:
                continue

            # Check reflection
            if payload not in response_html and payload[:30] not in response_html:
                continue

            dashboard.log(f"[{agent_name}] POST param '{param}' reflects payload!", "SUCCESS")

            validated, evidence = await validate_fn(
                param, payload, response_html, screenshots_dir
            )

            if validated:
                return build_post_finding(form_action, param, payload, evidence)

    return None


async def discover_and_test_post_forms(
    url: str,
    interactsh_url: str,
    golden_payloads: List[str],
    validate_fn: Callable[..., Awaitable[Tuple[bool, Dict]]],
    agent_name: str = "XSS",
    screenshots_dir: Optional[Path] = None,
    max_impact_check: Optional[Callable[[], bool]] = None,
) -> List[XSSFinding]:
    """
    Discover POST forms and test them for XSS.

    Fetches the page HTML, parses all POST forms, extracts their action URLs
    and parameters, then tests each form for XSS injection.

    Args:
        url: Target URL to scrape for forms.
        interactsh_url: OOB callback URL for payload templating.
        golden_payloads: List of payload templates to test.
        validate_fn: Async callable(param, payload, response_html, screenshots_dir) -> (bool, evidence).
        agent_name: Agent name for logging.
        screenshots_dir: Optional directory for screenshots.
        max_impact_check: Optional callable() -> bool to check early termination.

    Returns:
        List of XSSFinding objects for confirmed vulnerabilities.
    """
    from bs4 import BeautifulSoup

    findings: List[XSSFinding] = []
    html = await fetch_page_forms(url)
    if not html:
        return findings

    soup = BeautifulSoup(html, 'html.parser')

    for form in soup.find_all('form'):
        form_action, post_params = extract_form_data(form, url)
        if not post_params:
            continue

        finding = await test_post_params(
            form_action, post_params, interactsh_url, golden_payloads,
            validate_fn,
            agent_name=agent_name,
            screenshots_dir=screenshots_dir,
            max_impact_check=max_impact_check,
        )
        if finding:
            findings.append(finding)
            if max_impact_check and max_impact_check():
                break

    return findings


__all__ = [
    # Pure
    "extract_form_data",
    "build_post_finding",
    # I/O
    "fetch_page_forms",
    "send_post_request",
    "test_post_params",
    "discover_and_test_post_forms",
]
