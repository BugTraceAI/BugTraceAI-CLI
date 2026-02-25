"""
CSTI Discovery

I/O functions for CSTI-specific parameter discovery and template engine fingerprinting.
These functions perform network requests (browser, HTTP) to discover attack surface.
"""

from typing import Dict, List
from urllib.parse import urlparse, parse_qs

from bugtrace.agents.csti.engines import fingerprint_engines
from bugtrace.agents.csti.payloads import prioritize_csti_params
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.csti.discovery")


async def discover_csti_params(url: str) -> Dict[str, str]:  # I/O
    """
    CSTI-focused parameter discovery (AUTONOMOUS SPECIALIST PATTERN v1.0).

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select) - template content
    3. Links on the page (same-origin only)
    4. Detects template engine in use

    Args:
        url: Target URL to discover parameters on

    Returns:
        Dict mapping param names to default values
        Example: {"category": "Juice", "template": "", "message": ""}

    Architecture Note:
        Specialists must be AUTONOMOUS - they discover their own attack surface.
        The finding from DASTySAST is just a "signal" that the URL is interesting.
        We IGNORE the specific parameter and test ALL discoverable params.
    """
    from bugtrace.tools.visual.browser import browser_manager
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin

    all_params: Dict[str, str] = {}

    # 1. Extract URL query parameters
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"[CSTIDiscovery] Failed to parse URL params: {e}")

    # 2. Fetch HTML and extract form parameters
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if html:
            soup = BeautifulSoup(html, "html.parser")

            # Extract from <input>, <textarea>, <select> with name attribute
            for tag in soup.find_all(["input", "textarea", "select"]):
                param_name = tag.get("name")
                if param_name and param_name not in all_params:
                    # Exclude CSRF tokens and submit buttons
                    input_type = tag.get("type", "text").lower()
                    if input_type not in ["submit", "button", "reset"]:
                        if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                            default_value = tag.get("value", "")
                            all_params[param_name] = default_value

            # 3. Extract params from <a> href links (same-origin only)
            parsed_base = urlparse(url)
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                    continue
                try:
                    resolved = urljoin(url, href)
                    parsed_href = urlparse(resolved)
                    if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                        continue
                    href_params = parse_qs(parsed_href.query)
                    for p_name, p_vals in href_params.items():
                        if p_name not in all_params and "csrf" not in p_name.lower() and "token" not in p_name.lower():
                            all_params[p_name] = p_vals[0] if p_vals else ""
                except Exception:
                    continue

            # 4. CSTI-specific: Detect template engine in use
            detected_engines = fingerprint_engines(html)
            if detected_engines and detected_engines[0] != "unknown":
                logger.info(f"[CSTIDiscovery] Detected template engine(s): {', '.join(detected_engines)}")

    except Exception as e:
        logger.error(f"[CSTIDiscovery] HTML parsing failed: {e}")

    logger.info(f"[CSTIDiscovery] Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
    return all_params


def discover_all_params_sync(url: str) -> List[Dict]:  # PURE (no I/O, just URL parsing)
    """
    DEPRECATED (2026-02-06): Use discover_csti_params() instead (async).

    Synchronous parameter discovery from URL only.

    Sources:
    1. URL query string params (ALWAYS - first-class)
    2. Common vulnerable param names (ALWAYS - for comprehensive coverage)

    Args:
        url: Target URL

    Returns:
        List of param dicts with 'parameter' and 'source' keys
    """
    discovered = []

    # 1. Extract from URL query string (ALWAYS - first-class citizens)
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    for param_name in query_params.keys():
        discovered.append({"parameter": param_name, "source": "url_query"})

    # 2. ALWAYS add common vulnerable params for comprehensive coverage
    common_vuln_params = [
        "category", "search", "q", "query", "filter", "sort",
        "template", "view", "page", "lang", "theme", "type", "action",
    ]
    for param in common_vuln_params:
        if param not in query_params:
            discovered.append({"parameter": param, "source": "common_vuln"})

    return discovered


async def detect_engines_for_escalation(
    url: str, finding: dict,
    tech_profile: dict = None,
    fetch_page_fn=None,
) -> List[str]:  # I/O
    """
    Detect template engines from HTML fingerprinting + finding metadata + tech_profile.

    Args:
        url: Target URL
        finding: The DRY finding dict
        tech_profile: Optional tech profile from recon
        fetch_page_fn: Async callable(session) -> str for fetching page HTML

    Returns:
        List of detected engine names
    """
    from bugtrace.core.http_manager import http_manager, ConnectionProfile

    engines = []

    # From finding metadata
    suggested = finding.get("template_engine", "unknown")
    if suggested and suggested != "unknown":
        engines.append(suggested)

    # From tech_profile (Nuclei detection)
    if tech_profile and tech_profile.get("frameworks"):
        for framework in tech_profile["frameworks"]:
            fw_lower = framework.lower()
            if "angular" in fw_lower and "angular" not in engines:
                engines.append("angular")
            elif "vue" in fw_lower and "vue" not in engines:
                engines.append("vue")

    # From HTML fingerprinting
    try:
        async with http_manager.isolated_session(ConnectionProfile.PROBE) as session:
            if fetch_page_fn:
                html = await fetch_page_fn(session)
            else:
                try:
                    async with session.get(url, timeout=10) as resp:
                        html = await resp.text()
                except Exception:
                    html = ""
            if html:
                html_engines = fingerprint_engines(html)
                for e in html_engines:
                    if e != "unknown" and e not in engines:
                        engines.append(e)
    except Exception:
        pass

    logger.info(f"[CSTIDiscovery] Detected engines for escalation: {engines or ['unknown']}")
    return engines
