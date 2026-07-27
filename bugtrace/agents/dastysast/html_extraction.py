"""
PURE functions for HTML content parsing and parameter extraction.

Every function in this module depends only on its arguments.
No network, no filesystem, no global state mutation.
"""
import re
from typing import Dict, List
from urllib.parse import urlparse, parse_qs, urljoin

from loguru import logger

from bugtrace.agents.dastysast.types import JS_PARAM_SKIP


def extract_html_params(html: str, agent_name: str = "DASTySAST") -> List[str]:
    """
    Extract parameter names from HTML forms and JS URL patterns.

    Finds parameters like ``searchTerm`` that exist in forms but
    are not in the current URL.  Critical for discovering hidden
    attack surfaces.

    Args:
        html: Raw HTML content to parse.
        agent_name: Agent name for log context.

    Returns:
        Deduplicated list of parameter names found in forms and JS.
    """  # PURE
    from bs4 import BeautifulSoup

    params: List[str] = []
    if not html:
        return params

    try:
        soup = BeautifulSoup(html, "html.parser")

        # --- Extract from all <form> elements ---
        for form in soup.find_all("form"):
            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                name = inp.get("name")
                inp_type = inp.get("type", "text").lower()

                if not name:
                    continue
                if inp_type in ("submit", "button", "image", "reset"):
                    continue
                if name.lower() in (
                    "csrf", "token", "_token",
                    "csrfmiddlewaretoken", "__requestverificationtoken",
                ):
                    continue

                params.append(name)
                logger.debug(
                    f"[{agent_name}] Found form param: {name} "
                    f"(type={inp_type}, method={form.get('method', 'GET').upper()})"
                )

        # --- Deduplicate while preserving order ---
        seen: set = set()
        unique_params: List[str] = []
        for p in params:
            if p not in seen:
                seen.add(p)
                unique_params.append(p)

        # --- JavaScript URL construction patterns (SPA discovery) ---
        js_count = 0
        for match in re.finditer(r"[?&]([a-zA-Z_]\w{1,30})=", html):
            param_name = match.group(1)
            if param_name.lower() in JS_PARAM_SKIP:
                continue
            if param_name not in seen:
                seen.add(param_name)
                unique_params.append(param_name)
                js_count += 1
                logger.debug(
                    f"[{agent_name}] Found JS URL param: {param_name} "
                    f"(source=js_url_pattern)"
                )
        if js_count:
            logger.info(
                f"[{agent_name}] Extracted {js_count} params from JS URL patterns"
            )

        if unique_params:
            logger.info(
                f"[{agent_name}] Extracted {len(unique_params)} total params "
                f"from HTML: {unique_params}"
            )

        return unique_params

    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to extract HTML params: {e}")
        return []


def extract_link_sqli_targets(
    html: str, url: str, agent_name: str = "DASTySAST"
) -> Dict[str, Dict[str, str]]:
    """
    Extract query parameters from ``<a href>`` links in the HTML.

    Returns a dict mapping endpoint URLs to their query params.
    Only same-origin links are included.

    Example return::

        {
            "https://example.com/catalog?category=Juice": {"category": "Juice"},
            "https://example.com/product?id=1": {"id": "1"},
        }

    Args:
        html: Raw HTML content.
        url: Current page URL (for same-origin checks).
        agent_name: Agent name for log context.

    Returns:
        Dict mapping clean endpoint URLs to param dicts.
    """  # PURE
    from bs4 import BeautifulSoup

    targets: Dict[str, Dict[str, str]] = {}
    if not html:
        return targets

    try:
        parsed_self = urlparse(url)
        soup = BeautifulSoup(html, "html.parser")

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                continue
            try:
                resolved_url = urljoin(url, href)
                resolved = urlparse(resolved_url)

                # Same-origin only
                if resolved.netloc and resolved.netloc != parsed_self.netloc:
                    continue

                link_params = parse_qs(resolved.query)
                if not link_params:
                    continue

                clean_url = f"{resolved.scheme}://{resolved.netloc}{resolved.path}"
                if clean_url not in targets:
                    targets[clean_url] = {}

                for p_name, p_vals in link_params.items():
                    if p_name not in targets[clean_url]:
                        targets[clean_url][p_name] = p_vals[0] if p_vals else ""

            except Exception:
                continue

        if targets:
            total_params = sum(len(v) for v in targets.values())
            logger.info(
                f"[{agent_name}] Extracted {total_params} params from "
                f"{len(targets)} link endpoints for SQLi probing"
            )

    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to extract link params: {e}")

    return targets


def detect_frontend_frameworks(
    html: str, existing_frameworks: List[str], agent_name: str = "DASTySAST"
) -> List[str]:
    """
    Detect frontend frameworks from raw HTML content.

    Updates and returns the framework list so callers can merge it
    back into ``tech_profile["frameworks"]``.

    Args:
        html: Full HTML content.
        existing_frameworks: Frameworks already detected (e.g. from Nuclei).
        agent_name: Agent name for log context.

    Returns:
        Updated frameworks list (may contain new entries).
    """  # PURE
    if not html:
        return existing_frameworks

    detected: List[str] = []
    html_lower = html.lower()

    # AngularJS detection
    angular_indicators = [
        "ng-app", "ng-controller", "ng-model", "ng-bind", "ng-repeat",
        "data-ng-app", "data-ng-controller", "x-ng-app",
        "{{", "}}",
    ]
    if any(indicator in html_lower for indicator in angular_indicators):
        if "ng-app" in html_lower or "ng-controller" in html_lower or "angular" in html_lower:
            detected.append("AngularJS")
            logger.info(f"[{agent_name}] Detected AngularJS from HTML (ng-app/ng-controller/angular)")
        elif "{{" in html and "}}" in html:
            if "ng-" in html_lower or "angular" in html_lower:
                detected.append("AngularJS")
                logger.info(f"[{agent_name}] Detected AngularJS from HTML (ng-* + {{{{}}}})")

    # Vue.js detection
    vue_indicators = [
        "v-bind", "v-model", "v-if", "v-for", "v-on:", "@click", ":href",
        "vue.js", "vue.min.js", "vue@", "vuejs",
    ]
    if any(indicator in html_lower for indicator in vue_indicators):
        detected.append("Vue.js")
        logger.info(f"[{agent_name}] Detected Vue.js from HTML")

    # React detection
    react_indicators = ["data-reactroot", "data-reactid", "__react", "react-dom"]
    if any(indicator in html_lower for indicator in react_indicators):
        detected.append("React")
        logger.info(f"[{agent_name}] Detected React from HTML")

    # Merge into existing list
    result = list(existing_frameworks)
    for fw in detected:
        if fw not in result:
            result.append(fw)

    if detected:
        logger.info(f"[{agent_name}] Updated frameworks: {result}")

    return result
