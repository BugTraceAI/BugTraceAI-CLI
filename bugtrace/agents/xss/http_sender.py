"""
HTTP payload sending for XSS testing.

I/O layer - makes HTTP requests to target with WAF awareness.
Separated from pure logic to enable testability and clear I/O boundaries.

Extracted from xss_agent.py (lines 7291-7377):
- _update_block_counter -> update_block_counter (PURE)
- _handle_send_error -> handle_send_error (PURE)
- _send_payload -> send_payload (I/O)
- _fast_reflection_check -> fast_reflection_check (I/O)
- _python_reflection_check -> python_reflection_check (I/O)
"""

from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.http_manager import http_manager, ConnectionProfile

logger = get_logger("agents.xss.http_sender")


# =========================================================================
# BLOCK STATE MANAGEMENT (PURE)
# =========================================================================

def update_block_counter(block_state: Dict, status_code: int, agent_name: str = "XSSAgent") -> Dict:
    """
    Return updated block state based on response status code.

    Instead of mutating self.consecutive_blocks / self.stealth_mode, this
    function takes an immutable state dict and returns a NEW dict with
    updated counters.

    PURE function - no side effects beyond logging.

    Args:
        block_state: Dict with keys:
            - consecutive_blocks (int): Current consecutive block count
            - stealth_mode (bool): Whether stealth mode is active
        status_code: HTTP response status code
        agent_name: Agent name for log messages

    Returns:
        New dict with updated consecutive_blocks and stealth_mode.
    """
    new_state = dict(block_state)

    if status_code == 200:
        if new_state["consecutive_blocks"] > 0:
            logger.info(f"[{agent_name}] Target responded 200. Recovering...")
        new_state["consecutive_blocks"] = 0
        return new_state

    if status_code in [403, 406, 501]:
        new_state["consecutive_blocks"] = new_state["consecutive_blocks"] + 1
        logger.warning(
            f"[{agent_name}] Potential WAF Block ({status_code}). "
            f"Counter: {new_state['consecutive_blocks']}"
        )

    return new_state


def should_enter_stealth_mode(block_state: Dict) -> bool:
    """
    Check if too many consecutive blocks require entering stealth mode.

    PURE function.

    Args:
        block_state: Dict with consecutive_blocks and stealth_mode.

    Returns:
        True if stealth mode should be activated.
    """
    return (
        block_state["consecutive_blocks"] >= 3
        and not block_state["stealth_mode"]
    )


def handle_send_error(block_state: Dict, agent_name: str = "XSSAgent") -> Dict:
    """
    Handle a network error / WAF TCP reset and return updated block state.

    Increments the consecutive block counter. If the threshold is reached
    and stealth mode is not yet active, activates it.

    PURE function (returns new state, does not mutate input).

    Args:
        block_state: Dict with consecutive_blocks and stealth_mode.
        agent_name: Agent name for log messages.

    Returns:
        New dict with updated consecutive_blocks and stealth_mode.
    """
    new_state = dict(block_state)
    new_state["consecutive_blocks"] = new_state["consecutive_blocks"] + 1
    logger.warning(
        f"[{agent_name}] Network Failure / WAF TCP Reset. "
        f"Counter: {new_state['consecutive_blocks']}"
    )

    if should_enter_stealth_mode(new_state):
        new_state["stealth_mode"] = True
        dashboard.log(
            f"[{agent_name}] WAF DETECTED! Entering Stealth Mode (Slow-down & Random Delay)",
            "WARN",
        )
        logger.warning(
            f"[{agent_name}] WAF confirmed via network resets. Enabling Stealth Mode."
        )

    return new_state


def make_block_state(consecutive_blocks: int = 0, stealth_mode: bool = False) -> Dict:
    """
    Create a new block state dict.

    Convenience constructor for the immutable block state used by
    update_block_counter and handle_send_error.

    PURE function.

    Args:
        consecutive_blocks: Initial consecutive block count.
        stealth_mode: Initial stealth mode flag.

    Returns:
        Block state dict.
    """
    return {
        "consecutive_blocks": consecutive_blocks,
        "stealth_mode": stealth_mode,
    }


# =========================================================================
# HTTP SENDING (I/O)
# =========================================================================

async def send_payload(
    url: str,
    param: str,
    payload: str,
    http_method: str = "GET",
    block_state: Dict = None,
    agent_name: str = "XSSAgent",
) -> Tuple[str, Dict]:
    """
    Send a single XSS payload via HTTP.

    Supports both GET (payload in query string) and POST (payload in form body).
    Returns the response HTML and the updated block state.

    I/O function - makes HTTP requests.

    Args:
        url: Target URL.
        param: Parameter name to inject payload into.
        payload: XSS payload string.
        http_method: "GET" or "POST".
        block_state: Current WAF block state dict. If None, creates a fresh one.
        agent_name: Agent name for logging.

    Returns:
        Tuple of (response_html: str, updated_block_state: Dict).
        On error, response_html is "" and block_state is updated with error.
    """
    if block_state is None:
        block_state = make_block_state()

    parsed = urlparse(url)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    try:
        async with http_manager.session(ConnectionProfile.PROBE) as session:
            if http_method == "POST":
                # POST: payload in form body, keep original URL intact
                base_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, parsed.query, parsed.fragment,
                ))
                post_data = {param: payload}
                async with session.post(
                    base_url, data=post_data, headers=headers, ssl=False
                ) as resp:
                    new_state = update_block_counter(block_state, resp.status, agent_name)
                    return await resp.text(), new_state
            else:
                # GET: payload in query string
                params = {
                    k: v[0] if isinstance(v, list) else v
                    for k, v in parse_qs(parsed.query).items()
                }
                params[param] = payload
                attack_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params), parsed.fragment,
                ))
                async with session.get(
                    attack_url, headers=headers, ssl=False
                ) as resp:
                    new_state = update_block_counter(block_state, resp.status, agent_name)
                    return await resp.text(), new_state

    except Exception:
        new_state = handle_send_error(block_state, agent_name)
        return "", new_state


async def fast_reflection_check(
    url: str,
    param: str,
    payloads: List[str],
    external_tools=None,
    http_method: str = "GET",
    block_state: Dict = None,
    agent_name: str = "XSSAgent",
) -> Tuple[List[Dict], Dict]:
    """
    Check which payloads reflect in HTTP responses.

    Uses Go fuzzer if available, otherwise falls back to Python.
    Returns list of reflection objects and updated block state.

    I/O function.

    Args:
        url: Target URL.
        param: Parameter name.
        payloads: List of payload strings to test.
        external_tools: External tools module (for Go fuzzer). If None, uses Python.
        http_method: HTTP method for fallback Python check.
        block_state: Current WAF block state.
        agent_name: Agent name for logging.

    Returns:
        Tuple of (reflections: List[Dict], updated_block_state: Dict).
        Each reflection dict has: {"payload": str, "encoded": bool, "context": str}
    """
    if block_state is None:
        block_state = make_block_state()

    # Try Go fuzzer first
    if external_tools is not None:
        go_result = await external_tools.run_go_xss_fuzzer(url, param, payloads)

        if go_result and go_result.get("reflections"):
            duration = go_result.get("metadata", {}).get("duration_ms", 0)
            logger.info(
                f"[{agent_name}] Go fuzzer found "
                f"{len(go_result['reflections'])} reflections in {duration}ms"
            )
            return go_result["reflections"], block_state

    # Fallback to Python
    reflected_payloads, block_state = await python_reflection_check(
        url, param, payloads, http_method, block_state, agent_name
    )
    reflections = [
        {"payload": p, "encoded": False, "context": "unknown"}
        for p in reflected_payloads
    ]
    return reflections, block_state


async def python_reflection_check(
    url: str,
    param: str,
    payloads: List[str],
    http_method: str = "GET",
    block_state: Dict = None,
    agent_name: str = "XSSAgent",
) -> Tuple[List[str], Dict]:
    """
    Fallback reflection check using Python aiohttp.

    Tests each payload individually and checks if it appears in the response.

    I/O function.

    Args:
        url: Target URL.
        param: Parameter name.
        payloads: List of payload strings to test.
        http_method: HTTP method to use.
        block_state: Current WAF block state.
        agent_name: Agent name for logging.

    Returns:
        Tuple of (reflected_payloads: List[str], updated_block_state: Dict).
    """
    if block_state is None:
        block_state = make_block_state()

    reflected = []
    for p in payloads:
        html, block_state = await send_payload(
            url, param, p, http_method, block_state, agent_name
        )
        if p in html:
            reflected.append(p)

    return reflected, block_state


__all__ = [
    # Pure state management
    "make_block_state",
    "update_block_counter",
    "should_enter_stealth_mode",
    "handle_send_error",
    # I/O functions
    "send_payload",
    "fast_reflection_check",
    "python_reflection_check",
]
