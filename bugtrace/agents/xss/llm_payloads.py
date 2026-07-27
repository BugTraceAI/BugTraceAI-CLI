"""
LLM-driven payload generation and analysis for XSS.

Pure prompt building + response parsing, with thin I/O wrappers for
the LLM client.

Extracted from xss_agent.py (lines 7146-7290).
"""

import json
import re
from typing import Dict, List, Optional, Any

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("agents.xss.llm_payloads")


# ---------------------------------------------------------------------------
# PURE FUNCTIONS
# ---------------------------------------------------------------------------

def build_analysis_system_prompt(
    interactsh_url: str,
    context_str: str,
    probe_string: str,
    system_prompt_override: Optional[str] = None,
) -> str:
    """
    Build system prompt for LLM XSS analysis.

    If system_prompt_override is provided and contains a "# Master XSS Analysis Prompt"
    section, it replaces the default prompt body. The prompt template always has
    placeholders replaced for interactsh_url, probe, and context_data.

    Args:
        interactsh_url: OOB callback URL for payload validation.
        context_str: JSON-formatted string of reflection context metadata.
        probe_string: The probe string used for reflection detection.
        system_prompt_override: Optional custom system prompt from agent configuration.

    Returns:
        Complete system prompt string with all placeholders replaced.
    """
    master_prompt = """You are an elite XSS (Cross-Site Scripting) expert.
Analyze the provided HTML and the reflection context metadata.
Your goal is to generate a payload that will execute JavaScript.
The payload MUST include this callback URL for validation: {interactsh_url}

REFLECTION CONTEXT METADATA:
{context_data}

Rules:
1. If reflection is in 'html_text', use tags like <svg/onload=...> or <img src=x onerror=...>.
2. If reflection is in 'attribute_value', try to break out using "> or '>.
3. If reflection is in 'script' context, try to break out using '; or "; or use template literals.
4. ONLY generate a payload if the 'surviving_chars' allow for the necessary breakout.
5. If major characters like < or > are missing, try event handlers or javascript: pseudo-protocol if applicable.

Response Format (XML-Like):
<thought>Analysis of the context and why the chosen payload will work</thought>
<payload>The payload string</payload>
<validation_method>interactsh OR vision OR cdp</validation_method>
<context>Description of target context (e.g., inside href, between tags)</context>
<confidence>0.0 to 1.0</confidence>
"""

    if system_prompt_override:
        parts = system_prompt_override.split("# XSS Bypass Prompt")
        master_prompt = parts[0].replace("# Master XSS Analysis Prompt", "").strip()
        master_prompt += f"\n\nREFLECTION CONTEXT METADATA:\n{context_str}"

    return master_prompt.replace("{interactsh_url}", interactsh_url) \
                        .replace("{probe}", probe_string) \
                        .replace("{PROBE}", probe_string) \
                        .replace("{context_data}", context_str)


def parse_analysis_response(
    response: str,
    param: str,
    clean_payload_fn=None,
) -> Optional[Dict]:
    """
    Parse LLM response and extract payload data.

    Tries structured XML parsing first (via XmlParser), then falls back to
    heuristic extraction of lines containing alert() or fetch().

    Args:
        response: Raw LLM response string.
        param: Parameter name (used for payload cleaning).
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        Dict with keys: vulnerable, payload, validation_method, context, confidence.
        Returns None if no payload could be extracted.
    """
    from bugtrace.utils.parsers import XmlParser
    tags = ["payload", "validation_method", "context", "confidence"]
    data = XmlParser.extract_tags(response, tags)

    if data.get("payload"):
        cleaned_payload = data["payload"]
        if clean_payload_fn:
            cleaned_payload = clean_payload_fn(cleaned_payload, param)
        return {
            "vulnerable": True,
            "payload": cleaned_payload,
            "validation_method": data.get("validation_method", "interactsh"),
            "context": data.get("context", "LLM Generated"),
            "confidence": float(data.get("confidence", 0.9))
        }

    # Fallback for non-XML compliant models
    if "alert(" in response or "fetch(" in response:
        logger.warning("LLM failed XML tags but returned code. Attempting to extract payload manually.")
        lines = [l.strip() for l in response.strip().split("\n") if l.strip()]
        for line in reversed(lines):
            if "alert(" in line or "fetch(" in line:
                cleaned = line
                if clean_payload_fn:
                    cleaned = clean_payload_fn(cleaned, param)
                return {
                    "vulnerable": True,
                    "payload": cleaned,
                    "validation_method": "interactsh",
                    "context": "Heuristic Extraction",
                    "confidence": 0.5
                }
    return None


def build_bypass_prompt(
    previous_payload: str,
    response_snippet: str,
    interactsh_url: str,
    system_prompt_override: Optional[str] = None,
) -> str:
    """
    Build prompt for LLM bypass payload generation.

    Args:
        previous_payload: The payload that failed.
        response_snippet: HTTP response snippet showing the failure (truncated to 3000 chars).
        interactsh_url: OOB callback URL.
        system_prompt_override: Optional custom system prompt with "# XSS Bypass Prompt" section.

    Returns:
        Formatted bypass prompt string.
    """
    bypass_prompt_template = """The previous payload did not trigger a callback.
Previous payload: {previous_payload}
HTTP Response: {response_snippet}
Analyze why it failed and generate a BYPASS payload with {interactsh_url}.

Response Format (XML-Like):
<thought>Analysis of failure</thought>
<bypass_payload>New payload to try</bypass_payload>
<confidence>0.1 to 1.0</confidence>
"""

    if system_prompt_override and "# XSS Bypass Prompt" in system_prompt_override:
        bypass_prompt_template = system_prompt_override.split("# XSS Bypass Prompt")[1].strip()

    return bypass_prompt_template.replace("{previous_payload}", previous_payload) \
                                 .replace("{response_snippet}", response_snippet[:3000]) \
                                 .replace("{interactsh_url}", interactsh_url)


# ---------------------------------------------------------------------------
# I/O FUNCTIONS
# ---------------------------------------------------------------------------

async def llm_analyze(
    llm_client,
    url: str,
    html: str,
    param: str,
    probe_string: str,
    interactsh_url: str,
    context_data: Optional[Dict] = None,
    system_prompt_override: Optional[str] = None,
    clean_payload_fn=None,
) -> Optional[Dict]:
    """
    Ask LLM to analyze HTML and generate payload.

    Args:
        llm_client: LLM client instance with async generate() method.
        url: Target URL.
        html: HTML response source (truncated to 12000 chars in prompt).
        param: Parameter name being tested.
        probe_string: The probe string used for reflection detection.
        interactsh_url: OOB callback URL.
        context_data: Optional reflection context metadata dict.
        system_prompt_override: Optional custom system prompt.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        Dict with payload data, or None.
    """
    context_str = json.dumps(context_data or {}, indent=2)

    system_prompt = build_analysis_system_prompt(
        interactsh_url, context_str, probe_string, system_prompt_override
    )

    user_prompt = f"""Target URL: {url}
Parameter: {param}
Probe: {probe_string}
Interactsh: {interactsh_url}

HTML Reflection Source (truncated):
```html
{html[:12000]}
```

Generate the OPTIMAL XSS payload based on the metadata and HTML.
"""

    try:
        response = await llm_client.generate(
            prompt=user_prompt,
            module_name="XSS_AGENT",
            system_prompt=system_prompt,
            model_override=settings.MUTATION_MODEL,
            max_tokens=8000  # Increased for reasoning models
        )

        logger.info(f"LLM Raw Response ({len(response)} chars)")
        return parse_analysis_response(response, param, clean_payload_fn)

    except Exception as e:
        logger.error(f"LLM analysis failed: {e}", exc_info=True)
        return None


async def llm_generate_bypass(
    llm_client,
    previous_payload: str,
    response_snippet: str,
    interactsh_url: str,
    system_prompt_override: Optional[str] = None,
    clean_payload_fn=None,
) -> Optional[Dict]:
    """
    Ask LLM to generate bypass payload after a failed attempt.

    Args:
        llm_client: LLM client instance with async generate() method.
        previous_payload: The payload that failed.
        response_snippet: HTTP response snippet showing the failure.
        interactsh_url: OOB callback URL.
        system_prompt_override: Optional custom system prompt.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        Dict with bypass_payload and confidence, or None.
    """
    prompt = build_bypass_prompt(
        previous_payload, response_snippet, interactsh_url, system_prompt_override
    )

    try:
        response = await llm_client.generate(
            prompt=prompt,
            module_name="XSS_AGENT_BYPASS",
            system_prompt="You are a WAF bypass expert. Respond ONLY in XML tags: <bypass_payload>, <confidence>.",
            model_override=settings.MUTATION_MODEL,
        )

        from bugtrace.utils.parsers import XmlParser
        tags = ["bypass_payload", "confidence"]
        data = XmlParser.extract_tags(response, tags)

        if data.get("bypass_payload"):
            if clean_payload_fn:
                data["bypass_payload"] = clean_payload_fn(data["bypass_payload"], "fake")
            return data
        return None

    except Exception as e:
        logger.error(f"LLM bypass generation failed: {e}", exc_info=True)
        return None


__all__ = [
    # Pure
    "build_analysis_system_prompt",
    "parse_analysis_response",
    "build_bypass_prompt",
    # I/O
    "llm_analyze",
    "llm_generate_bypass",
]
