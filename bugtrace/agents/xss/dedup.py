"""
XSS finding deduplication.

Pure fingerprinting combined with I/O for LLM-based dedup.
Handles the WET -> DRY pipeline for XSS findings.

Extracted from xss_agent.py:
- analyze_and_dedup_queue (line 3308) - partially, queue I/O stays in agent
- _llm_analyze_and_dedup (line 3425) -> llm_analyze_and_dedup (I/O)
- _fallback_fingerprint_dedup (line 3547) -> fallback_fingerprint_dedup (PURE)
- _load_recon_urls_with_params (line 3560) -> load_recon_urls_with_params (I/O - filesystem)
"""

import json
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard

logger = get_logger("agents.xss.dedup")


# =========================================================================
# PURE DEDUPLICATION
# =========================================================================

def fallback_fingerprint_dedup(
    wet_findings: List[Dict],
    fingerprint_fn: Callable[[Dict], Tuple] = None,
) -> List[Dict]:
    """
    Deduplicate findings using fingerprint-based approach.

    Falls back to this when LLM dedup fails. Uses the provided fingerprint
    function or a default XSS fingerprint.

    PURE function.

    Args:
        wet_findings: List of WET finding dicts to deduplicate.
        fingerprint_fn: Callable that takes a finding dict and returns
            a hashable tuple. If None, uses default (url, param, context).

    Returns:
        Deduplicated list of findings (order preserved, first wins).
    """
    if fingerprint_fn is None:
        fingerprint_fn = _default_xss_fingerprint

    seen, dry_list = set(), []
    for f in wet_findings:
        fp = fingerprint_fn(f)
        if fp not in seen:
            seen.add(fp)
            dry_list.append(f)
    return dry_list


def _default_xss_fingerprint(finding: Dict) -> Tuple:
    """
    Default XSS finding fingerprint for dedup.

    Uses (url, parameter, context) with optional sink/source.

    PURE function.

    Args:
        finding: Finding dict with url, parameter, context, and optional evidence.

    Returns:
        Hashable tuple fingerprint.
    """
    evidence = finding.get("evidence") or {}
    return (
        finding.get("url", ""),
        finding.get("parameter", ""),
        finding.get("context", "html"),
        evidence.get("sink", ""),
        evidence.get("source", ""),
    )


def expand_wet_findings(
    wet_findings: List[Dict],
    discovered_params: Dict[str, Dict],
    param_methods: Dict[str, str],
    scan_context: str,
) -> List[Dict]:
    """
    Expand WET findings with additional discovered parameters.

    Takes the original WET findings and discovered params, merges them
    ensuring all original WET params are preserved and new discovered
    params are added.

    PURE function.

    Args:
        wet_findings: Original WET findings from queue.
        discovered_params: Dict of param_name -> metadata from discovery.
        param_methods: Dict of param_name -> HTTP method.
        scan_context: Scan context string for new findings.

    Returns:
        Expanded list of WET findings including discovered params.
    """
    expanded = []
    seen_params = set()

    # 1. Always include ALL original WET params first
    for wet_item in wet_findings:
        url = wet_item.get("url", "")
        param = wet_item.get("parameter", "") or (
            wet_item.get("finding", {}) or {}
        ).get("parameter", "")

        if param and (url, param) not in seen_params:
            seen_params.add((url, param))
            if "http_method" not in wet_item:
                wet_item["http_method"] = (
                    wet_item.get("finding", {}) or {}
                ).get("http_method") or "GET"
            expanded.append(wet_item)

    # 2. Add discovered params per unique URL
    seen_urls = set()
    for wet_item in wet_findings:
        url = wet_item.get("url", "")
        if url in seen_urls:
            continue
        seen_urls.add(url)

        for param_name, meta in discovered_params.items():
            if (url, param_name) not in seen_params:
                seen_params.add((url, param_name))
                expanded.append({
                    "url": url,
                    "parameter": param_name,
                    "context": wet_item.get("context", "html"),
                    "finding": wet_item.get("finding", {}),
                    "scan_context": scan_context,
                    "_discovered": True,
                    "http_method": param_methods.get(param_name, "GET"),
                    "param_source": meta.get("source", "unknown"),
                    "form_enctype": meta.get("enctype", ""),
                    "form_action": meta.get("action_url", ""),
                })

    return expanded


def merge_wet_metadata_into_dry(
    dry_list: List[Dict],
    wet_findings: List[Dict],
) -> List[Dict]:
    """
    Post-LLM merge: ensure deterministic fields are preserved.

    LLM may drop metadata fields like http_method, param_source, etc.
    This restores them from the original WET findings.

    PURE function (returns the same list, mutated in place for efficiency).

    Args:
        dry_list: Deduplicated list from LLM.
        wet_findings: Original WET findings with full metadata.

    Returns:
        dry_list with metadata fields restored.
    """
    wet_meta_map = {}
    for wf in wet_findings:
        key = (wf.get("url", ""), wf.get("parameter", ""))
        wet_meta_map[key] = {
            "http_method": wf.get("http_method", "GET"),
            "param_source": wf.get("param_source", ""),
            "form_enctype": wf.get("form_enctype", ""),
            "form_action": wf.get("form_action", ""),
        }

    for df in dry_list:
        key = (df.get("url", ""), df.get("parameter", ""))
        wet_meta = wet_meta_map.get(key, {})
        if not df.get("http_method"):
            df["http_method"] = wet_meta.get("http_method", "GET")
        if not df.get("param_source"):
            df["param_source"] = wet_meta.get("param_source", "")
        if not df.get("form_enctype"):
            df["form_enctype"] = wet_meta.get("form_enctype", "")
        if not df.get("form_action"):
            df["form_action"] = wet_meta.get("form_action", "")

    return dry_list


# =========================================================================
# LLM DEDUP PROMPT (PURE)
# =========================================================================

def build_dedup_system_prompt(
    wet_findings: List[Dict],
    tech_stack: Dict,
    xss_prime_directive: str = "",
    xss_dedup_context: str = "",
) -> str:
    """
    Build the LLM system prompt for XSS deduplication.

    PURE function.

    Args:
        wet_findings: List of WET findings for context.
        tech_stack: Tech stack info dict with lang, server, waf, frameworks.
        xss_prime_directive: Prime directive prompt string.
        xss_dedup_context: Dedup context prompt string.

    Returns:
        Complete system prompt string for LLM dedup call.
    """
    lang = tech_stack.get("lang", "generic")
    server = tech_stack.get("server", "generic")
    waf = tech_stack.get("waf")
    frameworks = tech_stack.get("frameworks", [])

    return f"""You are an expert XSS security analyst with deep knowledge of web frameworks.

{xss_prime_directive}

{xss_dedup_context}

## TARGET CONTEXT
- Backend Language: {lang}
- Web Server: {server}
- WAF: {waf or 'None detected'}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'Unknown'}

## WET LIST ({len(wet_findings)} potential XSS findings):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Analyze each finding considering the injection context (HTML body, attribute, JS, etc.)
2. **CRITICAL - Framework Detection from Findings:**
   - ALWAYS check each item's nested "finding.reasoning" field for framework mentions
   - Look for: AngularJS, Angular, Vue, React, Ember, Svelte in the reasoning text
   - If reasoning mentions "AngularJS" or "Angular 1.x" -> recommended_payload_type: "template"
   - If reasoning mentions "Vue" -> recommended_payload_type: "template"
   - If reasoning mentions "React" -> recommended_payload_type: "template"
   - Template payloads like {{{{constructor.constructor('alert(1)')()}}}} bypass framework sandboxes
   - Event handlers (onclick, onerror, onfocus) are BLOCKED by Angular/Vue/React CSP
   - THIS IS CRITICAL: Event handler payloads WILL FAIL on these frameworks
3. Apply context-aware deduplication:
   - **CRITICAL:** If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param -> DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context type -> DIFFERENT (keep both)
   - Different endpoints -> DIFFERENT (keep both)
   - ONLY mark as DUPLICATE if: Same URL + Same param + Same context
4. Prioritize findings based on framework exploitability
5. Filter findings unlikely to succeed given the tech stack
6. **ATTACK STRATEGY REASONING**: For each finding, reason about the BEST way to attack it:
   - Consider the http_method (GET vs POST -- POST params must be sent in form body, not URL)
   - Consider the param_source (form_input, url_query, anchor_href)
   - Consider form_enctype if present (multipart vs url-encoded)
   - Consider the reflection context and server escaping behavior from the reasoning
   - Example: "POST form param reflecting unescaped in HTML text. Use visual DOM payload via POST body."
   - Example: "GET param in JS single-quoted string. Server escapes backslash to double-backslash but NOT quotes. Backslash-quote breakout: \\' followed by JS payload."

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "context": "html_body|attribute|javascript|url|css",
      "http_method": "GET or POST (preserve from input, default GET)",
      "attack_strategy": "Brief reasoning about HOW to exploit this param considering method, context, escaping",
      "rationale": "why this is unique and exploitable",
      "attack_priority": 1-5,
      "recommended_payload_type": "svg|img|script|event_handler|template"
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation of deduplication strategy"
}}"""


# =========================================================================
# LLM-BASED DEDUP (I/O)
# =========================================================================

async def llm_analyze_and_dedup(
    llm_client,
    wet_findings: List[Dict],
    tech_stack: Dict,
    xss_prime_directive: str = "",
    xss_dedup_context: str = "",
    agent_name: str = "XSSAgent",
) -> List[Dict]:
    """
    Call LLM to analyze WET list and generate DRY list (v3.2: Context-Aware).

    Uses tech stack context for intelligent XSS-specific filtering.

    I/O function - calls LLM API.

    Args:
        llm_client: LLM client instance for generating responses.
        wet_findings: List of WET findings to deduplicate.
        tech_stack: Tech stack info dict.
        xss_prime_directive: Prime directive prompt.
        xss_dedup_context: Dedup context prompt.
        agent_name: Agent name for logging.

    Returns:
        Deduplicated DRY list.

    Raises:
        Exception: If LLM call fails (caller should fall back to fingerprint dedup).
    """
    system_prompt = build_dedup_system_prompt(
        wet_findings, tech_stack, xss_prime_directive, xss_dedup_context,
    )

    response = await llm_client.generate(
        prompt="Analyze the WET list above and return deduplicated XSS findings in JSON format.",
        system_prompt=system_prompt,
        module_name="XSS_DEDUP",
        temperature=0.2,
    )

    dry_data = json.loads(response)
    dry_list = dry_data.get("findings", wet_findings)

    # Restore metadata that LLM may have dropped
    dry_list = merge_wet_metadata_into_dry(dry_list, wet_findings)

    logger.info(
        f"[{agent_name}] LLM deduplication: "
        f"{dry_data.get('reasoning', 'No reasoning provided')}"
    )
    return dry_list


# =========================================================================
# RECON URL LOADING (I/O - filesystem)
# =========================================================================

def load_recon_urls_with_params(
    report_dir: Path,
    base_url: str,
    max_urls: int = 10,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Load recon URLs that have query parameters from GoSpider output.

    Only includes URLs with ?param=value (they have injectable surfaces).
    Capped to avoid excessive testing.

    I/O function - reads filesystem.

    Args:
        report_dir: Path to the report directory.
        base_url: Base URL for same-domain filtering.
        max_urls: Maximum number of URLs to return.
        agent_name: Agent name for logging.

    Returns:
        List of recon URLs with query parameters.
    """
    if not report_dir:
        return []

    urls_file = Path(report_dir) / "recon" / "urls.txt"
    if not urls_file.exists():
        return []

    try:
        base_domain = urlparse(base_url).netloc
        recon_urls = []

        for line in urls_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = urlparse(line)
            # Only same-domain URLs with query params
            if parsed.netloc == base_domain and parsed.query:
                recon_urls.append(line)
                if len(recon_urls) >= max_urls:
                    break

        if recon_urls:
            logger.info(
                f"[{agent_name}] Loaded {len(recon_urls)} recon URLs with params"
            )
        return recon_urls

    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to load recon URLs: {e}")
        return []


__all__ = [
    # Pure
    "fallback_fingerprint_dedup",
    "expand_wet_findings",
    "merge_wet_metadata_into_dry",
    "build_dedup_system_prompt",
    # I/O
    "llm_analyze_and_dedup",
    "load_recon_urls_with_params",
]
