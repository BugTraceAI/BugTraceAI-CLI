"""
Specialist Agent Utilities

Shared utilities for specialist agents (XSSAgent, SQLiAgent, etc.)
to handle common operations like payload loading from JSON reports.

Version: 2.1.0
Date: 2026-02-02
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.specialist_utils")


def extract_param_metadata(html: str, url: str) -> Dict[str, Dict[str, str]]:
    """
    Extract deterministic parameter metadata from HTML and URL.

    Shared utility for ALL specialists. Returns method, source, action_url,
    and enctype for each discovered parameter. This is the GROUND TRUTH for
    HTTP method detection — deterministic, not LLM-dependent.

    Args:
        html: HTML content of the page
        url: URL of the page (for extracting query params and resolving relative URLs)

    Returns:
        Dict mapping param names to metadata dicts:
        {
            "searchFor": {
                "method": "POST",
                "action_url": "http://example.com/search.php",
                "enctype": "application/x-www-form-urlencoded",
                "source": "form_input",
                "default_value": ""
            },
            "category": {
                "method": "GET",
                "action_url": "",
                "enctype": "",
                "source": "url_query",
                "default_value": "Juice"
            }
        }

    Sources detected:
        - url_query: Parameter in URL query string (always GET)
        - form_input: Parameter in HTML <form> (<input>, <textarea>, <select>)
        - anchor_href: Parameter in <a href="?param=val"> link (always GET)
        - js_url_pattern: Parameter found in JavaScript URL construction (SPA discovery)
    """
    from bs4 import BeautifulSoup

    metadata = {}
    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    # 1. URL query parameters → always GET
    try:
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            metadata[param_name] = {
                "method": "GET",
                "action_url": f"{base_origin}{parsed.path}",
                "enctype": "",
                "source": "url_query",
                "default_value": values[0] if values else "",
            }
    except Exception:
        pass

    if not html:
        return metadata

    try:
        soup = BeautifulSoup(html, "html.parser")

        # 2. HTML form inputs → method from parent <form>
        for tag in soup.find_all(["input", "textarea", "select"]):
            param_name = tag.get("name")
            if not param_name:
                continue
            if param_name in metadata:
                continue  # URL query takes precedence

            input_type = tag.get("type", "text").lower()
            if input_type in ("submit", "button", "reset"):
                continue
            if "csrf" in param_name.lower() or "token" in param_name.lower():
                continue

            parent_form = tag.find_parent("form")
            if parent_form:
                form_method = (parent_form.get("method") or "GET").upper()
                form_action = parent_form.get("action", "")
                action_url = urljoin(url, form_action) if form_action else url
                form_enctype = parent_form.get("enctype", "application/x-www-form-urlencoded")
            else:
                form_method = "GET"
                action_url = url
                form_enctype = ""

            metadata[param_name] = {
                "method": form_method,
                "action_url": action_url,
                "enctype": form_enctype,
                "source": "form_input",
                "default_value": tag.get("value", ""),
            }

        # 3. Anchor href params → always GET
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                continue
            try:
                link = urljoin(url, href)
                parsed_link = urlparse(link)
                if parsed_link.netloc and parsed_link.netloc != parsed.netloc:
                    continue
                link_params = parse_qs(parsed_link.query)
                for p_name, p_vals in link_params.items():
                    if p_name not in metadata and "csrf" not in p_name.lower():
                        metadata[p_name] = {
                            "method": "GET",
                            "action_url": f"{base_origin}{parsed_link.path}",
                            "enctype": "",
                            "source": "anchor_href",
                            "default_value": p_vals[0] if p_vals else "",
                        }
            except Exception:
                continue

        # 4. JavaScript URL construction patterns (SPA parameter discovery)
        # Catches React/Vue/Angular SPAs that build URLs via JS instead of HTML forms.
        # E.g., window.location.href = `/?search=${encodeURIComponent(term)}`
        # These inputs often lack name= attributes, so sources 2-3 miss them.
        _JS_PARAM_SKIP = frozenset({
            "v", "ver", "version", "cb", "ts", "timestamp", "t", "hash",
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
            "fbclid", "gclid", "nonce", "lang", "locale", "charset", "encoding",
        })
        for match in re.finditer(r'[?&]([a-zA-Z_]\w{1,30})=', html):
            param_name = match.group(1)
            if param_name.lower() in _JS_PARAM_SKIP:
                continue
            if param_name not in metadata:
                metadata[param_name] = {
                    "method": "GET",
                    "action_url": f"{base_origin}{parsed.path}",
                    "enctype": "",
                    "source": "js_url_pattern",
                    "default_value": "",
                }

    except Exception as e:
        logger.warning(f"[extract_param_metadata] HTML parsing failed: {e}")

    return metadata


def resolve_param_endpoints(html: str, base_url: str) -> Dict[str, str]:
    """
    Map parameter names to their actual endpoint URLs from HTML links and forms.

    When a specialist receives a base URL (e.g., http://example.com/) but the params
    belong to different endpoints (e.g., /artists.php?artist=1), this function resolves
    each param to its correct endpoint URL by analyzing <a href> and <form action>.

    Args:
        html: HTML content of the page
        base_url: Base URL of the page (for resolving relative URLs)

    Returns:
        Dict mapping param names to their resolved endpoint URLs.
        Only includes params where the endpoint differs from base_url path.

    Example:
        >>> resolve_param_endpoints(html, "http://example.com/")
        {"artist": "http://example.com/artists.php", "q": "http://example.com/search.php"}
    """
    from bs4 import BeautifulSoup

    endpoint_map = {}
    base_parsed = urlparse(base_url)
    base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    try:
        soup = BeautifulSoup(html, "html.parser")

        # 1. Extract params from <a href="page.php?param=value"> links
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            try:
                if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                    continue

                resolved_url = urljoin(base_url, href)
                parsed = urlparse(resolved_url)

                # Only same-domain links
                if parsed.netloc and parsed.netloc != base_parsed.netloc:
                    continue

                link_params = parse_qs(parsed.query)
                if link_params:
                    endpoint = f"{base_origin}{parsed.path}"
                    for param_name in link_params:
                        if param_name not in endpoint_map:
                            endpoint_map[param_name] = endpoint
            except Exception:
                continue

        # 2. Extract params from <form action="page.php"> + <input name="param">
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if not action:
                continue

            try:
                resolved_action = urljoin(base_url, action)
                parsed_action = urlparse(resolved_action)

                if parsed_action.netloc and parsed_action.netloc != base_parsed.netloc:
                    continue

                endpoint = f"{base_origin}{parsed_action.path}"

                for input_tag in form.find_all(["input", "textarea", "select"]):
                    param_name = input_tag.get("name")
                    if param_name:
                        input_type = input_tag.get("type", "text").lower()
                        if input_type not in ["submit", "button", "reset"]:
                            if param_name not in endpoint_map:
                                endpoint_map[param_name] = endpoint
            except Exception:
                continue

    except Exception as e:
        logger.warning(f"[resolve_param_endpoints] HTML parsing failed: {e}")

    return endpoint_map


def resolve_param_from_reasoning(wet_findings: List[Dict[str, Any]], base_url: str) -> Dict[str, str]:
    """
    Extract endpoint URLs from DASTySAST reasoning text as fallback.

    When resolve_param_endpoints() can't find parameterized links in the HTML
    (e.g., homepage has bare links like <a href="artists.php"> without query params),
    this function parses the reasoning text for URL patterns like:
    - "artists.php?artist=1" (full URL with query string)
    - "'artist' in artists.php" (param name associated with a page)

    Args:
        wet_findings: List of WET findings with reasoning/finding_data
        base_url: Base URL for resolving relative paths

    Returns:
        Dict mapping param names to their resolved endpoint URLs.
    """
    endpoint_map = {}
    base_parsed = urlparse(base_url)
    base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    _EXT = r'\.(?:php|asp|aspx|jsp|html|htm|cgi|pl|py|rb|do|action)'

    # Pattern 1: page.php?param=value (full URL with query string)
    url_pattern = re.compile(
        r'([\w./-]+' + _EXT + r')\?'
        r'([\w]+=[\w%+.-]*(?:&[\w]+=[\w%+.-]*)*)'
    )

    # Pattern 2: "'param' in page.php" or "param in page.php" (LLM prose)
    prose_pattern = re.compile(
        r"""['"]([\w]+)['"]\s+(?:in|on|at|from|of|via)\s+"""
        r'([\w./-]+' + _EXT + r')'
    )

    # Pattern 3: "page.php" bare mention near param name (e.g., "listproducts.php is a")
    bare_page_pattern = re.compile(
        r'([\w./-]+' + _EXT + r')'
    )

    for finding in wet_findings:
        # Check both top-level and nested finding_data for reasoning
        reasoning = finding.get("reasoning", "")
        finding_data = finding.get("finding_data", {})
        if not reasoning and finding_data:
            reasoning = finding_data.get("reasoning", "")
        skeptical = finding.get("skeptical_reasoning", "")
        if not skeptical and finding_data:
            skeptical = finding_data.get("skeptical_reasoning", "")

        all_text = f"{reasoning} {skeptical}"

        param_name = finding.get("parameter", "")
        if not all_text.strip() or not param_name:
            continue

        if param_name in endpoint_map:
            continue

        # Try Pattern 1: page.php?param=value
        for match in url_pattern.finditer(all_text):
            path_part = match.group(1)
            query_part = match.group(2)
            try:
                params_in_url = parse_qs(query_part)
                if param_name in params_in_url:
                    endpoint = f"{base_origin}/{path_part.lstrip('/')}"
                    if param_name not in endpoint_map:
                        endpoint_map[param_name] = endpoint
                        logger.debug(
                            f"[resolve_param_from_reasoning] {param_name} -> {endpoint} "
                            f"(pattern 1: URL with query)"
                        )
            except Exception:
                continue

        if param_name in endpoint_map:
            continue

        # Try Pattern 2: "'param' in page.php"
        for match in prose_pattern.finditer(all_text):
            mentioned_param = match.group(1)
            path_part = match.group(2)
            if mentioned_param == param_name:
                endpoint = f"{base_origin}/{path_part.lstrip('/')}"
                endpoint_map[param_name] = endpoint
                logger.debug(
                    f"[resolve_param_from_reasoning] {param_name} -> {endpoint} "
                    f"(pattern 2: prose mention)"
                )
                break

        if param_name in endpoint_map:
            continue

        # Try Pattern 3: bare page mention near param name
        # Only use if exactly one page is mentioned and it's not the base path
        pages_found = set()
        for match in bare_page_pattern.finditer(all_text):
            page = match.group(1)
            if page not in ("index.php", "index.html", "index.asp"):
                pages_found.add(page)
        if len(pages_found) == 1:
            path_part = pages_found.pop()
            endpoint = f"{base_origin}/{path_part.lstrip('/')}"
            base_path = base_parsed.path.rstrip("/")
            endpoint_path = urlparse(endpoint).path.rstrip("/")
            if endpoint_path != base_path:
                endpoint_map[param_name] = endpoint
                logger.debug(
                    f"[resolve_param_from_reasoning] {param_name} -> {endpoint} "
                    f"(pattern 3: unique page mention)"
                )

    return endpoint_map


def load_full_payload_from_json(finding: Dict[str, Any]) -> Optional[str]:
    """
    Load full payload from JSON report when event payload is truncated.

    v2.1.0: Event payloads are truncated to 200 chars to keep events small.
    If a payload appears truncated, this function reads the full payload
    from the JSON report file generated by DASTySASTAgent.

    Args:
        finding: Finding dict from queue with optional _report_files field

    Returns:
        Full payload string if found, None if not available or error

    Example:
        >>> finding = {
        ...     "type": "XSS",
        ...     "parameter": "q",
        ...     "payload": "<script>alert(1)</script>...",  # Truncated to 200
        ...     "_report_files": {"json": "/path/to/1.json"}
        ... }
        >>> full_payload = load_full_payload_from_json(finding)
        >>> # Returns: "<script>alert(document.cookie)</script>{{long_payload}}"
    """
    # Get truncated payload from finding
    truncated_payload = finding.get("payload", "")

    # If payload is short enough, no need to read from JSON
    if len(truncated_payload) < 199:
        return truncated_payload

    # Check if report files reference exists
    report_files = finding.get("_report_files", {})
    json_path = report_files.get("json")

    if not json_path:
        logger.debug("[load_full_payload] No JSON report path available, using truncated payload")
        return truncated_payload

    # Read full payload from JSON
    try:
        json_file = Path(json_path)
        if not json_file.exists():
            logger.warning(f"[load_full_payload] JSON report not found: {json_path}")
            return truncated_payload

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Find matching vulnerability by type and parameter
        finding_type = finding.get("type", "").lower()
        finding_param = finding.get("parameter", "")

        for vuln in data.get("vulnerabilities", []):
            vuln_type = vuln.get("type", "").lower()
            vuln_param = vuln.get("parameter", "")

            # Match by type and parameter
            if finding_type in vuln_type and finding_param == vuln_param:
                full_payload = vuln.get("exploitation_strategy") or vuln.get("payload", "")
                if full_payload and len(full_payload) > len(truncated_payload):
                    logger.info(
                        f"[load_full_payload] Loaded full payload from JSON: "
                        f"{len(full_payload)} chars (was {len(truncated_payload)})"
                    )
                    return full_payload

        logger.debug(
            f"[load_full_payload] No matching vulnerability found in JSON for "
            f"{finding_type}/{finding_param}"
        )
        return truncated_payload

    except Exception as e:
        logger.warning(f"[load_full_payload] Failed to read JSON report: {e}")
        return truncated_payload


def load_full_finding_data(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load full finding data from JSON report, including reasoning and other fields
    that may be truncated in the event.

    Args:
        finding: Finding dict from queue with optional _report_files field

    Returns:
        Finding dict with full data merged from JSON, or original if not available

    Example:
        >>> finding = {"type": "SQLi", "reasoning": "Long reasoning..."[:500]}
        >>> full_finding = load_full_finding_data(finding)
        >>> # full_finding["reasoning"] now contains complete text
    """
    # Check if report files reference exists
    report_files = finding.get("_report_files", {})
    json_path = report_files.get("json")

    if not json_path:
        return finding

    try:
        json_file = Path(json_path)
        if not json_file.exists():
            return finding

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Find matching vulnerability
        finding_type = finding.get("type", "").lower()
        finding_param = finding.get("parameter", "")

        for vuln in data.get("vulnerabilities", []):
            vuln_type = vuln.get("type", "").lower()
            vuln_param = vuln.get("parameter", "")

            if finding_type in vuln_type and finding_param == vuln_param:
                # Merge full data into finding (prefer JSON values for truncated fields)
                merged = finding.copy()
                merged.update({
                    "payload": vuln.get("exploitation_strategy") or vuln.get("payload", merged.get("payload", "")),
                    "reasoning": vuln.get("reasoning", merged.get("reasoning", "")),
                    "fp_reason": vuln.get("fp_reason", merged.get("fp_reason", "")),
                    # Add any other fields that might be useful
                    "context": vuln.get("context", merged.get("context", "")),
                    "reflection_detected": vuln.get("reflection_detected", merged.get("reflection_detected", False)),
                })
                logger.info(f"[load_full_finding_data] Merged full data from JSON for {finding_type}/{finding_param}")
                return merged

        return finding

    except Exception as e:
        logger.warning(f"[load_full_finding_data] Failed to read JSON report: {e}")
        return finding


# =============================================================================
# VISUAL TELEMETRY INSTRUMENTATION (v4.2)
# =============================================================================
# Helper functions for specialist agents to report status to the dashboard.
# Usage: Call these functions at key points in start_queue_consumer() lifecycle.
# =============================================================================


def report_specialist_start(agent_name: str, queue_depth: int = 0):
    """
    Report that a specialist agent has started queue consumption.

    Call this at the start of start_queue_consumer().

    Args:
        agent_name: Agent name (e.g., 'SQLiAgent', 'XSSAgent')
        queue_depth: Initial queue depth
    """
    try:
        from bugtrace.core.ui import dashboard
        dashboard.update_specialist_status(
            agent_name,
            status="ACTIVE",
            queue=queue_depth,
            processed=0,
            vulns=0
        )
        logger.debug(f"[Telemetry] {agent_name} started (queue: {queue_depth})")
    except Exception as e:
        logger.debug(f"[Telemetry] Failed to report start: {e}")

    # Bridge to WebSocket via conductor
    try:
        from bugtrace.core.conductor import conductor
        conductor.notify_log("INFO", f"[SPECIALIST] {agent_name} started (queue: {queue_depth})")
        conductor.notify_agent_update(
            agent=agent_name, status="active",
            queue=queue_depth, processed=0, vulns=0,
        )
    except Exception:
        pass


def report_specialist_progress(agent_name: str, processed: int = None, queue: int = None):
    """
    Report specialist processing progress.

    Call this periodically during queue processing (e.g., after each item).

    Args:
        agent_name: Agent name
        processed: Number of items processed so far
        queue: Current queue depth (optional, for dynamic updates)
    """
    try:
        from bugtrace.core.ui import dashboard
        kwargs = {"status": "ACTIVE"}
        if processed is not None:
            kwargs["processed"] = processed
        if queue is not None:
            kwargs["queue"] = queue
        dashboard.update_specialist_status(agent_name, **kwargs)
    except Exception as e:
        logger.debug(f"[Telemetry] Failed to report progress: {e}")

    # Bridge to WebSocket via conductor
    try:
        from bugtrace.core.conductor import conductor
        conductor.notify_agent_update(
            agent=agent_name, status="active",
            queue=queue if queue is not None else 0,
            processed=processed if processed is not None else 0,
        )
        # Log only every 5 items to avoid flooding
        if processed is not None and processed % 5 == 0:
            queue_str = f", queue: {queue}" if queue is not None else ""
            conductor.notify_log("INFO", f"[SPECIALIST] {agent_name} processed {processed}{queue_str}")
    except Exception:
        pass


def report_specialist_vuln(agent_name: str, vulns_count: int):
    """
    Report that a specialist found a vulnerability.

    Call this when a vulnerability is confirmed.

    Args:
        agent_name: Agent name
        vulns_count: Total vulnerabilities found by this agent
    """
    try:
        from bugtrace.core.ui import dashboard
        dashboard.update_specialist_status(agent_name, vulns=vulns_count)
        logger.debug(f"[Telemetry] {agent_name} reported {vulns_count} vulns")
    except Exception as e:
        logger.debug(f"[Telemetry] Failed to report vuln: {e}")

    # Bridge to WebSocket via conductor
    try:
        from bugtrace.core.conductor import conductor
        conductor.notify_log("INFO", f"[SPECIALIST] {agent_name} found vulnerability ({vulns_count} total)")
    except Exception:
        pass


def report_specialist_done(agent_name: str, processed: int, vulns: int = 0):
    """
    Report that a specialist has finished queue consumption.

    Call this at the end of start_queue_consumer().

    Args:
        agent_name: Agent name
        processed: Total items processed
        vulns: Total vulnerabilities found
    """
    try:
        from bugtrace.core.ui import dashboard
        dashboard.update_specialist_status(
            agent_name,
            status="DONE",
            queue=0,
            processed=processed,
            vulns=vulns
        )
        logger.debug(f"[Telemetry] {agent_name} done (processed: {processed}, vulns: {vulns})")
    except Exception as e:
        logger.debug(f"[Telemetry] Failed to report done: {e}")

    # Bridge to WebSocket via conductor
    try:
        from bugtrace.core.conductor import conductor
        conductor.notify_log("INFO", f"[SPECIALIST] {agent_name} complete (processed: {processed}, vulns: {vulns})")
        conductor.notify_agent_update(
            agent=agent_name, status="complete",
            queue=0, processed=processed, vulns=vulns,
        )
    except Exception:
        pass


def write_dry_file(agent, dry_list, wet_count: int, specialist_name: str):
    """
    Write DRY findings to disk for human auditability.

    Called after Phase A (dedup), before Phase B (exploit).
    Creates specialists/dry/{specialist_name}_dry.json with actual findings.

    Args:
        agent: Specialist agent instance (must have report_dir attribute)
        dry_list: List of deduplicated findings
        wet_count: Number of WET items before dedup
        specialist_name: Queue key (e.g., 'sqli', 'xss')
    """
    try:
        scan_dir = getattr(agent, 'report_dir', None)
        if not scan_dir:
            logger.debug(f"[write_dry_file] No report_dir on {specialist_name}, skipping")
            return

        dry_dir = Path(scan_dir) / "specialists" / "dry"
        dry_dir.mkdir(parents=True, exist_ok=True)
        dry_file = dry_dir / f"{specialist_name}_dry.json"

        import json as _json
        with open(dry_file, 'w', encoding='utf-8') as f:
            _json.dump({
                "specialist": specialist_name,
                "wet_count": wet_count,
                "dry_count": len(dry_list) if dry_list else 0,
                "findings": dry_list or []
            }, f, indent=2, default=str)

        logger.info(f"[write_dry_file] Wrote {specialist_name}_dry.json ({len(dry_list) if dry_list else 0} findings)")
    except Exception as e:
        logger.warning(f"[write_dry_file] Failed to write DRY file for {specialist_name}: {e}")


def report_specialist_wet_dry(agent_name: str, wet_count: int, dry_count: int):
    """
    Report WET→DRY transformation metrics for integrity verification.

    Call this after Phase A (deduplication) completes, before Phase B (exploitation).

    Args:
        agent_name: Agent name (e.g., 'XSSAgent', 'SQLiAgent')
        wet_count: Number of WET items consumed from queue
        dry_count: Number of DRY items after deduplication

    Example:
        >>> dry_list = await self.analyze_and_dedup_queue()
        >>> report_specialist_wet_dry(self.name, initial_depth, len(dry_list))
    """
    try:
        from bugtrace.core.batch_metrics import batch_metrics
        # Extract specialist key from agent name (e.g., 'XSSAgent' -> 'xss')
        specialist_key = agent_name.lower().replace("agent", "").strip()
        batch_metrics.record_specialist_wet_dry(specialist_key, wet_count, dry_count)
        logger.info(f"[Telemetry] {agent_name} WET→DRY: {wet_count} → {dry_count} ({wet_count - dry_count} dedup'd)")
    except Exception as e:
        logger.debug(f"[Telemetry] Failed to report WET/DRY: {e}")
