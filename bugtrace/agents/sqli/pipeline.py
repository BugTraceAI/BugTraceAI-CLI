"""
SQLi Agent Pipeline (ORCHESTRATION)

Orchestration functions for the SQLi escalation pipeline:
- 5-level escalation pipeline (L0-L4)
- WET -> DRY two-phase processing (analyze_and_dedup + exploit)
- LLM-powered deduplication
- Queue consumer workflow

These functions orchestrate calls to exploitation, validation, and discovery modules.
"""

import asyncio
import json
import time
import aiohttp
from typing import Dict, List, Optional, Set, Any

from loguru import logger

from bugtrace.core.config import settings
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.ui import dashboard

from bugtrace.agents.sqli.types import SQLiFinding
from bugtrace.agents.sqli.payloads import get_base_url, build_url_with_param
from bugtrace.agents.sqli.validation import extract_info_from_error, finding_to_dict
from bugtrace.agents.sqli.context import (
    get_sqlmap_technique_hint,
    determine_validation_status,
)
from bugtrace.agents.sqli.dedup import fallback_fingerprint_dedup
from bugtrace.agents.sqli.discovery import discover_sqli_params, detect_and_resolve_spa_url
from bugtrace.agents.sqli.exploitation import (
    detect_filtered_chars,
    detect_prepared_statements,
    test_error_based,
    test_boolean_based,
    test_union_based,
    test_time_based,
    test_oob_sqli,
    test_json_body_injection,
    test_second_order_sqli,
    run_sqlmap_on_param,
    test_cookie_sqli,
    test_header_sqli,
    escalation_l4_llm_bombing,
    escalation_l5_http_manipulator,
)


# =============================================================================
# 5-LEVEL ESCALATION PIPELINE
# =============================================================================

async def sqli_escalation_pipeline(
    url: str,
    param: str,
    dry_item: dict,
    baseline_response_time: float = 0,
    baseline_content_length: int = 0,
    baseline_status_code: int = 0,
    detected_db_type: Optional[str] = None,
    interactsh_client: Any = None,
    scan_depth: str = "",
    verbose_emitter: Any = None,
    agent_name: str = "SQLiAgent",
) -> Optional[SQLiFinding]:
    """
    # ORCHESTRATION
    5-level SQLi escalation pipeline (v3.5).

    Progressive cost escalation - stops at first confirmation:
        L0: WET payload          (~1 req)    - Test DASTySAST's payload first
        L1: Error-based          (~20 reqs)  - SQL error signatures
        L2: Boolean + Union      (~103 reqs) - Differential + canary reflection
        L3: OOB + Time-based     (~10 + wait)- DNS exfiltration + SLEEP verification
        L4: SQLMap Docker        (2-5 min)   - The gold standard for SQLi

    Args:
        url: Target URL
        param: Parameter name
        dry_item: DRY finding dict with metadata
        baseline_response_time: Baseline response time
        baseline_content_length: Baseline content length
        baseline_status_code: Baseline HTTP status
        detected_db_type: Known DB type
        interactsh_client: OOB detection client
        scan_depth: Scan depth setting ("quick", "normal", "thorough")
        verbose_emitter: Optional verbose event emitter
        agent_name: Agent name for logging

    Returns:
        SQLiFinding or None
    """
    from bugtrace.tools.external import external_tools

    pipeline_start = time.time()
    filtered_chars: Set[str] = set()
    db_type = detected_db_type

    if verbose_emitter:
        verbose_emitter.emit("exploit.sqli.param.started", {"param": param, "url": url})
        verbose_emitter.reset("exploit.sqli.level.progress")

    try:
        async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
            # Initialize baseline if needed
            if baseline_response_time == 0:
                try:
                    start = time.time()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        baseline_content = await resp.text()
                        baseline_response_time = time.time() - start
                        baseline_content_length = len(baseline_content)
                        baseline_status_code = resp.status
                        from bugtrace.agents.sqli.validation import detect_database_type
                        db_type = detect_database_type(baseline_content) or db_type
                except Exception as e:
                    logger.warning(f"Baseline failed: {e}")

                if verbose_emitter:
                    verbose_emitter.emit("exploit.sqli.baseline", {
                        "param": param,
                        "response_time": baseline_response_time,
                        "content_length": baseline_content_length,
                        "db_type": db_type,
                    })

            # Check for prepared statements (early exit)
            if await detect_prepared_statements(session, url, param, agent_name):
                logger.info(f"[{agent_name}] Pipeline: {param} uses prepared statements, skipping")
                return None

            # -- L0: WET PAYLOAD --
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.started", {"level": 0, "name": "wet_payload", "param": param})
            dashboard.log(f"[{agent_name}] L0: Testing WET payload for {param}...", "INFO")
            result = await _escalation_l0_wet_payload(session, url, param, dry_item, baseline_status_code, agent_name)
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.completed", {"level": 0, "param": param, "found": result is not None})
            if result:
                logger.info(f"[{agent_name}] L0 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                return result

            # -- L1: ERROR-BASED --
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.started", {"level": 1, "name": "error_based", "param": param})
            dashboard.log(f"[{agent_name}] L1: Error-based probing for {param}...", "INFO")
            filtered_chars = await detect_filtered_chars(session, url, param, agent_name, verbose_emitter)
            error_finding, error_db = await test_error_based(
                session, url, param, filtered_chars, baseline_status_code, verbose_emitter, agent_name
            )
            if error_db:
                db_type = error_db
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.completed", {"level": 1, "param": param, "found": error_finding is not None})
            if error_finding:
                logger.info(f"[{agent_name}] L1 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                return error_finding

            # -- DEPTH GATE: quick stops after L1 --
            _depth = scan_depth or settings.SCAN_DEPTH
            if _depth == "quick":
                logger.info(f"[{agent_name}] Quick depth: stopping at L1 for {param}")
                return None

            # -- L2: BOOLEAN + UNION --
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.started", {"level": 2, "name": "boolean_union", "param": param})
            dashboard.log(f"[{agent_name}] L2: Boolean + Union for {param}...", "INFO")

            bool_finding = await test_boolean_based(session, url, param, db_type, verbose_emitter, agent_name)
            if bool_finding:
                if verbose_emitter:
                    verbose_emitter.emit("exploit.sqli.level.completed", {"level": 2, "param": param, "found": True})
                logger.info(f"[{agent_name}] L2 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                return bool_finding

            union_finding = await test_union_based(session, url, param, filtered_chars, verbose_emitter, agent_name)
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.completed", {"level": 2, "param": param, "found": union_finding is not None})
            if union_finding:
                logger.info(f"[{agent_name}] L2 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                return union_finding

            # -- L3: OOB + TIME-BASED --
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.started", {"level": 3, "name": "oob_time", "param": param})
            dashboard.log(f"[{agent_name}] L3: OOB + Time-based for {param}...", "INFO")

            if interactsh_client:
                oob_finding = await test_oob_sqli(
                    session, url, param, interactsh_client, db_type, filtered_chars, verbose_emitter, agent_name
                )
                if oob_finding:
                    if verbose_emitter:
                        verbose_emitter.emit("exploit.sqli.level.completed", {"level": 3, "param": param, "found": True})
                    logger.info(f"[{agent_name}] L3 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                    return oob_finding

            time_finding = await test_time_based(session, url, param, db_type, verbose_emitter, agent_name)
            if verbose_emitter:
                verbose_emitter.emit("exploit.sqli.level.completed", {"level": 3, "param": param, "found": time_finding is not None})
            if time_finding:
                logger.info(f"[{agent_name}] L3 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
                return time_finding

        # -- DEPTH GATE: only thorough runs SQLMap --
        _depth = scan_depth or settings.SCAN_DEPTH
        if _depth != "thorough":
            logger.info(f"[{agent_name}] {_depth.title()} depth: skipping SQLMap for {param}")
            return None

        # -- L4: SQLMAP DOCKER --
        if verbose_emitter:
            verbose_emitter.emit("exploit.sqli.level.started", {"level": 4, "name": "sqlmap", "param": param})
        dashboard.log(f"[{agent_name}] L4: SQLMap for {param}...", "INFO")
        technique_hint = dry_item.get("recommended_technique", "")
        result = await run_sqlmap_on_param(url, param, technique_hint=get_sqlmap_technique_hint(technique_hint) if technique_hint else "EBUT", verbose_emitter=verbose_emitter, agent_name=agent_name)
        if verbose_emitter:
            verbose_emitter.emit("exploit.sqli.level.completed", {"level": 4, "param": param, "found": result is not None})
        if result:
            logger.info(f"[{agent_name}] L4 CONFIRMED: {param} ({time.time() - pipeline_start:.1f}s)")
            return result

        logger.info(f"[{agent_name}] Pipeline exhausted for {param} (no SQLi found, {time.time() - pipeline_start:.1f}s)")
        return None

    except Exception as e:
        logger.error(f"[{agent_name}] Escalation pipeline failed for {param}: {e}")
        return None


async def _escalation_l0_wet_payload(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    dry_item: dict,
    baseline_status_code: int,
    agent_name: str,
) -> Optional[SQLiFinding]:
    """
    # ORCHESTRATION
    L0: Test the DASTySAST WET payload first (~1 req).
    """
    from bugtrace.agents.sqli.exploitation import _create_error_based_finding

    finding_data = dry_item.get("finding_data", {})
    wet_payload = finding_data.get("payload", "")

    if not wet_payload:
        return None

    dashboard.set_current_payload(wet_payload[:60], "SQLi L0 WET", "1/1", agent_name)

    base_url = get_base_url(url)
    try:
        test_url = build_url_with_param(base_url, param, wet_payload)
        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            content = await resp.text()
            status_code = resp.status

            error_info = extract_info_from_error(content)

            if error_info.get("db_type"):
                logger.info(f"[{agent_name}] L0: WET payload triggered SQL error! DB={error_info['db_type']}")
                return _create_error_based_finding(url, param, wet_payload, error_info)

            baseline_ok = baseline_status_code and baseline_status_code < 400
            if baseline_ok and status_code >= 400:
                error_info["db_type"] = error_info.get("db_type") or "unknown"
                error_info["status_differential"] = {
                    "baseline": baseline_status_code,
                    "payload": status_code,
                }
                logger.info(
                    f"[{agent_name}] L0: WET payload caused status change "
                    f"{baseline_status_code}->{status_code}"
                )
                return _create_error_based_finding(url, param, wet_payload, error_info)
            elif status_code >= 400:
                sql_keywords = ["sql", "query", "syntax", "database", "select", "insert",
                                "update", "delete", "error", "exception", "operationalerror"]
                content_lower = content.lower()
                if any(kw in content_lower for kw in sql_keywords):
                    logger.info(f"[{agent_name}] L0: WET payload caused {status_code} with SQL keywords")
                    error_info["db_type"] = error_info.get("db_type") or "unknown"
                    return _create_error_based_finding(url, param, wet_payload, error_info)

    except Exception as e:
        logger.debug(f"[{agent_name}] L0 failed: {e}")

    return None


# =============================================================================
# WET -> DRY ANALYSIS & DEDUPLICATION
# =============================================================================

async def analyze_and_dedup_queue(
    url: str,
    tech_stack_context: Dict,
    prime_directive: str,
    discover_fn=None,
    last_discovery_html: str = None,
    agent_name: str = "SQLiAgent",
) -> List[Dict]:
    """
    # ORCHESTRATION
    Phase A: Global analysis of WET list with LLM-powered deduplication.

    Steps:
    1. Wait for queue to have items (polling loop)
    2. Drain ALL items from queue until stable empty (WET list)
    3. Run autonomous parameter discovery
    4. Resolve endpoint URLs from HTML
    5. Call LLM with expert system prompt for deduplication
    6. Return DRY list

    Args:
        url: Target URL
        tech_stack_context: Tech stack dict with db/server/lang
        prime_directive: LLM context prompt
        discover_fn: Optional custom discover function (defaults to discover_sqli_params)
        last_discovery_html: Cached HTML for endpoint resolution
        agent_name: Agent name for logging

    Returns:
        List of unique findings (DRY list) to attack in Phase B
    """
    queue = queue_manager.get_queue("sqli")
    wet_findings = []

    # 1. Wait for queue to have items
    logger.info(f"[{agent_name}] Phase A: Waiting for queue to receive items...")
    wait_start = time.monotonic()
    max_wait = 300.0

    while (time.monotonic() - wait_start) < max_wait:
        depth = queue.depth() if hasattr(queue, 'depth') else 0
        if depth > 0:
            logger.info(f"[{agent_name}] Phase A: Queue has {depth} items, starting drain...")
            break
        await asyncio.sleep(0.5)
    else:
        logger.info(f"[{agent_name}] Phase A: No items received after {max_wait}s")
        return []

    # 2. Drain ALL items until queue is stable empty
    empty_count = 0
    max_empty_checks = 10

    while empty_count < max_empty_checks:
        item = await queue.dequeue(timeout=0.5)

        if item is None:
            empty_count += 1
            await asyncio.sleep(0.5)
            continue

        empty_count = 0

        finding = item.get("finding", {})
        wet_findings.append({
            "url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "technique": finding.get("technique", ""),
            "priority": item.get("priority", 0),
            "finding_data": finding
        })

    logger.info(f"[{agent_name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

    if not wet_findings:
        return []

    # 3. Autonomous parameter discovery
    logger.info(f"[{agent_name}] Phase A: Expanding WET findings with SQLi-focused discovery...")
    expanded_wet_findings = []
    seen_urls = set()
    seen_params = set()

    # Include ALL original WET params first
    for wet_item in wet_findings:
        item_url = wet_item.get("url", "")
        param = wet_item.get("parameter", "") or (wet_item.get("finding_data", {}) or wet_item.get("finding", {})).get("parameter", "")
        if param and (item_url, param) not in seen_params:
            seen_params.add((item_url, param))
            expanded_wet_findings.append(wet_item)

    # Discover additional params per unique URL
    _discover = discover_fn or discover_sqli_params
    _last_html = None
    for wet_item in wet_findings:
        item_url = wet_item.get("url", "")
        if item_url in seen_urls:
            continue
        seen_urls.add(item_url)

        try:
            all_params = await _discover(item_url, agent_name)
            if not all_params:
                continue

            new_count = 0
            for param_name, param_value in all_params.items():
                if (item_url, param_name) not in seen_params:
                    seen_params.add((item_url, param_name))
                    expanded_wet_findings.append({
                        "url": item_url,
                        "parameter": param_name,
                        "technique": wet_item.get("technique", ""),
                        "priority": wet_item.get("priority", 0),
                        "finding_data": {},
                        "_discovered": True
                    })
                    new_count += 1

            if new_count:
                logger.info(f"[{agent_name}] Discovered {new_count} additional params on {item_url}")

        except Exception as e:
            logger.error(f"[{agent_name}] Discovery failed for {item_url}: {e}")

    # 4. Resolve endpoint URLs from HTML links/forms
    from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning

    _html = last_discovery_html
    if _html:
        for base_url in seen_urls:
            endpoint_map = resolve_param_endpoints(_html, base_url)
            reasoning_map = resolve_param_from_reasoning(expanded_wet_findings, base_url)
            for k, v in reasoning_map.items():
                if k not in endpoint_map:
                    endpoint_map[k] = v
            if endpoint_map:
                resolved_count = 0
                for item in expanded_wet_findings:
                    if item.get("url") == base_url:
                        param = item.get("parameter", "")
                        if param in endpoint_map and endpoint_map[param] != base_url:
                            item["url"] = endpoint_map[param]
                            resolved_count += 1
                if resolved_count:
                    logger.info(f"[{agent_name}] Resolved {resolved_count} params to actual endpoint URLs")

    logger.info(f"[{agent_name}] Phase A: Expanded {len(wet_findings)} hints -> {len(expanded_wet_findings)} testable params")

    wet_findings = expanded_wet_findings

    # 5. Load global context with tech stack
    tech_stack = tech_stack_context or {"db": "generic", "server": "generic", "lang": "generic"}
    context = {
        "target_url": url or "unknown",
        "wet_count": len(wet_findings),
        "tech_stack": tech_stack,
        "prime_directive": prime_directive or "",
    }

    # 6. Call LLM for global analysis
    dry_list = await _llm_analyze_and_dedup(wet_findings, context, agent_name)

    logger.info(f"[{agent_name}] Phase A: Deduplication complete. {len(wet_findings)} WET -> {len(dry_list)} DRY ({len(wet_findings) - len(dry_list)} duplicates removed)")

    return dry_list


async def _llm_analyze_and_dedup(
    wet_findings: List[Dict],
    context: Dict,
    agent_name: str = "SQLiAgent",
) -> List[Dict]:
    """
    # I/O
    Call LLM to analyze WET list and generate DRY list.

    Uses llm_client with SQLi expert prompt.
    Incorporates tech stack context for intelligent database-specific filtering.

    Args:
        wet_findings: WET findings list
        context: Context dict with target_url, wet_count, tech_stack, prime_directive
        agent_name: Agent name for logging

    Returns:
        DRY findings list
    """
    from bugtrace.core.llm_client import llm_client
    from bugtrace.agents.mixins.tech_context import TechContextMixin

    tech_stack = context.get('tech_stack', {})
    db_type = tech_stack.get('db', 'generic') if isinstance(tech_stack, dict) else 'generic'
    server = tech_stack.get('server', 'generic') if isinstance(tech_stack, dict) else 'generic'
    lang = tech_stack.get('lang', 'generic') if isinstance(tech_stack, dict) else 'generic'

    prime_directive = context.get('prime_directive', '')

    # Generate tech context section if possible
    tech_context_section = ""
    if db_type != "generic":
        # Use a temporary mixin instance for the helper
        class _TempMixin(TechContextMixin):
            pass
        _mixin = _TempMixin()
        tech_context_section = _mixin.generate_dedup_context(tech_stack)

    system_prompt = f"""You are an expert SQL Injection security analyst.

{prime_directive}

{tech_context_section}

## TARGET CONTEXT
- Target: {context['target_url']}
- Detected Database: {db_type}
- Detected Server: {server}
- Detected Language: {lang}

## WET LIST ({context['wet_count']} potential findings):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Analyze each finding for real exploitability based on the detected tech stack
2. Identify attack paths worth testing - prioritize {db_type}-compatible techniques
3. Apply expert deduplication rules:
   - **CRITICAL - Autonomous Discovery:**
     * If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
     * Even if they share the same "finding_data" object, treat them as SEPARATE based on "parameter" field
     * Same URL + DIFFERENT param -> DIFFERENT (keep all)
     * Same URL + param + DIFFERENT context -> DIFFERENT (keep both)
   - **Standard Deduplication:**
     * Cookie-based SQLi: GLOBAL scope (same cookie on different URLs = DUPLICATE)
     * Header-based SQLi: GLOBAL scope (same header on different URLs = DUPLICATE)
     * URL param SQLi: PER-ENDPOINT scope (same param on different URLs = DIFFERENT)
     * POST param SQLi: PER-ENDPOINT scope (same param on different endpoints = DIFFERENT)
     * Same URL + Same param + Same context -> DUPLICATE (keep best)
4. Filter OUT findings incompatible with {db_type} (if known)
5. Return DRY list in JSON format

## EXAMPLES
- Cookie: TrackingId @ /blog/post?id=3 = Cookie: TrackingId @ /catalog?id=1 (DUPLICATE - same injection point)
- URL param 'id' @ /blog/post?id=3 != URL param 'id' @ /catalog?id=1 (DIFFERENT - separate endpoints)

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "dry_findings": [
    {{
      "url": "...",
      "parameter": "...",
      "rationale": "why this is unique and exploitable for {db_type}",
      "attack_priority": 1-5,
      "recommended_technique": "error_based|union|boolean|time_based|oob"
    }}
  ],
  "duplicates_removed": <count>,
  "tech_filtered": <count of findings filtered due to incompatible db>,
  "reasoning": "Brief explanation of deduplication strategy"
}}"""

    try:
        response = await llm_client.generate(
            system=system_prompt,
            user="Analyze the WET list above and return DRY findings in JSON format.",
            response_format="json"
        )

        dry_data = json.loads(response)
        dry_list = dry_data.get("dry_findings", [])

        logger.info(f"[{agent_name}] LLM deduplication: {dry_data.get('reasoning', 'No reasoning provided')}")

        return dry_list

    except Exception as e:
        logger.error(f"[{agent_name}] LLM deduplication failed: {e}. Falling back to fingerprint dedup.")
        return fallback_fingerprint_dedup(wet_findings)


__all__ = [
    "sqli_escalation_pipeline",
    "analyze_and_dedup_queue",
]
