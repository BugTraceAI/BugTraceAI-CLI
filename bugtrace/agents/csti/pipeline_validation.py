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

async def validate_csti(
    url: str,
    param: str,
    payload: str,
    response_html: str,
    screenshots_dir: Path,
    agent_name: str,
    interactsh_client=None,
    check_oob_hit_fn=None,
) -> Tuple[bool, Dict]:  # I/O
    """
    4-LEVEL VALIDATION PIPELINE (V2.0) - CSTI/SSTI Alignment.

    L1: HTTP Static Reflection Check (Arithmetic/Signatures)
    L2: AI-Powered Manipulator (Logic Evasion)
    L3: Playwright Browser Execution (Client-side engines)
    L4: Return False for AgenticValidator escalation

    v3.2 FIX: For JS-rendered sites (empty response_html), skip L1/L2 and go
    directly to L3 Playwright for client-side payloads (Angular, Vue).

    Args:
        url: Target URL
        param: Parameter name
        payload: The CSTI payload
        response_html: HTTP response body
        screenshots_dir: Directory for screenshots
        agent_name: Agent name for logging
        interactsh_client: Optional Interactsh client for OOB checks
        check_oob_hit_fn: Optional async callable for OOB hit checking

    Returns:
        Tuple of (validated: bool, evidence: dict)
    """
    evidence = {"payload": payload}

    # Detect JS-rendered site and client-side payload
    response_len = len(response_html.strip())
    is_js_rendered = response_len < 500
    is_csp = is_client_side_payload(payload)

    logger.info(
        f"[{agent_name}] CSTI validate: response_len={response_len}, "
        f"is_js_rendered={is_js_rendered}, is_client_side={is_csp}"
    )

    if is_js_rendered and is_csp:
        logger.info(f"[{agent_name}] JS-rendered site + client-side payload - skipping L1/L2, going to L3 Playwright")
        if await _validate_with_playwright(url, param, payload, screenshots_dir, evidence, agent_name):
            return True, evidence
        logger.debug(f"[{agent_name}] L3 Playwright failed for JS-rendered CSTI, escalating to L4")
        return False, evidence

    # Standard flow for server-side or non-JS sites
    # Level 1: HTTP Static Reflection Check
    logger.info(f"[{agent_name}] L1 checking: {payload[:40]}...")
    try:
        l1_result = await _validate_http_reflection(
            url, param, payload, response_html, evidence, agent_name,
            check_oob_hit_fn=check_oob_hit_fn,
        )
        if l1_result:
            logger.info(f"[{agent_name}] L1 CONFIRMED: {evidence.get('method')}")
            return True, evidence
    except Exception as e:
        logger.warning(f"[{agent_name}] L1 exception: {e}")
    logger.info(f"[{agent_name}] L1 failed, trying L2")

    # Level 2: AI-Powered Manipulator (placeholder)
    try:
        if response_html and payload in response_html:
            # Payload reflected but not evaluated - L2 placeholder
            pass
    except Exception as e:
        logger.warning(f"[{agent_name}] L2 exception: {e}")
    logger.info(f"[{agent_name}] L2 failed, trying L3 Playwright")

    # Level 3: Playwright Browser Execution
    try:
        l3_result = await _validate_with_playwright(
            url, param, payload, screenshots_dir, evidence, agent_name
        )
        if l3_result:
            return True, evidence
    except Exception as e:
        logger.warning(f"[{agent_name}] L3 exception: {e}")

    # Level 4: Return False for AgenticValidator
    logger.info(f"[{agent_name}] L1-L3 all failed for {payload[:40]}")
    return False, evidence


async def _validate_http_reflection(
    url: str,
    param: str,
    payload: str,
    response_html: str,
    evidence: Dict,
    agent_name: str,
    check_oob_hit_fn=None,
) -> bool:  # I/O
    """Level 1: Fast HTTP static evaluation check."""
    # Tier 1.1: OOB Interactsh
    if check_oob_hit_fn:
        if await check_oob_hit_fn(f"csti_{param}"):
            evidence["method"] = "L1: OOB Interactsh"
            evidence["level"] = 1
            return True

    if not response_html:
        return False

    # Tier 1.2: Signatures and Arithmetic
    async with http_manager.isolated_session(ConnectionProfile.PROBE) as session:
        baseline = await get_baseline_content(session, url)
        if check_arithmetic_evaluation(response_html, payload, baseline):
            evidence["method"] = "L1: Arithmetic Evaluation"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

    if check_string_multiplication(response_html, payload):
        evidence["method"] = "L1: String Multiplication"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    if check_config_reflection(response_html, payload):
        evidence["method"] = "L1: Config Reflection"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    if check_engine_signatures(response_html, payload):
        evidence["method"] = "L1: Engine Signature"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    if check_error_signatures(response_html):
        evidence["method"] = "L1: Error Signature"
        evidence["level"] = 1
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True

    return False


async def _validate_with_playwright(
    url: str,
    param: str,
    payload: str,
    screenshots_dir: Path,
    evidence: Dict,
    agent_name: str,
) -> bool:  # I/O
    """Level 3: Playwright browser execution (Client-side engines like Angular)."""
    attack_url = inject_param(url, param, payload)

    logger.info(f"[{agent_name}] L3 Playwright validating CSTI: {payload[:50]}...")

    from bugtrace.agents.agentic_validator import _verifier_pool
    verifier = await _verifier_pool.get_verifier()
    try:
        result = await verifier.verify_xss(
            url=attack_url,
            screenshot_dir=str(screenshots_dir),
            timeout=15.0,
            max_level=3,
        )

        logger.info(f"[{agent_name}] L3 Playwright result: success={result.success}, details={result.details}")

        if result.success:
            evidence.update(result.details or {})
            evidence["playwright_confirmed"] = True
            evidence["screenshot_path"] = result.screenshot_path
            evidence["method"] = "L3: Playwright Browser"
            evidence["level"] = 3
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True
    finally:
        _verifier_pool.release()

    return False


async def test_payload_with_validation(
    session,
    url: str,
    param: str,
    payload: str,
    agent_name: str,
) -> Tuple[Optional[str], Optional[str]]:  # I/O
    """
    Inject payload and perform 4-level validation.
    Returns (content, effective_url) if validated (L1-L3).
    Returns (None, None) if validation fails.

    Args:
        session: aiohttp session
        url: Target URL
        param: Parameter name
        payload: The payload
        agent_name: Agent name for logging

    Returns:
        Tuple of (content, final_url) or (None, None)
    """
    target_url = inject_param(url, param, payload)

    try:
        async with session.get(target_url, timeout=5) as resp:
            content = await resp.text()
            final_url = str(resp.url)

            logger.debug(f"[{agent_name}] CSTI test: response {len(content)} chars for {payload[:30]}")

            validated, evidence = await validate_csti(
                url, param, payload, content, Path(settings.LOG_DIR), agent_name
            )
            if validated:
                logger.info(
                    f"[{agent_name}] CSTI VALIDATED: {payload[:50]} via {evidence.get('method', 'unknown')}"
                )
                return content, final_url

            logger.debug(f"[{agent_name}] CSTI L1-L3 failed for {payload[:30]}")
    except Exception as e:
        logger.debug(f"[{agent_name}] CSTI test error: {e}")

    return None, None


# =========================================================================
# ESCALATION LEVEL IMPLEMENTATIONS (L0-L6)
# =========================================================================

async def escalation_smart_probe(
    url: str,
    param: str,
    engines: List[str],
    baseline_html: str,
    agent_name: str,
    verbose_emitter=None,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Tuple[Optional[CSTIFinding], bool]:  # I/O
    """
    Smart probe: 1 request to check if template syntax reflects or evaluates.

    Args:
        url: Target URL
        param: Parameter to test
        engines: Detected engines
        baseline_html: Baseline HTML for false positive check
        agent_name: Agent name for logging
        verbose_emitter: Optional verbose event emitter
        tech_profile: Optional tech profile
        tech_stack_context: Optional tech stack context

    Returns:
        Tuple of (CSTIFinding or None, should_continue: bool)
        - If finding returned: confirmed CSTI
        - should_continue=False: no reflection, skip this param entirely
        - should_continue=True: reflects, continue normal escalation
    """
    # Marker must not contain the expected result: a literal result in the
    # reflected marker would self-trigger a false positive.
    probe = "BT_CSTI_PROBE{{1000003*1000003}}${1000003*1000003}"
    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
        response, verified_url = await send_csti_payload_raw(session, url, param, probe)
        if response is None:
            return None, True  # Network error, continue anyway

        # Check if probe marker reflects at all
        if "BT_CSTI_PROBE" not in response:
            if any(e in ["angular", "vue"] for e in engines):
                dashboard.log(
                    f"[{agent_name}] Smart probe: no HTTP reflection for '{param}' "
                    f"but client-side engine detected, continuing to browser testing",
                    "INFO",
                )
                return None, True
            dashboard.log(
                f"[{agent_name}] Smart probe: no reflection for '{param}', skipping",
                "INFO",
            )
            return None, False

        # Check if template evaluation happened
        if "1000006000009" in response and "1000003*1000003" not in response and "1000006000009" not in baseline_html:
            if verbose_emitter:
                verbose_emitter.emit(
                    "exploit.specialist.signature_match",
                    {"agent": "CSTI", "param": param, "payload": probe[:100], "method": "smart_probe"},
                )
            dashboard.log(
                f"[{agent_name}] Smart probe: CONFIRMED CSTI on '{param}' ({{{{1000003*1000003}}}}=1000006000009)",
                "INFO",
            )
            engine = "unknown"
            if any(e in ["angular", "vue"] for e in engines):
                engine = engines[0]
            finding = create_finding(
                url, param, "{{1000003*1000003}}", "smart_probe", agent_name,
                verified_url=verified_url, tech_profile=tech_profile,
                tech_stack_context=tech_stack_context,
            )
            finding.evidence = {
                "method": "arithmetic_eval",
                "proof": "{{1000003*1000003}} evaluated to 1000006000009",
                "status": "VALIDATED_CONFIRMED",
                "level": "smart_probe",
                "engine": engine,
            }
            return finding, True

        dashboard.log(
            f"[{agent_name}] Smart probe: '{param}' reflects, continuing escalation",
            "INFO",
        )
        return None, True


