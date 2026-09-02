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

from bugtrace.agents.csti.pipeline_validation import _validate_with_playwright


# =========================================================================
# VALIDATION PIPELINE (4-Level)
# =========================================================================

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
        "{{1000003*1000003}}${1000003*1000003}<%= 1000003*1000003 %>#{1000003*1000003}",
        "{{1000003*1000003}}",
        "${1000003*1000003}",
        "<%= 1000003*1000003 %>",
        "#{1000003*1000003}",
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
            if payload in response or ("1000006000009" in response and "1000006000009" not in baseline_html):
                reflecting.append(payload)

    # Batch OOB check
    if not first_finding and interactsh_client:
        try:
            interactions = await interactsh_client.poll()
            if interactions:
                best = all_payloads[0] if all_payloads else "{{1000003*1000003}}"
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
        f"Focus on arithmetic evaluation (1000003*1000003=1000006000009), config access, sandbox bypasses, and RCE. "
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

            if payload in response or ("1000006000009" in response and "1000006000009" not in baseline_html):
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
            base_params[param] = "{{1000003*1000003}}"

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
            original_value = base_params.get(param, "{{1000003*1000003}}")

            # Verify the TARGET param was actually mutated
            if working_payload == original_value:
                logger.info(f"[{agent_name}] L4: ManipulatorOrchestrator exploited different param, not '{param}'")
                await manipulator.shutdown()
                return None, reflecting

            # Verify payload contains CSTI/SSTI indicators
            csti_indicators = [
                "{{", "${", "<%", "#{", "#set", "#if", "#include",
                "1000003*1000003", "constructor", "__class__", "config",
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
                        verify_status = resp.status
                        verify_body = await resp.text()
                    baseline_params = dict(base_params)
                    baseline_params[param] = "btai_baseline_test"
                    async with session.get(verify_url, params=baseline_params, timeout=15) as resp:
                        baseline_body = await resp.text()
                # A 4xx on the verify request means this is not a reflection sink — a stray
                # A result marker in the error page must not confirm. 5xx remains eligible for error-signature SSTI.
                if 400 <= verify_status < 500:
                    logger.info(
                        f"[{agent_name}] L4: verify returned {verify_status} (not a reflection sink) — dropping: {param}"
                    )
                    reflecting.append(working_payload)
                    await manipulator.shutdown()
                    return None, reflecting
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

