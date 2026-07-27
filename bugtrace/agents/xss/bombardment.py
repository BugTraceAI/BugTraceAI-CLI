"""
XSS Agent Bombardment Module

Hybrid engine phases for XSS payload testing:
- Phase 1: Omniprobe (reconnaissance)
- Phase 2: Seed generation (LLM-assisted)
- Phase 3: Amplification (breakout prefixes)
- Phase 4: Mass attack (Go fuzzer)

This module provides the high-speed payload testing infrastructure
using the Go fuzzer for maximum throughput.
"""

from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection
from bugtrace.utils.payload_amplifier import PayloadAmplifier

from bugtrace.agents.xss.constants import (
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
)

logger = get_logger("agents.xss.bombardment")


@dataclass
class BombardmentConfig:
    """Configuration for bombardment phases."""
    seed_count: int = 50
    max_amplification_priority: int = 3
    max_validations: int = 10
    golden_payload_limit: int = 20
    fragment_payload_limit: int = 10


async def phase1_omniprobe(
    url: str,
    param: str,
    go_bridge: Optional[GoFuzzerBridge],
    agent_name: str = "XSSAgent",
) -> Optional[Reflection]:
    """
    Phase 1: Quick omniprobe test using Go fuzzer.

    Uses OMNIPROBE_PAYLOAD for reconnaissance - tests what characters
    survive and where they reflect. NO execution code.

    Probe tests: ' " < > ` \\' \\"

    Args:
        url: Target URL
        param: Parameter to test
        go_bridge: Go fuzzer bridge instance
        agent_name: Agent name for logging

    Returns:
        Reflection with context info if reflected, None otherwise
    """
    if not go_bridge:
        logger.warning(f"[{agent_name}] Go bridge unavailable for omniprobe")
        return None

    dashboard.log(f"[{agent_name}] Phase 1: Go Omniprobe on '{param}'", "INFO")
    dashboard.set_current_payload(OMNIPROBE_PAYLOAD[:50], "XSS Omniprobe", "Testing")

    try:
        reflection = await go_bridge.run_omniprobe(
            url=url,
            param=param,
            omniprobe_payload=OMNIPROBE_PAYLOAD
        )

        if reflection and reflection.reflected:
            if not reflection.encoded:
                dashboard.log(
                    f"[{agent_name}] Omniprobe REFLECTED unencoded in {reflection.context}!",
                    "SUCCESS"
                )
                return reflection
            else:
                dashboard.log(
                    f"[{agent_name}] Omniprobe reflected but encoded ({reflection.encoding_type})",
                    "WARN"
                )
        return None

    except Exception as e:
        logger.error(f"[{agent_name}] Phase 1 omniprobe error: {e}")
        return None


async def phase2_seed_generation(
    param: str,
    html: str,
    context_data: Dict[str, Any],
    interactsh_url: str,
    llm_analyzer: Callable[..., Awaitable[List[Dict]]],
    probe_string: str,
    config: Optional[BombardmentConfig] = None,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Phase 2: Generate seed payloads using LLM.

    Analyzes the DOM context and generates targeted seed payloads
    optimized for the specific injection point.

    Args:
        param: Parameter name
        html: HTML response from probe
        context_data: Reflection context analysis
        interactsh_url: Interactsh callback URL
        llm_analyzer: LLM analysis function
        probe_string: Probe string used for reflection detection
        config: Bombardment configuration
        agent_name: Agent name for logging

    Returns:
        List of seed payload strings
    """
    config = config or BombardmentConfig()

    dashboard.log(
        f"[{agent_name}] Phase 2: LLM Seed Generation ({config.seed_count} seeds)",
        "INFO"
    )

    seeds = []

    # Get LLM-generated payloads
    try:
        smart_payloads = await llm_analyzer(
            html=html,
            param=param,
            probe_string=probe_string,
            interactsh_url=interactsh_url,
            context_data=context_data
        )

        for sp in smart_payloads:
            payload = sp.get("payload", "")
            if payload:
                seeds.append(payload)
    except Exception as e:
        logger.warning(f"[{agent_name}] LLM seed generation failed: {e}")

    # Add GOLDEN_PAYLOADS as additional seeds (proven effective)
    for gp in GOLDEN_PAYLOADS[:config.golden_payload_limit]:
        payload = gp.replace("{{interactsh_url}}", interactsh_url)
        if payload not in seeds:
            seeds.append(payload)

    # Add fragment payloads for DOM XSS coverage
    for fp in FRAGMENT_PAYLOADS[:config.fragment_payload_limit]:
        payload = fp.replace("{{interactsh_url}}", interactsh_url)
        if payload not in seeds:
            seeds.append(payload)

    logger.info(f"[{agent_name}] Phase 2 generated {len(seeds)} seed payloads")
    return seeds


async def phase3_amplification(
    seeds: List[str],
    context_data: Dict[str, Any],
    amplifier: Optional[PayloadAmplifier],
    config: Optional[BombardmentConfig] = None,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Phase 3: Amplify seeds using breakout prefixes.

    Multiplies seed payloads by combining with context-appropriate
    breakout prefixes from breakouts.json.

    Args:
        seeds: List of seed payloads
        context_data: Reflection context (determines which breakouts to use)
        amplifier: Payload amplifier instance
        config: Bombardment configuration
        agent_name: Agent name for logging

    Returns:
        Amplified list of payloads (seeds x breakouts)
    """
    if not amplifier:
        logger.warning(f"[{agent_name}] Amplifier unavailable, returning seeds as-is")
        return seeds

    config = config or BombardmentConfig()

    dashboard.log(f"[{agent_name}] Phase 3: Amplifying {len(seeds)} seeds", "INFO")

    # Determine priority based on context
    context = context_data.get("context", "html_text")
    max_priority = 2 if context in ("javascript", "attribute_value") else config.max_amplification_priority

    amplified = amplifier.amplify(
        seed_payloads=seeds,
        category="xss",
        max_priority=max_priority,
        deduplicate=True
    )

    expansion_factor = len(amplified) // max(len(seeds), 1)
    dashboard.log(
        f"[{agent_name}] Amplified to {len(amplified)} payloads (x{expansion_factor} expansion)",
        "INFO"
    )

    return amplified


async def phase4_mass_attack(
    url: str,
    param: str,
    payloads: List[str],
    go_bridge: Optional[GoFuzzerBridge],
    agent_name: str = "XSSAgent",
) -> FuzzResult:
    """
    Phase 4: Mass payload testing using Go fuzzer.

    Fires all amplified payloads at high speed using the Go binary,
    collecting reflection data.

    Args:
        url: Target URL
        param: Parameter to test
        payloads: Amplified payload list
        go_bridge: Go fuzzer bridge instance
        agent_name: Agent name for logging

    Returns:
        FuzzResult with reflections and metadata
    """
    if not go_bridge:
        logger.warning(f"[{agent_name}] Go bridge unavailable, skipping mass attack")
        return FuzzResult(
            target=url,
            param=param,
            total_payloads=0,
            total_requests=0,
            duration_ms=0,
            requests_per_second=0.0
        )

    dashboard.log(
        f"[{agent_name}] Phase 4: Go Mass Attack ({len(payloads)} payloads)",
        "INFO"
    )
    dashboard.set_status("XSS Mass Attack", f"Testing {len(payloads)} payloads on {param}")

    result = await go_bridge.run(
        url=url,
        param=param,
        payloads=payloads
    )

    if result.reflections:
        dashboard.log(
            f"[{agent_name}] Mass attack: {len(result.reflections)} reflections "
            f"@ {result.requests_per_second:.1f} req/s",
            "INFO"
        )
    else:
        dashboard.log(
            f"[{agent_name}] Mass attack: No reflections detected",
            "WARN"
        )

    return result


async def run_full_bombardment(
    url: str,
    param: str,
    html: str,
    interactsh_url: str,
    go_bridge: Optional[GoFuzzerBridge],
    amplifier: Optional[PayloadAmplifier],
    llm_analyzer: Callable[..., Awaitable[List[Dict]]],
    probe_string: str,
    config: Optional[BombardmentConfig] = None,
    agent_name: str = "XSSAgent",
) -> FuzzResult:
    """
    Run the complete 4-phase bombardment pipeline.

    Orchestrates phases 1-4 in sequence:
    1. Omniprobe for reconnaissance
    2. LLM seed generation based on context
    3. Amplification with breakout prefixes
    4. Mass attack with Go fuzzer

    Args:
        url: Target URL
        param: Parameter to test
        html: HTML content for analysis
        interactsh_url: Interactsh callback URL
        go_bridge: Go fuzzer bridge
        amplifier: Payload amplifier
        llm_analyzer: LLM analysis function
        probe_string: Probe string
        config: Bombardment configuration
        agent_name: Agent name for logging

    Returns:
        FuzzResult from the mass attack phase
    """
    config = config or BombardmentConfig()

    # Phase 1: Omniprobe
    reflection = await phase1_omniprobe(url, param, go_bridge, agent_name)

    context_data = {}
    if reflection:
        context_data = {
            "context": reflection.context,
            "encoded": reflection.encoded,
            "encoding_type": reflection.encoding_type,
        }

    # Phase 2: Seed generation
    seeds = await phase2_seed_generation(
        param=param,
        html=html,
        context_data=context_data,
        interactsh_url=interactsh_url,
        llm_analyzer=llm_analyzer,
        probe_string=probe_string,
        config=config,
        agent_name=agent_name,
    )

    # Phase 3: Amplification
    amplified = await phase3_amplification(
        seeds=seeds,
        context_data=context_data,
        amplifier=amplifier,
        config=config,
        agent_name=agent_name,
    )

    # Phase 4: Mass attack
    result = await phase4_mass_attack(
        url=url,
        param=param,
        payloads=amplified,
        go_bridge=go_bridge,
        agent_name=agent_name,
    )

    return result


__all__ = [
    "BombardmentConfig",
    "phase1_omniprobe",
    "phase2_seed_generation",
    "phase3_amplification",
    "phase4_mass_attack",
    "run_full_bombardment",
]
