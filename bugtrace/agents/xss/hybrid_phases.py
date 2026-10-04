"""
Hybrid engine shell: omniprobe → seed → amplify → mass attack → visual → browser validation.

Extracted from xss_agent.py so no single shell file exceeds the agent-workable
limit (hard max 1500 LOC per module). XSSAgent composes this mixin.
"""
from __future__ import annotations

# --- shell runtime deps (mixin methods used these from xss_agent module scope) ---
import asyncio
import aiohttp
import json
import re
import urllib.parse
import html as html_module
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch
from bugtrace.tools.external import external_tools
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.types import XSSFinding, InjectionContext, ValidationMethod
from bugtrace.agents.xss.constants import (
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
)
from bugtrace.agents.xss.finding_builder import (
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
)
logger = get_logger(__name__)
from bugtrace.agents.xss.shell_constants import (
    _BROWSER_ONLY_CONTEXTS,
    _CDP_PROOF_LOCK,
    _L05_CHAR_PROBE,
    _LEGACY_PROBE_MARKER,
    _PROBE_NO_REFLECTION,
    _PROBE_NO_RESPONSE,
    _PROBE_REFLECTED,
    _REDIRECT_PARAM_SET,
    _REFLECTION_SNIPPET_RADIUS,
)
from bugtrace.agents.xss.context_reflection import as_context_set as _as_context_set
# --- end shell runtime deps ---


class XSSHybridPhasesMixin:
    """Hybrid engine phases and param test loop."""

    async def _init_hybrid_engine(self) -> bool:
        """
        Initialize the hybrid engine components (Go fuzzer + Amplifier).

        Returns:
            True if initialization succeeded
        """
        try:
            # Initialize Go bridge with WAF-aware settings
            concurrency = 50 if not self._detected_waf else 10  # Slower for WAF
            timeout = 5 if not self._detected_waf else 10

            self._go_bridge = GoFuzzerBridge(
                concurrency=concurrency,
                timeout=timeout
            )

            # Try to compile Go binary if needed
            await self._go_bridge.compile_if_needed()

            # Initialize payload amplifier
            self._payload_amplifier = PayloadAmplifier()

            logger.info(f"[{self.name}] Hybrid engine initialized (Go concurrency={concurrency})")
            return True

        except FileNotFoundError as e:
            logger.warning(f"[{self.name}] Hybrid engine unavailable: {e}")
            logger.warning(f"[{self.name}] Falling back to pure Python mode")
            self._hybrid_mode = False
            return False
        except Exception as e:
            logger.error(f"[{self.name}] Hybrid engine init failed: {e}")
            self._hybrid_mode = False
            return False
    async def _hybrid_phase1_omniprobe(
        self,
        param: str,
        interactsh_url: str
    ) -> Optional[Reflection]:
        """
        Phase 1: Quick omniprobe test using Go fuzzer.

        Uses OMNIPROBE_PAYLOAD for reconnaissance - tests what characters
        survive and where they reflect. NO execution code.

        Probe tests: ' " < > ` \\' \\" {{7*7}} ${7*7}

        Returns:
            Reflection with context info if reflected, None otherwise
        """
        if not self._go_bridge:
            return None

        # Use dedicated OMNIPROBE_PAYLOAD for reconnaissance (not GOLDEN_PAYLOADS)
        omniprobe = self.OMNIPROBE_PAYLOAD

        dashboard.log(f"[{self.name}] ⚡ Phase 1: Go Omniprobe on '{param}'", "INFO")
        dashboard.set_current_payload(omniprobe[:50], "XSS Omniprobe", "Testing")

        try:
            reflection = await self._go_bridge.run_omniprobe(
                url=self.url,
                param=param,
                omniprobe_payload=omniprobe
            )

            if reflection and reflection.reflected:
                if not reflection.encoded:
                    dashboard.log(
                        f"[{self.name}] 🎯 Omniprobe REFLECTED unencoded in {reflection.context}!",
                        "SUCCESS"
                    )
                    return reflection
                else:
                    dashboard.log(
                        f"[{self.name}] ⚠️ Omniprobe reflected but encoded ({reflection.encoding_type})",
                        "WARN"
                    )
            return None

        except Exception as e:
            logger.error(f"[{self.name}] Phase 1 omniprobe error: {e}")
            return None
    async def _hybrid_phase2_seed_generation(
        self,
        param: str,
        html: str,
        context_data: Dict,
        interactsh_url: str,
        seed_count: int = 50
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
            seed_count: Number of seeds to generate

        Returns:
            List of seed payload strings
        """
        dashboard.log(f"[{self.name}] 🧠 Phase 2: LLM Seed Generation ({seed_count} seeds)", "INFO")

        # Use existing LLM analysis but request more payloads
        smart_payloads = await self._llm_smart_dom_analysis(
            html=html,
            param=param,
            probe_string=self.PROBE_STRING,
            interactsh_url=interactsh_url,
            context_data=context_data
        )

        seeds = []

        # Extract payload strings from LLM response
        for sp in smart_payloads:
            payload = sp.get("payload", "")
            if payload:
                seeds.append(self._clean_payload(payload, param))

        # Add GOLDEN_PAYLOADS as additional seeds (proven effective)
        for gp in self.GOLDEN_PAYLOADS[:20]:  # Top 20 golden payloads
            payload = gp.replace("{{interactsh_url}}", interactsh_url)
            if payload not in seeds:
                seeds.append(payload)

        # Add fragment payloads for DOM XSS coverage
        for fp in self.FRAGMENT_PAYLOADS[:10]:
            payload = fp.replace("{{interactsh_url}}", interactsh_url)
            if payload not in seeds:
                seeds.append(payload)

        logger.info(f"[{self.name}] Phase 2 generated {len(seeds)} seed payloads")
        return seeds
    async def _hybrid_phase3_amplification(
        self,
        seeds: List[str],
        context_data: Dict
    ) -> List[str]:
        """
        Phase 3: Amplify seeds using breakout prefixes.

        Multiplies seed payloads by combining with context-appropriate
        breakout prefixes from breakouts.json.

        Args:
            seeds: List of seed payloads
            context_data: Reflection context (determines which breakouts to use)

        Returns:
            Amplified list of payloads (seeds × breakouts)
        """
        if not self._payload_amplifier:
            return seeds

        dashboard.log(f"[{self.name}] 🔄 Phase 3: Amplifying {len(seeds)} seeds", "INFO")

        # Determine priority based on context
        context = context_data.get("context", "html_text")
        max_priority = 2 if context in ("javascript", "attribute_value") else 3

        amplified = self._payload_amplifier.amplify(
            seed_payloads=seeds,
            category="xss",
            max_priority=max_priority,
            deduplicate=True
        )

        dashboard.log(
            f"[{self.name}] 📈 Amplified to {len(amplified)} payloads "
            f"(×{len(amplified) // max(len(seeds), 1)} expansion)",
            "INFO"
        )

        return amplified
    async def _hybrid_phase4_mass_attack(
        self,
        param: str,
        payloads: List[str]
    ) -> FuzzResult:
        """
        Phase 4: Mass payload testing using Go fuzzer.

        Fires all amplified payloads at high speed using the Go binary,
        collecting reflection data.

        Args:
            param: Parameter to test
            payloads: Amplified payload list

        Returns:
            FuzzResult with reflections and metadata
        """
        if not self._go_bridge:
            logger.warning(f"[{self.name}] Go bridge unavailable, skipping mass attack")
            return FuzzResult(
                target=self.url,
                param=param,
                total_payloads=0,
                total_requests=0,
                duration_ms=0,
                requests_per_second=0.0
            )

        dashboard.log(
            f"[{self.name}] 🚀 Phase 4: Go Mass Attack ({len(payloads)} payloads)",
            "INFO"
        )
        dashboard.set_status("XSS Mass Attack", f"Testing {len(payloads)} payloads on {param}")

        result = await self._go_bridge.run(
            url=self.url,
            param=param,
            payloads=payloads
        )

        if result.reflections:
            dashboard.log(
                f"[{self.name}] 📊 Mass attack: {len(result.reflections)} reflections "
                f"@ {result.requests_per_second:.1f} req/s",
                "INFO"
            )
        else:
            dashboard.log(
                f"[{self.name}] ⚠️ Mass attack: No reflections detected",
                "WARN"
            )

        return result
    async def _hybrid_phase5_validation(
        self,
        param: str,
        fuzz_result: FuzzResult,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any,
        visual_payloads: Optional[List[str]] = None
    ) -> Optional[XSSFinding]:
        """
        Phase 5: Validate suspicious reflections using browser.

        PRIORITY ORDER:
        1. Visual payloads (from Phase 4.5) - tested FIRST because they provide
           screenshot evidence with "HACKED BY BUGTRACEAI" banner for Vision AI
        2. Regular candidates from Go fuzzer

        Args:
            param: Parameter name
            fuzz_result: Results from Go mass attack
            screenshots_dir: Directory for validation screenshots
            reflection_type: Context type for reporting
            surviving_chars: Character survival metadata
            injection_ctx: Injection context for reporting
            visual_payloads: Payloads with visible banner (from Phase 4.5)

        Returns:
            XSSFinding if validated, None otherwise
        """
        # =====================================================================
        # STEP 1: Test VISUAL PAYLOADS first (BULLETPROOF validation)
        # These payloads inject visible "HACKED BY BUGTRACEAI" banner
        # If one works → Screenshot → Vision confirms → MAXIMUM EVIDENCE
        # =====================================================================
        if visual_payloads:
            dashboard.log(
                f"[{self.name}] 🎨 Phase 5.1: Testing {len(visual_payloads)} VISUAL payloads first",
                "INFO"
            )

            for i, payload in enumerate(visual_payloads):
                if self._max_impact_achieved:
                    break

                dashboard.set_current_payload(
                    f"VISUAL [{i+1}/{len(visual_payloads)}]",
                    "XSS Visual Test",
                    "Testing banner payload"
                )

                logger.debug(f"[{self.name}] Testing visual payload: {payload[:60]}...")

                # Use browser validation with screenshot capture
                evidence = await self._validate_visual_payload(
                    param=param,
                    payload=payload,
                    screenshots_dir=screenshots_dir
                )

                if evidence and evidence.get("vision_confirmed"):
                    dashboard.log(
                        f"[{self.name}] ✅ XSS CONFIRMED via VISUAL + VISION AI!",
                        "SUCCESS"
                    )

                    finding = self._create_xss_finding(
                        param=param,
                        payload=payload,
                        context="Visual Banner Injection",
                        validation_method="visual_playwright_vision",
                        evidence=evidence,
                        confidence=0.99,  # Maximum confidence with visual proof
                        reflection_type=reflection_type,
                        surviving_chars=surviving_chars,
                        successful_payloads=[payload],
                        injection_ctx=injection_ctx,
                        bypass_technique="visual_banner_injection",
                        bypass_explanation="DeepSeek generated visual payload, Playwright executed, Vision AI confirmed banner visible"
                    )

                    return finding

            dashboard.log(
                f"[{self.name}] Visual payloads tested, falling back to regular candidates",
                "INFO"
            )

        # =====================================================================
        # STEP 2: Test regular candidates from Go fuzzer
        # v3.3: HTTP-first validation - only browser if HTTP can't confirm
        # =====================================================================
        if not fuzz_result.reflections:
            return None

        # Prioritize candidates by suspiciousness
        candidates = sorted(
            fuzz_result.reflections,
            key=lambda r: (
                r.is_suspicious,
                r.context in ("javascript", "attribute_value"),
                not r.encoded
            ),
            reverse=True
        )

        # Skip encoded reflections unless in very dangerous context
        candidates = [
            r for r in candidates
            if not r.encoded or r.context in ("javascript", "event_handler")
        ]

        if not candidates:
            return None

        dashboard.log(
            f"[{self.name}] 🎯 Phase 5.2: Validating {len(candidates)} candidates (HTTP-first)",
            "INFO"
        )

        # --- PASS 1: HTTP validation (fast, no browser) ---
        browser_candidates = []
        for reflection in candidates[:15]:
            if self._max_impact_achieved:
                break

            payload = reflection.payload
            dashboard.set_current_payload(payload[:50], "XSS HTTP Check", "Validating")

            # Re-send payload and check HTTP response for confirmation
            response_html = await self._send_payload(param, payload)
            if not response_html:
                continue

            evidence = {}
            if self._can_confirm_from_http_response(payload, response_html, evidence):
                dashboard.log(
                    f"[{self.name}] ✅ XSS CONFIRMED via HTTP analysis (no browser needed)!",
                    "SUCCESS"
                )
                finding = self._create_xss_finding(
                    param=param, payload=payload,
                    context=f"Hybrid Engine: {reflection.context}",
                    validation_method="hybrid_go_http",
                    evidence=evidence, confidence=0.90,
                    reflection_type=reflection_type,
                    surviving_chars=surviving_chars,
                    successful_payloads=[payload],
                    injection_ctx=injection_ctx,
                    bypass_technique=f"breakout_{reflection.context}",
                    bypass_explanation=f"Go fuzzer detected reflection, HTTP response confirmed executable XSS"
                )
                self._update_learned_breakouts(payload)
                return finding

            # Payload reflects but HTTP can't confirm → browser candidate
            if payload in (response_html or ""):
                browser_candidates.append(reflection)

        # --- PASS 2: Browser validation (slow, only for promising reflections) ---
        if browser_candidates:
            dashboard.log(
                f"[{self.name}] Phase 5.2b: Browser validation for {min(len(browser_candidates), 5)} promising reflections",
                "INFO"
            )
            for reflection in browser_candidates[:5]:
                if self._max_impact_achieved:
                    break

                payload = reflection.payload
                dashboard.set_current_payload(payload[:50], "XSS Browser", "Validating")

                evidence = await self._validate_via_browser(self.url, param, payload)
                if evidence:
                    dashboard.log(
                        f"[{self.name}] ✅ XSS CONFIRMED via browser validation!",
                        "SUCCESS"
                    )
                    finding = self._create_xss_finding(
                        param=param, payload=payload,
                        context=f"Hybrid Engine: {reflection.context}",
                        validation_method="hybrid_go_playwright",
                        evidence=evidence, confidence=0.95,
                        reflection_type=reflection_type,
                        surviving_chars=surviving_chars,
                        successful_payloads=[payload],
                        injection_ctx=injection_ctx,
                        bypass_technique=f"breakout_{reflection.context}",
                        bypass_explanation=f"Go fuzzer detected reflection in {reflection.context}, validated via Playwright"
                    )
                    self._update_learned_breakouts(payload)
                    return finding

        dashboard.log(
            f"[{self.name}] Phase 5: {len(candidates)} candidates tested, none confirmed",
            "WARN"
        )

        return None
    async def _run_hybrid_test_param(
        self,
        param: str,
        interactsh_domain: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Run the full 5-phase hybrid test on a single parameter.

        This is the main hybrid engine entry point that orchestrates
        all phases: Omniprobe → Seed → Amplify → Mass Attack → Validate.

        Args:
            param: Parameter to test
            interactsh_domain: Interactsh callback domain
            screenshots_dir: Directory for screenshots

        Returns:
            XSSFinding if XSS confirmed, None otherwise
        """
        interactsh_url = f"http://{interactsh_domain}" if interactsh_domain else ""

        # Probe and analyze context first (reuse existing logic)
        probe_data = await self._param_probe_and_setup(param)
        if not probe_data:
            return None

        html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx, _ = probe_data

        # Skip if no reflection detected and not blocked
        if not context_data.get("reflected") and not context_data.get("is_blocked"):
            dashboard.log(f"[{self.name}] No reflection on '{param}', skipping hybrid", "INFO")
            return None

        # === PHASE 1: OMNIPROBE (Reconnaissance) ===
        # Purpose: Detect reflection points and what characters survive
        # Does NOT exploit - just gathers context for Phase 2
        omni_reflection = await self._hybrid_phase1_omniprobe(param, interactsh_url)
        if omni_reflection:
            # Log what we learned from the probe
            dashboard.log(
                f"[{self.name}] 🔍 Omniprobe results: context={omni_reflection.context}, "
                f"encoded={omni_reflection.encoded}, suspicious={omni_reflection.is_suspicious}",
                "INFO"
            )
            # Context info passed to Phase 2 via context_data (already available)

        # === PHASE 2: SEED GENERATION (LLM) ===
        seeds = await self._hybrid_phase2_seed_generation(
            param=param,
            html=html,
            context_data=context_data,
            interactsh_url=interactsh_url
        )

        if not seeds:
            dashboard.log(f"[{self.name}] No seeds generated, skipping amplification", "WARN")
            return None

        # === PHASE 3: AMPLIFICATION (Python) ===
        amplified_payloads = await self._hybrid_phase3_amplification(
            seeds=seeds,
            context_data=context_data
        )

        # === PHASE 4: MASS ATTACK (Go) ===
        fuzz_result = await self._hybrid_phase4_mass_attack(
            param=param,
            payloads=amplified_payloads
        )

        # === PHASE 4.5 ↔ 5 RETRY LOOP ===
        # If visual validation fails, retry Phase 4.5 with feedback about failed payloads
        # Max 3 attempts before falling back to regular candidates only
        max_visual_retries = 3
        failed_visual_payloads: List[str] = []
        finding = None

        for attempt in range(max_visual_retries):
            # === PHASE 4.5: VISUAL PAYLOAD GENERATION (DeepSeek) ===
            visual_payloads = await self._hybrid_phase45_visual_generation(
                param=param,
                fuzz_result=fuzz_result,
                failed_payloads=failed_visual_payloads  # Pass failed payloads to avoid
            )

            if not visual_payloads:
                dashboard.log(
                    f"[{self.name}] Phase 4.5: No visual payloads generated (attempt {attempt+1}/{max_visual_retries})",
                    "WARN"
                )
                break  # No point retrying if LLM can't generate payloads

            # === PHASE 5: VALIDATION (Python/Playwright) ===
            finding = await self._hybrid_phase5_validation(
                param=param,
                fuzz_result=fuzz_result,
                screenshots_dir=screenshots_dir,
                reflection_type=reflection_type,
                surviving_chars=surviving_chars,
                injection_ctx=injection_ctx,
                visual_payloads=visual_payloads
            )

            if finding:
                # Success! Visual payload worked
                return finding

            # Visual validation failed - add to failed list and retry
            failed_visual_payloads.extend(visual_payloads)
            dashboard.log(
                f"[{self.name}] Phase 5 failed, retrying Phase 4.5 (attempt {attempt+1}/{max_visual_retries})",
                "WARN"
            )

        # All visual attempts failed - try regular candidates one last time
        if not finding:
            dashboard.log(
                f"[{self.name}] All visual retries exhausted, final attempt with regular candidates",
                "WARN"
            )
            finding = await self._hybrid_phase5_validation(
                param=param,
                fuzz_result=fuzz_result,
                screenshots_dir=screenshots_dir,
                reflection_type=reflection_type,
                surviving_chars=surviving_chars,
                injection_ctx=injection_ctx,
                visual_payloads=[]  # No visual payloads, only regular candidates
            )

        return finding
    def _hybrid_build_probe_result(
        self,
        context_data: Dict,
        surviving_chars: str,
        reflection_type: str,
        status_code: int
    ):
        """Build ProbeResult for adaptive batching."""
        from bugtrace.agents.payload_batches import ProbeResult

        waf_detected = self._detected_waf is not None or context_data.get("is_blocked", False)
        return ProbeResult(
            reflected=context_data.get("reflected", False),
            surviving_chars=surviving_chars,
            waf_detected=waf_detected,
            waf_name=self._detected_waf,
            context=reflection_type,
            status_code=status_code
        )
    def _hybrid_get_adaptive_payloads(
        self,
        probe_result,
        reflection_type: str,
        raw_payloads: List[str]
    ) -> List[str]:
        """Get adaptive payloads using batcher escalation."""
        from bugtrace.agents.payload_batches import payload_batcher

        current_batch = "universal"
        tested_batches = set()
        hybrid_payloads = []

        while current_batch and current_batch not in tested_batches and len(hybrid_payloads) < 100:
            tested_batches.add(current_batch)

            new_payloads = payload_batcher.get_batch(current_batch)
            filtered_batch = self._filter_payloads_by_context(new_payloads, reflection_type)
            hybrid_payloads.extend(filtered_batch)

            current_batch = payload_batcher.decide_escalation(probe_result, tested_batches)

        if not hybrid_payloads:
            hybrid_payloads = self._filter_payloads_by_context(raw_payloads, reflection_type)[:50]

        return hybrid_payloads
    async def _test_hybrid_payloads(
        self,
        param: str,
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        context_data: Dict,
        status_code: int,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Phase 3: Test hybrid payloads (Learned + Curated + Golden)."""
        raw_payloads = self.payload_learner.get_prioritized_payloads(self.GOLDEN_PAYLOADS)

        probe_result = self._hybrid_build_probe_result(
            context_data, surviving_chars, reflection_type, status_code
        )

        hybrid_payloads = self._hybrid_get_adaptive_payloads(
            probe_result, reflection_type, raw_payloads
        )

        # Q-Learning WAF bypass
        if self._detected_waf:
            original_count = len(hybrid_payloads)
            hybrid_payloads = await self._get_waf_optimized_payloads(hybrid_payloads, max_variants=3)
            logger.info(f"[{self.name}] 🧠 Q-Learning WAF bypass: {original_count} → {len(hybrid_payloads)} payloads")

        logger.info(f"[{self.name}] ⚡ Adaptive Strategy: Testing {len(hybrid_payloads)} payloads for {param}...")

        return await self._test_payload_list(
            param, hybrid_payloads, interactsh_url, screenshots_dir,
            reflection_type, surviving_chars, injection_ctx
        )
