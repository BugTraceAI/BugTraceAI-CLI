"""
DASTySASTAgent — thin orchestrator.

All heavy logic lives in sibling modules:
  - types.py            : Constants and data definitions (PURE)
  - html_extraction.py  : HTML parsing and parameter extraction (PURE)
  - probing.py          : Reflection analysis and probe formatting (PURE)
  - classification.py   : Vulnerability naming, severity, FP scoring (PURE)
  - prompts.py          : LLM prompt construction and response parsing (PURE)
  - exploitation.py     : Active probes, SQLi testing, cookie analysis (I/O)

This module wires them together via the ``DASTySASTAgent`` class which
inherits from ``BaseAgent`` and drives the analysis pipeline.
"""
import asyncio
import json
import time as _time
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter

from bugtrace.agents.base import BaseAgent

# Sibling modules
from bugtrace.agents.dastysast.types import APPROACH_MODEL_MAP
from bugtrace.agents.dastysast.html_extraction import (
    detect_frontend_frameworks,
)
from bugtrace.agents.dastysast.probing import (
    extract_cookies_from_http_headers,
    format_probe_evidence,
)
from bugtrace.agents.dastysast.classification import (
    normalize_vulnerability_name,
    get_severity_for_type,
    get_safe_name,
    calculate_fp_confidence,
    assess_evidence_quality,
    deduplicate_vulnerabilities,
    count_by_type,
    inject_param_based_candidates,
)
from bugtrace.agents.dastysast.prompts import (
    build_analysis_prompt,
    build_skeptical_prompt,
    build_review_prompt,
    get_skeptical_system_prompt,
    parse_approach_response,
    parse_skeptical_response,
    parse_review_approval,
)
from bugtrace.agents.dastysast.exploitation import (
    run_reflection_probes,
    probe_char_survival,
    check_sqli_probes,
    check_cookie_sqli_probes,
    generate_synthetic_cookies,
    detect_auth_artifacts,
)


class DASTySASTAgent(BaseAgent):
    """
    DAST + SAST Analysis Agent.

    Performs multi-approach analysis on a URL to identify potential
    vulnerabilities.  Phase 2 (Part A) of the Sequential Pipeline.
    """

    # Class-level dedup for cookie config findings (shared across instances)
    _emitted_cookie_configs: set = set()

    def __init__(
        self,
        url: str,
        tech_profile: Dict,
        report_dir: Path,
        state_manager: Any = None,
        scan_context: str = None,
        url_index: int = None,
    ):
        super().__init__(
            "DASTySASTAgent", "Security Analysis", agent_id="analysis_agent",
        )
        self.url = url
        self.tech_profile = tech_profile
        self.report_dir = report_dir
        self.state_manager = state_manager
        self.scan_context = scan_context or f"scan_{id(self)}"
        self.url_index = url_index

        # Core LLM approaches (each togglable via APPROACH_* in conf)
        self.approach_mode = getattr(settings, "APPROACH_MODE", "ALL").upper()
        approach_toggles = {
            "pentester": settings.ANALYSIS_APPROACH_PENTESTER,
            "bug_bounty": settings.ANALYSIS_APPROACH_BUG_BOUNTY,
            "code_auditor": settings.ANALYSIS_APPROACH_CODE_AUDITOR,
            "red_team": settings.ANALYSIS_APPROACH_RED_TEAM,
            "researcher": settings.ANALYSIS_APPROACH_RESEARCHER,
        }
        self.approaches = [name for name, enabled in approach_toggles.items() if enabled]
        if not self.approaches:
            self.approaches = ["pentester"]
        self.approaches.append("skeptical_agent")  # Always last
        self.model = (
            getattr(settings, "ANALYSIS_PENTESTER_MODEL", None)
            or settings.DEFAULT_MODEL
        )

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------

    async def run_loop(self):
        """Standard run loop executing the DAST+SAST analysis."""
        return await self.run()

    async def run(self) -> Dict:
        """Performs multi-approach analysis on the URL with event emission."""  # I/O
        self._v = create_emitter("DASTySAST", self.scan_context)
        self._run_start = _time.time()
        self._v.emit("discovery.url.started", {"url": self.url, "index": self.url_index})
        dashboard.current_agent = self.name
        dashboard.log(
            f"[{self.name}] Running DAST+SAST Analysis on {self.url[:50]}...", "INFO",
        )

        # Phase semaphore (v2.4)
        phase_ctx = None
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores, ScanPhase
            phase_semaphores.initialize()
            phase_ctx = phase_semaphores.acquire(ScanPhase.ANALYSIS)
        except ImportError:
            pass

        try:
            if phase_ctx:
                await phase_ctx.__aenter__()

            # 1. Prepare Context
            context = await self._run_prepare_context()

            # 2. Parallel Analysis
            valid_analyses = await self._run_execute_analyses(context)
            if not valid_analyses:
                dashboard.log(f"[{self.name}] All analysis approaches failed.", "ERROR")
                await self._emit_url_analyzed([])
                return {"error": "Analysis failed", "vulnerabilities": []}

            # 3. Consolidate & Review
            consolidated = self._consolidate(valid_analyses)
            consolidated = inject_param_based_candidates(
                consolidated, self.url,
                getattr(self, "_reflection_probes", []),
                self.name,
            )
            vulnerabilities = await self._skeptical_review(consolidated)

            # 4. Save Results
            await self._run_save_results(vulnerabilities)

            # 5. Emit url_analyzed event
            self._v.emit("discovery.url.completed", {
                "url": self.url,
                "findings_count": len(vulnerabilities),
                "duration_ms": int((_time.time() - self._run_start) * 1000),
            })
            await self._emit_url_analyzed(vulnerabilities)

            if self.url_index is not None:
                base_filename = str(self.url_index)
            else:
                base_filename = f"vulnerabilities_{get_safe_name(self.url)}"

            return {
                "url": self.url,
                "vulnerabilities": vulnerabilities,
                "json_report_file": str(self.report_dir / f"{base_filename}.json"),
                "url_index": self.url_index,
                "fp_stats": {
                    "total_findings": len(vulnerabilities),
                    "high_confidence": len([v for v in vulnerabilities if v.get("fp_confidence", 0) >= 0.7]),
                    "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get("fp_confidence", 0) < 0.7]),
                    "low_confidence": len([v for v in vulnerabilities if v.get("fp_confidence", 0) < 0.5]),
                },
            }

        except Exception as e:
            logger.error(f"DASTySASTAgent failed: {e}", exc_info=True)
            try:
                await self._emit_url_analyzed([])
            except Exception:
                pass
            return {"error": str(e), "vulnerabilities": []}
        finally:
            if phase_ctx:
                try:
                    await phase_ctx.__aexit__(None, None, None)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Context preparation
    # ------------------------------------------------------------------

    async def _run_prepare_context(self) -> Dict:
        """Prepare analysis context with OOB payload, HTML, and active probes."""  # I/O
        from bugtrace.tools.interactsh import interactsh_client, get_oob_payload

        if not interactsh_client.registered:
            await interactsh_client.register()

        oob_payload, oob_url = await get_oob_payload("generic")

        context: Dict = {
            "url": self.url,
            "tech_stack": self.tech_profile.get("frameworks", []),
            "html_content": "",
            "oob_info": {
                "callback_url": oob_url,
                "payload_template": oob_payload,
                "instructions": (
                    "Use this callback URL for Blind XSS/SSRF/RCE testing. "
                    "If you inject this and it's triggered, we will detect it Out-of-Band."
                ),
            },
            "reflection_probes": [],
        }

        # Fetch HTML
        try:
            from bugtrace.tools.visual.browser import browser_manager
            await browser_manager.start()
            capture = await browser_manager.capture_state(self.url)
            if capture and capture.get("html"):
                html_full = capture["html"]
                self._analysis_html = html_full
                if len(html_full) > 15000:
                    context["html_content"] = (
                        html_full[:7500] + "\n...[TRUNCATED]...\n" + html_full[-7500:]
                    )
                else:
                    context["html_content"] = html_full

                logger.info(
                    f"[{self.name}] Fetched HTML content "
                    f"({len(context['html_content'])} chars) for analysis."
                )
                self._v.emit("discovery.url.html_captured", {
                    "url": self.url, "html_length": len(context["html_content"]),
                })

                # Detect frameworks from HTML
                self.tech_profile["frameworks"] = detect_frontend_frameworks(
                    html_full,
                    self.tech_profile.get("frameworks", []),
                    self.name,
                )
                if self.tech_profile.get("frameworks"):
                    self._v.emit("discovery.url.frameworks_detected", {
                        "url": self.url,
                        "frameworks": self.tech_profile["frameworks"][:5],
                    })
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to fetch HTML content: {e}")

        # Detect auth artifacts
        try:
            await detect_auth_artifacts(
                self.url,
                context.get("html_content", ""),
                self.emit_finding,
                self.name,
            )
        except Exception as e:
            logger.warning(f"[{self.name}] Auth artifact detection failed: {e}")

        # Active recon probes
        if settings.ACTIVE_RECON_PROBES:
            try:
                if not hasattr(self, "_http_cookies"):
                    self._http_cookies = {}
                probes, self._http_cookies = await run_reflection_probes(
                    self.url,
                    context.get("html_content", ""),
                    self._http_cookies,
                    self._v,
                    self.name,
                )
                context["reflection_probes"] = probes
                self._reflection_probes = probes
                reflecting = [p for p in probes if p.get("reflects")]
                self._v.emit("discovery.probe.completed", {
                    "url": self.url,
                    "total": len(probes),
                    "reflecting": len(reflecting),
                    "non_reflecting": len(probes) - len(reflecting),
                })
                logger.info(f"[{self.name}] Active recon: {len(probes)} parameters probed")
            except Exception as e:
                logger.warning(f"[{self.name}] Active recon probes failed: {e}")

        return context

    # ------------------------------------------------------------------
    # Parallel analysis execution
    # ------------------------------------------------------------------

    async def _run_execute_analyses(self, context: Dict) -> List[Dict]:
        """Execute parallel analyses with all approaches."""  # I/O
        core_approaches = [a for a in self.approaches if a != "skeptical_agent"]

        if self.approach_mode == "AUTO":
            valid_analyses = await self._run_auto_waves(context, core_approaches)
        else:
            valid_analyses = await self._run_all_approaches(context, core_approaches)

        if "skeptical_agent" in self.approaches:
            skeptical_result = await self._run_skeptical_approach(context, valid_analyses)
            if skeptical_result and not skeptical_result.get("error"):
                valid_analyses.append(skeptical_result)

        return valid_analyses

    async def _run_all_approaches(self, context: Dict, core_approaches: List[str]) -> List[Dict]:
        """ALL mode: run every enabled approach + probes in parallel."""  # I/O
        self._v.emit("discovery.llm.started", {"url": self.url, "approaches": core_approaches})
        tasks = [self._analyze_with_approach(context, a) for a in core_approaches]
        tasks.append(check_sqli_probes(
            self.url, getattr(self, "_analysis_html", ""), self._v, self.name,
        ))
        tasks.append(check_cookie_sqli_probes(
            self.url, getattr(self, "_http_cookies", {}),
            self.scan_context, DASTySASTAgent._emitted_cookie_configs,
            self._v, self.name,
        ))

        analyses = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [a for a in analyses if isinstance(a, dict) and not a.get("error")]
        self._v.emit("discovery.llm.completed", {
            "url": self.url, "valid_analyses": len(valid), "total": len(analyses),
        })
        return valid

    async def _run_auto_waves(self, context: Dict, core_approaches: List[str]) -> List[Dict]:
        """AUTO mode: wave 1 first, wave 2 only if wave 1 found nothing."""  # I/O
        wave1_names = ["pentester", "bug_bounty"]
        wave1 = [a for a in core_approaches if a in wave1_names]
        if not wave1:
            wave1 = core_approaches[:2]

        self._v.emit("discovery.llm.started", {
            "url": self.url, "approaches": wave1, "mode": "AUTO/wave1",
        })
        tasks = [self._analyze_with_approach(context, a) for a in wave1]
        tasks.append(check_sqli_probes(
            self.url, getattr(self, "_analysis_html", ""), self._v, self.name,
        ))
        tasks.append(check_cookie_sqli_probes(
            self.url, getattr(self, "_http_cookies", {}),
            self.scan_context, DASTySASTAgent._emitted_cookie_configs,
            self._v, self.name,
        ))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in results if isinstance(r, dict) and not r.get("error")]
        self._v.emit("discovery.llm.completed", {
            "url": self.url, "valid_analyses": len(valid),
            "total": len(results), "mode": "AUTO/wave1",
        })

        wave1_has_findings = any(
            r.get("vulnerabilities") for r in valid if isinstance(r, dict)
        )
        if wave1_has_findings:
            logger.info(f"[AUTO] Wave 1 found findings for {self.url[:50]}, skipping wave 2")
            return valid

        wave2_names = ["code_auditor", "red_team"]
        wave2 = [a for a in core_approaches if a in wave2_names and a not in wave1]
        if not wave2:
            return valid

        logger.info(f"[AUTO] Wave 1 empty for {self.url[:50]}, launching wave 2: {wave2}")
        self._v.emit("discovery.llm.started", {
            "url": self.url, "approaches": wave2, "mode": "AUTO/wave2",
        })
        tasks2 = [self._analyze_with_approach(context, a) for a in wave2]
        results2 = await asyncio.gather(*tasks2, return_exceptions=True)
        valid2 = [r for r in results2 if isinstance(r, dict) and not r.get("error")]
        self._v.emit("discovery.llm.completed", {
            "url": self.url, "valid_analyses": len(valid2),
            "total": len(results2), "mode": "AUTO/wave2",
        })

        return valid + valid2

    # ------------------------------------------------------------------
    # Per-approach LLM analysis
    # ------------------------------------------------------------------

    async def _analyze_with_approach(self, context: Dict, approach: str) -> Dict:
        """Analyse the URL with a specific LLM persona."""  # I/O
        skill_context = self._approach_get_skill_context()
        system_prompt = self._get_system_prompt(approach)
        user_prompt = build_analysis_prompt(
            self.url, self.tech_profile, context, skill_context,
        )

        model_attr = APPROACH_MODEL_MAP.get(approach)
        model_override = getattr(settings, model_attr, None) if model_attr else None

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                module_name="DASTySASTAgent",
                max_tokens=8000,
                model_override=model_override,
            )
            if not response:
                return {"error": "Empty response from LLM"}
            return parse_approach_response(response)
        except Exception as e:
            logger.error(f"Failed to analyze with approach {approach}: {e}", exc_info=True)
            return {"vulnerabilities": []}

    def _approach_get_skill_context(self) -> str:
        """Get skill context for enrichment."""  # PURE
        from bugtrace.agents.skills.loader import get_skills_for_findings

        if hasattr(self, "_prior_findings") and self._prior_findings:
            return get_skills_for_findings(self._prior_findings, max_skills=2)
        return ""

    def _get_system_prompt(self, approach: str) -> str:
        """Get system prompt from external config."""  # PURE
        if approach == "skeptical_agent":
            return get_skeptical_system_prompt()

        personas = self.agent_config.get("personas", {})
        if approach in personas:
            return personas[approach].strip()

        return self.system_prompt or "You are an expert security analyst."

    # ------------------------------------------------------------------
    # Skeptical review pipeline
    # ------------------------------------------------------------------

    async def _run_skeptical_approach(self, context: Dict, prior_analyses: List[Dict]) -> Dict:
        """Run skeptical_agent approach to review prior findings."""  # I/O
        prior_findings: List[Dict] = []
        for analysis in prior_analyses:
            for vuln in analysis.get("vulnerabilities", []):
                prior_findings.append(vuln)

        if not prior_findings:
            return {"vulnerabilities": []}

        system_prompt = get_skeptical_system_prompt()
        user_prompt = build_skeptical_prompt(self.url, prior_findings)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model_override=settings.SKEPTICAL_MODEL,
                module_name="DASTySASTAgent_Skeptical",
                max_tokens=4000,
            )
            if not response:
                return {"error": "Empty response from skeptical agent"}
            return parse_skeptical_response(response, prior_findings, self.name)
        except Exception as e:
            logger.error(f"Skeptical approach failed: {e}", exc_info=True)
            return {"error": str(e)}

    async def _skeptical_review(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Final gate: skeptical LLM review before specialist dispatch."""  # I/O
        self._v.emit("discovery.skeptical.started", {
            "url": self.url, "findings_to_review": len(vulnerabilities),
        })

        # Separate probe-validated findings (bypass LLM review)
        probe_validated: List[Dict] = []
        llm_findings: List[Dict] = []
        for v in vulnerabilities:
            if v.get("probe_validated"):
                probe_validated.append(v)
                logger.info(
                    f"[{self.name}] Probe-validated finding bypasses skeptical review: "
                    f"{v.get('type')} on {v.get('parameter')}"
                )
            else:
                llm_findings.append(v)

        # Pre-filter by FP confidence
        threshold = getattr(settings, "THINKING_FP_THRESHOLD", 0.5)
        pre_filtered: List[Dict] = []
        rejected_count = 0
        for v in llm_findings:
            fp_conf = v.get("fp_confidence", 0.5)
            skeptical_score = v.get("skeptical_score", 5)
            if skeptical_score <= 3 and fp_conf < threshold:
                logger.info(
                    f"[{self.name}] Pre-filtered FP: {v.get('type')} on '{v.get('parameter')}' "
                    f"(fp_confidence: {fp_conf:.2f}, skeptical: {skeptical_score})"
                )
                rejected_count += 1
            else:
                pre_filtered.append(v)

        if rejected_count > 0:
            logger.info(
                f"[{self.name}] FP pre-filter: {rejected_count} removed "
                f"(threshold: {threshold}), {len(pre_filtered)} remaining"
            )

        if not pre_filtered:
            return probe_validated

        # Deduplicate
        deduped = self._review_deduplicate(pre_filtered)
        if not deduped:
            return probe_validated

        # Build prompt and execute review
        prompt = build_review_prompt(self.url, deduped)

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt="You are a skeptical security expert. Reject false positives ruthlessly.",
                model_override=settings.SKEPTICAL_MODEL,
                module_name="DASTySAST_Skeptical",
                max_tokens=2000,
            )
            if not response:
                logger.warning(f"[{self.name}] Skeptical review empty - keeping all")
                return probe_validated + deduped

            llm_approved = parse_review_approval(
                response, deduped, settings.get_threshold_for_type, self.name,
            )
            return probe_validated + llm_approved

        except Exception as e:
            logger.error(f"[{self.name}] Skeptical review failed: {e}", exc_info=True)
            return probe_validated + deduped

    def _review_deduplicate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Deduplicate by type+parameter keeping highest confidence."""  # PURE
        deduped: Dict[tuple, Dict] = {}
        for v in vulnerabilities:
            key = (v.get("type"), v.get("parameter"))
            existing = deduped.get(key)
            if not existing or v.get("confidence", 0) > existing.get("confidence", 0):
                deduped[key] = v
        result = list(deduped.values())
        logger.info(f"[{self.name}] Deduplicated: {len(result)} unique findings")
        return result

    # ------------------------------------------------------------------
    # Consolidation
    # ------------------------------------------------------------------

    def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
        """Consolidate findings from approaches using voting and evidence quality."""  # PURE (aside from logger)
        merged: Dict[str, Dict] = {}
        skeptical_data: Dict[str, Dict] = {}

        def _evidence_quality(vuln: Dict) -> int:
            score = 0
            if vuln.get("probe_validated"):
                score += 5
            if vuln.get("html_evidence"):
                score += 3
            if vuln.get("xss_context") and vuln.get("xss_context") != "none":
                score += 2
            if vuln.get("chars_survive"):
                score += 1
            reasoning = vuln.get("reasoning", "")
            if "line" in reasoning.lower() or "snippet" in reasoning.lower():
                score += 1
            return score

        num_core = len([a for a in self.approaches if a != "skeptical_agent"])

        for analysis in analyses:
            is_skeptical = analysis.get("approach") == "skeptical_agent"
            for vuln in analysis.get("vulnerabilities", []):
                v_type = vuln.get("type", vuln.get("vulnerability", "Unknown"))
                v_param = vuln.get("parameter", "none")
                key = f"{v_type}:{v_param}"
                conf = int(vuln.get("confidence_score", 5))

                if is_skeptical:
                    skeptical_data[key] = {
                        "skeptical_score": vuln.get("skeptical_score", 5),
                        "fp_reason": vuln.get("fp_reason", ""),
                    }
                else:
                    if key not in merged:
                        merged[key] = vuln.copy()
                        merged[key]["votes"] = vuln.get("votes", 1)
                        merged[key]["confidence_score"] = conf
                        merged[key]["_evidence_score"] = _evidence_quality(vuln)
                    else:
                        existing_ev = merged[key].get("_evidence_score", 0)
                        new_ev = _evidence_quality(vuln)

                        if new_ev > existing_ev:
                            old_votes = merged[key].get("votes", 1)
                            old_conf = merged[key].get("confidence_score", 5)
                            merged[key] = vuln.copy()
                            merged[key]["votes"] = old_votes + 1
                            merged[key]["confidence_score"] = int((old_conf + conf) / 2)
                            merged[key]["_evidence_score"] = new_ev
                            logger.debug(
                                f"[{self.name}] Dedup: Replaced {key} with better evidence "
                                f"({new_ev} > {existing_ev})"
                            )
                        else:
                            merged[key]["votes"] += 1
                            merged[key]["confidence_score"] = int(
                                (merged[key]["confidence_score"] + conf) / 2
                            )

        # Merge skeptical scores and calculate FP confidence
        for key, vuln in merged.items():
            if vuln.get("probe_validated"):
                vuln["fp_reason"] = "Validated by active probe testing"
            elif key in skeptical_data:
                vuln["skeptical_score"] = skeptical_data[key]["skeptical_score"]
                vuln["fp_reason"] = skeptical_data[key]["fp_reason"]
                vuln["fp_confidence"] = calculate_fp_confidence(
                    vuln, num_core, self.approaches,
                )
            else:
                vuln["skeptical_score"] = 5
                vuln["fp_reason"] = "Not reviewed by skeptical agent"
                vuln["fp_confidence"] = calculate_fp_confidence(
                    vuln, num_core, self.approaches,
                )

        # Consensus filter
        min_votes = getattr(settings, "ANALYSIS_CONSENSUS_VOTES", 4)
        filtered = [v for v in merged.values() if v.get("votes", 1) >= min_votes]

        self._v.emit("discovery.consolidation.completed", {
            "url": self.url,
            "raw": sum(len(a.get("vulnerabilities", [])) for a in analyses),
            "dedup": len(merged),
            "passing": len(filtered),
        })

        low_skeptical = [v for v in filtered if v.get("skeptical_score", 5) <= 3]
        if low_skeptical:
            logger.info(
                f"[{self.name}] Skeptical filter: {len(low_skeptical)} findings flagged as likely FP"
            )

        return filtered

    # ------------------------------------------------------------------
    # Result saving
    # ------------------------------------------------------------------

    async def _run_save_results(self, vulnerabilities: List[Dict]):
        """Save vulnerabilities to state manager and JSON report."""  # I/O
        vulnerabilities = deduplicate_vulnerabilities(vulnerabilities, self.url, self.name)

        logger.info(f"DASTySAST Result: {len(vulnerabilities)} candidates for {self.url[:50]}")

        for v in vulnerabilities:
            self._save_single_vulnerability(v)

        if self.url_index is not None:
            base_filename = str(self.url_index)
        else:
            base_filename = f"vulnerabilities_{get_safe_name(self.url)}"

        json_path = self.report_dir / f"{base_filename}.json"
        self._save_json_report(json_path, vulnerabilities)

        dashboard.log(
            f"[{self.name}] Found {len(vulnerabilities)} potential vulnerabilities.", "SUCCESS",
        )

    def _save_single_vulnerability(self, v: Dict):
        """Save a single vulnerability to state manager."""  # I/O
        v_name = (
            v.get("vulnerability_name") or v.get("name")
            or v.get("vulnerability") or "Vulnerability"
        )
        v_desc = (
            v.get("description") or v.get("reasoning")
            or v.get("details") or "No description provided."
        )
        v_name = normalize_vulnerability_name(v_name, v_desc, v)
        v_type_upper = (v.get("type") or v_name or "").upper()
        v_severity = get_severity_for_type(v_type_upper, v.get("severity"))

        self.state_manager.add_finding(
            url=self.url,
            type=str(v_name),
            description=str(v_desc),
            severity=str(v_severity),
            parameter=v.get("parameter") or v.get("vulnerable_parameter"),
            payload=v.get("payload") or v.get("logic") or v.get("exploitation_strategy"),
            evidence=v.get("evidence") or v.get("reasoning"),
            screenshot_path=v.get("screenshot_path"),
            validated=v.get("validated", False),
            fp_confidence=v.get("fp_confidence", 0.5),
            skeptical_score=v.get("skeptical_score", 5),
            fp_reason=v.get("fp_reason", ""),
            reproduction_command=v.get("reproduction", ""),
        )

    def _save_json_report(self, path: Path, vulnerabilities: List[Dict]):
        """Save JSON report with complete structured data."""  # I/O
        report = {
            "metadata": {
                "url": self.url,
                "url_index": self.url_index,
                "scan_context": self.scan_context,
                "timestamp": _time.time(),
                "tech_profile": {
                    "frameworks": self.tech_profile.get("frameworks", []),
                    "libraries": self.tech_profile.get("libraries", []),
                    "server": self.tech_profile.get("server", ""),
                    "language": self.tech_profile.get("language", ""),
                },
            },
            "statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "high_confidence": len([v for v in vulnerabilities if v.get("fp_confidence", 0) >= 0.7]),
                "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get("fp_confidence", 0) < 0.7]),
                "low_confidence": len([v for v in vulnerabilities if v.get("fp_confidence", 0) < 0.5]),
                "by_type": count_by_type(vulnerabilities),
            },
            "vulnerabilities": [],
        }

        for v in vulnerabilities:
            vuln_data = {
                "type": v.get("type", "Unknown"),
                "parameter": v.get("parameter", "N/A"),
                "fp_confidence": v.get("fp_confidence", 0.5),
                "skeptical_score": v.get("skeptical_score", 5),
                "votes": v.get("votes", 1),
                "severity": v.get("severity", "Medium"),
                "confidence_score": v.get("confidence_score", 5),
                "reasoning": v.get("reasoning", ""),
                "payload": v.get("payload", v.get("exploitation_strategy", "")),
                "evidence": v.get("evidence", ""),
                "fp_reason": v.get("fp_reason", ""),
                "validation_result": v.get("validation_result"),
                "http_method": v.get("http_method", ""),
                "url": v.get("url", self.url),
            }
            for key, value in v.items():
                if key not in vuln_data:
                    vuln_data[key] = value
            report["vulnerabilities"].append(vuln_data)

        report["vulnerabilities"].sort(
            key=lambda x: x.get("fp_confidence", 0), reverse=True,
        )

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.debug(f"[{self.name}] Saved JSON report to {path}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to save JSON report to {path}: {e}")

    def _save_markdown_report(self, path: Path, vulnerabilities: List[Dict]):
        """Save markdown report with FP confidence scores."""  # I/O
        content = f"# Potential Vulnerabilities for {self.url}\n\n"

        if not vulnerabilities:
            content += "No vulnerabilities detected by DAST+SAST analysis.\n"
        else:
            content += "| Type | Parameter | FP Confidence | Skeptical Score | Votes |\n"
            content += "|------|-----------|---------------|-----------------|-------|\n"

            for v in sorted(vulnerabilities, key=lambda x: x.get("fp_confidence", 0), reverse=True):
                fp_conf = v.get("fp_confidence", 0.5)
                fp_indicator = "++" if fp_conf >= 0.7 else "+" if fp_conf >= 0.5 else "-"
                param_safe = f"`{v.get('parameter', 'N/A')}`"
                content += (
                    f"| {v.get('type', 'Unknown')} | {param_safe} | "
                    f"{fp_conf:.2f} {fp_indicator} | {v.get('skeptical_score', 5)}/10 | "
                    f"{v.get('votes', 1)}/5 |\n"
                )

            content += "\n## Details\n\n"
            for v in vulnerabilities:
                param_safe = f"`{v.get('parameter', 'N/A')}`"
                content += f"### {v.get('type')} on {param_safe}\n\n"
                content += f"- **FP Confidence**: {v.get('fp_confidence', 0.5):.2f}\n"
                content += f"- **Skeptical Score**: {v.get('skeptical_score', 5)}/10\n"
                content += f"- **Votes**: {v.get('votes', 1)}/5 approaches\n"
                reasoning = v.get("reasoning", "N/A")
                content += f"- **Reasoning**: {reasoning}\n"
                if v.get("payload") or v.get("exploitation_strategy"):
                    payload = v.get("payload") or v.get("exploitation_strategy")
                    content += f"- **Payload**: `{payload}`\n"
                if v.get("evidence"):
                    evidence = v.get("evidence")
                    if len(str(evidence)) > 100:
                        content += f"- **Evidence**:\n```\n{evidence}\n```\n"
                    else:
                        content += f"- **Evidence**: `{evidence}`\n"
                if v.get("fp_reason"):
                    content += f"- **FP Analysis**: {v.get('fp_reason')}\n"
                content += "\n"

        with open(path, "w") as f:
            f.write(content)

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _emit_url_analyzed(self, vulnerabilities: List[Dict]):
        """Emit url_analyzed event with filtered findings."""  # I/O
        if self.url_index is not None:
            base_filename = str(self.url_index)
        else:
            base_filename = f"vulnerabilities_{get_safe_name(self.url)}"

        json_report_path = str(self.report_dir / f"{base_filename}.json")
        md_report_path = str(self.report_dir / f"{base_filename}.md")

        findings_payload: List[Dict] = []
        for v in vulnerabilities:
            findings_payload.append({
                "type": v.get("type", "Unknown"),
                "parameter": v.get("parameter", "unknown"),
                "url": self.url,
                "fp_confidence": v.get("fp_confidence", 0.5),
                "skeptical_score": v.get("skeptical_score", 5),
                "confidence_score": v.get("confidence_score", 5),
                "votes": v.get("votes", 1),
                "severity": v.get("severity", "Medium"),
                "reasoning": v.get("reasoning", "")[:500],
                "payload": v.get("exploitation_strategy", v.get("payload", ""))[:200],
                "fp_reason": v.get("fp_reason", "")[:200],
            })

        event_data = {
            "url": self.url,
            "scan_context": self.scan_context,
            "findings": findings_payload,
            "stats": {
                "total": len(findings_payload),
                "high_confidence": len([f for f in findings_payload if f.get("fp_confidence", 0) >= 0.7]),
                "by_type": count_by_type(findings_payload),
            },
            "tech_profile": {
                "frameworks": self.tech_profile.get("frameworks", [])[:5],
            },
            "report_files": {
                "json": json_report_path,
                "markdown": md_report_path,
                "url_index": self.url_index,
            },
            "timestamp": _time.time(),
        }

        try:
            await event_bus.emit(EventType.URL_ANALYZED, event_data)
            logger.info(
                f"[{self.name}] Emitted url_analyzed: {len(findings_payload)} findings "
                f"for {self.url[:50]}"
            )
        except Exception as e:
            logger.error(f"[{self.name}] Failed to emit url_analyzed event: {e}")
