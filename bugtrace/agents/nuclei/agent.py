"""
Nuclei Agent — Thin Orchestrator.

Inherits from BaseAgent and delegates all logic to pure (core.py) and
I/O (runner.py) modules. This class owns only:
- Agent lifecycle (init, run, run_loop)
- State wiring (target, report_dir)
- Orchestration of the 2-phase scan pipeline
- Tech profile construction and saving
"""

import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard

from bugtrace.agents.nuclei.core import (
    categorize_tech_finding,
    detect_frameworks_from_html,
    detect_js_versions,
    extract_html_from_nuclei_response,
)
from bugtrace.agents.nuclei.runner import (
    fetch_html,
    check_security_headers,
    check_insecure_cookies,
    check_graphql_introspection,
    check_rate_limiting,
    check_access_control,
    verify_waf_detections,
    detect_frameworks_from_recon_urls,
)


class NucleiAgent(BaseAgent):
    """
    Specialized Agent for Technology Detection and Vulnerability Scanning using Nuclei.
    Phase 1 of the Sequential Pipeline.
    """

    def __init__(self, target: str, report_dir: Path, event_bus: Any = None):
        super().__init__(
            "NucleiAgent", "Tech Discovery",
            event_bus=event_bus, agent_id="nuclei_agent",
        )
        self.target = target
        self.report_dir = report_dir

    async def run(self) -> Dict:
        """Runs two-phase Nuclei scan for technology detection and vulnerability discovery.

        Returns:
            Comprehensive tech_profile used by specialist agents.
        """
        dashboard.current_agent = self.name
        dashboard.log(
            f"[{self.name}] Starting 2-phase Nuclei scan (tech-detect + auto-scan)...",
            "INFO",
        )

        try:
            # Run two-phase Nuclei scan
            nuclei_results = await external_tools.run_nuclei(self.target)

            tech_findings = nuclei_results.get("tech_findings", [])
            vuln_findings = nuclei_results.get("vuln_findings", [])

            # Build tech profile
            tech_profile = self._build_initial_profile(tech_findings, vuln_findings)

            # Categorize tech findings
            self._categorize_findings(tech_profile, tech_findings)

            # Deduplicate lists
            for key in [
                "infrastructure", "frameworks", "languages",
                "servers", "cms", "waf", "cdn", "tech_tags",
            ]:
                tech_profile[key] = list(set(tech_profile[key]))

            # Verify WAF detections
            if tech_profile["waf"]:
                verified_wafs = await verify_waf_detections(
                    tech_profile["waf"], tech_findings, self.target
                )
                if verified_wafs != tech_profile["waf"]:
                    removed = set(tech_profile["waf"]) - set(verified_wafs)
                    if removed:
                        dashboard.log(
                            f"[{self.name}] WAF FP filtered: {', '.join(removed)} (Nuclei FP)",
                            "INFO",
                        )
                    tech_profile["waf"] = verified_wafs

            # Get HTML content (used for framework fallback + JS version detection)
            html_content = extract_html_from_nuclei_response(tech_findings)
            if not html_content:
                html_content = await fetch_html(self.target)

            # Framework detection fallback (check for JS frontend frameworks)
            self._run_framework_fallback(tech_profile, html_content)

            # Check recon URLs for frameworks if still none found
            await self._run_recon_framework_fallback(tech_profile)

            # JS dependency version detection
            if html_content:
                js_vulns = detect_js_versions(html_content, self.target)
                if js_vulns:
                    tech_profile["js_vulnerabilities"].extend(js_vulns)
                    dashboard.log(
                        f"[{self.name}] Found {len(js_vulns)} vulnerable JS dependencies",
                        "INFO",
                    )

            # Security checks
            existing_template_ids = {
                mc.get("template_id", "").lower()
                for mc in tech_profile["misconfigurations"]
            }

            header_findings = await check_security_headers(self.target, existing_template_ids)
            if header_findings:
                tech_profile["misconfigurations"].extend(header_findings)
                dashboard.log(
                    f"[{self.name}] {len(header_findings)} missing security headers detected",
                    "INFO",
                )

            cookie_findings = await check_insecure_cookies(
                self.target, self.report_dir, existing_template_ids
            )
            if cookie_findings:
                tech_profile["misconfigurations"].extend(cookie_findings)
                dashboard.log(
                    f"[{self.name}] {len(cookie_findings)} insecure cookie(s) detected",
                    "INFO",
                )

            graphql_findings = await check_graphql_introspection(
                self.target, self.report_dir, existing_template_ids
            )
            if graphql_findings:
                tech_profile["misconfigurations"].extend(graphql_findings)
                dashboard.log(
                    f"[{self.name}] GraphQL introspection enabled on "
                    f"{len(graphql_findings)} endpoint(s)",
                    "WARNING",
                )

            rate_findings = await check_rate_limiting(self.target, self.report_dir)
            if rate_findings:
                tech_profile["misconfigurations"].extend(rate_findings)
                dashboard.log(
                    f"[{self.name}] No rate limiting detected on auth endpoints",
                    "WARNING",
                )

            access_findings = await check_access_control(self.target, self.report_dir)
            if access_findings:
                tech_profile["misconfigurations"].extend(access_findings)
                dashboard.log(
                    f"[{self.name}] {len(access_findings)} admin endpoint(s) accessible without auth",
                    "WARNING",
                )

            # Save comprehensive tech profile
            profile_path = self.report_dir / "tech_profile.json"
            with open(profile_path, "w") as f:
                json.dump(tech_profile, f, indent=2)

            # Log summary
            self._log_summary(tech_profile, vuln_findings)

            return tech_profile

        except Exception as e:
            logger.error(f"NucleiAgent failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] Error: {e}", "ERROR")
            return {
                "error": str(e),
                "infrastructure": [],
                "frameworks": [],
                "languages": [],
                "servers": [],
                "cms": [],
                "waf": [],
                "cdn": [],
                "tech_tags": [],
                "raw_tech_findings": [],
                "raw_vuln_findings": [],
            }

    async def run_loop(self):
        """Standard run loop for BaseAgent contract."""
        await self.run()

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    def _build_initial_profile(
        self,
        tech_findings: List[Dict],
        vuln_findings: List[Dict],
    ) -> Dict:
        """Build initial empty tech profile."""
        return {
            "url": self.target,
            "infrastructure": [],
            "frameworks": [],
            "languages": [],
            "servers": [],
            "cms": [],
            "waf": [],
            "cdn": [],
            "tech_tags": [],
            "misconfigurations": [],
            "js_vulnerabilities": [],
            "raw_tech_findings": tech_findings,
            "raw_vuln_findings": vuln_findings,
        }

    def _categorize_findings(self, tech_profile: Dict, tech_findings: List[Dict]) -> None:
        """Categorize all tech findings into profile buckets."""
        for finding in tech_findings:
            info = finding.get("info", {})
            tags = info.get("tags", [])

            category, data = categorize_tech_finding(finding, self.target)

            if category == "misconfigurations":
                tech_profile["misconfigurations"].append(data)
            elif category and isinstance(data, str):
                tech_profile[category].append(data)
                # Also add to tech_tags if applicable
                if "tech" in tags or "detect" in tags:
                    tech_profile["tech_tags"].append(info.get("name", "Unknown"))
            elif category is None:
                if "tech" in tags or "detect" in tags:
                    tech_profile["tech_tags"].append(info.get("name", "Unknown"))

    def _run_framework_fallback(self, tech_profile: Dict, html_content: Optional[str]) -> None:
        """Run HTML-based framework detection fallback."""
        _js_fw_names = ('angular', 'react', 'vue', 'jquery', 'backbone', 'ember', 'svelte')
        has_js_fw = any(
            any(fw in f.lower() for fw in _js_fw_names)
            for f in tech_profile["frameworks"]
        )
        if not has_js_fw and html_content:
            logger.info(f"[{self.name}] No frameworks detected by Nuclei - trying HTML fallback")
            detected_frameworks = detect_frameworks_from_html(html_content)
            if detected_frameworks:
                tech_profile["frameworks"].extend(detected_frameworks)
                dashboard.log(
                    f"[{self.name}] HTML Fallback: Detected {', '.join(detected_frameworks)}",
                    "SUCCESS",
                )

    async def _run_recon_framework_fallback(self, tech_profile: Dict) -> None:
        """Check recon URLs for frameworks if none found yet."""
        _js_fw_names = ('angular', 'react', 'vue', 'jquery', 'backbone', 'ember', 'svelte')
        has_js_fw = any(
            any(fw in f.lower() for fw in _js_fw_names)
            for f in tech_profile["frameworks"]
        )
        if not has_js_fw:
            recon_frameworks = await detect_frameworks_from_recon_urls(self.report_dir)
            if recon_frameworks:
                tech_profile["frameworks"].extend(recon_frameworks)
                dashboard.log(
                    f"[{self.name}] Recon Fallback: Detected {', '.join(recon_frameworks)}",
                    "SUCCESS",
                )

    def _log_summary(self, tech_profile: Dict, vuln_findings: List[Dict]) -> None:
        """Log tech profile summary to dashboard."""
        summary_parts = []
        if tech_profile["infrastructure"]:
            summary_parts.append(f"{len(tech_profile['infrastructure'])} infra")
        if tech_profile["frameworks"]:
            summary_parts.append(f"{len(tech_profile['frameworks'])} frameworks")
        if tech_profile["servers"]:
            summary_parts.append(f"{len(tech_profile['servers'])} servers")
        if tech_profile["waf"]:
            summary_parts.append("WAF detected")

        summary = ", ".join(summary_parts) if summary_parts else "Basic detection"
        dashboard.log(
            f"[{self.name}] Tech Profile: {summary} | {len(vuln_findings)} vulns",
            "SUCCESS",
        )
