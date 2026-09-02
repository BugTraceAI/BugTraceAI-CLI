"""Prompts, emit, JSON report.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser

logger = get_logger(__name__)

class AnalysisLlmReportMixin:
    async def _run_all_approaches(self, context: Dict, core_approaches: List[str]) -> List[Dict]:
        """ALL mode: run every enabled approach + probes in parallel."""
        self._v.emit("discovery.llm.started", {"url": self.url, "approaches": core_approaches})
        tasks = [self._analyze_with_approach(context, a) for a in core_approaches]
        tasks.append(self._check_sqli_probes())
        tasks.append(self._check_cookie_sqli_probes())

        analyses = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [a for a in analyses if isinstance(a, dict) and not a.get("error")]
        self._v.emit("discovery.llm.completed", {"url": self.url, "valid_analyses": len(valid), "total": len(analyses)})
        return valid

    async def _run_save_results(self, vulnerabilities: List[Dict]):
        """Save vulnerabilities to state manager, JSON (structured data), and markdown report (human-readable)."""
        # Apply post-deduplication (safety net for LLM-generated duplicates)
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        logger.info(f"🔍 DASTySAST Result: {len(vulnerabilities)} candidates for {self.url[:50]}")

        for v in vulnerabilities:
            self._save_single_vulnerability(v)

        # Determine base filename
        if self.url_index is not None:
            base_filename = str(self.url_index)
        else:
            # Fallback for compatibility with old calls
            base_filename = f"vulnerabilities_{self._get_safe_name()}"

        # Save JSON report ONLY (structured data - 100% robust, no character interpretation)
        # NOTE: Markdown reports removed in v3.1 - payloads must be preserved exactly
        # JSON with ensure_ascii=False + indent=2 guarantees no payload corruption
        json_path = self.report_dir / f"{base_filename}.json"
        self._save_json_report(json_path, vulnerabilities)

        dashboard.log(f"[{self.name}] Found {len(vulnerabilities)} potential vulnerabilities.", "SUCCESS")

    def _save_single_vulnerability(self, v: Dict):
        """Save a single vulnerability to state manager with fp_confidence."""
        # Normalize field names
        v_name = v.get("vulnerability_name") or v.get("name") or v.get("vulnerability") or "Vulnerability"
        v_desc = v.get("description") or v.get("reasoning") or v.get("details") or "No description provided."

        # Ensure v_name is descriptive
        v_name = self._normalize_vulnerability_name(v_name, v_desc, v)

        # Get severity
        v_type_upper = (v.get("type") or v_name or "").upper()
        v_severity = self._get_severity_for_type(v_type_upper, v.get("severity"))

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
            # Phase 17: Add FP confidence fields
            fp_confidence=v.get("fp_confidence", 0.5),
            skeptical_score=v.get("skeptical_score", 5),
            fp_reason=v.get("fp_reason", ""),
            # Phase 27: Add reproduction command for probe validation
            reproduction_command=v.get("reproduction", "")
        )

    async def _analyze_with_approach(self, context: Dict, approach: str) -> Dict:
        """Analyze with a specific persona."""
        skill_context = self._approach_get_skill_context()
        system_prompt = self._get_system_prompt(approach)
        user_prompt = self._approach_build_prompt(context, skill_context)

        # Resolve per-approach model from config (None = use default PRIMARY_MODELS)
        model_attr = self._APPROACH_MODEL_MAP.get(approach)
        model_override = getattr(settings, model_attr, None) if model_attr else None

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                module_name="DASTySASTAgent",
                max_tokens=8000,
                model_override=model_override
            )

            if not response:
                return {"error": "Empty response from LLM"}

            return self._approach_parse_response(response)

        except Exception as e:
            logger.error(f"Failed to analyze with approach {approach}: {e}", exc_info=True)
            return {"vulnerabilities": []}

    def _approach_build_prompt(self, context: Dict, skill_context: str) -> str:
        """Build analysis prompt with context and ACTIVE PROBE RESULTS.

        IMPROVED (2026-02-01): Now includes reflection probe results.
        The LLM receives CONCRETE evidence about parameter behavior.
        """
        # Format reflection probes as evidence section
        probe_section = self._format_probe_evidence(context.get("reflection_probes", []))

        # Format tech profile for LLM context
        tech_info_parts = []
        if self.tech_profile.get('infrastructure'):
            tech_info_parts.append(f"Infrastructure: {', '.join(self.tech_profile['infrastructure'])}")
        if self.tech_profile.get('frameworks'):
            tech_info_parts.append(f"Frameworks: {', '.join(self.tech_profile['frameworks'])}")
        if self.tech_profile.get('servers'):
            tech_info_parts.append(f"Servers: {', '.join(self.tech_profile['servers'])}")
        if self.tech_profile.get('waf'):
            tech_info_parts.append(f"⚠️ WAF Detected: {', '.join(self.tech_profile['waf'])}")
        if self.tech_profile.get('cdn'):
            tech_info_parts.append(f"CDN: {', '.join(self.tech_profile['cdn'])}")

        tech_stack_summary = "\n".join(tech_info_parts) if tech_info_parts else "Basic web application (no specific technologies detected)"

        return f"""Analyze this URL for security vulnerabilities.

URL: {self.url}

=== TECHNOLOGY STACK (Use this to craft precise exploits) ===
{tech_stack_summary}

NOTE: Use detected technologies to:
        - Generate version-specific tests only for technologies and versions actually observed
- Identify infrastructure-specific attack vectors (e.g., AWS ALB header manipulation)
- Avoid wasting time on irrelevant attacks (e.g., PHP attacks on Node.js)
- Craft payloads that bypass detected WAF/CDN protections

=== ACTIVE RECONNAISSANCE RESULTS (MANDATORY EVIDENCE) ===
{probe_section if probe_section else "No parameters detected in URL."}

=== PAGE HTML SOURCE (Snippet) ===
{context.get('html_content', 'Not available')[:8000]}

=== ANALYSIS RULES (STRICT - NO SMOKE ALLOWED) ===

MANDATORY: Base your analysis ONLY on the probe results above.
- If a parameter REFLECTS, specify the EXACT context (html_text, html_attribute, script_block, url_context)
- If characters like < > " ' survive, that is EVIDENCE of XSS potential
- If NO reflection is detected, you CANNOT claim XSS - the parameter does NOT reflect

CONFIDENCE SCORING (Evidence-Based):
- 0-3: No probe evidence, speculation only → DO NOT REPORT
- 4-5: Reflection detected but chars are encoded → Low priority
- 6-7: Reflection in dangerous context (attribute/script) with some chars surviving
- 8-9: Reflection with < > " ' all surviving in dangerous context
- 10: Confirmed execution (script block with unfiltered input)

=== PROHIBITED (Will be rejected) ===
- "Could be vulnerable" without probe evidence
- "Potentially exploitable" without concrete context
- XSS claims on parameters that DO NOT reflect
- SQLi claims without error response or behavioral evidence
- Vague descriptions like "try injecting", "test for", "might work"

=== REQUIRED OUTPUT FORMAT ===

For EACH vulnerability, you MUST provide:
- html_evidence: The EXACT line/snippet where the vulnerability exists (from probe results)
- xss_context: For XSS, specify ONE OF: html_text, html_attribute, script_block, url_context, none
- chars_survive: Which special chars survive unencoded (< > " ' `)

OOB Callback: {context.get('oob_info', {}).get('callback_url', 'http://oast.fun')}

{f"=== SPECIALIZED KNOWLEDGE ==={chr(10)}{skill_context}{chr(10)}" if skill_context else ""}

OUTPUT FORMAT (XML):
<vulnerabilities>
  <vulnerability>
    <type>XSS (Reflected)</type>
    <parameter>search</parameter>
    <confidence_score>8</confidence_score>
    <xss_context>html_attribute</xss_context>
    <html_evidence>Line 47: &lt;input value="bugtraceomni7x9z"&gt;</html_evidence>
    <chars_survive>&lt; &gt; "</chars_survive>
    <reasoning>Parameter reflects in input value attribute at line 47. Chars &lt; &gt; survive unencoded.</reasoning>
    <severity>High</severity>
    <payload>" onfocus=alert(1) autofocus="</payload>
  </vulnerability>
</vulnerabilities>

Return ONLY valid XML tags. No markdown. No explanations.
"""

    def _approach_parse_response(self, response: str) -> Dict:
        """Parse LLM response into vulnerabilities."""
        parser = XmlParser()
        vuln_contents = parser.extract_list(response, "vulnerability")

        vulnerabilities = []
        for vc in vuln_contents:
            vuln = self._parse_single_vulnerability(parser, vc)
            if vuln:
                vulnerabilities.append(vuln)

        return {"vulnerabilities": vulnerabilities}

    def _get_system_prompt(self, approach: str) -> str:
        """Get system prompt from external config."""
        if approach == "skeptical_agent":
            return self._get_skeptical_system_prompt()

        personas = self.agent_config.get("personas", {})
        if approach in personas:
            return personas[approach].strip()

        return self.system_prompt or "You are an expert security analyst."

    async def _emit_url_analyzed(self, vulnerabilities: List[Dict]):
        """
        Emit url_analyzed event with filtered findings.

        Event payload:
        - url: The analyzed URL
        - scan_context: Context for ordering guarantees
        - findings: List of findings with fp_confidence
        - stats: Summary statistics
        - report_files: Paths to JSON and MD reports (v2.1.0)

        This event is consumed by:
        - ThinkingConsolidationAgent (Phase 18): For deduplication and queue distribution
        - Dashboard: For real-time progress updates

        v2.1.0: Added report_files to allow specialists to read full payloads from JSON
        when event payload is truncated (>200 chars).
        """
        # Determine base filename based on url_index
        if self.url_index is not None:
            base_filename = str(self.url_index)
        else:
            # Fallback for compatibility with old calls
            base_filename = f"vulnerabilities_{self._get_safe_name()}"

        # Calculate report file paths
        json_report_path = str(self.report_dir / f"{base_filename}.json")
        md_report_path = str(self.report_dir / f"{base_filename}.md")

        # Prepare findings payload with essential fields
        findings_payload = []
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
                "reasoning": v.get("reasoning", "")[:500],  # Truncate for event size
                "payload": v.get("exploitation_strategy", v.get("payload", ""))[:200],  # Truncated - full version in JSON
                "fp_reason": v.get("fp_reason", "")[:200]
            })

        # Build event data
        event_data = {
            "url": self.url,
            "scan_context": self.scan_context,
            "findings": findings_payload,
            "stats": {
                "total": len(findings_payload),
                "high_confidence": len([f for f in findings_payload if f.get("fp_confidence", 0) >= 0.7]),
                "by_type": self._count_by_type(findings_payload)
            },
            "tech_profile": {
                "frameworks": self.tech_profile.get("frameworks", [])[:5]  # Limit for event size
            },
            "report_files": {  # v2.1.0: Allow specialists to read full payloads from JSON
                "json": json_report_path,
                "markdown": md_report_path,
                "url_index": self.url_index  # For correlation with urls.txt
            },
            "timestamp": __import__('time').time()
        }

        # Emit event
        try:
            await event_bus.emit(EventType.URL_ANALYZED, event_data)
            logger.info(f"[{self.name}] Emitted url_analyzed: {len(findings_payload)} findings for {self.url[:50]}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to emit url_analyzed event: {e}")

    def _save_markdown_report(self, path: Path, vulnerabilities: List[Dict]):
        """Saves markdown report with FP confidence scores."""
        content = f"# Potential Vulnerabilities for {self.url}\n\n"

        if not vulnerabilities:
            content += "No vulnerabilities detected by DAST+SAST analysis.\n"
        else:
            content += "| Type | Parameter | FP Confidence | Skeptical Score | Votes |\n"
            content += "|------|-----------|---------------|-----------------|-------|\n"

            for v in sorted(vulnerabilities, key=lambda x: x.get('fp_confidence', 0), reverse=True):
                fp_conf = v.get('fp_confidence', 0.5)
                fp_indicator = '++' if fp_conf >= 0.7 else '+' if fp_conf >= 0.5 else '-'

                # Wrap parameter in code block to preserve special chars
                param_safe = f"`{v.get('parameter', 'N/A')}`"
                content += f"| {v.get('type', 'Unknown')} | {param_safe} | "
                content += f"{fp_conf:.2f} {fp_indicator} | {v.get('skeptical_score', 5)}/10 | "
                content += f"{v.get('votes', 1)}/5 |\n"

            content += "\n## Details\n\n"

            for v in vulnerabilities:
                # Wrap parameter in code block
                param_safe = f"`{v.get('parameter', 'N/A')}`"
                content += f"### {v.get('type')} on {param_safe}\n\n"
                content += f"- **FP Confidence**: {v.get('fp_confidence', 0.5):.2f}\n"
                content += f"- **Skeptical Score**: {v.get('skeptical_score', 5)}/10\n"
                content += f"- **Votes**: {v.get('votes', 1)}/5 approaches\n"

                # Wrap reasoning in code block if it contains payloads/evidence
                reasoning = v.get('reasoning', 'N/A')
                content += f"- **Reasoning**: {reasoning}\n"

                # Add payload in code block if present
                if v.get('payload') or v.get('exploitation_strategy'):
                    payload = v.get('payload') or v.get('exploitation_strategy')
                    content += f"- **Payload**: `{payload}`\n"

                # Add evidence in code block if present
                if v.get('evidence'):
                    evidence = v.get('evidence')
                    # If evidence is long, use code fence; otherwise inline code
                    if len(str(evidence)) > 100:
                        content += f"- **Evidence**:\n```\n{evidence}\n```\n"
                    else:
                        content += f"- **Evidence**: `{evidence}`\n"

                if v.get('fp_reason'):
                    content += f"- **FP Analysis**: {v.get('fp_reason')}\n"
                content += "\n"

        with open(path, "w") as f:
            f.write(content)

    def _save_json_report(self, path: Path, vulnerabilities: List[Dict]):
        """
        Saves JSON report with complete structured data for 100% payload preservation.

        This format ensures all special characters in payloads, parameters, and evidence
        are preserved exactly as-is, without any Markdown interpretation issues.
        """
        import time

        # Build complete report structure
        report = {
            "metadata": {
                "url": self.url,
                "url_index": self.url_index,
                "scan_context": self.scan_context,
                "timestamp": time.time(),
                "tech_profile": {
                    "frameworks": self.tech_profile.get("frameworks", []),
                    "libraries": self.tech_profile.get("libraries", []),
                    "server": self.tech_profile.get("server", ""),
                    "language": self.tech_profile.get("language", "")
                }
            },
            "statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "high_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) >= 0.7]),
                "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get('fp_confidence', 0) < 0.7]),
                "low_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) < 0.5]),
                "by_type": self._count_by_type(vulnerabilities)
            },
            "vulnerabilities": []
        }

        # Add vulnerabilities with all fields preserved
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
                "url": v.get("url", self.url)
            }

            # Include any additional fields that might be present
            for key, value in v.items():
                if key not in vuln_data:
                    vuln_data[key] = value

            report["vulnerabilities"].append(vuln_data)

        # Sort vulnerabilities by FP confidence (highest first)
        report["vulnerabilities"].sort(key=lambda x: x.get('fp_confidence', 0), reverse=True)

        # Save JSON with proper formatting
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.debug(f"[{self.name}] Saved JSON report to {path}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to save JSON report to {path}: {e}")

