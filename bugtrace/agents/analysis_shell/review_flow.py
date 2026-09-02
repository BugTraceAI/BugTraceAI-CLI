"""Consolidate/skeptic/evidence.

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

class AnalysisReviewMixin:
    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """
        Remove duplicate vulnerabilities based on type+normalized_parameter+url.

        This is a safety net deduplication layer that catches duplicates missed
        by the LLM (e.g., when the LLM generates slightly different parameter names
        for the same vulnerability).

        Args:
            vulns: List of vulnerability findings

        Returns:
            Deduplicated list of findings
        """
        if not vulns:
            return vulns

        seen = {}
        deduped = []

        def _normalize_param(param: str, vuln_type: str) -> str:
            """Normalize parameter name for deduplication."""
            param_lower = param.lower()

            # XXE: Normalize all POST body variations
            # Catch all variants: "POST Body", "XML Body", "stockCheckForm", etc.
            if vuln_type.lower() == "xxe":
                xxe_indicators = ["post", "body", "xml", "stock", "form"]
                if any(indicator in param_lower for indicator in xxe_indicators):
                    return "post_body"

            # SQLi: Normalize cookie names
            if "cookie:" in param_lower:
                parts = param_lower.split("cookie:")
                if len(parts) > 1:
                    cookie_name = parts[1].strip().split()[0]
                    return f"cookie:{cookie_name}"

            return param_lower

        for v in vulns:
            vuln_type = v.get('type', 'Unknown')
            param_raw = v.get('parameter', 'unknown')
            url = v.get('url', self.url)

            # Create dedup key with normalized parameter
            param_normalized = _normalize_param(param_raw, vuln_type)
            key = (vuln_type.lower(), param_normalized, url)

            if key not in seen:
                seen[key] = v
                deduped.append(v)
            else:
                # Keep the one with higher fp_confidence
                existing = seen[key]
                if v.get('fp_confidence', 0) > existing.get('fp_confidence', 0):
                    deduped.remove(existing)
                    deduped.append(v)
                    seen[key] = v

        if len(vulns) != len(deduped):
            logger.info(f"[{self.name}] Post-deduplication: {len(vulns)} → {len(deduped)} findings ({len(vulns)-len(deduped)} duplicates removed)")

        return deduped

    def _get_skeptical_system_prompt(self) -> str:
        """
        Get system prompt for skeptical_agent approach.

        The skeptical agent's job is to:
        1. Challenge findings from other approaches
        2. Identify common false positive patterns
        3. Assign FP likelihood scores
        """
        return """You are a SKEPTICAL security auditor. Your job is to CHALLENGE vulnerability findings and identify FALSE POSITIVES.

SKEPTICAL MINDSET:
- Parameter names alone (id, user, file) are NOT evidence of vulnerability
- Generic patterns without concrete evidence are likely false positives
- Error messages must be SPECIFIC SQL/command errors, not generic 500s
- XSS requires UNESCAPED reflection in dangerous contexts, not just reflection
- WAF-blocked requests indicate the app HAS protections

FALSE POSITIVE INDICATORS:
- "Could be vulnerable" or "potentially" without concrete evidence
- Vulnerability based on parameter NAME only (id -> SQLi assumption)
- No specific payload that would trigger the issue
- Technology stack inference without actual testing
- Assumptions based on common patterns

LIKELY TRUE POSITIVE INDICATORS:
- Specific error messages (SQL syntax errors, stack traces)
- Unescaped user input in script/event handler contexts
- Demonstrated behavioral differences (time-based, boolean-based)
- OOB callbacks received
- Specific version with known CVE

For EACH potential vulnerability, assign a SKEPTICAL_SCORE:
- 0-3: LIKELY FALSE POSITIVE - Reject, based on weak evidence
- 4-5: UNCERTAIN - Could be either, needs specialist validation
- 6-7: PLAUSIBLE - Some evidence, worth specialist investigation
- 8-10: LIKELY TRUE POSITIVE - Strong evidence, high priority

REMEMBER: Being skeptical SAVES TIME. False positives waste specialist agent resources."""

    def _assess_evidence_quality(self, finding: Dict) -> float:
        """
        Assess the quality of evidence for a finding.

        Evidence Quality Scale (0.0-1.0):
        - 0.0: No concrete evidence (parameter name only)
        - 0.5: Some patterns/indicators
        - 1.0: Concrete proof (error messages, reflection, OOB callback)

        Args:
            finding: Vulnerability finding dict

        Returns:
            float: Evidence quality score between 0.0 and 1.0
        """
        evidence_score = 0.0
        reasoning = str(finding.get('reasoning', '')).lower()
        payload = str(finding.get('exploitation_strategy', finding.get('payload', ''))).lower()
        vuln_type = str(finding.get('type', '')).lower()

        # Strong evidence indicators (+0.3 each, max 1.0)
        strong_indicators = [
            # SQL error patterns
            ('sql' in vuln_type and any(err in reasoning for err in ['syntax error', 'mysql', 'postgresql', 'sqlite', 'ora-'])),
            # XSS reflection
            ('xss' in vuln_type and any(ind in reasoning for ind in ['unescaped', 'reflected', 'rendered', 'executed'])),
            # Error messages
            any(err in reasoning for err in ['stack trace', 'exception', 'error message', 'debug']),
            # OOB callback
            'callback' in reasoning or 'oob' in reasoning or 'interactsh' in reasoning,
            # Validated/confirmed
            finding.get('validated', False) or 'confirmed' in reasoning,
        ]

        for indicator in strong_indicators:
            if indicator:
                evidence_score += 0.3

        # Medium evidence indicators (+0.15 each)
        medium_indicators = [
            # Has specific payload
            len(payload) > 10 and any(c in payload for c in ["'", '"', '<', '>', '{', '}']),
            # Has confidence score >= 7
            finding.get('confidence_score', 5) >= 7,
            # Multiple votes
            finding.get('votes', 1) >= 3,
        ]

        for indicator in medium_indicators:
            if indicator:
                evidence_score += 0.15

        # Weak evidence penalty (-0.2 each)
        weak_indicators = [
            # Parameter name only
            'parameter name' in reasoning or 'common parameter' in reasoning,
            # Speculation
            'could be' in reasoning or 'might be' in reasoning or 'potentially' in reasoning,
            # No payload
            len(payload) < 5,
        ]

        for indicator in weak_indicators:
            if indicator:
                evidence_score -= 0.2

        return max(0.0, min(1.0, evidence_score))

    async def _run_skeptical_approach(self, context: Dict, prior_analyses: List[Dict]) -> Dict:
        """
        Run skeptical_agent approach to review findings from core approaches.

        The skeptical agent sees ALL prior findings and challenges them,
        assigning skeptical_scores to help filter false positives early.
        """
        # Consolidate prior findings for skeptical review
        prior_findings = []
        for analysis in prior_analyses:
            for vuln in analysis.get("vulnerabilities", []):
                prior_findings.append(vuln)

        if not prior_findings:
            return {"vulnerabilities": []}

        # Build skeptical review prompt
        system_prompt = self._get_skeptical_system_prompt()
        user_prompt = self._build_skeptical_prompt(context, prior_findings)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model_override=settings.SKEPTICAL_MODEL,  # Use fast model for efficiency
                module_name="DASTySASTAgent_Skeptical",
                max_tokens=4000
            )

            if not response:
                return {"error": "Empty response from skeptical agent"}

            return self._parse_skeptical_response(response, prior_findings)

        except Exception as e:
            logger.error(f"Skeptical approach failed: {e}", exc_info=True)
            return {"error": str(e)}

    def _build_skeptical_prompt(self, context: Dict, prior_findings: List[Dict]) -> str:
        """Build prompt for skeptical review of prior findings."""
        findings_summary = []
        for i, f in enumerate(prior_findings):
            findings_summary.append(
                f"{i+1}. {f.get('type', 'Unknown')} on '{f.get('parameter', 'unknown')}' "
                f"(confidence: {f.get('confidence_score', 5)}/10)\n"
                f"   Reasoning: {f.get('reasoning', 'No reasoning')[:200]}"
            )

        return f"""Review these vulnerability findings and identify FALSE POSITIVES:

=== TARGET ===
URL: {self.url}

=== FINDINGS TO REVIEW ({len(prior_findings)} total) ===
{chr(10).join(findings_summary)}

=== YOUR TASK ===
For EACH finding, assign a SKEPTICAL_SCORE (0-10):
- 0-3: LIKELY FALSE POSITIVE (reject)
- 4-5: UNCERTAIN (needs validation)
- 6-7: PLAUSIBLE (investigate)
- 8-10: LIKELY TRUE POSITIVE (high priority)

Return XML:
<skeptical_review>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <skeptical_score>3</skeptical_score>
    <fp_reason>Based on parameter name only, no evidence of reflection</fp_reason>
  </finding>
</skeptical_review>

Be RUTHLESS. False positives waste resources."""

    def _parse_skeptical_response(self, response: str, prior_findings: List[Dict]) -> Dict:
        """Parse skeptical review response and tag findings with skeptical scores."""
        parser = XmlParser()
        finding_blocks = parser.extract_list(response, "finding")

        scored_findings = []

        for block in finding_blocks:
            try:
                idx = int(parser.extract_tag(block, "index")) - 1
                if 0 <= idx < len(prior_findings):
                    finding = prior_findings[idx].copy()
                    finding["skeptical_score"] = int(parser.extract_tag(block, "skeptical_score") or "5")
                    finding["fp_reason"] = parser.extract_tag(block, "fp_reason") or ""
                    scored_findings.append(finding)
            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse skeptical finding: {e}")

        logger.info(f"[{self.name}] Skeptical review: {len(scored_findings)} findings scored")
        return {"vulnerabilities": scored_findings, "approach": "skeptical_agent"}

    def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
        """
        Consolidate findings from different approaches using voting/merging.

        IMPROVED (2026-02-01): Technical deduplication - keep the finding with
        the most precise HTML evidence, not the one that "explains better".

        Evidence quality scoring:
        - html_evidence field present: +3 points
        - xss_context specified: +2 points
        - chars_survive specified: +1 point
        - probe_validated: +5 points (highest priority)
        """
        merged = {}
        skeptical_data = {}  # Track skeptical scores separately

        def to_float(val, default=0.5):
            try:
                return float(val)
            except (ValueError, TypeError):
                return default

        def _evidence_quality(vuln: Dict) -> int:
            """Score a finding's evidence quality. Higher = better evidence."""
            score = 0
            if vuln.get("probe_validated"):
                score += 5
            if vuln.get("html_evidence"):
                score += 3
            if vuln.get("xss_context") and vuln.get("xss_context") != "none":
                score += 2
            if vuln.get("chars_survive"):
                score += 1
            # Bonus for specific reasoning with line numbers
            reasoning = vuln.get("reasoning", "")
            if "line" in reasoning.lower() or "snippet" in reasoning.lower():
                score += 1
            return score

        # First pass: collect all findings
        for analysis in analyses:
            is_skeptical = analysis.get("approach") == "skeptical_agent"

            for vuln in analysis.get("vulnerabilities", []):
                v_type = vuln.get("type", vuln.get("vulnerability", "Unknown"))
                v_param = vuln.get("parameter", "none")
                key = f"{v_type}:{v_param}"

                conf = int(vuln.get("confidence_score", 5))

                if is_skeptical:
                    # Store skeptical data for later merge
                    skeptical_data[key] = {
                        "skeptical_score": vuln.get("skeptical_score", 5),
                        "fp_reason": vuln.get("fp_reason", "")
                    }
                else:
                    # Standard consolidation for core approaches
                    if key not in merged:
                        merged[key] = vuln.copy()
                        merged[key]["votes"] = vuln.get("votes", 1)  # Preserve probe's boost
                        merged[key]["confidence_score"] = conf
                        merged[key]["_evidence_score"] = _evidence_quality(vuln)
                    else:
                        # TECHNICAL DEDUPLICATION: Keep finding with BETTER EVIDENCE
                        existing_evidence = merged[key].get("_evidence_score", 0)
                        new_evidence = _evidence_quality(vuln)

                        if new_evidence > existing_evidence:
                            # New finding has better evidence - replace but keep vote count
                            old_votes = merged[key].get("votes", 1)
                            old_conf = merged[key].get("confidence_score", 5)
                            merged[key] = vuln.copy()
                            merged[key]["votes"] = old_votes + 1
                            merged[key]["confidence_score"] = int((old_conf + conf) / 2)
                            merged[key]["_evidence_score"] = new_evidence
                            logger.debug(f"[{self.name}] Dedup: Replaced {key} with better evidence ({new_evidence} > {existing_evidence})")
                        else:
                            # Existing has better or equal evidence - just add vote
                            merged[key]["votes"] += 1
                            merged[key]["confidence_score"] = int((merged[key]["confidence_score"] + conf) / 2)

        # Second pass: merge skeptical scores and calculate fp_confidence
        for key, vuln in merged.items():
            # Probe-validated findings keep their original scores (active testing > LLM analysis)
            if vuln.get("probe_validated"):
                vuln["fp_reason"] = "Validated by active probe testing"
                # Don't override skeptical_score or fp_confidence - probe's scores are authoritative
            elif key in skeptical_data:
                vuln["skeptical_score"] = skeptical_data[key]["skeptical_score"]
                vuln["fp_reason"] = skeptical_data[key]["fp_reason"]
                # Calculate FP confidence (Phase 17 enhancement)
                vuln['fp_confidence'] = self._calculate_fp_confidence(vuln)
            else:
                # No skeptical review for this finding - default to uncertain
                vuln["skeptical_score"] = 5
                vuln["fp_reason"] = "Not reviewed by skeptical agent"
                vuln['fp_confidence'] = self._calculate_fp_confidence(vuln)

        # Apply consensus filter - require at least 4 votes to reduce false positives
        min_votes = getattr(settings, "ANALYSIS_CONSENSUS_VOTES", 4)
        filtered = [v for v in merged.values() if v.get("votes", 1) >= min_votes]

        self._v.emit("discovery.consolidation.completed", {
            "url": self.url, "raw": sum(len(a.get("vulnerabilities", [])) for a in analyses),
            "dedup": len(merged), "passing": len(filtered),
        })

        # Log skeptical filtering stats
        low_skeptical = [v for v in filtered if v.get("skeptical_score", 5) <= 3]
        if low_skeptical:
            logger.info(f"[{self.name}] Skeptical filter: {len(low_skeptical)} findings flagged as likely FP")

        return filtered

    async def _skeptical_review(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Use a skeptical LLM (Claude Haiku) to review findings and filter false positives.
        This is the final gate before findings reach specialist agents.

        Phase 17: Now uses fp_confidence for smart pre-filtering.
        Findings with low fp_confidence AND low skeptical_score are rejected early.

        Phase 27: Probe-validated findings bypass LLM review (active testing > LLM analysis).
        """
        self._v.emit("discovery.skeptical.started", {"url": self.url, "findings_to_review": len(vulnerabilities)})
        # 0. Separate probe-validated findings (they bypass LLM review)
        probe_validated = []
        llm_findings = []
        for v in vulnerabilities:
            if v.get("probe_validated"):
                probe_validated.append(v)
                logger.info(f"[{self.name}] Probe-validated finding bypasses skeptical review: {v.get('type')} on {v.get('parameter')}")
            else:
                llm_findings.append(v)

        # 1. Pre-filter based on fp_confidence threshold (Phase 17 enhancement)
        # FIX: Use correct config attribute name (was FP_CONFIDENCE_THRESHOLD, now THINKING_FP_THRESHOLD)
        threshold = getattr(settings, 'THINKING_FP_THRESHOLD', 0.5)

        pre_filtered = []
        rejected_count = 0
        for v in llm_findings:
            fp_conf = v.get('fp_confidence', 0.5)
            skeptical_score = v.get('skeptical_score', 5)

            # Reject if BOTH skeptical_score is low AND fp_confidence is below threshold
            if skeptical_score <= 3 and fp_conf < threshold:
                logger.info(f"[{self.name}] Pre-filtered FP: {v.get('type')} on '{v.get('parameter')}' "
                           f"(fp_confidence: {fp_conf:.2f}, skeptical: {skeptical_score})")
                rejected_count += 1
            else:
                pre_filtered.append(v)

        if rejected_count > 0:
            logger.info(f"[{self.name}] FP pre-filter: {rejected_count} removed (threshold: {threshold}), {len(pre_filtered)} remaining")

        if not pre_filtered:
            # Still return probe-validated findings
            return probe_validated

        # 2. Deduplicate
        vulnerabilities = self._review_deduplicate(pre_filtered)
        if not vulnerabilities:
            return probe_validated

        # 3. Build prompt
        prompt = self._review_build_prompt(vulnerabilities)

        # 4. Execute review
        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt="You are a skeptical security expert. Reject false positives ruthlessly.",
                model_override=settings.SKEPTICAL_MODEL,
                module_name="DASTySAST_Skeptical",
                max_tokens=2000
            )

            if not response:
                logger.warning(f"[{self.name}] Skeptical review empty - keeping all")
                return probe_validated + vulnerabilities

            # 4. Parse and approve, then add probe-validated
            llm_approved = self._review_parse_approval(response, vulnerabilities)
            return probe_validated + llm_approved

        except Exception as e:
            logger.error(f"[{self.name}] Skeptical review failed: {e}", exc_info=True)
            return probe_validated + vulnerabilities

    def _review_deduplicate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Deduplicate vulnerabilities by type+parameter, keeping highest confidence."""
        deduped = {}
        for v in vulnerabilities:
            key = (v.get('type'), v.get('parameter'))
            existing = deduped.get(key)
            if not existing or v.get('confidence', 0) > existing.get('confidence', 0):
                deduped[key] = v

        result = list(deduped.values())
        logger.info(f"[{self.name}] Deduplicated: {len(result)} unique findings")
        return result

    def _review_build_prompt(self, vulnerabilities: List[Dict]) -> str:
        """Build skeptical review prompt with enriched context."""
        from bugtrace.agents.skills.loader import get_scoring_guide, get_false_positives

        vulns_summary_parts = []
        for i, v in enumerate(vulnerabilities):
            vuln_type = v.get('type', 'Unknown')
            scoring_guide = get_scoring_guide(vuln_type)
            fp_guide = get_false_positives(vuln_type)

            part = f"""{i+1}. {vuln_type} on '{v.get('parameter')}'
   DASTySAST Score: {v.get('confidence_score', 5)}/10 | Votes: {v.get('votes', 1)}/5
   Reasoning: {v.get('reasoning') or 'No reasoning'}

   {scoring_guide[:500] if scoring_guide else ''}
   {fp_guide[:300] if fp_guide else ''}"""
            vulns_summary_parts.append(part)

        vulns_summary = "\n\n".join(vulns_summary_parts)

        return f"""You are a security expert reviewing vulnerability findings.

=== TARGET ===
URL: {self.url}

=== FINDINGS ({len(vulnerabilities)} total) ===
{vulns_summary}

=== YOUR TASK ===
For EACH finding, evaluate and assign a FINAL CONFIDENCE SCORE (0-10).

SCORING GUIDE:
- 0-3: REJECT - No evidence, parameter name only, "EXPECTED: SAFE" present
- 4-5: LOW - Weak indicators, probably false positive
- 6-7: MEDIUM - Some patterns, worth testing by specialist
- 8-9: HIGH - Clear evidence (SQL errors, unescaped reflection)
- 10: CONFIRMED - Obvious vulnerability

RULES:
1. If the "DASTySAST Score" is high AND "Votes" are 4/5 or 5/5, lean towards a higher FINAL SCORE (6+).
2. Parameter NAME alone (webhook, id, xml) is NOT enough for score > 5, UNLESS votes are 5/5.
3. If "EXPECTED: SAFE" is found in reasoning, REJECT immediately (score 0-3).
4. "EXPECTED: VULNERABLE" in context → score 8-10
5. SQL errors visible → score 8+
6. Unescaped HTML reflection → score 7+
7. Adjust DASTySAST score up/down based on your analysis

Return XML:
<reviewed>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <final_score>7</final_score>
    <reasoning>Brief explanation</reasoning>
  </finding>
</reviewed>
"""

    def _review_parse_approval(self, response: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """Parse skeptical review response and approve findings above threshold."""
        parser = XmlParser()
        finding_blocks = parser.extract_list(response, "finding")

        approved = []

        for block in finding_blocks:
            self._process_review_finding(parser, block, vulnerabilities, approved)

        logger.info(f"[{self.name}] Skeptical Review: {len(approved)} passed, {len(vulnerabilities)-len(approved)} rejected")
        return approved

    def _process_review_finding(self, parser: XmlParser, block: str,
                                vulnerabilities: List[Dict], approved: List[Dict]):
        """Process a single review finding."""
        try:
            idx = int(parser.extract_tag(block, "index")) - 1
            vuln_type = parser.extract_tag(block, "type") or "UNKNOWN"
            final_score = int(parser.extract_tag(block, "final_score") or "0")
            reasoning = parser.extract_tag(block, "reasoning") or ""

            if not (0 <= idx < len(vulnerabilities)):
                return

            vuln = vulnerabilities[idx]
            vuln["skeptical_score"] = final_score
            vuln["skeptical_reasoning"] = reasoning

            # Get type-specific threshold
            threshold = settings.get_threshold_for_type(vuln_type)

            if final_score >= threshold:
                logger.info(f"[{self.name}] ✅ APPROVED #{idx+1} {vuln_type} (score: {final_score}/10 >= {threshold}): {reasoning[:60]}")
                approved.append(vuln)
            else:
                logger.info(f"[{self.name}] ❌ REJECTED #{idx+1} {vuln_type} (score: {final_score}/10 < {threshold}): {reasoning[:60]}")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse finding: {e}")

