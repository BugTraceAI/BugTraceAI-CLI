"""Remaining analysis helpers.

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

# Shared with analysis/agent.py — contexts that mean "no reflection evidence"
_NO_REFLECTION_CONTEXTS = frozenset({"none", "unknown", "no_reflection", "n/a"})

class AnalysisMiscMixin:
    def _normalize_vulnerability_name(self, v_name: str, v_desc: str, v: Dict) -> str:
        """Normalize vulnerability name to be more descriptive."""
        if v_name.lower() not in ["vulnerability", "security issue", "finding"]:
            return v_name

        desc_lower = str(v_desc).lower()
        if "xss" in desc_lower or "script" in desc_lower:
            return "Potential XSS Issue"
        if "sql" in desc_lower:
            return "Potential SQL Injection Issue"
        return f"Potential {v.get('type', 'Security')} Issue"

    def _get_safe_name(self) -> str:
        """Generate safe filename from URL."""
        return self.url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:50]

    def _get_severity_for_type(self, vuln_type: str, llm_severity: Optional[str] = None) -> str:
        """
        Maps vulnerability type to appropriate severity.
        SQLi, RCE, XXE = CRITICAL
        XSS, Header Injection = HIGH  
        IDOR, SSRF, CSRF = MEDIUM
        Info Disclosure = LOW
        """
        vuln_type_upper = vuln_type.upper()
        
        # CRITICAL: Direct database/system compromise
        critical_patterns = ["SQL", "SQLI", "RCE", "REMOTE CODE", "COMMAND INJECTION", 
                           "XXE", "XML EXTERNAL", "DESERIALIZATION", "NOSQL", "SSTI"]
        for pattern in critical_patterns:
            if pattern in vuln_type_upper:
                return "Critical"
        
        # HIGH: Client-side execution or significant impact
        high_patterns = ["XSS", "CROSS-SITE SCRIPTING", "HEADER INJECTION", "CRLF", 
                        "RESPONSE SPLITTING", "LFI", "LOCAL FILE", "PATH TRAVERSAL",
                        "AUTHENTICATION BYPASS", "SESSION", "CSTI"]
        for pattern in high_patterns:
            if pattern in vuln_type_upper:
                return "High"
        
        # MEDIUM: Authorization/logic flaws
        medium_patterns = ["IDOR", "INSECURE DIRECT", "OBJECT REFERENCE", "BROKEN ACCESS",
                          "SSRF", "SERVER-SIDE REQUEST", "CSRF", "CROSS-SITE REQUEST",
                          "PROTOTYPE POLLUTION", "BUSINESS LOGIC", "OPEN REDIRECT"]
        for pattern in medium_patterns:
            if pattern in vuln_type_upper:
                return "Medium"
        
        # LOW: Information disclosure
        low_patterns = ["INFORMATION", "DISCLOSURE", "VERBOSE", "DEBUG", "STACK TRACE"]
        for pattern in low_patterns:
            if pattern in vuln_type_upper:
                return "Low"
        
        # Fallback to LLM's suggestion or default to High
        if llm_severity and llm_severity.capitalize() in ["Critical", "High", "Medium", "Low", "Information"]:
            return llm_severity.capitalize()
        return "High"

    def _parse_single_vulnerability(self, parser: XmlParser, vc: str) -> Optional[Dict]:
        """Parse a single vulnerability entry."""
        try:
            conf = self._parse_confidence_score(parser, vc)

            # Extract payload/exploitation_strategy with HTML unescaping to preserve special chars
            # (e.g., convert &lt;?xml to <?xml)
            payload = (
                parser.extract_tag(vc, "payload", unescape_html=True) or
                parser.extract_tag(vc, "exploitation_strategy", unescape_html=True) or
                ""
            )

            # Evidence fields the prompt marks as REQUIRED. They were never read, so every
            # finding reached _consolidate() with an identical (zero) evidence score and
            # every XSS candidate reached the specialist labelled with the default "html"
            # — discarding the one context signal the analysis stage actually produces.
            xss_context = (parser.extract_tag(vc, "xss_context") or "").strip().lower()
            raw_type = parser.extract_tag(vc, "type") or "Unknown"
            parameter = parser.extract_tag(vc, "parameter") or "unknown"
            reasoning = parser.extract_tag(vc, "reasoning") or ""
            # Pure type inference when LLM omits <type> (A/B: Unknown → lost RCE/SQLi route)
            from bugtrace.core.finding_type_policy import infer_finding_type

            resolved_type = infer_finding_type(
                raw_type,
                parameter=parameter,
                reasoning=reasoning,
                payload=payload,
            )
            vuln = {
                "type": resolved_type,
                "parameter": parameter,
                "confidence_score": conf,
                "reasoning": reasoning,
                "severity": parser.extract_tag(vc, "severity") or "Medium",
                "exploitation_strategy": payload,
                "xss_context": xss_context,
                "html_evidence": parser.extract_tag(vc, "html_evidence", unescape_html=True) or "",
                "chars_survive": parser.extract_tag(vc, "chars_survive", unescape_html=True) or "",
            }
            # Promote to the finding-wide "context" key, which is what the specialist queue
            # reads (finding.get("context", "html")). Only a real label: _NO_REFLECTION_CONTEXTS
            # carry no positional information, so they must leave the default in place.
            if xss_context and xss_context not in _NO_REFLECTION_CONTEXTS:
                vuln["context"] = xss_context
            return vuln
        except Exception as ex:
            logger.warning(f"Failed to parse vulnerability entry: {ex}")
            return None

    def _parse_confidence_score(self, parser: XmlParser, vc: str) -> int:
        """Parse and validate confidence score."""
        conf_str = parser.extract_tag(vc, "confidence_score") or parser.extract_tag(vc, "confidence") or "5"
        try:
            conf = int(float(conf_str))
            return max(0, min(10, conf))  # Clamp to 0-10
        except (ValueError, TypeError):
            return 5

    def _calculate_fp_confidence(self, finding: Dict) -> float:
        """
        Calculate false positive confidence score for a finding.

        FP Confidence Scale (0.0-1.0):
        - 0.0: Almost certainly a FALSE POSITIVE
        - 0.5: Uncertain - needs specialist investigation
        - 1.0: Almost certainly a TRUE POSITIVE

        Formula:
        fp_confidence = (skeptical_component + votes_component + evidence_component)

        Where:
        - skeptical_component = (skeptical_score / 10) * FP_SKEPTICAL_WEIGHT
        - votes_component = (votes / max_votes) * FP_VOTES_WEIGHT
        - evidence_component = evidence_quality * FP_EVIDENCE_WEIGHT

        Args:
            finding: Vulnerability finding dict

        Returns:
            float: FP confidence score between 0.0 and 1.0
        """
        # Get weights from config
        skeptical_weight = getattr(settings, 'FP_SKEPTICAL_WEIGHT', 0.4)
        votes_weight = getattr(settings, 'FP_VOTES_WEIGHT', 0.3)
        evidence_weight = getattr(settings, 'FP_EVIDENCE_WEIGHT', 0.3)

        # 1. Skeptical component (0.0 - 0.4)
        skeptical_score = finding.get('skeptical_score', 5)
        skeptical_component = (skeptical_score / 10.0) * skeptical_weight

        # 2. Votes component (0.0 - 0.3)
        votes = finding.get('votes', 1)
        max_votes = len([a for a in self.approaches if a != 'skeptical_agent'])  # 5 core approaches
        votes_component = min(votes / max_votes, 1.0) * votes_weight

        # 3. Evidence component (0.0 - 0.3)
        evidence_quality = self._assess_evidence_quality(finding)
        evidence_component = evidence_quality * evidence_weight

        # Sum components (max = 1.0)
        fp_confidence = skeptical_component + votes_component + evidence_component

        # Clamp to 0.0-1.0
        return max(0.0, min(1.0, fp_confidence))

    def _count_by_type(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        counts = {}
        for f in findings:
            v_type = f.get("type", "Unknown")
            counts[v_type] = counts.get(v_type, 0) + 1
        return counts

