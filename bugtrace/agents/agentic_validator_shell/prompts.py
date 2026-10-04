"""
AgenticValidator: AI-Powered Vulnerability Validation Agent (v2 - OPTIMIZED)

PERFORMANCE OPTIMIZATIONS (2026-01-21):
1. Parallel validation with configurable concurrency (3x-5x faster)
2. Browser session pooling (reuse instead of launch per validation)
3. Early-exit when CDP confirms (skip expensive vision API)
4. Result caching for similar payloads/URLs (avoid re-validation)
5. Smart fast-path for high-confidence/pre-validated findings
6. Reduced timeouts and eliminated unnecessary sleeps
7. Batch screenshot capture for similar URLs

This validator uses an LLM with vision capabilities to:
1. Navigate to target URLs with payloads
2. Capture screenshots
3. Reason about the visual state to determine if vulnerability is real
4. Adapt testing strategy based on context
"""

from typing import List, Dict, Any, Tuple, Optional, Set
import asyncio
import base64
import json
import hashlib
import time
from pathlib import Path
from loguru import logger
from dataclasses import dataclass, field
from collections import OrderedDict

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager, BrowserManager
from bugtrace.tools.visual.verifier import XSSVerifier, VerificationResult
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus as global_event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.core.validation_metrics import validation_metrics
# Import specialist utilities for full payload loading (v2.1.0+)
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.core.verbose_events import create_emitter
# NOTE: ValidationFeedback imports removed - feedback loop eliminated for simplicity
# AgenticValidator is now a linear CDP specialist (no loopback to specialist agents)


# =============================================================================
# OPTIMIZATION 1: Validation Result Cache (LRU)
# =============================================================================

class ValidatorPromptsMixin:
    def _load_prompts(self) -> Dict[str, str]:
        """Load specialized prompts for different vulnerability types."""
        prompts = {
            "xss": self._get_xss_prompt(),
            "sqli": self._get_sqli_prompt(),
            "csti": self._get_csti_prompt(),
            "general": self._get_general_prompt()
        }

        # Override with custom prompts if provided
        if self.system_prompt:
            self._apply_custom_prompts(prompts)

        return prompts

    def _get_xss_prompt(self) -> str:
        """Get XSS validation prompt template."""
        return """You are a security expert analyzing a screenshot for XSS vulnerability validation.

CONTEXT:
- BugTraceAI security scanner found a potential XSS vulnerability
- We injected a test payload that creates a visual banner or triggers an alert
- Our payloads create text containing: "HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED", or trigger alert dialogs

TASK:
Look at this screenshot and determine if the XSS was successful.

SUCCESS indicators (HIGH CONFIDENCE - mark success=true):
1. ANY text containing "HACKED", "BUGTRACEAI", "BUGTRACE", "PWNED", "XSS" appearing on the page (banner, div, any element)
2. A browser alert/confirm/prompt dialog box (usually a small popup with OK button)
3. Red or colored banner at top/bottom of page with security-related text
4. Text like "FRAGMENT XSS" or "MXSS DETECTED" visible anywhere

MEDIUM CONFIDENCE indicators (mark success=true, confidence=0.7):
1. Unusual HTML elements that look injected (e.g., floating divs, unexpected banners)
2. JavaScript code visible as rendered content (not escaped)
3. Page layout disruption suggesting DOM manipulation

FAILURE indicators (mark success=false):
1. Normal page content with no abnormalities
2. Error message like "Invalid input" or "Not found"
3. The payload is visible as escaped text (e.g., "&lt;script&gt;" shown literally)
4. WAF/security block page ("Request blocked", "Forbidden")

IMPORTANT: If you see ANY text containing "HACKED" or "BUGTRACEAI" or "XSS" that wasn't part of the original page content, this is SUCCESS - our payload executed.

Respond in JSON format:
{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence": "description of what you see that proves/disproves XSS",
    "recommendation": "next steps if any"
}"""

    def _get_sqli_prompt(self) -> str:
        """Get SQL Injection validation prompt template."""
        return """You are a security expert analyzing a screenshot for SQL Injection validation.

CONTEXT:
- A security scanner found a potential SQL Injection vulnerability
- We injected a test payload into the page
- Look for signs of SQL error messages or data exfiltration

SUCCESS indicators:
1. SQL error messages (MySQL, PostgreSQL, MSSQL syntax errors)
2. Database version disclosure
3. Unexpected data being displayed
4. "You have an error in your SQL syntax" message
5. Column/table names visible in error

FAILURE indicators:
1. Normal page with expected content
2. Generic "Invalid input" error (input validation, not SQLi)
3. WAF block page
4. HTTP 500 with no SQL-related info

Respond in JSON format:
{
    "success": true/false,
    "confidence": 0.0-1.0,
    "evidence": "description of what you see",
    "sql_error_type": "MySQL/PostgreSQL/MSSQL/None",
    "recommendation": "next steps"
}"""

    def _get_csti_prompt(self) -> str:
        """Get CSTI/SSTI validation prompt template."""
        return """You are a security expert analyzing a screenshot for Template Injection validation.

CONTEXT:
- We injected a template payload like `{{7*7}}` or `{{111111+111111}}`
- We expect the server or client-side engine (Angular, Vue, Jinja2) to evaluate this math
- Seeing "49" or "222222" is proof of vulnerability

SUCCESS indicators (HIGH CONFIDENCE):
1. The number "49" is visible where the payload was injected (arithmetic evaluation)
2. The number "111111" etc. if other math was used
3. Text like "Config", "Smarty", "class 'os'" if object printing was used
4. "uid=..." or system command output (rare for visual)
5. Angular bindings visible (e.g., `ng-bind` attributes not rendered correctly, or successful interpolation)

FAILURE indicators:
1. The literal text `{{7*7}}` is displayed (means it was reflected but NOT evaluated)
2. Normal page content without numbers
3. "Invalid input" error
4. WAF Block Page

Respond in JSON (same format)."""

    def _get_general_prompt(self) -> str:
        """Get general vulnerability validation prompt template."""
        return """You are a security expert analyzing a screenshot for vulnerability validation.

Examine the screenshot and determine if there are any signs of:
1. Security vulnerability exploitation
2. Error messages revealing sensitive information
3. Unexpected behavior that indicates a vulnerability
4. WAF/security tool blocking

Respond in JSON format:
{
    "anomaly_detected": true/false,
    "confidence": 0.0-1.0,
    "description": "what you observe",
    "security_implications": "potential impact if any"
}"""

    def _apply_custom_prompts(self, prompts: Dict[str, str]):
        """Override default prompts with custom ones from system_prompt."""
        import re
        parts = re.split(r'#+\s+', self.system_prompt)

        for part in parts:
            self._process_prompt_section(part, prompts)

    def _process_prompt_section(self, part: str, prompts: Dict[str, str]):
        """Process a single prompt section and update prompts dict."""
        import re
        part_lower = part.lower()

        # Guard: XSS validation prompt
        if part_lower.startswith("xss validation prompt"):
            prompts["xss"] = re.sub(r'^xss validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return

        # Guard: SQLi validation prompt (was unreachable — sat after the XSS return with no
        # guard of its own, so the SQLi vision prompt was parsed then dropped and SQLi fell
        # back to the generic prompt).
        if part_lower.startswith("sqli validation prompt"):
            prompts["sqli"] = re.sub(r'^sqli validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return

        # Guard: CSTI validation prompt
        if part_lower.startswith("csti/ssti validation prompt"):
            prompts["csti"] = re.sub(r'^csti/ssti validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return

        # Guard: General validation prompt
        if part_lower.startswith("general validation prompt"):
            prompts["general"] = re.sub(r'^general validation prompt\s*', '', part, flags=re.IGNORECASE).strip()
            return
