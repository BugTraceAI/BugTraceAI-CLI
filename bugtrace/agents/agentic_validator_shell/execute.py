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
from bugtrace.agents.agentic_validator_shell.types import _verifier_pool
# NOTE: ValidationFeedback imports removed - feedback loop eliminated for simplicity
# AgenticValidator is now a linear CDP specialist (no loopback to specialist agents)


# =============================================================================
# OPTIMIZATION 1: Validation Result Cache (LRU)
# =============================================================================

class ValidatorExecuteMixin:
    def _check_logs_for_execution(self, logs: List[str], vuln_type: str) -> bool:
        """Check browser logs for successful exploitation indicators."""
        if not logs:
            return False
            
        success_markers = {
            "xss": ["alert", "prompt", "confirm", "XSS", "HACKED", "fetch"],
            "sqli": ["SQL syntax", "mysql_", "ORA-"],
            "lfi": ["root:x:0:0", "daemon:x:1:1"], 
            "csti": ["1000006000009", "7777777"]  # arithmetic-eval results (1000003*1000003, '7'*7) — NOT bare "49", which collides with prices/IDs/timestamps in console logs and never matched the current probe
        }
        
        markers = success_markers.get(vuln_type.lower(), [])
        
        for log in logs:
            if any(marker in str(log) for marker in markers):
                return True
                
        return False

    async def _execute_payload_optimized(
        self,
        url: str,
        payload: Optional[str],
        vuln_type: str,
        param: Optional[str] = None
    ) -> Tuple[str, List[str], bool]:
        """
        OPTIMIZED payload execution using pooled verifiers.
        """
        if vuln_type in ["xss", "csti"]:
            # Use pooled verifier instead of creating new one each time
            verifier = await _verifier_pool.get_verifier()
            try:
                target_url = self._construct_payload_url(url, payload, param)
                if self._v:
                    self._v.emit("validation.browser.navigating", {
                        "vuln_type": vuln_type, "url": target_url[:100],
                    })
                result = await verifier.verify_xss(
                    target_url,
                    screenshot_dir=str(settings.LOG_DIR),
                    timeout=self.FAST_VALIDATION_TIMEOUT - 5,  # Leave margin
                    max_level=4  # Explicitly allow L4 CDP
                )
                if self._v:
                    self._v.emit("validation.browser.loaded", {
                        "success": result.success,
                        "has_screenshot": bool(result.screenshot_path),
                        "console_events": len(result.console_logs or []),
                        "alert": result.alert_message[:50] if result.alert_message else None,
                    })
                return result.screenshot_path, result.console_logs or [], result.success, result.alert_message
            finally:
                _verifier_pool.release()
        else:
            path, logs, triggered = await self._generic_capture(url, payload, param)
            return path, logs, triggered, None

    def _generate_manual_review_brief(self, finding: Dict, vision_result: Dict, browser_logs: List) -> str:
        """Constructs a detailed explanation for manual triagers."""
        url = finding.get("url", "N/A")
        param = finding.get("parameter", "N/A")
        payload = finding.get("payload", "N/A")
        vision_evidence = vision_result.get("evidence", "No evidence provided by vision model.")
        confidence = vision_result.get("confidence", 0.0)
        
        brief = [
            "### 🔎 DETAILED MANUAL REVIEW BRIEF",
            f"**Target:** {url}",
            f"**Parameter:** `{param}`",
            f"**Payload:** `{payload}`",
            "",
            "#### 🕵️ HUNTER OBSERVATIONS",
            "- Reflection detected in raw HTML (possible decoded or mutated form).",
            "- WAF presence suspected or bypass attempts initiated.",
            "",
            "#### 🤖 AUDITOR (AGENTIC) AUDIT",
            f"- **Vision Confidence:** {confidence:.0%}",
            f"- **Execution Events (CDP):** {'None' if not browser_logs else f'Detected {len(browser_logs)} events'}",
            f"- **Vision Analysis:** {vision_evidence}",
            "",
            "#### 🛠️ WHAT TO LOOK FOR (MANUAL CHECK)",
            "1. Open the target URL with the payload.",
            "2. Check if a **RED BANNER** with text **'HACKED BY BUGTRACEAI'** appears at the top.",
            "3. Check the Browser Console for successful `fetch` requests or execution logs.",
            "",
            "#### ❓ WHY MANUAL REVIEW?",
            "Automatic validation is inconclusive because " + 
            ("the Vision AI detected a potential anomaly but no low-level protocol event (like an alert) was captured." if confidence >= 0.7 
             else "there is a strong indicator of vulnerability (reflection) but visual proof is obscured or non-standard.")
        ]
        return "\n".join(brief)

    async def _execute_payload(
        self, 
        url: str, 
        payload: Optional[str],
        vuln_type: str,
        param: Optional[str] = None
    ) -> Tuple[str, List[str], bool]:
        """
        Execute the payload in browser and capture result.
        Returns (screenshot_path, logs, basic_triggered)
        """
        if vuln_type in ["xss", "csti"]:
            # Use Playwright for current environment stability
            verifier = XSSVerifier(headless=settings.HEADLESS_BROWSER, prefer_cdp=True)
            target_url = self._construct_payload_url(url, payload, param)
            
            result = await verifier.verify_xss(target_url, screenshot_dir=str(settings.LOG_DIR))
            return result.screenshot_path, result.console_logs, result.success
        else:
            # Generic page capture for other types
            return await self._generic_capture(url, payload, param)

    def _check_sql_errors(self, content: str) -> Optional[str]:
        """Check page content for SQL error indicators. Returns error name if found."""
        sql_errors = [
            "SQL syntax",
            "mysql_",
            "ORA-",
            "PostgreSQL",
            "SQLITE_ERROR",
            "Microsoft SQL Server"
        ]

        content_lower = content.lower()
        for error in sql_errors:
            if error.lower() in content_lower:
                return error
        return None

    async def _generic_capture(
        self,
        url: str,
        payload: Optional[str],
        param: Optional[str] = None
    ) -> Tuple[str, List[str], bool]:
        """
        Generic page capture for non-XSS validations.
        """
        logs = []
        screenshot_path = ""

        target_url = self._construct_payload_url(url, payload, param) if payload else url

        async with browser_manager.get_page() as page:
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(2000)

                import uuid
                screenshot_path = str(settings.LOG_DIR / f"validate_{uuid.uuid4().hex[:8]}.png")
                await page.screenshot(path=screenshot_path)

                content = await page.content()
                sql_error = self._check_sql_errors(content)
                if sql_error:
                    logs.append(f"SQL Error detected: {sql_error}")
                    return screenshot_path, logs, True

            except Exception as e:
                logs.append(f"Capture error: {e}")
                logger.error(f"Generic capture failed: {e}", exc_info=True)

        return screenshot_path, logs, False

    def _construct_payload_url(self, url: str, payload: Optional[str], param: Optional[str] = None) -> str:
        """Construct URL with payload injected."""
        if not payload or payload in url:
            return url
            
        import urllib.parse as urlparse
        from urllib.parse import urlencode, parse_qs
        
        parsed = urlparse.urlparse(url)
        qs = parse_qs(parsed.query)

        if param:
            # 1. Targeted Injection: Inject ONLY into the specific parameter
            # Logic: If param exists, replace it. If not, APPEND it.
            qs[param] = [payload]
        elif parsed.query:
            # 2. Spray Mode (Legacy): Inject into ALL parameters (Blind)
            for k in qs:
                qs[k] = payload
        else:
            # 3. No targets available? Return original URL to avoid errors
            # (Though technically we could append ?payload=...)
            return url
            
        new_query = urlencode(qs, doseq=True)
        return urlparse.urlunparse(parsed._replace(query=new_query))

    def _detect_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Detect vulnerability type from finding data."""
        title = finding.get("title", "").upper()
        vuln_type = finding.get("type", "").upper()
        
        if "XSS" in title or "XSS" in vuln_type or "CROSS-SITE" in title:
            return "xss"
        elif "SQL" in title or "SQLI" in vuln_type:
            return "sqli"
        elif "CSTI" in title or "CSTI" in vuln_type or "TEMPLATE" in title or "SSTI" in vuln_type:
            return "csti"
        else:
            return "general"

    async def _call_vision_model(self, prompt: str, screenshot_path: str) -> str:
        """
        Call a vision-capable LLM to analyze the screenshot.
        Uses OpenRouter with a vision model.
        """
        from bugtrace.core.llm_client import LLMClient
        
        llm = LLMClient()
        
        # Use a vision-capable model from settings
        response = await llm.generate_with_image(
            prompt=prompt,
            image_path=screenshot_path,
            model_override=settings.VISION_MODEL,
            temperature=0.1
        )
        
        return response

    def _parse_vision_response(self, response: str) -> Dict[str, Any]:
        """Parse the JSON response from vision model."""
        import json
        import re
        
        try:
            # 1. Direct JSON extraction (more robust than the previous regex)
            # Find the first { and last }
            start = response.find('{')
            end = response.rfind('}')
            if start != -1 and end != -1:
                json_str = response[start:end+1]
                # Clean potential markdown ticks
                json_str = json_str.strip('`').strip()
                data = json.loads(json_str)
                # Normalize keys
                if 'success' not in data and 'validated' in data:
                    data['success'] = data['validated']
                if 'evidence' not in data and 'description' in data:
                    data['evidence'] = data['description']
                return data
        except Exception as e:
            logger.debug(f"JSON parsing failed: {e}")
            
        # 2. Fallback: Parse as text (More conservative)
        # Search for confirmation keywords but ensure they aren't negated
        positive = ["confirmed", "validated", "execution detected", "payload successful"]
        response_lower = response.lower()
        
        # If we see "success": false or "validated": false, it's a clear NO
        if '"success": false' in response_lower or '"validated": false' in response_lower:
            return {"success": False, "confidence": 1.0, "evidence": response[:500]}
            
        is_success = any(p in response_lower for p in positive)
        # Handle "success": true
        if '"success": true' in response_lower or '"validated": true' in response_lower:
            is_success = True
            
        return {
            "success": is_success,
            "confidence": 0.5 if is_success else 0.0,
            "evidence": response[:500]
        }
