"""LLM client shell mixin — extracted from llm_client for size policy."""

from __future__ import annotations

import os
import re
import time
import hashlib
import aiohttp
import json
import asyncio
import aiofiles
from typing import Optional, Dict, Any, List
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    LLMError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMParseError,
    LLMServiceUnavailableError,
    NetworkError,
    TimeoutError as BugTraceTimeoutError,
    ConnectionError as BugTraceConnectionError,
    JSONParseError,
    is_transient,
)
from bugtrace.core.llm_shell.types import (
    LLMHealthState,
    CB_FAILURE_THRESHOLD,
    CB_COOLDOWN_SECONDS,
    CB_DEGRADED_DELAY,
    CB_SUCCESS_THRESHOLD,
    LLM_TOTAL_TIMEOUT,
    LLM_CONNECT_TIMEOUT,
    ModelMetrics,
    TokenUsageTracker,
    VULNERABILITY_SCHEMA,
    _ProviderRateLimiter,
    _parse_rpm,
    sanitize_text,
)

logger = get_logger("core.llm_client")


class LLMMiscMixin:
    async def update_balance(self):
        """Polls OpenRouter for current credit balance. Skipped for non-OpenRouter providers."""
        if self.provider_id != "openrouter" or not self.api_key:
            return

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with orchestrator.session(DestinationType.LLM) as session:
                async with session.get("https://openrouter.ai/api/v1/auth/key", headers=headers, timeout=5) as resp:
                    await self._process_balance_response(resp)
        except Exception as e:
            logger.debug(f"Failed to update balance telemetry: {e}")
            dashboard.log(f"Balance Check Error: {e}", "ERROR")

    async def _process_balance_response(self, resp: aiohttp.ClientResponse):
        """Process balance API response."""
        if resp.status != 200:
            dashboard.log(f"Failed to check balance: Status {resp.status}", "ERROR")
            return

        data = await resp.json()
        key_data = data.get('data', {})
        usage = key_data.get('usage', 0)
        limit = key_data.get('limit', 0)

        self._update_dashboard_credits(limit, usage)

    def _update_dashboard_credits(self, limit: Optional[float], usage: float):
        """Update dashboard with credit balance."""
        if limit is not None:
            balance = float(limit - usage)
            dashboard.credits = balance
            dashboard.log(f"OpenRouter Balance Checked: ${balance:.4f}", "SUCCESS")
        else:
            dashboard.credits = 999.0  # Visual indicator for unlimited
            dashboard.log("OpenRouter Balance: Unlimited", "SUCCESS")

    async def detect_waf(self, response_text: str, response_headers: str) -> Optional[str]:
        """
        Specialized method for WAF detection using the requested WAF detection models.
        """
        prompt = f"""
        Analyze the following HTTP response for signs of a WAF (Web Application Firewall).
        Identify the WAF type if possible (e.g., Cloudflare, Akamai, ModSecurity).
        
        Response Headers:
        {response_headers}
        
        Response Body Snippet:
        {response_text[:1000]}
        
        Output only the name of the WAF or 'NONE' if no WAF is detected.
        """
        
        waf_models = [m.strip() for m in settings.WAF_DETECTION_MODELS.split(",")]
        
        for model in waf_models:
            res = await self.generate(prompt, module_name="WAF-Detection", model_override=model)
            if res and "NONE" not in res.upper():
                return res.strip()
        
        return "NONE"

    async def _audit_log(self, module: str, model: str, prompt: str, response: str):
        """Saves LLM transactions using XML-like format with Base64 for payload integrity.

        TASK-128: Sanitizes prompts and responses to remove sensitive data.
        
        Format (v3.1):
        <LLM_CALL>
          <TIMESTAMP>...</TIMESTAMP>
          <MODULE>...</MODULE>
          <MODEL>...</MODEL>
          <PROMPT_B64>base64_encoded</PROMPT_B64>
          <RESPONSE_B64>base64_encoded</RESPONSE_B64>
        </LLM_CALL>
        """
        import base64
        
        try:
            log_dir = settings.LOG_DIR
            log_dir.mkdir(parents=True, exist_ok=True)
            audit_file = log_dir / "llm_audit.log"
            
            # Sanitize and then Base64 encode to preserve any special chars
            sanitized_prompt = sanitize_text(prompt)
            sanitized_response = sanitize_text(response)
            
            prompt_b64 = base64.b64encode(sanitized_prompt.encode('utf-8')).decode('ascii')
            response_b64 = base64.b64encode(sanitized_response.encode('utf-8')).decode('ascii')
            
            entry = (
                f"<LLM_CALL>\n"
                f"  <TIMESTAMP>{datetime.now().isoformat()}</TIMESTAMP>\n"
                f"  <MODULE>{module}</MODULE>\n"
                f"  <MODEL>{model}</MODEL>\n"
                f"  <PROMPT_B64>{prompt_b64}</PROMPT_B64>\n"
                f"  <RESPONSE_B64>{response_b64}</RESPONSE_B64>\n"
                f"</LLM_CALL>\n"
            )
            
            async with aiofiles.open(audit_file, "a", encoding="utf-8") as f:
                await f.write(entry)
        except Exception as e:
            # Fallback to printing if logging fails
            print(f"FAILED TO AUDIT: {e}")

    def validate_json_response(self, response: str, schema: Optional[Dict] = None) -> Optional[Dict]:
        """Validate and parse JSON response from LLM.

        Args:
            response: Raw LLM response string
            schema: Optional JSON schema to validate against

        Returns:
            Parsed JSON dict, or None if invalid
        """
        try:
            # Try to extract JSON from response (may be wrapped in markdown)
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = response.strip()

            data = json.loads(json_str)

            # Schema validation if provided
            if schema:
                try:
                    from jsonschema import validate, ValidationError
                    validate(instance=data, schema=schema)
                except ImportError:
                    logger.debug("jsonschema not installed, skipping schema validation")
                except ValidationError as e:
                    logger.warning(f"Response schema validation failed: {e.message}")
                    return None

            return data

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in LLM response: {e}")
            # Don't raise - return None for graceful degradation
            return None

    def _record_model_call(self, model: str, success: bool, latency_ms: float):
        """Record metrics for a model call."""
        if model not in self.model_metrics:
            self.model_metrics[model] = ModelMetrics()

        metrics = self.model_metrics[model]
        metrics.calls += 1
        if success:
            metrics.successes += 1
            metrics.total_latency_ms += latency_ms
        else:
            metrics.failures += 1

    def get_model_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get performance metrics for all models."""
        return {
            model: {
                "calls": m.calls,
                "successes": m.successes,
                "failures": m.failures,
                "success_rate": f"{m.success_rate:.1%}",
                "avg_latency_ms": f"{m.avg_latency_ms:.0f}"
            }
            for model, m in self.model_metrics.items()
        }

    def get_token_summary(self) -> Dict[str, Any]:
        """Get token usage summary."""
        return self.token_tracker.get_summary()
