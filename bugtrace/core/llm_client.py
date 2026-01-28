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
from dataclasses import dataclass, field
from tenacity import retry, stop_after_attempt, wait_exponential
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("core.llm_client")


def sanitize_text(text: str) -> str:
    """Remove sensitive data from text before logging."""
    if not text:
        return text

    # Remove API keys and tokens
    text = re.sub(
        r'(api[_-]?key|token|secret|password|bearer|authorization)["\s:=]+([a-zA-Z0-9\-_]{20,})',
        r'\1: [REDACTED]',
        text,
        flags=re.IGNORECASE
    )

    # Remove URLs with embedded credentials
    text = re.sub(
        r'https?://[^:]+:[^@]+@',
        'https://[REDACTED]@',
        text
    )

    # Remove potential email addresses
    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        '[EMAIL]',
        text
    )

    # Remove AWS-style keys
    text = re.sub(
        r'AKIA[0-9A-Z]{16}',
        '[AWS_KEY]',
        text
    )

    return text


@dataclass
class ModelMetrics:
    """Tracks performance metrics for a single model."""
    calls: int = 0
    successes: int = 0
    failures: int = 0
    total_latency_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / self.calls if self.calls > 0 else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.successes if self.successes > 0 else 0.0


class TokenUsageTracker:
    """Tracks token usage across models and agents with cost estimation."""

    # OpenRouter pricing per 1M tokens (approximate, update as needed)
    PRICING = {
        "google/gemini-2.5-flash-preview": {"input": 0.05, "output": 0.15},
        "google/gemini-3-flash-preview": {"input": 0.05, "output": 0.15},
        "qwen/qwen-2.5-coder-32b-instruct": {"input": 0.20, "output": 0.60},
        "anthropic/claude-3-haiku": {"input": 0.25, "output": 1.25},
        "default": {"input": 0.50, "output": 1.50}
    }

    def __init__(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.by_model: Dict[str, Dict[str, int]] = {}
        self.by_agent: Dict[str, Dict[str, int]] = {}

    def record_usage(self, model: str, agent: str, input_tokens: int, output_tokens: int):
        """Record token usage for a single LLM call."""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

        # Track by model
        if model not in self.by_model:
            self.by_model[model] = {"input": 0, "output": 0}
        self.by_model[model]["input"] += input_tokens
        self.by_model[model]["output"] += output_tokens

        # Track by agent
        if agent not in self.by_agent:
            self.by_agent[agent] = {"input": 0, "output": 0}
        self.by_agent[agent]["input"] += input_tokens
        self.by_agent[agent]["output"] += output_tokens

    def estimate_cost(self) -> float:
        """Estimate total cost based on OpenRouter pricing."""
        total_cost = 0.0
        for model, usage in self.by_model.items():
            pricing = self.PRICING.get(model, self.PRICING["default"])
            input_cost = (usage["input"] / 1_000_000) * pricing["input"]
            output_cost = (usage["output"] / 1_000_000) * pricing["output"]
            total_cost += input_cost + output_cost
        return total_cost

    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive usage summary."""
        return {
            "total_input": self.total_input_tokens,
            "total_output": self.total_output_tokens,
            "total": self.total_input_tokens + self.total_output_tokens,
            "by_model": self.by_model,
            "by_agent": self.by_agent,
            "estimated_cost": self.estimate_cost()
        }


# Response validation schemas
VULNERABILITY_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerable": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "vuln_type": {"type": "string"},
        "payload": {"type": "string"}
    },
    "required": ["vulnerable", "confidence"]
}


class LLMClient:
    """
    Centralized client for LLM interactions via OpenRouter.
    Implements 'Model Shifting' & 'Hybrid Resilience':
    1. Shifts to alternative models if primary fails (API errors).
    2. Shifts to Uncensored/Permissive models if Refusal/Censorship is detected.
    """
    
    REFUSAL_PHRASES = [
        "I cannot assist",
        "I cannot help",
        "illegal",
        "ethical guidelines",
        "harmful activity",
        "against my policy",
        "I cannot generate",
        "I can't provide",
        "security testing only",
    ]
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.OPENROUTER_API_KEY
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.req_count = 0
        
        # Priority list for Model Shifting (Tiered by performance/intelligence)
        # Using the specific high-performance models requested by the user
        self.models = [m.strip() for m in settings.PRIMARY_MODELS.split(",")]
        
        # Fallback to defaults if list is empty
        # Fallback to defaults if list is empty
        if not self.models:
            logger.critical("No PRIMARY_MODELS found in configuration. Please check bugtraceaicli.conf.")
            self.models = []
        
        if not self.api_key:
            logger.warning("OPENROUTER_API_KEY is not set. LLM features will be disabled.")

        # Concurrency Control (Sequential vs Parallel)
        self.semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)

        # TASK-130: Token usage tracking
        self.token_tracker = TokenUsageTracker()

        # TASK-131: Response cache {hash: (response, timestamp)}
        self.cache: Dict[str, tuple] = {}
        self.cache_ttl = 3600  # 1 hour default

        # TASK-133: Model performance metrics
        self.model_metrics: Dict[str, ModelMetrics] = {}

    async def verify_connectivity(self) -> bool:
        """
        Conducts a 'Startup Health Check' on configured models.
        Returns True if at least one model is responsive.
        Removes unresponsive models from self.models.
        """
        if not self.api_key:
            return False

        dashboard.log("Verifying AI Model Connectivity...", "INFO")

        # We'll test up to 3 models to avoid long startup times
        test_pool = self.models[:3]
        valid_models = []

        for model in test_pool:
            if await self._ping_model(model):
                valid_models.append(model)

        return self._report_connectivity_status(valid_models)

    async def _ping_model(self, model: str) -> bool:
        """Ping a single model to check connectivity."""
        dashboard.log(f"Pinging model: {model}...", "INFO")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://bugtraceai.com",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Ping"}],
            "max_tokens": 5
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, headers=headers, json=payload, timeout=5) as resp:
                    return self._log_ping_result(model, resp.status)
        except Exception as e:
            dashboard.log(f"Model {model} unreachable: {e}", "WARN")
            return False

    def _log_ping_result(self, model: str, status: int) -> bool:
        """Log ping result and return success status."""
        if status == 200:
            dashboard.log(f"Model {model} is ONLINE.", "SUCCESS")
            return True

        dashboard.log(f"Model {model} failed health check ({status}).", "WARN")
        return False

    def _report_connectivity_status(self, valid_models: list) -> bool:
        """Report overall connectivity status."""
        if valid_models:
            return True

        dashboard.log("CRITICAL: No AI models are responding.", "ERROR")
        return False

    def _build_request_payload(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int
    ) -> Dict[str, Any]:
        """Build API request payload with common parameters."""
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        if settings.OPENROUTER_ONLINE:
            payload["online"] = True
        return payload

    def _build_headers(self, module_name: str) -> Dict[str, str]:
        """Build API request headers."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://bugtraceai.com",
            "X-Title": f"Bugtrace-{module_name}",
        }

    def _build_messages(self, prompt: str, system_prompt: Optional[str] = None) -> List[Dict[str, str]]:
        """Build message array for API request."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages

    async def _handle_refusal(
        self,
        text: str,
        current_model: str,
        model_override: Optional[str],
        prompt: str,
        module_name: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> Optional[str]:
        """Handle LLM refusal and attempt fallback to uncensored model."""
        if not (any(phrase.lower() in text.lower() for phrase in self.REFUSAL_PHRASES) and len(text) < 300):
            return text

        logger.warning(f"LLM Refusal Detected from {current_model}: '...{text[:50]}...'")

        fallback_model = settings.MUTATION_MODEL
        if model_override != fallback_model:
            logger.info(f"Triggering Hybrid Resilience: Switching to Uncensored Model ({fallback_model})")
            return await self.generate(
                prompt, module_name,
                model_override=fallback_model,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens
            )
        else:
            logger.error("Fallback Model also refused. Returning None to prevent crash.")
            return None

    async def _update_telemetry(self, data: Dict[str, Any], current_model: str, module_name: str):
        """Update dashboard telemetry and token tracking."""
        self.req_count += 1
        dashboard.total_requests += 1

        if 'usage' not in data:
            return

        input_tokens = data['usage'].get('prompt_tokens', 0)
        output_tokens = data['usage'].get('completion_tokens', 0)
        tokens = data['usage'].get('total_tokens', 0)

        self.token_tracker.record_usage(
            model=current_model,
            agent=module_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens
        )

        cost = (tokens / 1_000_000) * 0.20
        dashboard.session_cost += cost

        if self.req_count % 10 == 0:
            asyncio.create_task(self.update_balance())

    async def _handle_api_response(
        self,
        resp: aiohttp.ClientResponse,
        current_model: str,
        module_name: str,
        prompt: str,
        latency_ms: float,
        model_override: Optional[str],
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> Optional[str]:
        """Process API response and handle errors/refusals."""
        if resp.status == 200:
            data = await resp.json()
            if 'choices' not in data or len(data['choices']) == 0:
                self._record_model_call(current_model, success=False, latency_ms=latency_ms)
                logger.warning(f"LLM Shift: Model {current_model} returned empty response.")
                return None

            text = data['choices'][0]['message']['content']

            # Check for refusal
            result = await self._handle_refusal(
                text, current_model, model_override,
                prompt, module_name, system_prompt,
                temperature, max_tokens
            )
            if result != text:
                return result

            # Success path
            self._record_model_call(current_model, success=True, latency_ms=latency_ms)
            await self._update_telemetry(data, current_model, module_name)
            await self._audit_log(module_name, current_model, prompt, text)
            logger.info(f"LLM Shift Success: Using {current_model} for {module_name}")
            return text

        elif resp.status == 429:
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            logger.warning(f"LLM Shift: Model {current_model} rate limited (429). Shifting...")
        else:
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            error_text = await resp.text()
            await self._audit_log(module_name, current_model, prompt, f"ERROR: {resp.status} - {error_text}")
            logger.error(f"LLM Shift: Model {current_model} failed ({resp.status}). Reason: {error_text}. Shifting...")

        return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def generate(
        self,
        prompt: str,
        module_name: str,
        model_override: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1500
    ) -> Optional[str]:
        """
        Generates text using Model Shifting.
        If a model fails or is filtered, it 'shifts' to the next one in the list.
        """
        async with self.semaphore:
            if not self.api_key:
                logger.warning(f"LLM Client: No API Key found for {module_name}. Skipping generation.")
                await self._audit_log(module_name, "NONE", prompt, "SKIPPED: Missing API Key")
                return None

            models_to_try = [model_override] if model_override else self.models
            headers = self._build_headers(module_name)
            messages = self._build_messages(prompt, system_prompt)

            result = await self._try_generate_with_models(
                models_to_try, headers, messages, module_name, prompt,
                temperature, max_tokens, model_override, system_prompt
            )

            if not result:
                logger.critical(f"LLM Client: All models exhausted for module {module_name}. Check connectivity or API Key.")

            return result

    async def _try_generate_with_models(
        self,
        models_to_try: List[str],
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        module_name: str,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model_override: Optional[str],
        system_prompt: Optional[str]
    ) -> Optional[str]:
        """Try generation with each model in the list."""
        for current_model in models_to_try:
            result = await self._attempt_model_generation(
                current_model, headers, messages, module_name, prompt,
                temperature, max_tokens, model_override, system_prompt
            )
            if result:
                return result

            await asyncio.sleep(0.5)

        return None

    async def _attempt_model_generation(
        self,
        current_model: str,
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        module_name: str,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model_override: Optional[str],
        system_prompt: Optional[str]
    ) -> Optional[str]:
        """Attempt generation with a single model."""
        payload = self._build_request_payload(current_model, messages, temperature, max_tokens)
        start_time = time.time()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, headers=headers, json=payload) as resp:
                    latency_ms = (time.time() - start_time) * 1000
                    return await self._handle_api_response(
                        resp, current_model, module_name, prompt,
                        latency_ms, model_override, system_prompt,
                        temperature, max_tokens
                    )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            self._record_model_call(current_model, success=False, latency_ms=latency_ms)
            await self._audit_log(module_name, current_model, prompt, f"EXCEPTION: {str(e)}")
            logger.error(f"LLM Shift Exception with {current_model}: {str(e)}", exc_info=True)
            return None

    async def _handle_thread_response(
        self,
        resp: aiohttp.ClientResponse,
        current_model: str,
        module_name: str,
        thread: "ConversationThread",
        prompt: str
    ) -> Optional[str]:
        """Process API response for threaded generation."""
        if resp.status == 200:
            data = await resp.json()
            if 'choices' not in data or len(data['choices']) == 0:
                logger.warning(f"LLM Thread: Model {current_model} returned empty response.")
                return None

            response_text = data['choices'][0]['message']['content']
            thread.add_message("assistant", response_text)

            # Update telemetry
            self.req_count += 1
            dashboard.total_requests += 1
            if 'usage' in data:
                tokens = data['usage'].get('total_tokens', 0)
                cost = (tokens / 1_000_000) * 0.20
                dashboard.session_cost += cost

            if self.req_count % 10 == 0:
                asyncio.create_task(self.update_balance())

            await self._audit_log(module_name, current_model, f"[Thread: {thread.thread_id}] {prompt}", response_text)
            logger.info(f"LLM Thread Success: {current_model} for {module_name} (thread: {thread.thread_id})")
            return response_text

        elif resp.status == 429:
            logger.warning(f"LLM Thread: Model {current_model} rate limited (429). Shifting...")
        else:
            error_text = await resp.text()
            logger.error(f"LLM Thread: Model {current_model} failed ({resp.status}). Shifting...")

        return None

    async def _try_thread_models(
        self,
        models_to_try: List[str],
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        module_name: str,
        thread: "ConversationThread",
        prompt: str
    ) -> Optional[str]:
        """Try multiple models for threaded generation."""
        for current_model in models_to_try:
            result = await self._attempt_thread_model(
                current_model, headers, messages, temperature, max_tokens,
                module_name, thread, prompt
            )
            if result:
                return result

            await asyncio.sleep(0.5)
        return None

    async def _attempt_thread_model(
        self,
        current_model: str,
        headers: Dict[str, str],
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        module_name: str,
        thread: "ConversationThread",
        prompt: str
    ) -> Optional[str]:
        """Attempt threaded generation with a single model."""
        payload = {
            "model": current_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        if settings.OPENROUTER_ONLINE:
            payload["online"] = True

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, headers=headers, json=payload) as resp:
                    return await self._handle_thread_response(
                        resp, current_model, module_name, thread, prompt
                    )
        except Exception as e:
            logger.error(f"LLM Thread Exception with {current_model}: {str(e)}", exc_info=True)
            return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def generate_with_thread(
        self,
        prompt: str,
        thread: "ConversationThread",
        module_name: str,
        model_override: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> Optional[str]:
        """Generate text using ConversationThread for persistent context."""
        from bugtrace.core.conversation_thread import ConversationThread

        async with self.semaphore:
            if not self.api_key:
                logger.warning(f"LLM Client: No API Key for {module_name}")
                return None

            thread.add_message("user", prompt)
            messages = thread.get_messages(format_for_api=True)
            models_to_try = [model_override] if model_override else self.models

            result = await self._try_thread_models(
                models_to_try, self._build_headers(module_name), messages,
                temperature, max_tokens, module_name, thread, prompt
            )

            if not result:
                logger.critical(f"LLM Client: All models exhausted for threaded generation in {module_name}")

            return result

    async def update_balance(self):
        """Polls OpenRouter for current credit balance."""
        if not self.api_key:
            return

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with aiohttp.ClientSession() as session:
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

    async def analyze_visual(self, image_data: bytes, prompt: str, module_name: str = "Vision") -> Optional[str]:
        """
        Uses the specialized vision model (Qwen 3 VL or similar) to analyze screenshots.
        """
        import base64
        base64_image = base64.b64encode(image_data).decode('utf-8')

        headers = self._build_vision_headers(module_name)
        payload = self._build_vision_payload(prompt, base64_image)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.base_url, headers=headers, json=payload) as resp:
                    return await self._process_vision_response(resp, module_name, prompt)
        except Exception as e:
            logger.error(f"Visual Analysis failed: {e}", exc_info=True)
            await self._audit_log(f"Vision-{module_name}", settings.VISION_MODEL, prompt, f"ERROR: {str(e)}")
            return None

    def _build_vision_headers(self, module_name: str) -> Dict[str, str]:
        """Build headers for vision API request."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://bugtraceai.com",
            "X-Title": f"Bugtrace-{module_name}",
        }

    def _build_vision_payload(self, prompt: str, base64_image: str) -> Dict[str, Any]:
        """Build payload for vision API request."""
        payload = {
            "model": settings.VISION_MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            "max_tokens": 1500
        }

        if settings.OPENROUTER_ONLINE:
            payload["online"] = True

        return payload

    async def _process_vision_response(
        self,
        resp: aiohttp.ClientResponse,
        module_name: str,
        prompt: str
    ) -> Optional[str]:
        """Process vision API response."""
        if resp.status != 200:
            return None

        data = await resp.json()
        text = data['choices'][0]['message']['content']
        await self._audit_log(f"Vision-{module_name}", settings.VISION_MODEL, prompt, text)
        return text

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
        """Saves LLM transactions to a dedicated audit file asynchronously.

        TASK-128: Sanitizes prompts and responses to remove sensitive data.
        """
        try:
            log_dir = settings.LOG_DIR
            log_dir.mkdir(parents=True, exist_ok=True)
            audit_file = log_dir / "llm_audit.jsonl"
            entry = {
                "timestamp": datetime.now().isoformat(),
                "module": module,
                "model": model,
                "prompt": sanitize_text(prompt),
                "response": sanitize_text(response)
            }
            async with aiofiles.open(audit_file, "a") as f:
                await f.write(json.dumps(entry) + "\n")
        except Exception as e:
            # Fallback to printing if logging fails
            print(f"FAILED TO AUDIT: {e}")


    async def generate_with_image(self, prompt: str, image_path: str, model_override: str = None, module_name: str = "Vision", temperature: float = 0.3) -> str:
        """Generate LLM response with image input (vision model). Cost-conscious: Use sparingly."""
        import base64
        from pathlib import Path

        image_file = Path(image_path)
        if not image_file.exists():
            logger.error(f"[{module_name}] Image not found: {image_path}")
            return ""

        with open(image_path, 'rb') as f:
            image_data = base64.b64encode(f.read()).decode('utf-8')

        messages = [{"role": "user", "content": [{"type": "text", "text": prompt}, {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_data}"}}]}]

        async with self.semaphore:
            return await self._call_vision_api(messages, model_override, module_name, temperature)

    async def _call_vision_api(
        self,
        messages: List[Dict[str, Any]],
        model_override: Optional[str],
        module_name: str,
        temperature: float
    ) -> str:
        """Call vision API with image messages."""
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            payload = {
                "model": model_override or "qwen/qwen3-vl-8b-thinking",
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 100
            }

            try:
                async with session.post(self.base_url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    return await self._extract_vision_result(resp, module_name)
            except Exception as e:
                logger.error(f"[{module_name}] Vision call failed: {e}", exc_info=True)
                return ""

    async def _extract_vision_result(self, resp: aiohttp.ClientResponse, module_name: str) -> str:
        """Extract result from vision API response."""
        if resp.status != 200:
            error_text = await resp.text()
            logger.error(f"[{module_name}] Vision API error ({resp.status}): {error_text}")
            return ""

        data = await resp.json()
        result = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        logger.info(f"[{module_name}] Vision response: {result[:100]}")
        return result

    # ========== TASK-129: Response Validation ==========
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
            return None

    # ========== TASK-131: Request Caching ==========
    def _get_cache_key(self, model: str, prompt: str) -> str:
        """Generate cache key from model and prompt."""
        return hashlib.sha256(f"{model}:{prompt}".encode()).hexdigest()

    async def generate_with_cache(
        self,
        prompt: str,
        module_name: str,
        model_override: Optional[str] = None,
        cache_ttl: Optional[int] = None,
        **kwargs
    ) -> Optional[str]:
        """Generate with response caching to avoid duplicate LLM calls.

        Args:
            prompt: The prompt to send
            module_name: Module identifier
            model_override: Optional specific model
            cache_ttl: Cache TTL in seconds (default: self.cache_ttl)
            **kwargs: Additional args passed to generate()

        Returns:
            LLM response (cached or fresh)
        """
        model = model_override or (self.models[0] if self.models else "unknown")
        cache_key = self._get_cache_key(model, prompt)
        ttl = cache_ttl or self.cache_ttl

        # Check cache
        if cache_key in self.cache:
            cached_response, timestamp = self.cache[cache_key]
            if time.time() - timestamp < ttl:
                logger.debug(f"Cache hit for {module_name} ({model})")
                return cached_response

        # Generate fresh response
        response = await self.generate(
            prompt=prompt,
            module_name=module_name,
            model_override=model_override,
            **kwargs
        )

        # Cache valid responses
        if response:
            self.cache[cache_key] = (response, time.time())

        return response

    def clear_cache(self):
        """Clear all cached responses."""
        self.cache.clear()
        logger.info("LLM response cache cleared")

    # ========== TASK-133: Model Performance Metrics ==========
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

    # ========== TASK-132: Streaming Support ==========
    async def _process_stream_line(
        self,
        line: bytes,
        full_response: str,
        on_chunk: Optional[callable]
    ) -> tuple[str, Optional[str]]:
        """Process a single line from streaming response.

        Returns:
            Tuple of (updated_full_response, chunk_or_none)
        """
        line_str = line.decode('utf-8').strip()
        if not line_str or not line_str.startswith('data: '):
            return full_response, None

        data_str = line_str[6:]  # Remove 'data: ' prefix
        if data_str == '[DONE]':
            return full_response, None

        return self._extract_stream_chunk(data_str, full_response, on_chunk)

    def _extract_stream_chunk(
        self,
        data_str: str,
        full_response: str,
        on_chunk: Optional[callable]
    ) -> tuple[str, Optional[str]]:
        """Extract chunk from stream data."""
        try:
            data = json.loads(data_str)
            if 'choices' not in data or len(data['choices']) == 0:
                return full_response, None

            delta = data['choices'][0].get('delta', {})
            chunk = delta.get('content', '')

            if not chunk:
                return full_response, None

            full_response += chunk
            if on_chunk:
                on_chunk(chunk)
            return full_response, chunk

        except json.JSONDecodeError:
            return full_response, None

    async def _stream_response_content(
        self,
        resp: aiohttp.ClientResponse,
        full_response: str,
        on_chunk: Optional[callable]
    ):
        """Stream and yield response content line by line."""
        async for line in resp.content:
            full_response, chunk = await self._process_stream_line(
                line, full_response, on_chunk
            )
            if chunk:
                yield chunk, full_response
            else:
                yield None, full_response

    async def generate_stream(
        self,
        prompt: str,
        module_name: str,
        model_override: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1500,
        on_chunk: Optional[callable] = None
    ):
        """Generate with streaming response, yields chunks as they arrive."""
        async with self.semaphore:
            if not self.api_key:
                logger.warning(f"LLM Client: No API Key for streaming {module_name}")
                return

            model = model_override or (self.models[0] if self.models else None)
            if not model:
                logger.error("No model available for streaming")
                return

            headers = self._build_headers(module_name)
            messages = self._build_messages(prompt, system_prompt)
            payload = self._build_stream_payload(model, messages, temperature, max_tokens)

            async for chunk, full_response in self._execute_stream_request(
                headers, payload, on_chunk, module_name, model, prompt
            ):
                if chunk:
                    yield chunk

    def _build_stream_payload(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int
    ) -> Dict[str, Any]:
        """Build payload for streaming request."""
        return {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True
        }

    async def _execute_stream_request(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        on_chunk: Optional[callable],
        module_name: str,
        model: str,
        prompt: str
    ):
        """Execute streaming API request."""
        full_response = ""

        try:
            session = aiohttp.ClientSession()
            resp = await session.post(self.base_url, headers=headers, json=payload)

            try:
                async for chunk, full_response in self._handle_stream_response(
                    resp, full_response, on_chunk
                ):
                    yield chunk, full_response
            finally:
                await resp.close()
                await session.close()

            await self._audit_log(module_name, model, prompt, full_response)
        except Exception as e:
            logger.error(f"Streaming error: {e}", exc_info=True)

    async def _handle_stream_response(
        self,
        resp: aiohttp.ClientResponse,
        full_response: str,
        on_chunk: Optional[callable]
    ):
        """Handle streaming response and yield chunks."""
        if resp.status != 200:
            error_text = await resp.text()
            logger.error(f"Stream error ({resp.status}): {error_text}")
            return

        async for chunk, full_response in self._stream_response_content(
            resp, full_response, on_chunk
        ):
            yield chunk, full_response


# Singleton instance
llm_client = LLMClient()
