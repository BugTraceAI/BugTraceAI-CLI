import asyncio
import copy
from typing import List, Optional, Dict
from bugtrace.utils.logger import logger
from .models import MutableRequest, MutationStrategy, AgentFeedback, FeedbackStatus
from .controller import RequestController
from .specialists.implementations import PayloadAgent, EncodingAgent
from .breakout_manager import breakout_manager
from .context_analyzer import context_analyzer, ReflectionContext
from bugtrace.core.ui import dashboard

class ManipulatorOrchestrator:
    """
    Coordinates intelligent HTTP manipulation campaigns with context detection.

    Architecture:
    - Phase 0: Context detection (analyze WHERE probe reflects)
    - Phase 1a: Static payload bombardment (fast, regex validation)
    - Phase 1b: LLM expansion with intelligent breakouts
    - Phase 2: WAF bypass encoding (Q-learning strategy selection)
    - Phase 3: Agentic fallback when "blood smell" detected
    """
    def __init__(
        self,
        rate_limit: float = 0.5,
        enable_agentic_fallback: bool = False,
        enable_llm_expansion: bool = True
    ):
        self.controller = RequestController(rate_limit=rate_limit)
        self.payload_agent = PayloadAgent()
        self.encoding_agent = EncodingAgent()

        # Phase 1b: LLM payload expansion
        self.enable_llm_expansion = enable_llm_expansion

        # Phase 3: Agentic fallback
        self.enable_agentic_fallback = enable_agentic_fallback
        self.blood_smell_history: List[dict] = []  # Track interesting failures
        self._baseline_response_length: int = 0
        
    async def process_finding(self, base_request: MutableRequest, strategies: List[MutationStrategy] = None):
        """
        Intelligent multi-phase attack campaign with context detection.
        Returns: (success_bool, successful_mutation_request)
        """
        if strategies is None:
            strategies = [MutationStrategy.PAYLOAD_INJECTION]

        logger.info(f"Manipulator: Starting intelligent campaign on {base_request.url}")

        # ========== PHASE 0: CONTEXT DETECTION ==========
        logger.info("Phase 0: Analyzing reflection context...")
        context_info = await self._analyze_context(base_request)

        if context_info["contexts"][0] == ReflectionContext.NO_REFLECTION:
            logger.info("Phase 0: No reflection detected - skipping payload campaign")
            return False, None

        logger.info(f"Phase 0: {context_info['analysis']}")
        logger.info(f"Phase 0: Selected {len(context_info['recommended_breakouts'])} targeted breakouts")

        # Capture baseline response for anomaly detection
        try:
            _, baseline_body, _ = await self.controller.execute(base_request)
            self._baseline_response_length = len(baseline_body)
        except Exception:
            self._baseline_response_length = 0

        # ========== PHASE 1A: STATIC PAYLOAD BOMBARDMENT ==========
        logger.info("Phase 1a: Static payload bombardment...")
        request_count = 0
        self.blood_smell_history.clear()

        # Pass Phase 0 context to Phase 1a for context-aware payload selection
        detected_context = str(context_info["contexts"][0].value) if context_info["contexts"] else None

        async for mutation in self.payload_agent.generate_mutations(
            base_request, strategies, context_hint=detected_context
        ):
            request_count += 1
            if request_count % 20 == 0:
                logger.info(f"Phase 1a: Progress {request_count} mutations tested")

            result = await self._test_mutation_with_bypass(mutation, strategies)
            if result:
                logger.info(f"Phase 1a: SUCCESS after {request_count} static payloads")
                return result

        logger.info(f"Phase 1a: Exhausted {request_count} static payloads")

        # ========== PHASE 1B: LLM EXPANSION WITH INTELLIGENT BREAKOUTS ==========
        if self.enable_llm_expansion:
            logger.info("Phase 1b: LLM-powered expansion with context-aware breakouts...")

            vuln_type = self._detect_vuln_type_from_strategies(strategies)
            llm_payloads = await self._generate_llm_payloads_base(
                base_request,
                vuln_type=vuln_type,
                count=100
            )

            if llm_payloads:
                # Expand with ONLY the contextually relevant breakouts
                breakouts = context_info['recommended_breakouts']
                logger.info(f"Phase 1b: Expanding {len(llm_payloads)} payloads with {len(breakouts)} context-specific breakouts")

                expanded_payloads = []
                for base_payload in llm_payloads:
                    for breakout in breakouts:
                        expanded_payloads.append(breakout + base_payload)

                logger.info(f"Phase 1b: Testing {len(expanded_payloads)} intelligent payloads")

                # Test each payload
                llm_tested = 0
                for payload in expanded_payloads:
                    llm_tested += 1
                    if llm_tested % 100 == 0:
                        logger.info(f"Phase 1b: Progress {llm_tested}/{len(expanded_payloads)}")

                    # Test in each parameter
                    for param_name in base_request.params.keys():
                        mutation = copy.deepcopy(base_request)
                        mutation.params[param_name] = payload

                        result = await self._test_mutation_with_bypass(mutation, strategies)
                        if result:
                            logger.info(f"Phase 1b: SUCCESS with intelligent payload #{llm_tested}")
                            return result

                logger.info(f"Phase 1b: Exhausted {llm_tested} LLM-generated payloads")
            else:
                logger.warning("Phase 1b: Skipped (no payloads generated)")

        # ========== PHASE 2: WAF BYPASS (handled in _test_mutation_with_bypass) ==========

        # ========== PHASE 3: AGENTIC FALLBACK ==========
        if self.enable_agentic_fallback and self.blood_smell_history:
            result = await self._try_agentic_fallback(base_request)
            if result:
                return result

        logger.info("Manipulator: All phases exhausted without confirmation")
        return False, None

    async def _test_mutation_with_bypass(self, mutation: MutableRequest, strategies: List[MutationStrategy]):
        """Test mutation and optionally try WAF bypass encodings."""
        success = await self._try_mutation(mutation)
        if success:
            logger.info(f"Manipulator: Exploited successfully! URL: {mutation.url} Params: {mutation.params}")
            return True, mutation

        # Phase 2: Reactive Encoding (WAF Bypass)
        if MutationStrategy.BYPASS_WAF in strategies:
            async for encoded_mutation in self.encoding_agent.generate_mutations(mutation, strategies):
                success_enc = await self._try_mutation(encoded_mutation)
                if success_enc:
                    logger.info(f"Manipulator: Exploited with WAF Bypass! URL: {encoded_mutation.url} Params: {encoded_mutation.params}")
                    return True, encoded_mutation

        return None

    def _extract_potential_payloads(self, request: MutableRequest) -> List[str]:
        """Extract all potential payloads from request params, data, and JSON."""
        potential_payloads = list(request.params.values())

        if isinstance(request.data, dict):
            potential_payloads.extend(request.data.values())
        elif isinstance(request.data, str):
            potential_payloads.append(request.data)

        if request.json_payload:
            potential_payloads.extend(self._get_json_values(request.json_payload))

        return potential_payloads

    def _get_json_values(self, data):
        """Recursively extract all values from JSON structure."""
        vals = []
        if isinstance(data, dict):
            for v in data.values():
                vals.extend(self._get_json_values(v))
        elif isinstance(data, list):
            for item in data:
                vals.extend(self._get_json_values(item))
        else:
            vals.append(data)
        return vals

    async def _try_mutation(self, request: MutableRequest) -> bool:
        """
        Execute mutation and analyze result using modular validators.
        Tracks "blood smell" for potential LLM fallback.
        Auto-learns successful breakouts.
        """
        try:
            payload_sample = str(request.params)[:80]
            dashboard.set_current_payload(payload=payload_sample, vector="HTTP Mutation", status="Testing")
        except Exception as e:
            logger.debug(f"Dashboard update failed: {e}")

        status_code, body, duration = await self.controller.execute(request)

        # Track WAF blocks for learning
        if status_code in (403, 406):
            self.encoding_agent.record_failure(request)

        # Use modular validators from PayloadAgent
        potential_payloads = self._extract_potential_payloads(request)
        success_detected = (
            PayloadAgent.check_xss_success(body, potential_payloads) or
            PayloadAgent.check_sqli_success(body) or
            PayloadAgent.check_ssti_success(body) or
            PayloadAgent.check_cmd_success(body) or
            PayloadAgent.check_lfi_success(body)
        )

        if success_detected:
            self.encoding_agent.record_success(request)

            # 🎯 AUTO-LEARN: Record successful payload for breakout learning
            vuln_type = "xss"  # Default, can be improved with better detection
            if PayloadAgent.check_sqli_success(body):
                vuln_type = "sqli"
            elif PayloadAgent.check_ssti_success(body):
                vuln_type = "ssti"
            elif PayloadAgent.check_cmd_success(body):
                vuln_type = "cmd"
            elif PayloadAgent.check_lfi_success(body):
                vuln_type = "lfi"

            # Record all payloads for learning
            for payload in potential_payloads:
                await breakout_manager.record_success(
                    payload=str(payload),
                    vuln_type=vuln_type
                )

            return True

        # Phase 3 prep: Track "blood smell" for agentic fallback
        smell = PayloadAgent.detect_blood_smell(
            status_code, body, self._baseline_response_length
        )
        if smell["has_smell"] and smell["severity"] >= 3:
            self.blood_smell_history.append({
                "request": request,
                "status_code": status_code,
                "response_snippet": body[:500],
                "smell": smell,
            })
            logger.debug(f"Blood smell detected: {smell['reasons']} (severity {smell['severity']})")

        return False

    async def _try_agentic_fallback(self, base_request: MutableRequest):
        """
        PHASE 3 HOOK: LLM-powered analysis when static payloads fail.
        Currently a stub - implement with llm_client in next iteration.

        The LLM should analyze:
        - Why static payloads failed (WAF rules, input validation, encoding)
        - Generate context-aware payload based on response patterns
        - Act like a hacker using Burp Suite analyzing req/res

        Returns: (success_bool, successful_mutation) or None
        """
        if not self.blood_smell_history:
            return None

        # Sort by severity to analyze most promising first
        sorted_smells = sorted(
            self.blood_smell_history,
            key=lambda x: x["smell"]["severity"],
            reverse=True
        )

        logger.info(f"Agentic Fallback: {len(sorted_smells)} interesting responses to analyze")

        # TODO: Implement LLM analysis here
        # Example structure for future implementation:
        #
        # from bugtrace.core.llm_client import llm_client
        #
        # for entry in sorted_smells[:5]:  # Top 5 most interesting
        #     prompt = f"""Analyze this failed injection attempt:
        #     URL: {entry['request'].url}
        #     Status: {entry['status_code']}
        #     Smell: {entry['smell']['reasons']}
        #     Response snippet: {entry['response_snippet']}
        #
        #     Generate a payload that bypasses the detected protection."""
        #
        #     custom_payload = await llm_client.generate(prompt, ...)
        #     # Test custom_payload...

        return None

    async def _analyze_context(self, base_request: MutableRequest) -> Dict:
        """
        Send probe to analyze reflection context.
        Returns context info with recommended breakouts.
        """
        from bugtrace.core.config import settings

        probe = settings.OMNI_PROBE_MARKER

        # Send probe in each parameter
        for param_name in base_request.params.keys():
            probe_request = copy.deepcopy(base_request)
            probe_request.params[param_name] = probe

            try:
                status_code, body, duration = await self.controller.execute(probe_request)

                if probe in body:
                    logger.info(f"Probe reflected in parameter: {param_name}")
                    return context_analyzer.analyze_reflection(body, probe)
            except Exception as e:
                logger.debug(f"Probe failed for {param_name}: {e}")

        # No reflection detected
        return {
            "contexts": [ReflectionContext.NO_REFLECTION],
            "confidence": 1.0,
            "recommended_breakouts": [],
            "analysis": "Probe not reflected"
        }

    async def _generate_llm_payloads_base(
        self,
        base_request: MutableRequest,
        vuln_type: str,
        count: int = 100
    ) -> List[str]:
        """
        Generate BASE payloads using LLM (without breakouts).
        Breakouts will be applied locally after generation.
        """
        from bugtrace.core.llm_client import llm_client
        from bugtrace.core.config import settings

        param_names = list(base_request.params.keys())
        url_path = base_request.url.split('?')[0]

        prompt = f"""Generate {count} creative attack payloads for {vuln_type} vulnerability testing.

IMPORTANT: Generate ONLY the core payload, WITHOUT breakout prefixes (no ', ", >, etc.)
We will add breakout variations automatically.

CONTEXT:
- URL: {url_path}
- Parameters: {param_names}
- Method: {base_request.method}

PAYLOAD REQUIREMENTS:
1. Creative polyglot payloads (work in multiple contexts)
2. Mix encodings: URL, HTML entities, Unicode, hex, octal
3. Modern framework bypasses (React, Vue, Angular, CSP)
4. WAF evasion techniques (case mixing, null bytes, comments)
5. For XSS: Include visible BUGTRACE marker for detection
6. Variations with different syntax: (), {{}}, [], <>, etc.

EXAMPLES (base payloads WITHOUT breakout prefixes):
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
javascript:alert(1)
data:text/html,<script>alert(1)</script>

OUTPUT FORMAT:
- One payload per line
- No prefixes, no explanations, no markdown
- Only raw payload strings"""

        logger.info(f"Phase 1.5: Requesting {count} base payloads from DeepSeek...")

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="PayloadGenerator",
                model_override=settings.MUTATION_MODEL,  # deepseek/deepseek-chat
                temperature=0.9,  # High creativity
                max_tokens=3000
            )

            if not response:
                logger.warning("Phase 1.5: LLM returned no payloads")
                return []

            # Parse base payloads
            base_payloads = [
                line.strip()
                for line in response.split('\n')
                if line.strip() and not line.startswith('#') and not line.startswith('-')
            ]

            logger.info(f"Phase 1.5: Received {len(base_payloads)} base payloads from LLM")
            return base_payloads[:count]

        except Exception as e:
            logger.error(f"Phase 1.5: Payload generation failed: {e}")
            return []

    def _detect_vuln_type_from_strategies(self, strategies: List[MutationStrategy]) -> str:
        """Detect likely vulnerability type from mutation strategies."""
        strategy_map = {
            MutationStrategy.SSTI_INJECTION: "SSTI",
            MutationStrategy.CMD_INJECTION: "CMD",
            MutationStrategy.PATH_TRAVERSAL: "LFI",
        }

        for strategy in strategies:
            if strategy in strategy_map:
                return strategy_map[strategy]

        # Default to XSS if no specific strategy
        return "XSS"

    async def shutdown(self):
        await self.controller.close()
