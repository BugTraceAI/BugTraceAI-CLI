import asyncio
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.tools.external import external_tools
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = get_logger("agents.ssrf")

class SSRFAgent(BaseAgent):
    """
    Specialist Agent for Server-Side Request Forgery (SSRF).
    Target: Parameters containing URLs or likely to trigger outbound requests.
    """
    
    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="SSRFAgent",
            role="SSRF & Outbound Specialist",
            agent_id="ssrf_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        
        # Deduplication
        self._tested_params = set()
        
    async def _test_with_go_fuzzer(self, param: str) -> list:
        """Test parameter with Go SSRF fuzzer."""
        findings = []
        dashboard.log(f"[{self.name}] 🚀 Launching Go SSRF Fuzzer on '{param}'...", "INFO")
        go_result = await external_tools.run_go_ssrf_fuzzer(self.url, param)

        if go_result and go_result.get("hits"):
            for hit in go_result["hits"]:
                dashboard.log(f"[{self.name}] 🚨 SSRF HIT: {hit['payload']} ({hit['severity']})", "CRITICAL")
                findings.append({
                    "type": "SSRF",
                    "param": param,
                    "payload": hit["payload"],
                    "severity": hit["severity"].upper(),
                    "reason": hit["reason"],
                    "status": "VALIDATED_CONFIRMED",
                    "validated": True,
                    "cwe_id": get_cwe_for_vuln("SSRF"),
                    "remediation": get_remediation_for_vuln("SSRF"),
                    "cve_id": "N/A",
                    "http_request": f"GET {self.url}?{param}={hit['payload']}",
                    "http_response": hit.get("response", "Callback or internal response detected"),
                })
        return findings

    async def _test_with_llm_strategy(self, param: str) -> list:
        """Test parameter with LLM-generated payloads."""
        findings = []
        dashboard.log(f"[{self.name}] 🤖 Requesting LLM bypass strategy for '{param}'...", "INFO")
        strategy = await self._llm_get_strategy(param)

        if not strategy or "payloads" not in strategy:
            return findings

        return await self._test_strategy_payloads(strategy, param, findings)

    async def _test_strategy_payloads(self, strategy: Dict, param: str, findings: List) -> List:
        """Test each payload in the strategy."""
        for payload_item in strategy["payloads"]:
            payload = payload_item.get("payload")
            if not payload:
                continue

            res = await self._test_payload(param, payload)
            if res and self._determine_validation_status(res):
                findings.append({
                    "type": "SSRF",
                    "param": param,
                    "payload": payload,
                    "severity": "HIGH",
                    "reason": "Confirmed via LLM-designed payload",
                    "status": "VALIDATED_CONFIRMED",
                    "validated": True,
                    "cwe_id": get_cwe_for_vuln("SSRF"),
                    "remediation": get_remediation_for_vuln("SSRF"),
                    "cve_id": "N/A",
                    "http_request": f"GET {self.url}?{param}={payload}",
                    "http_response": res.get("text", "")[:200],
                })
                break
        return findings

    async def run_loop(self) -> Dict:
        """Main execution loop for SSRF testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting SSRF analysis on {self.url}", "INFO")

        all_findings = []
        for param in self.params:
            logger.info(f"[{self.name}] Testing {param} on {self.url}")

            key = f"{self.url}#{param}"
            if key in self._tested_params:
                logger.info(f"[{self.name}] Skipping {param} - already tested")
                continue

            # High-Performance Go Fuzzer
            findings = await self._test_with_go_fuzzer(param)

            # LLM-Driven deep strategy (fallback)
            if not findings:
                findings = await self._test_with_llm_strategy(param)

            if findings:
                all_findings.extend(findings)
                await self._create_finding(findings[0])

            self._tested_params.add(key)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(all_findings) > 0,
            "findings": all_findings,
            "findings_count": len(all_findings)
        }

    async def _test_payload(self, param: str, payload: str) -> Optional[Dict]:
        """Injects payload and returns results if interesting."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        
        try:
            async with aiohttp.ClientSession() as session:
                start_time = asyncio.get_event_loop().time()
                async with session.get(test_url, timeout=5) as response:
                    text = await response.text()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    
                    return {
                        "param": param,
                        "payload": payload,
                        "status": response.status,
                        "elapsed": elapsed,
                        "text": text,
                        "headers": dict(response.headers)
                    }
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {e}", exc_info=True)
            return None

    def _determine_validation_status(self, res: Dict) -> bool:
        """Determines if the response indicates a successful SSRF."""
        text = res.get("text", "").lower()
        
        # 🟢 CLASSIC Indicators
        indicators = [
            "root:x:", 
            "connected to internal",
            "aws metadata",
            "metadata-flavor",
            "computeMetadata/v1"
        ]
        
        for indicator in indicators:
            if indicator in text:
                return True
        
        # 🟡 TIMING Indicators (Potential)
        if res.get("elapsed", 0) > 3:
            return True
            
        return False

    async def _llm_get_strategy(self, param: str) -> Dict:
        """Asks LLM for best SSRF payloads based on context."""
        from bugtrace.core.llm_client import llm_client
        
        prompt = f"""
        Act as a SSRF Specialist.
        Target URL: {self.url}
        Vulnerable Parameter: {param}
        
        Provide 5 specialized SSRF payloads (Cloud metadata, bypasses, internal ports).
        Return in JSON:
        {{
          "thought": "reasons for these payloads",
          "payloads": [
             {{"payload": "http://...", "desc": "why this"}}
          ]
        }}
        """
        
        try:
            res = await llm_client.generate(prompt, module_name="SSRF_AGENT")
            from bugtrace.utils.parsers import XmlParser
            # The LLM might return XML if it follows general agent instructions
            json_str = XmlParser.extract_tag(res, "json") or res
            import json
            # Cleanup common junk
            json_str = json_str.replace("```json", "").replace("```", "").strip()
            return json.loads(json_str)
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return {}

    async def _create_finding(self, res: Dict):
        """Reports a confirmed finding to the conductor."""
        # This will be picked up by the ConductorV2
        finding = {
            "type": "SSRF",
            "severity": "CRITICAL",
            "url": self.url,
            "parameter": res["param"],
            "payload": res["payload"],
            "description": f"Confirmed SSRF in '{res['param']}'. Response contains internal data or indicators.",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": f"curl '{self.url}' --data-urlencode '{res['param']}={res['payload']}'",
            "cwe_id": get_cwe_for_vuln("SSRF"),
            "remediation": get_remediation_for_vuln("SSRF"),
            "cve_id": "N/A",
            "http_request": f"GET {self.url}?{res['param']}={res['payload']}",
            "http_response": res.get("text", res.get("reason", "Internal data or callback detected")),
        }
        # In a real integration, we'd emit an event or call state_manager directly
        logger.info(f"🔥🔥 SSRF CONFIRMED: {res['payload']} on {res['param']}")
