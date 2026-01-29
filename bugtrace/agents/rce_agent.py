import logging
import aiohttp
import time
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = logging.getLogger(__name__)

class RCEAgent(BaseAgent):
    """
    Specialist Agent for Remote Code Execution (RCE) and Command Injection.
    """
    
    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="RCEAgent",
            role="RCE Specialist",
            agent_id="rce_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        
    def _get_time_payloads(self) -> list:
        """Get time-based RCE payloads."""
        return [
            ";sleep 5", "|sleep 5", "&sleep 5", "`sleep 5`", "$(sleep 5)", "\nsleep 5\n",
            "__import__('time').sleep(5)", "eval('sleep(5)')", "1+1"
        ]

    def _create_time_based_finding(self, param: str, payload: str, elapsed: float) -> Dict:
        """Create finding for time-based RCE."""
        return {
            "type": "RCE",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "severity": "CRITICAL",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": f"Delay of {elapsed:.2f}s detected with payload: {payload}",
            "description": f"Time-based Command Injection confirmed. Parameter '{param}' executes OS commands. Payload caused {elapsed:.2f}s delay (expected 5s+).",
            "reproduction": f"# Time-based RCE test:\ntime curl '{self._inject_payload(self.url, param, payload)}'",
            "cwe_id": get_cwe_for_vuln("RCE"),
            "remediation": get_remediation_for_vuln("RCE"),
            "cve_id": "N/A",
            "http_request": f"GET {self._inject_payload(self.url, param, payload)}",
            "http_response": f"Time delay: {elapsed:.2f}s (indicates command execution)",
        }

    def _create_eval_finding(self, param: str, payload: str, target: str) -> Dict:
        """Create finding for eval-based RCE."""
        return {
            "type": "RCE",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "severity": "CRITICAL",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": f"Mathematical expression '1+1' evaluated to '2' in response.",
            "description": f"Remote Code Execution via eval() confirmed. Parameter '{param}' evaluates arbitrary code. Expression '1+1' returned '2'.",
            "reproduction": f"curl '{target}' | grep -i 'result'",
            "cwe_id": get_cwe_for_vuln("RCE"),
            "remediation": get_remediation_for_vuln("RCE"),
            "cve_id": "N/A",
            "http_request": f"GET {target}",
            "http_response": "Result: 2 (indicates code evaluation)",
        }

    async def run_loop(self) -> Dict:
        """Main RCE testing loop."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting RCE analysis on {self.url}", "INFO")

        all_findings = []
        time_payloads = self._get_time_payloads()

        async with aiohttp.ClientSession() as session:
            for param in self.params:
                logger.info(f"[{self.name}] Testing RCE on {self.url} (Param: {param})")
                finding = await self._test_parameter(session, param, time_payloads)
                if finding:
                    all_findings.append(finding)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    async def _test_parameter(self, session, param: str, payloads: List[str]) -> Optional[Dict]:
        """Test a single parameter with all payloads."""
        for p in payloads:
            finding = await self._test_single_payload(session, param, p)
            if finding:
                return finding
        return None

    async def _test_single_payload(self, session, param: str, payload: str) -> Optional[Dict]:
        """Test a single payload against a parameter."""
        if "sleep" in payload:
            return await self._test_time_based(session, param, payload)
        elif "1+1" in payload:
            return await self._test_eval_based(session, param, payload)
        return None

    async def _test_time_based(self, session, param: str, payload: str) -> Optional[Dict]:
        """Test time-based RCE payload."""
        dashboard.update_task(f"RCE:{param}", status=f"Testing Time: {payload}")
        start = time.time()

        if not await self._test_payload(session, payload, param):
            return None

        elapsed = time.time() - start
        if elapsed >= 5:
            return self._create_time_based_finding(param, payload, elapsed)
        return None

    async def _test_eval_based(self, session, param: str, payload: str) -> Optional[Dict]:
        """Test eval-based RCE payload."""
        dashboard.update_task(f"RCE:{param}", status=f"Testing Eval: {payload}")
        target = self._inject_payload(self.url, param, payload)

        try:
            async with session.get(target) as resp:
                text = await resp.text()
                if "Result: 2" in text:
                    return self._create_eval_finding(param, payload, target)
        except Exception as e:
            logger.debug(f"Eval test failed: {e}")

        return None

    async def _test_payload(self, session, payload, param) -> bool:
        """Injects payload and analyzes response."""
        target_url = self._inject_payload(self.url, param, payload)
        try:
            async with session.get(target_url, timeout=10) as resp:
                await resp.text()
                return True
        except Exception as e:
            logger.debug(f"Connectivity check failed: {e}")
        return False

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
