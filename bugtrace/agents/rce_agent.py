import logging
import aiohttp
import time
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard

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
        
    async def run_loop(self) -> Dict:
        """Main RCE testing loop."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting RCE analysis on {self.url}", "INFO")
        
        all_findings = []
        
        # 1. Time-based Payloads (Most reliable for discovery)
        time_payloads = [
            ";sleep 5",
            "|sleep 5",
            "&sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "\nsleep 5\n",
            # Python specific
            "__import__('time').sleep(5)",
            "eval('sleep(5)')", # Won't work directly in eval unless time is imported
            "1+1" # Simple math for eval checks
        ]

        async with aiohttp.ClientSession() as session:
            for param in self.params:
                logger.info(f"[{self.name}] Testing RCE on {self.url} (Param: {param})")
                
                # First, check for time-based injection
                for p in time_payloads:
                    if "sleep" in p:
                        dashboard.update_task(f"RCE:{param}", status=f"Testing Time: {p}")
                        start = time.time()
                        if await self._test_payload(session, p, param):
                            elapsed = time.time() - start
                            if elapsed >= 5:
                                all_findings.append({
                                    "type": "Command Injection (Time-based)",
                                    "url": self.url,
                                    "parameter": param,
                                    "payload": p,
                                    "severity": "CRITICAL",
                                    "validated": True,
                                    "status": "VALIDATED_CONFIRMED",
                                    "evidence": f"Delay of {elapsed:.2f}s detected with payload: {p}",
                                    "description": f"Time-based Command Injection confirmed. Parameter '{param}' executes OS commands. Payload caused {elapsed:.2f}s delay (expected 5s+).",
                                    "reproduction": f"# Time-based RCE test:\ntime curl '{self._inject_payload(self.url, param, p)}'"
                                })
                                break # Move to next param
                    elif "1+1" in p:
                        # Generic Eval check
                        dashboard.update_task(f"RCE:{param}", status=f"Testing Eval: {p}")
                        target = self._inject_payload(self.url, param, p)
                        async with session.get(target) as resp:
                            text = await resp.text()
                            if "Result: 2" in text:
                                all_findings.append({
                                    "type": "Remote Code Execution (Eval)",
                                    "url": self.url,
                                    "parameter": param,
                                    "payload": p,
                                    "severity": "CRITICAL",
                                    "validated": True,
                                    "status": "VALIDATED_CONFIRMED",
                                    "evidence": f"Mathematical expression '1+1' evaluated to '2' in response.",
                                    "description": f"Remote Code Execution via eval() confirmed. Parameter '{param}' evaluates arbitrary code. Expression '1+1' returned '2'.",
                                    "reproduction": f"curl '{target}' | grep -i 'result'"
                                })
                                break # Move to next param

        return {
            "vulnerable": len(all_findings) > 0,
            "findings": all_findings
        }

    async def _test_payload(self, session, payload, param) -> bool:
        """Injects payload and analyzes response."""
        target_url = self._inject_payload(self.url, param, payload)
        try:
            async with session.get(target_url, timeout=10) as resp:
                await resp.text()
                return True
        except Exception:
            pass
        return False

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
