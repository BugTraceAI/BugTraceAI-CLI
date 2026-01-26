import logging
import asyncio
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.utils.logger import get_logger
from bugtrace.tools.external import external_tools

logger = get_logger("agents.idor")

class IDORAgent(BaseAgent):
    """
    Specialist Agent for Insecure Direct Object Reference (IDOR).
    Target: Numeric ID parameters.
    Strategy: Test ID-1, ID+1 and compare with baseline.
    """
    
    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None):
        super().__init__(
            name="IDORAgent",
            role="IDOR Specialist",
            agent_id="idor_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        
        # Deduplication
        self._tested_params = set()
        
    def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
        """
        TIER 1 (VALIDATED_CONFIRMED):
            - Cookie tampering success (horizontal privilege escalation)
            - HIGH confidence differential with sensitive data markers

        TIER 2 (PENDING_VALIDATION):
            - MEDIUM/LOW confidence differential analysis
            - Needs human/CDP verification
        """
        if evidence_type == "cookie_tampering":
            return "VALIDATED_CONFIRMED"

        if evidence_type == "differential" and confidence == "HIGH":
            return "VALIDATED_CONFIRMED"

        return "PENDING_VALIDATION"
        
    async def run_loop(self) -> Dict:
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting IDOR analysis on {self.url}", "INFO")
        
        all_findings = []
        async with aiohttp.ClientSession() as session:
            for item in self.params:
                param = item.get("parameter")
                original_value = str(item.get("original_value", ""))
                
                if not param:
                    continue

                logger.info(f"[{self.name}] Testing IDOR on {param}={original_value}")

                # Deduplication check
                key = f"{self.url}#{param}"
                if key in self._tested_params:
                    logger.info(f"[{self.name}] Skipping {param} - already tested")
                    continue

                # 1. High-Performance Go IDOR Fuzzer
                dashboard.log(f"[{self.name}] 🚀 Launching Go IDOR Fuzzer on '{param}' (Range 1-1000)...", "INFO")
                # We use a broad range 1-1000 by default for faster identification
                go_result = await external_tools.run_go_idor_fuzzer(self.url, param, id_range="1-1000", baseline_id=original_value)
                
                if go_result and go_result.get("hits"):
                    for hit in go_result["hits"]:
                        dashboard.log(f"[{self.name}] 🚨 IDOR HIT: ID {hit['id']} ({hit['severity']})", "CRITICAL")
                        all_findings.append({
                            "type": "IDOR",
                            "url": self.url,
                            "parameter": param,
                            "payload": hit["id"],
                            "description": f"IDOR vulnerability detected on ID {hit['id']}. Differed from baseline ID {original_value}. Status: {hit['status_code']}. Contains sensitive data: {hit.get('contains_sensitive')}",
                            "severity": hit["severity"],
                            "validated": hit["severity"] == "CRITICAL",
                            "evidence": f"Status {hit['status_code']}. Diff Type: {hit['diff_type']}. Sensitive: {hit.get('contains_sensitive')}",
                            "status": self._determine_validation_status("differential", "HIGH" if hit["severity"] == "CRITICAL" else "MEDIUM"),
                            "reproduction": f"# Compare responses:\ncurl '{self.url}?{param}={original_value}'\ncurl '{self.url}?{param}={hit['id']}'"
                        })
                        self._tested_params.add(key)
                        break # Found one, move count
                
                # 2. Trust the fuzzer's semantic analysis
                # If fuzzer found no hits, differences are semantic (e.g., product catalog) not access control bypass
                if not (go_result and go_result.get("hits")):
                    logger.info(f"[{self.name}] ✅ No IDOR found on '{param}' - semantic analysis passed")

                self._tested_params.add(key)
        
        return {"findings": all_findings, "status": JobStatus.COMPLETED}

    async def _fetch(self, session, val, param_name, original_val) -> Optional[str]:
        text, _ = await self._fetch_full(session, val, param_name, original_val)
        return text

    async def _fetch_full(self, session, val, param_name, original_val):
        target = self._inject(val, param_name, original_val)
        try:
            dashboard.update_task(f"IDOR:{param_name}", status=f"Probing ID {val}")
            async with session.get(target, timeout=5) as resp:
                return await resp.text(), resp.status
        except:
            return None, 0

    def _inject(self, val, param_name, original_val):
        parsed = urlparse(self.url)
        path = parsed.path
        
        # 1. Path-based IDOR
        if original_val and str(original_val) in path:
            import re
            new_path = re.sub(rf'(^|/){re.escape(str(original_val))}(/|$)', rf'\g<1>{val}\g<2>', path)
            if new_path != path:
                return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

        # 2. Query-based IDOR
        q = parse_qs(parsed.query)
        q[param_name] = [val]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, new_query, parsed.fragment))

    async def _fetch_with_cookie(self, session, val, param_name, original_val, cookies):
        target = self._inject(val, param_name, original_val)
        try:
            dashboard.update_task(f"IDOR:{param_name}", status=f"Tampering Cookie for ID {val}")
            async with session.get(target, cookies=cookies, timeout=5) as resp:
                return await resp.text()
        except:
            return None
