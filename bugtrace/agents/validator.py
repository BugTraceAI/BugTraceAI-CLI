from typing import List, Dict, Any, Tuple
import asyncio
from loguru import logger
from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager
from bugtrace.core.ui import dashboard

class ValidatorAgent(BaseAgent):
    """
    Agent responsible for validating potential findings after the main analysis phase.
    It takes 'Potential' findings and attempts to elevate them to 'Verified' status
    using specialized tools (Browser, SQLMap, etc.).
    """
    
    def __init__(self, event_bus=None):
        super().__init__("ValidatorAgent", "Validation Specialist", event_bus)
        
    async def run_loop(self):
        # This agent is typically triggered systematically by the orchestrator
        # rather than running a continuous loop.
        pass
        
    async def validate_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes a list of findings and attempts to validate 'Potential' ones.
        Returns the updated list of findings.
        """
        self.think(f"Starting validation for {len(findings)} findings")
        
        validated_findings = []
        
        # Optimize: Group by type to reuse resources (e.g. browser session)
        for finding in findings:
            # Skip if already validated
            if finding.get("validated"):
                validated_findings.append(finding)
                continue
                
            # Skip if it's safe or info (unless we want to validate info?)
            severity = finding.get("severity", "").upper() 
            if severity in ["INFO", "SAFE", "LOW"] and "XSS" not in finding.get("title", "").upper():
                validated_findings.append(finding)
                continue
            
            try:
                updated_finding = await self.validate_finding(finding)
                validated_findings.append(updated_finding)
            except Exception as e:
                logger.error(f"Validation failed for finding {finding.get('title')}: {e}")
                validated_findings.append(finding)
            
        return validated_findings
    
    async def validate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        title = finding.get("title", "").upper()
        url = finding.get("url")
        # Extract payload from multiple possible sources
        payload = finding.get("payload") or finding.get("metadata", {}).get("payload")
        
        # 1. XSS Validation
        # Check both title and type for XSS
        vuln_type = finding.get("type", "").upper()
        if "XSS" in title or "XSS" in vuln_type:
            return await self._validate_xss(finding, url, payload)
            
        # 2. SQLi Validation
        # (Placeholder: Future SQLMap integration)
        
        return finding

    async def _validate_xss(self, finding: Dict[str, Any], url: str, payload: str) -> Dict[str, Any]:
        """
        Validates Cross-Site Scripting using the BrowserManager.
        Verifies if an alert popup (or mock alert) is triggered.
        """
        if not url:
            return finding
            
        # If no payload, we can't validate (unless we generate one, but that's ExploitAgent's job)
        if not payload:
            # Try to grab payload from evidence
            evidence = finding.get("evidence", [])
            if evidence and isinstance(evidence, list):
                for e in evidence:
                    if isinstance(e, dict) and "payload" in e.get("content", "").lower():
                        # Simple extraction heuristic could go here
                        pass
        
        if not payload:
             self.think(f"Skipping XSS validation on {url} (No payload)")
             return finding

        self.think(f"Validating XSS on {url} with payload {payload}")
        dashboard.update_task(self.name, status="Validating XSS", payload=payload)
        
        try:
            # BrowserManager.verify_xss expects the FULL url with payload if it's GET
            # But usually DAST provides payload separate from URL base.
            
            target_url = url
            # Naive injection for GET parameters if payload not in URL
            # Naive injection for GET parameters if payload not in url
            if payload not in url:
                import urllib.parse as urlparse
                from urllib.parse import urlencode, parse_qs
                
                parsed = urlparse.urlparse(url)
                if parsed.query:
                    qs = parse_qs(parsed.query)
                    
                    # 1. Use specific parameter if known
                    param = finding.get("parameter") or finding.get("param")
                    
                    if param and param in qs:
                        qs[param] = payload
                    else:
                        # 2. Heuristic: Inject into ALL parameters (aggressively)
                        # Since this is a validation confirmation, we want to trigger it.
                        for k in qs:
                            qs[k] = payload
                            
                    new_query = urlencode(qs, doseq=True)
                    target_url = urlparse.urlunparse(parsed._replace(query=new_query))
                    self.think(f"Constructed exploitation URL: {target_url}")
                    
                elif not parsed.query:
                     # No params? Append as path or default param
                     target_url = f"{url}?q={payload}"

            # If payload looks like a full URL, use it directly (override above)
            if payload.startswith("http"):
                target_url = payload
            
            screenshot_path, logs, triggered = await browser_manager.verify_xss(target_url)
            
            if triggered:
                finding["validated"] = True
                finding["validation_method"] = "Browser + ValidatorAgent"
                finding["screenshot_path"] = screenshot_path # This is absolute path from browser_manager
                
                # Relativize path for report if needed, but team.py handles relocation
                # team.py logic: if source_path.exists(), copy to captures/
                
                # Add evidence log
                if "evidence" not in finding:
                    finding["evidence"] = []
                finding["evidence"].append({
                    "description": "ValidatorAgent Verification Log",
                    "content": "\n".join(logs),
                    "timestamp": "now"
                })
                
                self.think(f"CONFIRMED XSS on {url}")
            else:
                self.think(f"Could not validate XSS (No alert triggered)")
                # We do NOT remove the finding, just leave it as Potential
                # finding["validated"] = False # Default
                
        except Exception as e:
            logger.error(f"XSS Validation failed: {e}")
            
        return finding
