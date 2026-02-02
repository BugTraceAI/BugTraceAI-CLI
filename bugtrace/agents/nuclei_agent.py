from typing import Dict, Optional, List, Any
from loguru import logger
from bugtrace.tools.external import external_tools
from bugtrace.core.ui import dashboard
import json
from pathlib import Path
from bugtrace.agents.base import BaseAgent

class NucleiAgent(BaseAgent):
    """
    Specialized Agent for Technology Detection and Vulnerability Scanning using Nuclei.
    Phase 1 of the Sequential Pipeline.
    """
    
    def __init__(self, target: str, report_dir: Path, event_bus: Any = None):
        super().__init__("NucleiAgent", "Tech Discovery", event_bus=event_bus, agent_id="nuclei_agent")
        self.target = target
        self.report_dir = report_dir
        
    async def run(self) -> Dict:
        """
        Runs two-phase Nuclei scan for technology detection and vulnerability discovery.

        Returns comprehensive tech_profile used by specialist agents.
        """
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting 2-phase Nuclei scan (tech-detect + auto-scan)...", "INFO")

        try:
            # Run two-phase Nuclei scan
            nuclei_results = await external_tools.run_nuclei(self.target)

            tech_findings = nuclei_results.get("tech_findings", [])
            vuln_findings = nuclei_results.get("vuln_findings", [])

            # Parse technology detections
            tech_profile = {
                "url": self.target,
                "infrastructure": [],      # AWS ALB, Cloudflare, etc.
                "frameworks": [],          # AngularJS, React, etc.
                "languages": [],           # PHP, Node.js, Python, etc.
                "servers": [],             # Nginx, Apache, etc.
                "cms": [],                 # WordPress, Drupal, etc.
                "waf": [],                 # ModSecurity, Cloudflare WAF, etc.
                "cdn": [],                 # Cloudflare, Akamai, etc.
                "tech_tags": [],           # All detected tags
                "raw_tech_findings": tech_findings,
                "raw_vuln_findings": vuln_findings
            }

            # Extract and categorize technologies
            for finding in tech_findings:
                info = finding.get("info", {})
                name = info.get("name", "Unknown")
                tags = info.get("tags", [])

                # Categorize by tags
                if "tech" in tags or "detect" in tags:
                    tech_profile["tech_tags"].append(name)

                # Infrastructure (AWS, Azure, GCP)
                if any(x in name.lower() for x in ["aws", "azure", "gcp", "alb", "cloudfront"]):
                    tech_profile["infrastructure"].append(name)
                # Web frameworks
                elif any(x in name.lower() for x in ["angular", "react", "vue", "jquery", "bootstrap"]):
                    tech_profile["frameworks"].append(name)
                # Languages
                elif any(x in name.lower() for x in ["php", "node", "python", "ruby", "java", "asp"]):
                    tech_profile["languages"].append(name)
                # Servers
                elif any(x in name.lower() for x in ["nginx", "apache", "iis", "tomcat"]):
                    tech_profile["servers"].append(name)
                # CMS
                elif any(x in name.lower() for x in ["wordpress", "drupal", "joomla", "magento"]):
                    tech_profile["cms"].append(name)
                # WAF
                elif any(x in name.lower() for x in ["waf", "modsecurity", "imperva"]):
                    tech_profile["waf"].append(name)
                # CDN
                elif any(x in name.lower() for x in ["cloudflare", "akamai", "fastly", "cdn"]):
                    tech_profile["cdn"].append(name)
                else:
                    # Default: add to frameworks
                    tech_profile["frameworks"].append(name)

            # Deduplicate lists
            for key in ["infrastructure", "frameworks", "languages", "servers", "cms", "waf", "cdn", "tech_tags"]:
                tech_profile[key] = list(set(tech_profile[key]))

            # Save comprehensive tech profile
            profile_path = self.report_dir / "tech_profile.json"
            with open(profile_path, "w") as f:
                json.dump(tech_profile, f, indent=2)

            # Log summary
            summary_parts = []
            if tech_profile["infrastructure"]:
                summary_parts.append(f"{len(tech_profile['infrastructure'])} infra")
            if tech_profile["frameworks"]:
                summary_parts.append(f"{len(tech_profile['frameworks'])} frameworks")
            if tech_profile["servers"]:
                summary_parts.append(f"{len(tech_profile['servers'])} servers")
            if tech_profile["waf"]:
                summary_parts.append(f"⚠️ WAF detected")

            summary = ", ".join(summary_parts) if summary_parts else "Basic detection"
            dashboard.log(f"[{self.name}] Tech Profile: {summary} | {len(vuln_findings)} vulns", "SUCCESS")

            return tech_profile

        except Exception as e:
            logger.error(f"NucleiAgent failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] Error: {e}", "ERROR")
            return {
                "error": str(e),
                "infrastructure": [],
                "frameworks": [],
                "languages": [],
                "servers": [],
                "cms": [],
                "waf": [],
                "cdn": [],
                "tech_tags": [],
                "raw_tech_findings": [],
                "raw_vuln_findings": []
            }

    async def run_loop(self):
        await self.run()
