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
        """Runs Nuclei for tech detection and initial scan."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting technology detection and initial scan...", "INFO")
        
        try:
            # 1. Run Nuclei Tech Detection
            # We use specific templates for tech detection to build the profile
            tech_results = await external_tools.run_nuclei(self.target)
            
            # 2. Extract technologies and versions
            tech_profile = {
                "url": self.target,
                "frameworks": [],
                "languages": [],
                "servers": [],
                "raw_findings": tech_results if tech_results else []
            }
            
            if tech_results:
                for res in tech_results:
                    info = res.get("info", {})
                    name = info.get("name", "Unknown")
                    tech_profile["frameworks"].append(name)
            
            # 3. Save Tech Profile Artifact
            profile_path = self.report_dir / "tech_profile.json"
            with open(profile_path, "w") as f:
                json.dump(tech_profile, f, indent=4)
                
            dashboard.log(f"[{self.name}] Technical profile saved to {profile_path.name}", "SUCCESS")
            
            return tech_profile
            
        except Exception as e:
            logger.error(f"NucleiAgent failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] Error: {e}", "ERROR")
            return {"error": str(e), "frameworks": []}

    async def run_loop(self):
        await self.run()
