"""
Reconnaissance Skills - Discovery and analysis capabilities.

Contains:
    - ReconSkill: URL crawling and input discovery
    - AnalyzeSkill: LLM-powered vulnerability pattern analysis
"""

from typing import Dict, Any
from .base import BaseSkill
from bugtrace.utils.logger import get_logger

logger = get_logger("skills.recon")


class ReconSkill(BaseSkill):
    """Recon skill - discovers URLs, inputs, and technology stack."""
    
    description = "Crawl target to discover URLs, forms, inputs, and detect technology stack"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.visual.crawler import VisualCrawler
        
        try:
            crawler = VisualCrawler()
            # Use existing crawl functionality
            result = await crawler.crawl(url, max_depth=params.get("depth", 1))
            
            # Update master's thread metadata
            if result.get("urls"):
                self.master.thread.update_metadata("urls_found", result["urls"])
            if result.get("inputs"):
                self.master.thread.update_metadata("inputs_found", result["inputs"])
            if result.get("tech_stack"):
                self.master.thread.update_metadata("tech_stack", result["tech_stack"])
            
            return {
                "success": True,
                "urls_found": len(result.get("urls", [])),
                "inputs_found": len(result.get("inputs", [])),
                "tech_stack": result.get("tech_stack", []),
                "data": result
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}


class AnalyzeSkill(BaseSkill):
    """Analyze skill - uses LLM to analyze responses for vulnerability patterns."""
    
    description = "Analyze page content and responses for vulnerability patterns"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        # Use existing AnalysisAgent logic
        from bugtrace.agents.analysis import AnalysisAgent
        
        try:
            analysis_agent = AnalysisAgent(name="AnalysisSkill-1")
            report = await analysis_agent.analyze_url(url)
            
            vulnerabilities = report.get("vulnerabilities", [])
            
            return {
                "success": True,
                "vulnerabilities_found": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "report": report
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
