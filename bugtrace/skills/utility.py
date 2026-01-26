"""
Utility Skills - Helper and support skills.

Contains:
    - BrowserSkill: Screenshot capture and page interaction
    - ReportSkill: Finding report generation
"""

from typing import Dict, Any
from .base import BaseSkill
from bugtrace.utils.logger import get_logger

logger = get_logger("skills.utility")


class BrowserSkill(BaseSkill):
    """Browser skill - screenshots and page interaction."""
    
    description = "Take screenshots and interact with web pages"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from bugtrace.tools.visual.browser import browser_manager
        from bugtrace.core.config import settings
        
        try:
            async with browser_manager.get_page() as page:
                await page.goto(url, wait_until="networkidle", timeout=15000)
                
                screenshot_path = str(settings.LOG_DIR / f"{self.master.thread.thread_id}_browser.png")
                await page.screenshot(path=screenshot_path)
                
                # Get page content
                html = await page.content()
                title = await page.title()
                
                # Update metadata
                self.master.thread.update_metadata("last_screenshot", screenshot_path)
                
                return {
                    "success": True,
                    "screenshot": screenshot_path,
                    "title": title,
                    "html_length": len(html)
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}


class ReportSkill(BaseSkill):
    """Report skill - generates and saves findings."""
    
    description = "Generate vulnerability report from findings"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        import json
        from bugtrace.core.config import settings
        from datetime import datetime
        
        try:
            findings = self.master.findings
            
            if not findings:
                return {"success": True, "message": "No findings to report"}
            
            # Create report directory
            report_dir = settings.REPORT_DIR
            report_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate report filename
            safe_url = url.replace("://", "_").replace("/", "_").replace("?", "_")[:50]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = report_dir / f"findings_{safe_url}_{timestamp}.json"
            
            # Prepare report data
            report_data = {
                "url": url,
                "scan_date": timestamp,
                "thread_id": self.master.thread.thread_id,
                "findings_count": len(findings),
                "findings": findings,
                "metadata": self.master.thread.metadata
            }
            
            # Save report
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"[{self.master.name}] 📄 Report saved: {report_file}")
            
            return {
                "success": True,
                "report_path": str(report_file),
                "findings_count": len(findings)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
