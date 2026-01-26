from mcp.server.fastmcp import FastMCP
from bugtrace.tools.visual.browser import browser_manager
from bugtrace.tools.visual.analyzer import visual_analyzer
import base64

# Initialize FastMCP Server
mcp = FastMCP("VisualIntelligence")

@mcp.tool()
async def capture_and_analyze(url: str, query: str) -> str:
    """
    Visits a URL, captures the screen, and analyzes it for specific visual elements.
    Useful for: Verifying exploits (did the admin panel appear?), finding buttons, reading captchas.
    """
    try:
        data = await browser_manager.capture_state(url)
        analysis = await visual_analyzer.analyze_screenshot(data["screenshot"], query)
        
        # We don't return the extensive HTML/Bytes to the agent logic, just the summary
        return f"Browsed to {url}. Title: {data['title']}.\nVisual Analysis: {analysis}"
    except Exception as e:
        return f"Error visualizing {url}: {str(e)}"
    finally:
        await browser_manager.stop()

if __name__ == "__main__":
    mcp.run()
