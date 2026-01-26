import asyncio
import os
import sys
from loguru import logger

# Add project root to path
sys.path.append(os.getcwd())

from bugtrace.core.event_bus import EventBus
from bugtrace.agents.analysis import AnalysisAgent
from bugtrace.tools.exploitation.sqli import sqli_detector
from bugtrace.tools.visual.browser import browser_manager

# Configure logging
logger.remove()
logger.add(sys.stdout, level="INFO")

async def verify_analysis_agent():
    print("\n[+] Verifying Analysis Agent (XML Protocol)...")
    bus = EventBus()
    agent = AnalysisAgent(bus)
    
    # Mock context
    event_data = {
        "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "html": "<html>...mysql_fetch_array...</html>" # simulate sql error in html
    }
    
    # Run analysis
    # We call analyze_url directly
    print("    Running analyze_url...")
    report = await agent.analyze_url(event_data)
    
    print("\n[+] Analysis Report:")
    vulns = report.get("likely_vulnerabilities", [])
    print(f"    Vulnerabilities found: {len(vulns)}")
    for v in vulns:
        print(f"    - Type: {v.get('type')}")
        print(f"    - Confidence: {v.get('confidence')}")
        print(f"    - Reasoning: {v.get('reasoning')}")
        
    if len(vulns) > 0 and vulns[0].get("type"):
        print("\n✅ XML Parsing SUCCESS: Vulnerabilities extracted correctly.")
    else:
        print("\n❌ XML Parsing FAILED or no vulns found.")

async def verify_sqli_agent():
    print("\n[+] Verifying AI SQLi Agent...")
    url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    
    # Initialize browser
    await browser_manager.start()
    
    try:
        async with browser_manager.get_page() as page:
            await page.goto(url)
            
            # Call _llm_check directly to verify AI logic
            print("    Calling _llm_check directly...")
            result = await sqli_detector._llm_check(page, url, "cat", "1")
            
            if result:
                print(f"\n✅ AI SQLi Check SUCCESS: {result}")
            else:
                print("\n⚠️ AI SQLi Check returned None (LLM might not have found a payload or failed)")
                
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        await browser_manager.stop()

async def main():
    await verify_analysis_agent()
    await verify_sqli_agent()

if __name__ == "__main__":
    asyncio.run(main())
