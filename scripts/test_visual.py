import asyncio
from bugtrace.tools.visual.browser import browser_manager

async def test_visual_capabilities():
    target = "http://localhost:8000" # Running test app
    print(f"Testing Visual Intelligence against {target}...")
    
    try:
        data = await browser_manager.capture_state(target)
        print(f"Successfully captured {len(data['screenshot'])} bytes.")
        print(f"Page Title: {data['title']}")
        
        # Save screenshot for manual inspection
        with open("evidence_screenshot.jpg", "wb") as f:
            f.write(data['screenshot'])
        print("Saved evidence_screenshot.jpg")
        
    except Exception as e:
        print(f"Test failed: {e}")
    finally:
        await browser_manager.stop()

if __name__ == "__main__":
    asyncio.run(test_visual_capabilities())
