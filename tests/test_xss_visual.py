
import asyncio
from playwright.async_api import async_playwright
import os

async def test_verify():
    html_content = """
    <html>
    <body>
        <h1>Vulnerable Page</h1>
        <script>alert('XSS')</script>
    </body>
    </html>
    """
    
    with open("vuln.html", "w") as f:
        f.write(html_content)
        
    file_url = f"file://{os.path.abspath('vuln.html')}"
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        triggered = False
        logs = []
        
        # 1. Setup Logic Proof (Callback)
        async def on_xss_triggered(msg):
            nonlocal triggered
            print(f"CALLBACK FIRED: {msg}")
            triggered = True
        
        await page.expose_function("bugtrace_xss_callback", on_xss_triggered)
        
        # 2. Setup Visual Proof (Mock Alert)
        await page.add_init_script("""
            window.alert = function(msg) {
                try {
                    console.log('ALERT CALLED');
                    
                    // 1. Visual Proof
                    const div = document.createElement('div');
                    div.id = 'xss-proof-banner';
                    div.style.position = 'fixed';
                    div.style.top = '20px';
                    div.style.left = '50%';
                    div.style.transform = 'translateX(-50%)';
                    div.style.zIndex = '2147483647';
                    div.style.background = '#dc2626';
                    div.style.color = 'white';
                    div.style.padding = '20px 40px';
                    div.style.fontSize = '24px';
                    div.style.border = '4px solid white';
                    div.innerText = '⚠️ BUGTRACE: XSS EXECUTED (' + msg + ')';
                    document.body.appendChild(div);
                    
                    // 2. Logic Proof
                    window.bugtrace_xss_callback(msg);
                } catch(e) { console.error(e); }
            };
        """)
        
        print(f"Navigating to {file_url}")
        await page.goto(file_url)
        await page.wait_for_timeout(2000)
        
        await page.screenshot(path="xss_test_proof.png")
        print(f"Screenshot saved. Triggered: {triggered}")
        
        await browser.close()
        
if __name__ == "__main__":
    asyncio.run(test_verify())
