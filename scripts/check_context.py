#!/usr/bin/env python3
"""
Check what context ginandjuice.shop actually uses
"""
import asyncio
import aiohttp

async def check_reflection_context():
    """Check how the parameter is reflected"""
    
    test_values = [
        ("PROBE123", "Simple text"),
        ("<test>", "HTML tag"),
        ('value="TEST"', "Quoted attribute"),
        ("value=TEST", "Unquoted attribute"),
    ]
    
    print("=" * 70)
    print("CHECKING GINANDJUICE.SHOP REFLECTION CONTEXT")
    print("=" * 70)
    
    async with aiohttp.ClientSession() as session:
        for test_val, description in test_values:
            url = f"https://ginandjuice.shop/catalog?searchTerm={test_val}"
            
            async with session.get(url) as resp:
                html = await resp.text()
                
                print(f"\n[{description}]")
                print(f"  Test: {test_val}")
                print(f"  Reflected: ", end="")
                
                if test_val in html:
                    print(f"✅ YES (raw)")
                    
                    # Find context
                    import re
                    # Look for the reflection context
                    patterns = [
                        (r'value="[^"]*' + re.escape(test_val), "in value attribute (quoted)"),
                        (r'value=[^\s>]*' + re.escape(test_val), "in value attribute (unquoted)"),
                        (r'>[^<]*' + re.escape(test_val), "in HTML text"),
                        (r'<script[^>]*>[^<]*' + re.escape(test_val), "in script tag"),
                    ]
                    
                    for pattern, ctx_desc in patterns:
                        if re.search(pattern, html):
                            print(f"    Context: {ctx_desc}")
                            break
                else:
                    print(f"❌ NO")

if __name__ == "__main__":
    asyncio.run(check_reflection_context())
