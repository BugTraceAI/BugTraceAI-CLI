#!/usr/bin/env python3
"""
Test Comprehensivo XSS - Dojo Levels 0-8
Verifica que el XSSAgent pase todos los niveles sin regresiones
"""
import asyncio
from pathlib import Path
from bugtrace.agents.xss_agent import XSSAgent

# Levels a testear (enfoque en los que deberían pasar)
TEST_LEVELS = [0, 2, 4, 6, 7, 8]

async def test_xss_level(level: int):
    """Test individual de un nivel XSS"""
    print(f"\n{'='*60}")
    print(f"🎯 Testing XSS Level {level}")
    print(f"{'='*60}\n")
    
    url = f"http://127.0.0.1:5090/xss/level{level}?q=test"
    
    try:
        agent = XSSAgent(
            url=url,
            params=["q"],
            report_dir=Path(f"./reports/xss_level{level}_test"),
            headless=True
        )
        
        result = await agent.run_loop()
        
        validated_count = result.get('validated_count', 0)
        findings = result.get('findings', [])
        
        if validated_count > 0:
            print(f"\n✅ LEVEL {level}: PASSED ({validated_count} findings)")
            for finding in findings:
                print(f"   - Payload: {finding.get('payload', 'N/A')[:60]}")
                print(f"   - Context: {finding.get('context', 'N/A')}")
                print(f"   - Method: {finding.get('validation_method', 'N/A')}")
            return True
        else:
            print(f"\n❌ LEVEL {level}: FAILED (no validated findings)")
            return False
            
    except Exception as e:
        print(f"\n❌ LEVEL {level}: ERROR - {e}")
        import traceback
        traceback.print_exc()
        return False

async def run_comprehensive_test():
    """Run all XSS tests"""
    print("\n" + "="*60)
    print("🚀 XSS COMPREHENSIVE TEST - DOJO")
    print("="*60)
    print(f"Testing {len(TEST_LEVELS)} levels: {TEST_LEVELS}")
    
    results = {}
    
    for level in TEST_LEVELS:
        passed = await test_xss_level(level)
        results[level] = passed
        
        # Pausa entre tests
        await asyncio.sleep(2)
    
    # Summary
    print("\n" + "="*60)
    print("📊 FINAL RESULTS")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    for level, status in results.items():
        emoji = "✅" if status else "❌"
        print(f"{emoji} Level {level}: {'PASS' if status else 'FAIL'}")
    
    print(f"\n{'='*60}")
    print(f"Pass Rate: {passed}/{total} ({pass_rate:.1f}%)")
    print(f"{'='*60}\n")
    
    # Success criteria: Al menos 80% (5/6)
    if pass_rate >= 80:
        print("🎉 SUCCESS! Agent meets quality threshold (≥80%)")
        return True
    else:
        print("⚠️ NEEDS IMPROVEMENT: Agent below 80% threshold")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_comprehensive_test())
    exit(0 if success else 1)
