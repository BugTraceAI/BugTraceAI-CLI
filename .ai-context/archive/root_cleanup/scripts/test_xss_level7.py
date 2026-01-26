#!/usr/bin/env python3
"""
Quick test for XSS Level 7 (WAF + CSP + DOM XSS)
This tests the new Fragment XSS capability
"""
import asyncio
from bugtrace.agents.xss_agent import XSSAgent
from pathlib import Path

async def test_level_7():
    print("\n" + "="*60)
    print("🎯 Testing XSS Level 7: WAF + CSP + DOM XSS (Fragment Bypass)")
    print("="*60 + "\n")
    
    url = "http://127.0.0.1:5090/xss/level7?q=test"
    
    agent = XSSAgent(
        url=url,
        params=["q"],
        report_dir=Path("./reports/xss_level7_test"),
        headless=True
    )
    
    result = await agent.run_loop()
    
    print("\n" + "="*60)
    print("📊 RESULTS")
    print("="*60)
    print(f"Findings: {result.get('validated_count', 0)}")
    print(f"Status: {'✅ PASSED' if result.get('validated_count', 0) > 0 else '❌ FAILED'}")
    
    if result.get('findings'):
        for finding in result['findings']:
            print(f"\n🎯 XSS Found:")
            print(f"   Parameter: {finding['parameter']}")
            print(f"   Payload: {finding['payload']}")
            print(f"   Context: {finding['context']}")
            print(f"   Method: {finding['validation_method']}")
    
    return result.get('validated_count', 0) > 0

if __name__ == "__main__":
    success = asyncio.run(test_level_7())
    exit(0 if success else 1)
