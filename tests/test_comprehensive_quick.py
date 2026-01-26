#!/usr/bin/env python3
"""
Quick Test: BugTraceAI vs Comprehensive Dojo

Tests a sample of levels from each vulnerability type to get quick assessment
"""

import asyncio
import sys
import time
sys.path.insert(0, '.')

from bugtrace.agents.xss_agent import XSSAgent
from bugtrace.tools.exploitation.sqli import SQLInjectionDetector
from bugtrace.core.event_bus import event_bus
import httpx


async def test_xss_levels():
    """Test XSS agent against various difficulty levels"""
    print("\n" + "="*70)
    print("XSS AGENT TESTING")
    print("="*70)

    test_cases = [
        (0, "http://127.0.0.1:5090/xss/level0?q=test", "Trivial - No protection"),
        (2, "http://127.0.0.1:5090/xss/level2?q=test", "Easy - Script blacklist"),
        (4, "http://127.0.0.1:5090/xss/level4?q=test", "Medium - Context aware"),
        (6, "http://127.0.0.1:5090/xss/level6?q=test", "Hard - Basic WAF"),
        (7, "http://127.0.0.1:5090/xss/level7?q=test", "Hard - WAF + CSP (TARGET)"),
    ]

    results = []

    for level, url, description in test_cases:
        print(f"\n🔍 Testing Level {level}: {description}")
        print(f"   URL: {url}")

        start = time.time()
        try:
            # Create XSSAgent instance with URL and params
            agent = XSSAgent(url=url, params=['q'], event_bus=event_bus, headless=True)

            # Run the agent
            result = await agent.run_loop()
            duration = time.time() - start

            # XSS Agent returns 'findings', not 'vulnerabilities'
            if result and result.get('findings'):
                findings = result['findings']
                print(f"   ✅ PASSED - Found {len(findings)} XSS in {duration:.1f}s")
                if findings:
                    payload = findings[0].get('payload', '')[:80]
                    print(f"   Payload: {payload}")
                results.append({'level': level, 'passed': True, 'time': duration, 'vulns': len(findings)})
            else:
                print(f"   ❌ FAILED - No XSS detected ({duration:.1f}s)")
                print(f"   DEBUG: result={result}")
                results.append({'level': level, 'passed': False, 'time': duration})

        except Exception as e:
            duration = time.time() - start
            print(f"   ❌ ERROR: {str(e)[:100]}")
            results.append({'level': level, 'passed': False, 'time': duration, 'error': str(e)})

        await asyncio.sleep(1)

    return results


async def test_sqli_levels():
    """Test SQLi detection against various difficulty levels"""
    print("\n" + "="*70)
    print("SQLi DETECTION TESTING")
    print("="*70)

    detector = SQLInjectionDetector()

    test_cases = [
        (0, "http://127.0.0.1:5090/sqli/level0?id=1", "Trivial - Error-based"),
        (2, "http://127.0.0.1:5090/sqli/level2?id=1", "Easy - Quote blocking"),
        (4, "http://127.0.0.1:5090/sqli/level4?id=1", "Medium - Prepared statements"),
        (6, "http://127.0.0.1:5090/sqli/level6?id=1", "Hard - Time-based blind"),
        (7, "http://127.0.0.1:5090/sqli/level7?id=1", "Hard - Advanced WAF (TARGET)"),
    ]

    results = []

    for level, url, description in test_cases:
        print(f"\n🔍 Testing Level {level}: {description}")
        print(f"   URL: {url}")

        start = time.time()
        try:
            # Test for SQLi using .check() method which returns (message, screenshot_path) or None
            result = await detector.check(url)
            duration = time.time() - start

            if result:
                msg, screenshot = result
                print(f"   ✅ PASSED - Found SQLi in {duration:.1f}s")
                print(f"   Detection: {msg}")
                results.append({'level': level, 'passed': True, 'time': duration, 'message': msg})
            else:
                print(f"   ❌ FAILED - No SQLi detected ({duration:.1f}s)")
                results.append({'level': level, 'passed': False, 'time': duration})

        except Exception as e:
            print(f"   ❌ ERROR: {str(e)[:100]}")
            results.append({'level': level, 'passed': False, 'error': str(e)})

        await asyncio.sleep(1)

    return results


async def test_basic_connectivity():
    """Test basic connectivity to all vulnerability types"""
    print("\n" + "="*70)
    print("BASIC CONNECTIVITY TEST")
    print("="*70)

    endpoints = [
        ("/xss/level0?q=test", "XSS"),
        ("/sqli/level0?id=1", "SQLi"),
        ("/ssrf/level0?url=http://example.com", "SSRF"),
        ("/upload/level0", "File Upload"),
        ("/csti/level0?name=test", "CSTI"),
        ("/jwt/level0?token=test", "JWT"),
        ("/idor/level0?id=1", "IDOR"),
    ]

    async with httpx.AsyncClient(timeout=5) as client:
        for path, vuln_type in endpoints:
            url = f"http://127.0.0.1:5090{path}"
            try:
                response = await client.get(url)
                if response.status_code < 500:
                    print(f"✅ {vuln_type:15s} - Endpoint responding ({response.status_code})")
                else:
                    print(f"❌ {vuln_type:15s} - Server error ({response.status_code})")
            except Exception as e:
                print(f"❌ {vuln_type:15s} - Connection failed: {str(e)[:50]}")


async def main():
    """Run quick comprehensive test"""
    print("\n")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║  BugTraceAI vs Comprehensive Dojo - Quick Assessment             ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")

    # Test connectivity
    await test_basic_connectivity()

    # Test XSS
    xss_results = await test_xss_levels()

    # Test SQLi
    sqli_results = await test_sqli_levels()

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    xss_passed = sum(1 for r in xss_results if r.get('passed'))
    sqli_passed = sum(1 for r in sqli_results if r.get('passed'))

    print(f"\n📊 XSS Agent:")
    print(f"   Tested: {len(xss_results)} levels")
    print(f"   Passed: {xss_passed}/{len(xss_results)}")
    print(f"   Success Rate: {xss_passed/len(xss_results)*100:.1f}%")

    max_xss_level = max([r['level'] for r in xss_results if r.get('passed')], default=-1)
    print(f"   Max Level: {max_xss_level}")

    if max_xss_level >= 7:
        print(f"   ✅ MEETS TARGET (Level 7+)")
    elif max_xss_level >= 5:
        print(f"   ⚠️  INTERMEDIATE (Level {max_xss_level})")
    else:
        print(f"   ❌ BELOW TARGET (Level {max_xss_level})")

    print(f"\n📊 SQLi Detection:")
    print(f"   Tested: {len(sqli_results)} levels")
    print(f"   Passed: {sqli_passed}/{len(sqli_results)}")
    print(f"   Success Rate: {sqli_passed/len(sqli_results)*100:.1f}%")

    max_sqli_level = max([r['level'] for r in sqli_results if r.get('passed')], default=-1)
    print(f"   Max Level: {max_sqli_level}")

    if max_sqli_level >= 7:
        print(f"   ✅ MEETS TARGET (Level 7+)")
    elif max_sqli_level >= 5:
        print(f"   ⚠️  INTERMEDIATE (Level {max_sqli_level})")
    else:
        print(f"   ❌ BELOW TARGET (Level {max_sqli_level})")

    print("\n" + "="*70)
    print("📝 RECOMMENDATION:")
    if max_xss_level >= 7 and max_sqli_level >= 7:
        print("✅ BugTraceAI is performing at professional pentesting level!")
        print("   Ready for real-world bug bounty hunting")
    elif max_xss_level >= 5 or max_sqli_level >= 5:
        print("⚠️  BugTraceAI shows intermediate capability")
        print("   Needs improvement to reach Level 7 target")
        print(f"   XSS gap: {7 - max_xss_level} levels")
        print(f"   SQLi gap: {7 - max_sqli_level} levels")
    else:
        print("❌ BugTraceAI needs significant improvement")
        print("   Current capability below professional pentesting level")

    print("="*70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
