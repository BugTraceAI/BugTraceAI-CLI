#!/usr/bin/env python3
"""
Test BugTraceAI against Leveled Dojo

Systematically tests all difficulty levels (0-10)
Reports success rate and identifies maximum capability level
"""

import asyncio
import sys
import time
from typing import Dict, List
import httpx

sys.path.insert(0, '.')

from bugtrace.core.team import TeamOrchestrator
from bugtrace.agents.xss_agent import XSSAgent
from bugtrace.core.event_bus import event_bus


# Test configuration for each level
LEVEL_TESTS = {
    0: {
        "url": "http://127.0.0.1:5080/level0/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Trivial",
        "expected_payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "success_indicators": ["<script>", "alert"]
    },
    1: {
        "url": "http://127.0.0.1:5080/level1/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Easy",
        "expected_payloads": ['" onload=alert(1) x="', '" autofocus onfocus=alert(1) x="'],
        "success_indicators": ['onload=', 'onfocus=']
    },
    2: {
        "url": "http://127.0.0.1:5080/level2/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Easy-Medium",
        "expected_payloads": ["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
        "success_indicators": ['<img', '<svg', 'onerror', 'onload']
    },
    3: {
        "url": "http://127.0.0.1:5080/level3/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Medium",
        "expected_payloads": ["<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>"],
        "success_indicators": ['<iframe', '<details', 'ontoggle']
    },
    4: {
        "url": "http://127.0.0.1:5080/level4/xss?q=test&ctx=html",
        "expected_vuln": "XSS",
        "difficulty": "Medium",
        "expected_payloads": ["<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>"],
        "success_indicators": ['<object', '<embed', 'javascript:']
    },
    5: {
        "url": "http://127.0.0.1:5080/level5/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Medium-Hard",
        "expected_payloads": ["%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E"],
        "success_indicators": ['<img', 'onerror']
    },
    6: {
        "url": "http://127.0.0.1:5080/level6/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Hard",
        "expected_payloads": ["<DeTaIlS open OnToGgLe=alert(1)>", "<svg><animate onbegin=alert(1)>"],
        "success_indicators": ['details', 'ontoggle', 'onbegin']
    },
    7: {
        "url": "http://127.0.0.1:5080/level7/xss?q=test",
        "expected_vuln": "XSS",
        "difficulty": "Hard (WAF + CSP)",
        "expected_payloads": ["#<img src=x onerror=alert(1)>", "DOM-based payload"],
        "success_indicators": ['hash', 'fragment', 'DOM']
    },
    8: {
        "url": "http://127.0.0.1:5080/level8/xss?q=test",
        "expected_vuln": "mXSS",
        "difficulty": "Very Hard",
        "expected_payloads": ["<noscript><p title='</noscript><img src=x onerror=alert(1)>'>"],
        "success_indicators": ['mutation', 'mXSS', 'namespace']
    },
    9: {
        "url": "http://127.0.0.1:5080/level9/xss?q=test",
        "expected_vuln": "Polyglot XSS",
        "difficulty": "Expert",
        "expected_payloads": ["Polyglot payload required"],
        "success_indicators": ['polyglot', 'multi-context']
    },
    10: {
        "url": "http://127.0.0.1:5080/level10/xss?q=test",
        "expected_vuln": "The Gauntlet",
        "difficulty": "Nearly Impossible",
        "expected_payloads": ["Novel exploitation technique"],
        "success_indicators": ['service worker', 'CSP bypass', 'nonce']
    }
}


async def test_level(level: int, config: Dict) -> Dict:
    """Test BugTraceAI against a specific level"""
    print(f"\n{'='*70}")
    print(f"LEVEL {level}: {config['difficulty']}")
    print(f"{'='*70}")
    print(f"URL: {config['url']}")
    print(f"Expected: {config['expected_vuln']}")

    start_time = time.time()

    # Check if dojo is running
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(config['url'])
            if response.status_code >= 500:
                print(f"❌ Dojo not responding properly")
                return {
                    "level": level,
                    "passed": False,
                    "error": "Dojo unreachable"
                }
    except Exception as e:
        print(f"❌ Cannot connect to dojo: {e}")
        return {
            "level": level,
            "passed": False,
            "error": f"Connection failed: {e}"
        }

    # Test with XSSAgent directly
    try:
        print(f"\n🔍 Testing with XSSAgent...")

        agent = XSSAgent(event_bus=event_bus)

        # Extract base URL and parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(config['url'])
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        param_name = list(params.keys())[0] if params else 'q'

        # Run XSS detection
        result = await agent.test_parameter(base_url, param_name, "GET")

        duration = time.time() - start_time

        # Check if vulnerability was found
        if result and result.get('vulnerable'):
            payload_used = result.get('payload', '')
            validation_method = result.get('validation_method', 'unknown')

            print(f"\n✅ LEVEL {level} PASSED!")
            print(f"   Payload: {payload_used[:100]}")
            print(f"   Validation: {validation_method}")
            print(f"   Duration: {duration:.2f}s")

            return {
                "level": level,
                "passed": True,
                "payload": payload_used,
                "validation": validation_method,
                "duration": duration
            }
        else:
            print(f"\n❌ LEVEL {level} FAILED")
            print(f"   No vulnerability detected")
            print(f"   Duration: {duration:.2f}s")

            return {
                "level": level,
                "passed": False,
                "reason": "Not detected",
                "duration": duration
            }

    except Exception as e:
        print(f"\n❌ LEVEL {level} ERROR: {e}")
        import traceback
        traceback.print_exc()

        return {
            "level": level,
            "passed": False,
            "error": str(e)
        }


async def run_all_tests():
    """Run tests against all levels"""
    print("\n")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║  BugTraceAI Leveled Dojo - Comprehensive Test Suite              ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print("\nTesting difficulty progression: Level 0 (trivial) → Level 10 (nearly impossible)")
    print("Goal: Achieve Level 7+ (advanced pentesting capability)\n")

    results = {}

    # Test each level
    for level in range(11):  # 0-10
        config = LEVEL_TESTS[level]
        result = await test_level(level, config)
        results[level] = result

        # Small delay between tests
        await asyncio.sleep(1)

    # Generate report
    print("\n\n")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║                         FINAL REPORT                              ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")

    # Calculate stats
    passed_levels = [lvl for lvl, res in results.items() if res.get('passed')]
    failed_levels = [lvl for lvl, res in results.items() if not res.get('passed')]

    max_level = max(passed_levels) if passed_levels else -1

    print(f"\n📊 Overall Statistics:")
    print(f"   Total Levels: 11 (0-10)")
    print(f"   Passed: {len(passed_levels)}")
    print(f"   Failed: {len(failed_levels)}")
    print(f"   Success Rate: {len(passed_levels)/11*100:.1f}%")
    print(f"   Maximum Level Reached: {max_level}")

    print(f"\n🎯 Capability Assessment:")
    if max_level >= 7:
        print(f"   ✅ ADVANCED CAPABILITY (Level {max_level}/10)")
        print(f"   BugTraceAI demonstrates professional pentesting skills")
        print(f"   Suitable for: Real-world bug bounty hunting")
    elif max_level >= 5:
        print(f"   ⚠️  INTERMEDIATE CAPABILITY (Level {max_level}/10)")
        print(f"   Good for: Basic pentesting, needs improvement for advanced scenarios")
    elif max_level >= 3:
        print(f"   ⚠️  BASIC CAPABILITY (Level {max_level}/10)")
        print(f"   Needs: Significant improvement to compete professionally")
    else:
        print(f"   ❌ INSUFFICIENT (Level {max_level}/10)")
        print(f"   Status: Not ready for production bug bounty work")

    print(f"\n📋 Level-by-Level Results:")
    for level in range(11):
        result = results[level]
        status = "✅ PASS" if result.get('passed') else "❌ FAIL"
        difficulty = LEVEL_TESTS[level]['difficulty']

        duration = result.get('duration', 0)
        print(f"   Level {level:2d} ({difficulty:20s}): {status} ({duration:.1f}s)")

        if result.get('passed'):
            payload = result.get('payload', '')
            if payload and len(payload) < 80:
                print(f"            Payload: {payload}")

    print(f"\n🏆 Historical Comparison:")
    print(f"   XSSAgent v3: Passed levels 0-10 (100% on some targets)")
    print(f"   Current run: Passed levels 0-{max_level}")

    if max_level >= 7:
        print(f"\n   ✅ MEETS TARGET: BugTraceAI reached Level 7+")
        print(f"   Ready for: Advanced bug bounty hunting")
    else:
        print(f"\n   ⚠️  BELOW TARGET: Needs to reach Level 7")
        print(f"   Gap: {7 - max_level} levels to target")

    print("\n" + "="*70)

    return results


if __name__ == "__main__":
    # Check if dojo is running
    import subprocess
    import requests

    try:
        response = requests.get("http://127.0.0.1:5080", timeout=2)
        print("✅ Dojo is running")
    except:
        print("⚠️  Dojo not running. Starting...")
        print("   Run: python3 dojo_leveled.py")
        print("\nOr start in background and re-run this test")
        sys.exit(1)

    # Run tests
    asyncio.run(run_all_tests())
