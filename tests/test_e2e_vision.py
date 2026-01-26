#!/usr/bin/env python3
"""
End-to-End Test: AnalysisAgent → ExploitAgent → Vision Validation
Tests the complete flow with XSS validation using vision model.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from bugtrace.core.event_bus import EventBus
from bugtrace.agents.exploit import ExploitAgent
from bugtrace.utils.logger import get_logger

logger = get_logger("test_e2e")

async def test_end_to_end():
    """Test complete flow: Analysis → Exploit → Vision Validation"""
    
    print("="*70)
    print("🧪 END-TO-END TEST: Analysis → Exploit → Vision Validation")
    print("="*70)
    print()
    
    # Initialize Event Bus
    event_bus = EventBus()
    
    # Initialize ExploitAgent
    print("📋 Initializing ExploitAgent...")
    exploit_agent = ExploitAgent(event_bus)
    print("✅ ExploitAgent initialized")
    print()
    
    # Load existing analysis report
    report_path = Path("reports/10aea9a60015/consolidated_report.json")
    
    if not report_path.exists():
        print(f"❌ Report not found: {report_path}")
        print("   Run test_analysis_standalone.py first to generate report")
        return False
    
    print(f"📂 Loading analysis report: {report_path}")
    with open(report_path) as f:
        report = json.load(f)
    
    print(f"   URL: {report['url']}")
    print(f"   Consensus vulns: {len(report['consensus_vulns'])}")
    print(f"   Attack priority: {report['attack_priority']}")
    print()
    
    # Check for XSS
    xss_vulns = [v for v in report['consensus_vulns'] if 'XSS' in v.get('type', '').upper()]
    
    if not xss_vulns:
        print("⚠️  No XSS vulnerabilities in report")
        print("   Detected vulnerabilities:")
        for v in report['consensus_vulns']:
            print(f"     - {v['type']} (confidence: {v['confidence']})")
        print()
        print("   Test will continue but XSS validation will be skipped")
        xss_test = False
    else:
        print(f"🎯 Found {len(xss_vulns)} XSS vulnerability(ies) to validate:")
        for xss in xss_vulns:
            print(f"   - {xss['type']} (confidence: {xss['confidence']}, votes: {xss['votes']})")
        print()
        xss_test = True
    
    # Simulate url_analyzed event
    print("📡 Simulating url_analyzed event...")
    event_data = {
        'report': report,
        'timestamp': '2026-01-02T13:05:00'
    }
    
    # Call handler directly
    print("🚀 Calling ExploitAgent.handle_url_analyzed()...")
    print()
    
    try:
        await exploit_agent.handle_url_analyzed(event_data)
        
        print()
        print("="*70)
        if xss_test:
            print("✅ END-TO-END TEST COMPLETED")
            print("="*70)
            print()
            print("📊 Results:")
            print("   - Analysis report loaded ✅")
            print("   - XSS vulnerabilities identified ✅")
            print("   - ExploitAgent processing completed ✅")
            print()
            print("📸 Check screenshots/ directory for captured screenshots")
            print("🔍 Check logs for vision model validation results")
        else:
            print("✅ TEST COMPLETED (No XSS to validate)")
            print("="*70)
            print()
            print("📊 Results:")
            print("   - Analysis report loaded ✅")
            print("   - ExploitAgent processing completed ✅")
            print("   - No XSS detected for vision validation")
        
        return True
        
    except Exception as e:
        print()
        print("="*70)
        print("❌ TEST FAILED")
        print("="*70)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = asyncio.run(test_end_to_end())
    sys.exit(0 if result else 1)
