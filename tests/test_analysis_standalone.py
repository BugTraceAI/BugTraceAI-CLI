"""
AnalysisAgent Standalone Test
Tests multi-model URL analysis without ExploitAgent integration.

This validates Phase 1 implementation is working correctly.
"""

import asyncio
from bugtrace.agents.analysis import AnalysisAgent
from bugtrace.core.event_bus import EventBus
from bugtrace.utils.logger import get_logger

logger = get_logger("test_analysis")


async def test_analysis_agent():
    """Test AnalysisAgent with simulated URL."""
    
    print("="*70)
    print("🧪 ANALYSIS AGENT STANDALONE TEST")
    print("="*70)
    print()
    
    # Initialize
    event_bus = EventBus()
    agent = AnalysisAgent(event_bus)
    
    print("✅ AnalysisAgent initialized")
    print(f"   Approaches: {agent.approaches}")
    print(f"   Model: {agent.model}")
    print(f"   Confidence threshold: {agent.confidence_threshold}")
    print(f"   Consensus votes: {agent.consensus_votes}")
    print()
    
    # Simulate URL discovery event
    print("📡 Simulating URL discovery event...")
    print()
    
    test_event = {
        "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "response": None  # No response object in this test
    }
    
    print(f"   URL: {test_event['url']}")
    print(f"   Has response: {test_event['response'] is not None}")
    print()
    
    # Start analysis
    print("🔍 Starting 5-approach analysis...")
    print("   This will call 5 approaches with Gemini 2.5 Flash:")
    print("   - Pentester (OSCP/OSCE focus)")
    print("   - Bug Bounty Hunter (High-severity)")
    print("   - Code Auditor (Static analysis)")
    print("   - Red Team (Attack chains)")
    print("   - Security Researcher (Novel vulns)")
    print()
    
    try:
        report = await agent.analyze_url(test_event)
        
        print("="*70)
        print("✅ ANALYSIS COMPLETE")
        print("="*70)
        print()
        
        # Display report
        print("📊 ANALYSIS REPORT:")
        print(f"   URL: {report.get('url')}")
        print(f"   Framework: {report.get('framework_detected')}")
        print(f"   Tech Stack: {report.get('tech_stack')}")
        print()
        
        print("🎯 CONSENSUS VULNERABILITIES:")
        consensus = report.get('consensus_vulns', [])
        if consensus:
            for vuln in consensus:
                print(f"   - {vuln['type']}")
                print(f"     Confidence: {vuln['confidence']:.2f}")
                print(f"     Votes: {vuln['votes']}/{len(agent.approaches)}")
                print(f"     Locations: {vuln['locations']}")
                print()
        else:
            print("   (none - requires 2+ models to agree)")
            print()
        
        print("💡 POSSIBLE VULNERABILITIES:")
        possible = report.get('possible_vulns', [])
        if possible:
            for vuln in possible:
                print(f"   - {vuln['type']}")
                print(f"     Confidence: {vuln['confidence']:.2f}")
                print(f"     Votes: {vuln['votes']}")
                print()
        else:
            print("   (none)")
            print()
        
        print("🚀 ATTACK PRIORITY:")
        priority = report.get('attack_priority', [])
        if priority:
            for i, vuln in enumerate(priority, 1):
                print(f"   {i}. {vuln}")
        else:
            print("   (no high-confidence vulnerabilities)")
        print()
        
        print("⏭️  SKIP TESTS:")
        skip = report.get('skip_tests', [])
        if skip:
            for vuln in skip:
                print(f"   - {vuln}")
        else:
            print("   (none)")
        print()
        
        # Statistics
        print("📈 STATISTICS:")
        stats = agent.get_statistics()
        print(f"   URLs analyzed: {stats['urls_analyzed']}")
        print(f"   Consensus count: {stats['consensus_count']}")
        print(f"   Avg analysis time: {stats['avg_analysis_time']:.2f}s")
        print(f"   Cache size: {stats['cache_size']}")
        print()
        
        print("="*70)
        print("✅ TEST PASSED")
        print("="*70)
        
        return report
        
    except Exception as e:
        print("="*70)
        print("❌ TEST FAILED")
        print("="*70)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    # Run test
    result = asyncio.run(test_analysis_agent())
    
    if result:
        print()
        print("🎉 AnalysisAgent is working correctly!")
        print()
        print("Next steps:")
        print("  1. Fix ExploitAgent integration")
        print("  2. Test full pipeline")
        print("  3. Run against testphp.vulnweb.com")
    else:
        print()
        print("⚠️  AnalysisAgent needs debugging")
