#!/usr/bin/env python3
"""
Integration test for the new compact UI with real components
"""
import asyncio
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from rich.live import Live

async def test_integration():
    """Test that UI integrates with LLMClient"""
    
    # Simulate initial setup
    dashboard.set_target("test.example.com")
    dashboard.set_phase("TESTING")
    dashboard.current_agent = "TestAgent"
    
    # Test LLMClient integration
    print("Testing LLMClient balance integration...")
    await llm_client.update_balance()
    print(f"✅ Balance captured: ${dashboard.credits:.2f}")
    
    # Simulate a scan
    with Live(dashboard, refresh_per_second=4, screen=False) as live:
        dashboard.log("🚀 Integration test started", "INFO")
        
        # Simulate payload testing
        for i in range(5):
            dashboard.set_current_payload(
                payload=f"<script>alert('test_{i}')</script>",
                vector=f"input#field_{i}",
                status="⏳ Testing" if i < 3 else "✓ Success",
                agent="ExploitAgent"
            )
            
            dashboard.payloads_tested = i + 1
            if i >= 3:
                dashboard.payloads_success += 1
            else:
                dashboard.payloads_failed += 1
            
            # Update cost
            dashboard.session_cost += 0.02
            dashboard.total_requests += 1
            
            # Add logs
            dashboard.log(f"Testing payload #{i+1}", "INFO")
            
            # Add findings
            if i == 2:
                dashboard.add_finding("XSS", f"input#field_{i}", "HIGH")
            
            await asyncio.sleep(1)
        
        dashboard.log("✅ Integration test complete", "SUCCESS")
        await asyncio.sleep(2)
    
    print("\n" + "="*60)
    print("✅ Integration Test Completed Successfully!")
    print(f"   - Balance: ${dashboard.credits:.2f}")
    print(f"   - Cost: ${dashboard.session_cost:.2f}")
    print(f"   - Requests: {dashboard.total_requests}")
    print(f"   - Payloads Tested: {dashboard.payloads_tested}")
    print(f"   - Findings: {len(dashboard.findings)}")
    print(f"   - CPU: {dashboard.cpu_usage:.1f}%")
    print(f"   - RAM: {dashboard.ram_usage:.1f}%")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(test_integration())
