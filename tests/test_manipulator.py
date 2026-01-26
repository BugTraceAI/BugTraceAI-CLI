import asyncio
import sys
import os

# Ensure project root is in path
sys.path.append(os.getcwd())

from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

async def main():
    print("Initializing Manipulator...")
    manipulator = ManipulatorOrchestrator()

    # Create a dummy request
    target_url = "http://localhost:8000/search" # Mock target
    req = MutableRequest(
        method="GET",
        url=target_url,
        params={"q": "test", "id": "123"},
        headers={"User-Agent": "BugTraceAI/1.0"}
    )
    
    print(f"Targeting: {req.to_curl()}")
    
    # Run campaign
    strategies = [
        MutationStrategy.PAYLOAD_INJECTION,
        MutationStrategy.BYPASS_WAF
    ]
    
    print("Starting campaign (Mock Request Controller will fail connection to localhost usually, but logic runs)...")
    try:
        success = await manipulator.process_finding(req, strategies)
        print(f"Campaign finished. Success: {success}")
    except Exception as e:
        print(f"Campaign threw exception as expected (no server): {e}")
    finally:
        await manipulator.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
