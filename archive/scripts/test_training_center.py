import asyncio
import os
import shutil
from pathlib import Path
from bugtrace.core.reactor import Reactor

async def main():
    print("🥋 [TRAINING CENTER] Starting Orchestration Test...")
    
    # 1. Clean previous state
    if os.path.exists("state/jobs.db"):
        os.remove("state/jobs.db")
    if os.path.exists("reports/jobs"):
        shutil.rmtree("reports/jobs")
    
    # 2. Target our new Mixed Training Dojo
    target = "http://127.0.0.1:5100"
    reactor = Reactor(target)
    
    print(f"☢️  Reactor Targeting Training Center: {target}")
    print("☢️  Challenge Mix: 10 URLs (L0-L5) + Decoys.")
    print("☢️  Objective: Observe Orchestration, Context Maintenance, and Hallucination Filtering.")
    print("-" * 60)
    
    await reactor.run()

if __name__ == "__main__":
    asyncio.run(main())
