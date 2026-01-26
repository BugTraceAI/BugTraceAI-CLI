import asyncio
import os
import shutil
from pathlib import Path
from bugtrace.core.reactor import Reactor

async def main():
    print("🧪 Starting Mixed Challenges Front App Test...")
    
    # 1. Clean previous state
    if os.path.exists("state/jobs.db"):
        os.remove("state/jobs.db")
    if os.path.exists("reports/jobs"):
        shutil.rmtree("reports/jobs")
    
    # 2. Target our new Mixed Front App
    target = "http://127.0.0.1:5095"
    reactor = Reactor(target)
    
    print(f"☢️  Reactor Targeting: {target}")
    print("☢️  This app has MIXED vulnerabilities and DECOYS to test the Brain (Orchestrator).")
    print("☢️  Starting Reaction Loop...")
    
    await reactor.run()

if __name__ == "__main__":
    asyncio.run(main())
