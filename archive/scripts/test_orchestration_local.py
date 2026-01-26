import asyncio
import os
import shutil
from pathlib import Path
from bugtrace.core.reactor import Reactor

async def main():
    print("🥋 Starting Local Orchestration Test against Dojo...")
    
    # Clean previous state to ensure fresh discovery
    if os.path.exists("state/jobs.db"):
        os.remove("state/jobs.db")
    if os.path.exists("reports/jobs"):
        shutil.rmtree("reports/jobs")
    
    # Target our local Dojo
    target = "http://127.0.0.1:5090"
    reactor = Reactor(target)
    
    print(f"☢️  Reactor Targeting: {target}")
    print("☢️  Starting Reaction Loop (Discovery -> Analysis -> Attack)...")
    
    # We'll run it in the background or just start it
    await reactor.run()

if __name__ == "__main__":
    asyncio.run(main())
