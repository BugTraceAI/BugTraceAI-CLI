#!/usr/bin/env python3
import os
import shutil
import asyncio
import subprocess
import time
from bugtrace.core.reactor import Reactor
from bugtrace.core.config import settings

async def main():
    print("🛑 Cleaning environment...")
    if os.path.exists("state"): shutil.rmtree("state")
    if os.path.exists("logs"):
        for f in os.listdir("logs"):
            if f.endswith(".json") or f.endswith(".log") or f.endswith(".jsonl"):
                try: os.remove(os.path.join("logs", f))
                except: pass
    
    # Ensure UPLOAD_DIR is clear
    UPLOAD_DIR = "/tmp/mega_uploads"
    if os.path.exists(UPLOAD_DIR): shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    print("🚀 Restarting Extreme Dojo (Masterpiece of Suffering)...")
    subprocess.run(["pkill", "-f", "extreme_mixed_dojo.py"])
    time.sleep(1)
    subprocess.Popen(["python3", "testing/extreme_mixed_dojo.py"])
    time.sleep(2)

    target = "http://127.0.0.1:5150"
    print(f"🔥 LAUNCHING SESSION VALIDATION AGAINST {target} 🔥")
    
    # Configure for speed and depth
    settings.MAX_URLS = 30
    settings.ANALYSIS_CONSENSUS_VOTES = 1 # Be aggressive
    settings.MAX_CONCURRENT_REQUESTS = 10 # Parallel AI calls
    settings.EARLY_EXIT_ON_FINDING = False # Force full coverage
    
    reactor = Reactor(target)
    await reactor.run()

if __name__ == "__main__":
    asyncio.run(main())
