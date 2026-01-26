import asyncio
from bugtrace.core.reactor import Reactor

async def main():
    print("🚀 Initializing Reactor V4 (Strix-Eater)...")
    
    # Targeting our local Dojo
    reactor = Reactor("http://127.0.0.1:5090")
    
    print("☢️  Starting Reaction Loop...")
    await reactor.run()
    
    print("✅ Reactor Shutdown. Check sqlite state/jobs.db for results.")

if __name__ == "__main__":
    asyncio.run(main())
