import asyncio
import aiohttp
from bugtrace.agents.idor_agent import IDORAgent

async def main():
    url = "http://127.0.0.1:5150/v1/billing/101/view"
    param = "ID"
    val = "101"
    
    agent = IDORAgent(url, param, val)
    result = await agent.run_loop()
    print(f"Result: {result}")

if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.getcwd())
    asyncio.run(main())
