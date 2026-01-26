import asyncio
import aiohttp
from bugtrace.agents.lfi_agent import LFIAgent

async def main():
    url = "http://127.0.0.1:5150/v1/backup/download?path=backup.zip"
    param = "path"
    
    agent = LFIAgent(url, param)
    
    # Mock _test_payload to log URLs
    original_test = agent._test_payload
    async def mocked_test(session, p):
        target = agent._inject_payload(agent.url, agent.param, p)
        print(f"Testing URL: {target}")
        res = await original_test(session, p)
        if res:
            print(f"  [+] SUCCESS with {p}")
        return res
    
    agent._test_payload = mocked_test
    
    result = await agent.run_loop()
    print(f"Final Result: {result}")

if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.getcwd())
    asyncio.run(main())
