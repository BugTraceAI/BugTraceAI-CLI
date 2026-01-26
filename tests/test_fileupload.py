import asyncio
import sys
from bugtrace.agents.fileupload_agent import FileUploadAgent

async def test():
    print("Testing FileUploadAgent against local lab...")
    agent = FileUploadAgent("http://127.0.0.1:5006")
    result = await agent.run_loop()
    print("\nFINAL RESULTS:")
    print(result)

if __name__ == "__main__":
    asyncio.run(test())
