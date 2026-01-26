import asyncio
import logging

# Configure logging to show info
logging.basicConfig(level=logging.INFO)

from bugtrace.agents.ssrf_agent import SSRFAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.agents.xxe_agent import XXEAgent
from bugtrace.tools.exploitation.csti import csti_detector

async def test():
    print("\n--- SSRF TEST ---")
    try:
        ssrf = SSRFAgent(url='http://127.0.0.1:5090/ssrf/level0', param='url')
        res = await ssrf.run_loop()
        print(f"SSRF Result: {res}")
    except Exception as e:
        print(f"SSRF Error: {e}")

    print("\n--- XXE TEST ---")
    try:
        xxe = XXEAgent(url='http://127.0.0.1:5090/xxe/level0')
        res = await xxe.run_loop()
        print(f"XXE Result: {res}")
    except Exception as e:
        print(f"XXE Error: {e}")

    print("\n--- FILE UPLOAD TEST ---")
    try:
        fup = FileUploadAgent(url='http://127.0.0.1:5090/upload/level0')
        res = await fup.run_loop()
        print(f"FileUpload Result: {res}")
    except Exception as e:
        print(f"FileUpload Error: {e}")
    
    print("\n--- CSTI TEST ---")
    try:
        csti = await csti_detector.check('http://127.0.0.1:5090/csti/level0?name=test')
        print(f"CSTI Result: {csti}")
    except Exception as e:
        print(f"CSTI Error: {e}")

if __name__ == "__main__":
    asyncio.run(test())
