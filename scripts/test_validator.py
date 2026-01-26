import asyncio
import os
import sys
from pathlib import Path
from loguru import logger

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bugtrace.agents.validator import ValidatorAgent

async def test_validator():
    print("Testing ValidatorAgent...")
    
    # Mock finding (known vulnerable endpoint)
    # testphp.vulnweb.com is a safe target for this
    finding = {
        "title": "Reflected XSS Test",
        "type": "XSS",
        "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "payload": "<script>alert('XSS')</script>",
        "validated": False,
        "severity": "High",
        "metadata": {"payload": "<script>alert('XSS')</script>"}
    }
    
    # Setup logger sink as per team.py
    log_file = Path("validation_test.log")
    if log_file.exists(): log_file.unlink()
    
    logger.add(log_file, filter=lambda r: "ValidatorAgent" in r["message"] or "Validating" in r["message"])
    
    agent = ValidatorAgent()
    await agent.start()
    
    print(f"Validating finding: {finding['url']} with payload {finding['payload']}")
    # This should trigger browser validation
    results = await agent.validate_batch([finding])
    
    await agent.stop()
    
    print("\n--- Results ---")
    for f in results:
        print(f"Title: {f['title']}")
        print(f"Validated: {f.get('validated')}")
        print(f"Screenshot: {f.get('screenshot_path')}")
        if f.get('evidence'):
            print(f"Evidence Count: {len(f['evidence'])}")
    
    print("\n--- Log File Check ---")
    if log_file.exists():
        print(f"Log file {log_file} exists.")
        with open(log_file, "r") as f:
            content = f.read()
            if content:
                print(f"Log content ({len(content)} chars) captured.")
            else:
                print("Log file is empty.")
    else:
        print("Log file NOT created.")

if __name__ == "__main__":
    asyncio.run(test_validator())
