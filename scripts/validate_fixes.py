
import asyncio
from loguru import logger
import sys

# Add project root to path
sys.path.append(".")

async def test_interactsh_access():
    print("Testing Interactsh Access...")
    from bugtrace.tools.interactsh import InteractshClient
    
    client = InteractshClient()
    print("Registering...")
    success = await client.register()
    
    if not success:
        print("❌ Registration failed!")
        return
        
    print(f"✅ Registered. Correlation ID: {client.correlation_id}")
    
    # Test the fixed method
    try:
        url = client.get_url("test_key")
        print(f"✅ get_url() success: {url}")
    except Exception as e:
        print(f"❌ get_url() failed: {e}")

    # Test attribute access (regression check)
    try:
        dom = client.domain
        print(f"❌ client.domain exists (Unexpected): {dom}")
    except AttributeError:
        print("✅ client.domain does NOT exist (Correct)")
        
    await client.deregister()

async def test_xss_agent_instantiation():
    print("\nTesting XSSAgentV3 Instantiation...")
    try:
        from bugtrace.agents.xss_agent_v3 import XSSAgentV3
        from pathlib import Path
        
        agent = XSSAgentV3("http://example.com", params=["q"], report_dir=Path("./reports"))
        
        # Verify run_loop exists
        if hasattr(agent, "run_loop"):
            print("✅ run_loop method exists")
        else:
            print("❌ run_loop method MISSING")
            
        print("✅ XSSAgentV3 Instantiated successfully")
        
    except Exception as e:
        print(f"❌ Instantiation failed: {e}")

async def main():
    await test_interactsh_access()
    await test_xss_agent_instantiation()

if __name__ == "__main__":
    asyncio.run(main())
