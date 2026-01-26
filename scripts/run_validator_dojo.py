import asyncio
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.getcwd())

from bugtrace.agents.agentic_validator import AgenticValidator
from bugtrace.core.config import settings

async def test_level_9_validation():
    print("🧙 Initiating AgenticValidator Audit for Dojo Level 9")
    print("="*60)
    
    # We'll try a payload that attempts to breakout or use the context
    # Since Level 9 is quite hard, let's see if the Validator can reason about it.
    
    # Target Level 9 with the backslash-breakout payload
    payload = "\\\");prompt(1)//" 
    target_url = "http://127.0.0.1:5090/xss/level9"
    
    finding = {
        "url": target_url,
        "parameter": "q",
        "payload": payload,
        "type": "xss",
        "evidence": {
            "status": "PENDING_CDP_VALIDATION",
            "context": "script"
        }
    }
    
    # Instantiate Validator
    validator = AgenticValidator()
    
    print(f"🕵️ Auditing finding: {payload} on {target_url}")
    
    try:
        result = await validator.validate_finding_agentically(finding)
        
        print("\n" + "="*60)
        print("🔍 AUDIT RESULT")
        print("="*60)
        print(f"Validated: {'✅ YES' if result.get('validated') else '❌ NO'}")
        print(f"Reasoning: {result.get('reasoning')}")
        if result.get('needs_manual_review'):
            print("⚠️ Recommendation: MANUAL REVIEW REQUIRED")
        
        if result.get('screenshot_path'):
            print(f"📸 Screenshot captured: {result.get('screenshot_path')}")
            
    except Exception as e:
        print(f"❌ Error during audit: {e}")

if __name__ == "__main__":
    asyncio.run(test_level_9_validation())
