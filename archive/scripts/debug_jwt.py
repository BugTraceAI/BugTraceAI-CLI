import asyncio
import json
import base64
from bugtrace.agents.jwt_agent import JWTAgent

async def main():
    # URL: http://127.0.0.1:5150/v1/auth/callback?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEwMSwicm9sZSI6Imd1ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEwMSwicm9sZSI6Imd1ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    url = "http://127.0.0.1:5150/v1/auth/callback"
    location = "manual"
    
    agent = JWTAgent()
    
    # Mocking think
    agent.think = lambda msg: print(f"THINK: {msg}")
    
    print("Testing 'none' algorithm...")
    await agent._check_none_algorithm(token, url, location)
    
    print(f"Findings: {agent.findings}")

if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.getcwd())
    asyncio.run(main())
