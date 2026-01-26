import asyncio
import jwt
from bugtrace.agents.jwt_agent import run_jwt_analysis

async def test_jwt_agent():
    # 1. Create a vulnerable JWT (None Algorithm)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "guest", "admin": False}
    # Standard token
    token = jwt.encode(payload, "secret", algorithm="HS256")
    
    print(f"Testing JWTAgent with token: {token}")
    
    # 2. Run analysis
    await run_jwt_analysis(token, "https://juice-shop.herokuapp.com/")
    
    print("Test complete. Check logs for agent 'thinking' and findings.")

if __name__ == "__main__":
    asyncio.run(test_jwt_agent())
