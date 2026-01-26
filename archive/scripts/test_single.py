import asyncio
from bugtrace.core.reactor import Reactor
from bugtrace.core.config import settings

async def main():
    targets = [
        "http://127.0.0.1:5150/v1/billing/101/view",
        "http://127.0.0.1:5150/v1/auth/callback?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEwMSwicm9sZSI6Imd1ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "http://127.0.0.1:5150/v1/upload-avatar",
        "http://127.0.0.1:5150/v1/debug/logs?file=app.log&debug=0",
        "http://127.0.0.1:5150/v1/backup/download?path=backup.zip"
    ]
    
    settings.EARLY_EXIT_ON_FINDING = False
    
    reactor = Reactor("http://127.0.0.1:5150") # Use base for session
    
    # Manual add
    for t in targets:
        reactor.job_manager.add_job("ANALYSIS", t, priority=100)
    
    await reactor.run()

if __name__ == "__main__":
    asyncio.run(main())
