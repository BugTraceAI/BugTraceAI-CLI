import asyncio
import os
import signal
import sys
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from pydantic import BaseModel

from bugtrace.core.config import settings
from bugtrace.core.team import TeamOrchestrator

# --- Global State ---
# In a production app, use a real database (SQLite/Postgres).
# For this integration, we use in-memory state for simplicity.
active_engagements: Dict[str, "EngagementContext"] = {}

class EngagementContext:
    def __init__(self, target: str, orchestrator: TeamOrchestrator):
        self.engagement_id = str(uuid.uuid4())
        self.target = target
        self.orchestrator = orchestrator
        self.start_time = datetime.utcnow()
        self.status = "initializing"  # initializing, running, paused, completed, failed, stopped
        self.thread: Optional[threading.Thread] = None

# --- Pydantic Models ---
class EngagementRequest(BaseModel):
    target_url: str
    passively: bool = False  # If True, sets safe_mode/passive flags
    use_vertical: bool = True

class EngagementStatus(BaseModel):
    engagement_id: str
    target: str
    status: str
    uptime_seconds: float
    findings_count: int
    active_agent: str
    phase: str

class FindingResponse(BaseModel):
    title: str
    severity: str
    url: str
    description: str

# --- Lifecycle & App ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("BugTraceAI API Initialized")
    yield
    # Shutdown
    logger.info("BugTraceAI API Shutting Down")
    # Clean up active threads if necessary
    for eid, ctx in active_engagements.items():
        if ctx.status == "running":
            logger.warning(f"Stopping engagement {eid} during shutdown")
            await ctx.orchestrator.stop()

app = FastAPI(
    title="BugTraceAI API",
    version="1.6.1",
    description="API for Autonomous Multi-Agent Web Security Framework",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Background Runner ---
def _run_orchestrator(ctx: EngagementContext):
    """
    Wrapper to run the orchestrator's event loop in a separate thread.
    Since TeamOrchestrator is async, we need a new loop for this thread.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        ctx.status = "running"
        logger.info(f"Engagement {ctx.engagement_id} started for {ctx.target}")
        
        # Run the standard vertical flow
        # We assume TeamOrchestrator.start() is the entry point
        loop.run_until_complete(ctx.orchestrator.start(ctx.target))
        
        ctx.status = "completed"
    except Exception as e:
        logger.error(f"Engagement {ctx.engagement_id} failed: {e}")
        ctx.status = "failed"
    finally:
        loop.close()

# --- Endpoints ---

@app.get("/")
async def root():
    return {"message": "BugTraceAI API is running", "version": "1.6.1"}

@app.post("/engage", response_model=EngagementStatus)
async def start_engagement(req: EngagementRequest, background_tasks: BackgroundTasks):
    """
    Launch a new security engagement against a target URL.
    """
    # 1. Configure Settings based on Request
    # Note: Global settings mutation is not thread-safe in a real shared env,
    # but for this CLI-wrapper mode, it's acceptable if one scan runs at a time.
    # ideally, pass config to Orchestrator instance.
    
    # 2. Initialize Orchestrator
    orchestrator = TeamOrchestrator()
    
    # 3. Create Context
    ctx = EngagementContext(target=req.target_url, orchestrator=orchestrator)
    active_engagements[ctx.engagement_id] = ctx
    
    # 4. Start in Background Thread
    # We use threading instead of pure asyncio.create_task because 
    # TeamOrchestrator might be CPU bound or blocking in parts.
    thread = threading.Thread(target=_run_orchestrator, args=(ctx,), daemon=True)
    ctx.thread = thread
    thread.start()
    
    return EngagementStatus(
        engagement_id=ctx.engagement_id,
        target=ctx.target,
        status="initializing",
        uptime_seconds=0,
        findings_count=0,
        active_agent="System",
        phase="BOOT"
    )

@app.get("/status/{engagement_id}", response_model=EngagementStatus)
async def get_status(engagement_id: str):
    if engagement_id not in active_engagements:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    ctx = active_engagements[engagement_id]
    
    # Extract real-time stats from orchestrator if possible
    # This requires TeamOrchestrator to expose a thread-safe stats property
    # For now, we return basic wrapper status
    stats = ctx.orchestrator.get_status() if hasattr(ctx.orchestrator, "get_status") else {}
    
    uptime = (datetime.utcnow() - ctx.start_time).total_seconds()
    
    return EngagementStatus(
        engagement_id=ctx.engagement_id,
        target=ctx.target,
        status=ctx.status,
        uptime_seconds=uptime,
        findings_count=stats.get("findings", 0),
        active_agent=stats.get("active_agent", "Orchestrator"),
        phase=stats.get("phase", "Processing")
    )

@app.post("/stop/{engagement_id}")
async def stop_engagement(engagement_id: str):
    if engagement_id not in active_engagements:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    ctx = active_engagements[engagement_id]
    if ctx.status in ["completed", "failed", "stopped"]:
        return {"message": "Engagement already finished"}
    
    # Signal orchestrator to stop
    await ctx.orchestrator.stop()
    ctx.status = "stopped"
    return {"message": f"Engagement {engagement_id} stop context signaled"}

@app.get("/findings/{engagement_id}", response_model=List[FindingResponse])
async def get_findings(engagement_id: str):
    if engagement_id not in active_engagements:
        raise HTTPException(status_code=404, detail="Engagement not found")
        
    ctx = active_engagements[engagement_id]
    
    # Retrieve findings from the orchestrator's internal storage
    # This assumes orchestrator.findings is a list of Finding objects
    raw_findings = getattr(ctx.orchestrator, "findings", [])
    
    response = []
    for f in raw_findings:
        # Adapt internal Finding object to API response
        # This depends on your Finding data structure
        response.append(FindingResponse(
            title=getattr(f, "title", "Unknown Finding"),
            severity=getattr(f, "severity", "Info"),
            url=getattr(f, "url", ctx.target),
            description=getattr(f, "description", "")
        ))
        
    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
