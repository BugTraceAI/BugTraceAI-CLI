"""
OOB Collaborator API routes.

Burp-Collaborator-style endpoints to start an on-demand interactsh session,
get its callback domain, poll captured interactions, and stop it — decoupled
from any scan. Engine: bugtrace.services.oob_service.oob_manager.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, status

from bugtrace.api.schemas import (
    OobStartRequest,
    OobSessionResponse,
    OobInteractionsResponse,
)
from bugtrace.services.oob_service import oob_manager

router = APIRouter()


@router.post("/oob/start", response_model=OobSessionResponse, status_code=status.HTTP_201_CREATED)
async def oob_start(request: Optional[OobStartRequest] = None):
    """Start a new OOB collaborator session and return its callback domain."""
    server = request.server if request else None
    try:
        session = await oob_manager.start(server=server)
    except RuntimeError as e:
        # interactsh unavailable / too many sessions — honest 503.
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    return OobSessionResponse(
        session_id=session.session_id,
        domain=session.domain,
        server=session.server,
        interaction_count=0,
    )


@router.get("/oob/{session_id}", response_model=OobInteractionsResponse)
async def oob_interactions(session_id: str):
    """Return interactions captured by an OOB session (keeps it alive)."""
    session = oob_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OOB session not found")
    items = oob_manager.interactions(session_id) or []
    return OobInteractionsResponse(
        session_id=session_id,
        domain=session.domain,
        interaction_count=len(items),
        interactions=items,
    )


@router.post("/oob/{session_id}/stop")
async def oob_stop(session_id: str):
    """Stop an OOB session and deregister it from the interactsh server."""
    stopped = await oob_manager.stop(session_id)
    if not stopped:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OOB session not found")
    return {"stopped": True, "session_id": session_id}
