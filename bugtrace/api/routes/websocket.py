"""
WebSocket Routes - Real-time event streaming endpoints.

Provides WebSocket connections for live scan updates.

Author: BugtraceAI Team
Date: 2026-02-02
Version: 1.0.0
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from bugtrace.api.websocket import ws_manager
from bugtrace.utils.logger import get_logger

logger = get_logger("api.routes.websocket")

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: int):
    """
    WebSocket endpoint for real-time scan updates.

    Streams events for a specific scan:
    - progress_update: URLs analyzed, queue depths, dedup stats
    - phase_update: Phase transitions and agent changes
    - finding_discovered: New findings in real-time
    - log: Log messages from the scan

    Args:
        websocket: WebSocket connection
        scan_id: Scan ID to subscribe to

    Example client usage:
        const ws = new WebSocket('ws://localhost:8000/api/ws/scans/123');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log(data.type, data.data);
        };
    """
    await ws_manager.connect(websocket, scan_id=scan_id)
    logger.info(f"WebSocket client connected for scan {scan_id}")

    try:
        # Keep connection alive and handle incoming messages
        while True:
            # Wait for any message from client (e.g., ping/pong)
            data = await websocket.receive_text()

            # Echo back for heartbeat
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from scan {scan_id}")
        await ws_manager.disconnect(websocket, scan_id=scan_id)


@router.websocket("/ws/global")
async def websocket_global_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for all scan events.

    Streams events from ALL active scans (admin/dashboard use).

    Args:
        websocket: WebSocket connection

    Example client usage:
        const ws = new WebSocket('ws://localhost:8000/api/ws/global');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log('Scan', data.scan_id, data.type, data.data);
        };
    """
    await ws_manager.connect(websocket)
    logger.info(f"WebSocket client connected globally")

    try:
        # Keep connection alive
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected globally")
        await ws_manager.disconnect(websocket)
