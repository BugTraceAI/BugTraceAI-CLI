"""
WebSocket Manager - Real-time event broadcasting for scan progress.

Provides WebSocket connections for live scan updates:
- Progress metrics updates
- Phase transitions
- Finding discoveries
- Queue status changes

Author: BugtraceAI Team
Date: 2026-02-02
Version: 1.0.0
"""

import asyncio
import json
from typing import Dict, Set, Any
from fastapi import WebSocket, WebSocketDisconnect
from loguru import logger


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events."""

    def __init__(self):
        # Active connections per scan_id
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # Global connections (receive all events)
        self.global_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, scan_id: int = None):
        """
        Accept a new WebSocket connection.

        Args:
            websocket: WebSocket connection to add
            scan_id: Optional scan ID to subscribe to specific scan events
        """
        await websocket.accept()

        async with self._lock:
            if scan_id is not None:
                # Subscribe to specific scan
                if scan_id not in self.active_connections:
                    self.active_connections[scan_id] = set()
                self.active_connections[scan_id].add(websocket)
                logger.info(f"WebSocket connected for scan {scan_id} (total: {len(self.active_connections[scan_id])})")
            else:
                # Global subscription
                self.global_connections.add(websocket)
                logger.info(f"WebSocket connected globally (total: {len(self.global_connections)})")

    async def disconnect(self, websocket: WebSocket, scan_id: int = None):
        """
        Remove a WebSocket connection.

        Args:
            websocket: WebSocket connection to remove
            scan_id: Optional scan ID if subscribed to specific scan
        """
        async with self._lock:
            if scan_id is not None and scan_id in self.active_connections:
                self.active_connections[scan_id].discard(websocket)
                if not self.active_connections[scan_id]:
                    del self.active_connections[scan_id]
                logger.info(f"WebSocket disconnected from scan {scan_id}")
            else:
                self.global_connections.discard(websocket)
                logger.info(f"WebSocket disconnected globally")

    async def broadcast_to_scan(self, scan_id: int, message: Dict[str, Any]):
        """
        Broadcast a message to all connections subscribed to a specific scan.

        Args:
            scan_id: Scan ID to broadcast to
            message: Message dict to send (will be JSON encoded)
        """
        async with self._lock:
            connections = self.active_connections.get(scan_id, set()).copy()

        if not connections:
            return

        # Add metadata
        message["scan_id"] = scan_id
        message["timestamp"] = asyncio.get_event_loop().time()

        # Broadcast to all connections for this scan
        disconnected = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket: {e}")
                disconnected.append(connection)

        # Clean up disconnected
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    if scan_id in self.active_connections:
                        self.active_connections[scan_id].discard(conn)

    async def broadcast_global(self, message: Dict[str, Any]):
        """
        Broadcast a message to all global connections.

        Args:
            message: Message dict to send (will be JSON encoded)
        """
        async with self._lock:
            connections = self.global_connections.copy()

        if not connections:
            return

        # Add metadata
        message["timestamp"] = asyncio.get_event_loop().time()

        # Broadcast to all global connections
        disconnected = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to global WebSocket: {e}")
                disconnected.append(connection)

        # Clean up disconnected
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    self.global_connections.discard(conn)

    async def send_progress_update(
        self,
        scan_id: int,
        urls_discovered: int = None,
        urls_analyzed: int = None,
        urls_total: int = None,
        findings_before_dedup: int = None,
        findings_after_dedup: int = None,
        findings_distributed: int = None,
        dedup_effectiveness: float = None,
        queue_stats: Dict[str, Dict] = None,
    ):
        """
        Send a progress metrics update.

        Args:
            scan_id: Scan ID
            urls_discovered: Number of URLs discovered
            urls_analyzed: Number of URLs analyzed
            urls_total: Total URLs to analyze
            findings_before_dedup: Findings before deduplication
            findings_after_dedup: Findings after deduplication
            findings_distributed: Findings distributed to queues
            dedup_effectiveness: Deduplication effectiveness percentage
            queue_stats: Per-specialist queue statistics
        """
        message = {
            "type": "progress_update",
            "data": {
                "urls_discovered": urls_discovered,
                "urls_analyzed": urls_analyzed,
                "urls_total": urls_total,
                "findings_before_dedup": findings_before_dedup,
                "findings_after_dedup": findings_after_dedup,
                "findings_distributed": findings_distributed,
                "dedup_effectiveness": dedup_effectiveness,
                "queue_stats": queue_stats,
            }
        }
        await self.broadcast_to_scan(scan_id, message)

    async def send_phase_update(self, scan_id: int, phase: str, agent: str = None):
        """
        Send a phase transition update.

        Args:
            scan_id: Scan ID
            phase: New phase name
            agent: Active agent name
        """
        message = {
            "type": "phase_update",
            "data": {
                "phase": phase,
                "agent": agent,
            }
        }
        await self.broadcast_to_scan(scan_id, message)

    async def send_finding_discovered(self, scan_id: int, finding: Dict[str, Any]):
        """
        Send a finding discovery event.

        Args:
            scan_id: Scan ID
            finding: Finding details
        """
        message = {
            "type": "finding_discovered",
            "data": finding,
        }
        await self.broadcast_to_scan(scan_id, message)

    async def send_log(self, scan_id: int, level: str, message: str):
        """
        Send a log message event.

        Args:
            scan_id: Scan ID
            level: Log level (INFO, WARNING, ERROR, etc.)
            message: Log message
        """
        log_message = {
            "type": "log",
            "data": {
                "level": level,
                "message": message,
            }
        }
        await self.broadcast_to_scan(scan_id, log_message)


# Global singleton
ws_manager = ConnectionManager()
