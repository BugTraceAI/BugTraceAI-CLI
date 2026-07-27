"""
OOB Collaborator Service.

Burp-Collaborator-style on-demand out-of-band server, decoupled from the scan
lifecycle. Lets the WEB Repeater (or any API client) start an interactsh
session, get a unique callback domain, and poll captured interactions live —
so OOB vulns (blind SSRF/XXE/RCE/SSTI/blind-XSS) can be replicated manually.

Engine lives here in the CLI (single source of truth for interactsh); the WEB
provides only the UI and calls the /api/oob/* endpoints.
"""

import asyncio
import time
import uuid
import logging
from typing import Dict, List, Optional

from bugtrace.tools.interactsh import InteractshClient, Interaction

logger = logging.getLogger(__name__)


class OobSession:
    """A single live OOB collaborator session wrapping one InteractshClient."""

    def __init__(self, session_id: str, client: InteractshClient, domain: str):
        self.session_id = session_id
        self.client = client
        self.domain = domain
        self.server = client.server
        self.created_at = time.time()
        self.last_activity = time.time()
        self.interactions: List[Dict] = []
        self._seen = set()
        self._task: Optional[asyncio.Task] = None

    def touch(self) -> None:
        self.last_activity = time.time()


class OobSessionManager:
    """In-process registry of live OOB sessions with background poll loops."""

    POLL_INTERVAL = 5.0          # seconds between /poll calls
    IDLE_TIMEOUT = 30 * 60       # auto-stop a session after 30 min of no reads
    MAX_SESSIONS = 20            # backstop against runaway session creation

    def __init__(self):
        self._sessions: Dict[str, OobSession] = {}

    async def start(self, server: Optional[str] = None) -> OobSession:
        """Register a new interactsh session and begin polling it."""
        if len(self._sessions) >= self.MAX_SESSIONS:
            # Reap idle/dead sessions before refusing.
            await self._reap_idle()
            if len(self._sessions) >= self.MAX_SESSIONS:
                raise RuntimeError("too many active OOB sessions")

        client = InteractshClient(server) if server else InteractshClient()
        registered = await client.register()
        if not registered:
            raise RuntimeError(f"interactsh registration failed ({client.server})")

        domain = client.get_url("collaborator")
        session_id = uuid.uuid4().hex[:12]
        session = OobSession(session_id, client, domain)
        session._task = asyncio.create_task(self._poll_loop(session))
        self._sessions[session_id] = session
        logger.info(f"[OOB] session {session_id} started — domain {domain}")
        return session

    async def _poll_loop(self, session: OobSession) -> None:
        """Poll the interactsh server until stopped or idle-timed-out."""
        try:
            while True:
                await asyncio.sleep(self.POLL_INTERVAL)
                if time.time() - session.last_activity > self.IDLE_TIMEOUT:
                    logger.info(f"[OOB] session {session.session_id} idle-timeout")
                    break
                try:
                    new = await session.client.poll()
                    for it in new:
                        self._record(session, it)
                except Exception as e:
                    logger.debug(f"[OOB] poll error ({session.session_id}): {e}")
        except asyncio.CancelledError:
            pass
        finally:
            try:
                await session.client.deregister()
            except Exception:
                pass
            self._sessions.pop(session.session_id, None)

    def _record(self, session: OobSession, it: Interaction) -> None:
        ts = it.timestamp.isoformat() if hasattr(it.timestamp, "isoformat") else str(it.timestamp)
        key = (it.full_id, ts, it.protocol, it.remote_address)
        if key in session._seen:
            return
        session._seen.add(key)
        session.interactions.append({
            "protocol": it.protocol,
            "full_id": it.full_id,
            "remote_address": it.remote_address,
            "raw_request": it.raw_request,
            "timestamp": ts,
        })
        logger.info(f"[OOB] {session.session_id} captured {it.protocol} from {it.remote_address}")

    def get(self, session_id: str) -> Optional[OobSession]:
        return self._sessions.get(session_id)

    def interactions(self, session_id: str) -> Optional[List[Dict]]:
        session = self._sessions.get(session_id)
        if not session:
            return None
        session.touch()  # reading keeps the session alive
        return session.interactions

    async def stop(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False
        if session._task:
            session._task.cancel()
            try:
                await session._task
            except (asyncio.CancelledError, Exception):
                pass
        self._sessions.pop(session_id, None)
        logger.info(f"[OOB] session {session_id} stopped")
        return True

    def list_sessions(self) -> List[OobSession]:
        return list(self._sessions.values())

    async def _reap_idle(self) -> None:
        now = time.time()
        for sid, s in list(self._sessions.items()):
            if now - s.last_activity > self.IDLE_TIMEOUT:
                await self.stop(sid)


# Module-level singleton (mirrors interactsh_client pattern)
oob_manager = OobSessionManager()
