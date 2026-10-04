"""Run the scanner outside the terminal renderer, with a JSON-lines event bridge."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from collections import deque
from typing import Callable


class EventBuffer:
    """Coalesce telemetry and bound noisy logs; findings/control events are lossless."""

    def __init__(self, max_logs: int = 1000):
        self.logs = deque(maxlen=max_logs)
        self.important = deque()
        self.phases = deque()
        self.telemetry = {}
        self.dropped_logs = 0

    def add(self, event: dict) -> None:
        kind = event.get("event")
        if kind == "phase":
            progress = float(event.get("progress", 0))
            # Only replace adjacent intermediate updates. Start/end events,
            # including repeated visits to Validation, retain their ordering.
            if (0 < progress < 1 and self.phases
                    and self.phases[-1].get("phase") == event.get("phase")
                    and 0 < float(self.phases[-1].get("progress", 0)) < 1):
                self.phases[-1] = event
            else:
                self.phases.append(event)
        elif kind in {"metrics", "agent", "payload"}:
            key = (kind, event.get("agent", ""))
            self.telemetry[key] = event
        elif kind == "log" and event.get("level") not in {"ERROR", "CRITICAL"}:
            if len(self.logs) == self.logs.maxlen:
                self.dropped_logs += 1
            self.logs.append(event)
        else:
            self.important.append(event)

    def drain(self, limit: int = 100) -> list[dict]:
        events = []
        while self.phases and len(events) < limit:
            events.append(self.phases.popleft())
        events.extend(self.telemetry.values())
        self.telemetry.clear()
        if self.dropped_logs:
            events.append({"event": "log", "level": "WARNING", "message":
                           f"Display condensed {self.dropped_logs} log lines; see execution logs for the engine trace."})
            self.dropped_logs = 0
        # Apply terminal states after preceding findings/telemetry in this batch.
        while self.important and len(events) < limit:
            events.append(self.important.popleft())
        while self.logs and len(events) < limit:
            events.append(self.logs.popleft())
        return events


class ScanProcess:
    """One owned scan process. Stop has a bounded grace period and kills its group."""

    def __init__(self, target: str, options: dict | None = None, command: list[str] | None = None):
        self.target = target
        self.options = options or {}
        self.command = command
        self.environment = {}
        self.process: asyncio.subprocess.Process | None = None
        self.stop_requested = False
        self._stop_lock = asyncio.Lock()
        self._group_reaped = False

    async def run(self, receive: Callable[[dict], None]) -> int:
        command = self.command or [sys.executable, "-u", "-m", "bugtrace.core.ui.tui.runner", self.target]
        environment = {**os.environ, **self.environment}
        environment["BUGTRACE_TUI_SESSION_KEY_NAMES"] = json.dumps(list(self.environment))
        self.process = await asyncio.create_subprocess_exec(
            *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, start_new_session=(os.name == "posix"),
            limit=4 * 1024 * 1024, env=environment,
        )
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write((json.dumps(self.options) + "\n").encode())
        await self.process.stdin.drain()
        if self.stop_requested:
            await self.stop(requested=False)
        reaper = asyncio.create_task(self._reap_on_exit())
        try:
            while line := await self.process.stdout.readline():
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict) or "event" not in event:
                        raise ValueError("Not a scan event")
                except (ValueError, UnicodeDecodeError):
                    event = {"event": "log", "level": "INFO", "message": line.decode(errors="replace").rstrip()}
                receive(event)
            return await self.process.wait()
        finally:
            await self.stop(requested=False)
            reaper.cancel()
            await asyncio.gather(reaper, return_exceptions=True)

    async def _reap_on_exit(self) -> None:
        while self.process.returncode is None:
            await asyncio.sleep(0.1)
        # A tool inheriting stdout must not keep the event reader open forever.
        self._kill_group()

    async def send(self, command: str) -> bool:
        if not self.process or self.process.returncode is not None or not self.process.stdin:
            return False
        try:
            self.process.stdin.write((json.dumps({"command": command}) + "\n").encode())
            await self.process.stdin.drain()
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False

    async def stop(self, grace: float = 3.0, requested: bool = True) -> None:
        if requested:
            self.stop_requested = True
        async with self._stop_lock:
            if not self.process:
                return
            if self.process.returncode is None:
                await self.send("stop")
                try:
                    await asyncio.wait_for(self.process.wait(), grace)
                except asyncio.TimeoutError:
                    self._kill_group()
                    await self.process.wait()
            # External tools can outlive the scanner leader. Reap the owned group too.
            self._kill_group()

    def _kill_group(self) -> None:
        if not self.process or self._group_reaped:
            return
        try:
            if os.name == "posix":
                os.killpg(self.process.pid, signal.SIGKILL)
            elif self.process.returncode is None:
                self.process.kill()
        except ProcessLookupError:
            pass
        self._group_reaped = True
