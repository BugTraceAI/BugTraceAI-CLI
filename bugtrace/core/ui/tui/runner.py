"""Private subprocess entry point. Stdout contains JSON events, never terminal UI."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import threading
import time


class ScanEvents:
    def __init__(self, output):
        self.output = output
        self.lock = threading.Lock()
        self.findings = 0
        self.total_findings = 0
        self._last_payload = 0.0

    def emit(self, event: str, **data) -> None:
        with self.lock:
            self.output.write(json.dumps({"event": event, **data}, default=str) + "\n")
            self.output.flush()

    def on_phase_change(self, phase, progress, status=""):
        self.emit("phase", phase=phase, progress=progress, status=status, observed_at=time.monotonic())

    def on_agent_update(self, agent, status, queue=0, processed=0, vulns=0, **kwargs):
        self.emit("agent", agent=agent, status=status, queue=queue, processed=processed, vulns=vulns)

    def on_finding(self, finding_type, details, severity, param=None, payload=None, **kwargs):
        self.findings += 1
        self.emit("finding", finding_type=finding_type, details=details, severity=severity,
                  param=param, payload=payload, url=kwargs.get("url"), request=kwargs.get("request"),
                  response_excerpt=kwargs.get("response_excerpt"))

    def on_log(self, level, message):
        self.emit("log", level=level, message=message)

    def on_metrics(self, **kwargs):
        self.emit("metrics", **kwargs)

    def on_payload_tested(self, payload, result, agent):
        now = time.monotonic()
        if now - self._last_payload >= 0.1:
            self._last_payload = now
            self.emit("payload", payload=payload, result=result, agent=agent)

    def on_complete(self, total_findings, duration):
        # Hunter may complete before Auditor. Only the runner emits final completion.
        self.total_findings = total_findings


class LogStream(io.TextIOBase):
    """Turn legacy print/Rich/Loguru output into events without touching the TTY."""

    def __init__(self, events: ScanEvents, level="INFO"):
        self.events = events
        self.level = level
        self.pending = ""
        self.lock = threading.Lock()

    def write(self, text):
        with self.lock:
            self.pending += text
            while "\n" in self.pending or len(self.pending) > 16000:
                line, separator, tail = self.pending.partition("\n")
                if not separator:
                    line, tail = self.pending[:16000], self.pending[16000:]
                self.pending = tail
                if line.strip():
                    self.events.on_log(self.level, line.rstrip())
        return len(text)

    def flush(self):
        pass


async def execute(target: str, options: dict, events: ScanEvents) -> int:
    import os
    # Capture session overrides before environment-specific dotenv loading.
    session_keys = {key: os.environ[key] for key in json.loads(os.environ.get("BUGTRACE_TUI_SESSION_KEY_NAMES", "[]")) if key in os.environ}
    from bugtrace.core.config import settings
    if options.get("provider"):
        from .provider_config import provider_presets
        if options["provider"] not in provider_presets():
            raise ValueError("Unknown provider preset")
        object.__setattr__(settings, "PROVIDER", options["provider"])
        settings._load_provider_preset()
        key_env = provider_presets()[options["provider"]].get("api_key_env")
        if key_env in session_keys:
            os.environ[key_env] = session_keys[key_env]
            object.__setattr__(settings, key_env, session_keys[key_env])
    from bugtrace.core.conductor import conductor
    from bugtrace.core.ui import dashboard

    if options.get("safe_mode") is not None:
        settings.SAFE_MODE = options["safe_mode"]
    conductor.set_ui_callback(events)
    started = time.monotonic()
    orchestrator = None
    stopped = False
    pipeline = None

    async def run_pipeline():
        nonlocal orchestrator
        from bugtrace.__main__ import _setup_output_directory
        output_dir = _setup_output_directory(target)
        output_dir.mkdir(parents=True, exist_ok=True)
        events.emit("report", path=str(output_dir.resolve()))
        if options.get("clean") and options.get("phase") != "manager":
            from bugtrace.utils.janitor import clean_environment
            clean_environment()
        focused = options.get("focused", {})
        if any(focused.values()):
            from bugtrace.__main__ import _execute_focused_agent, _parse_focused_params, _display_focused_results
            params = _parse_focused_params(target, options.get("param"))
            events.on_phase_change("exploitation", 0, "Running focused specialists")
            result = await _execute_focused_agent(target, params, output_dir, **focused)
            if result and result.get("error"):
                raise RuntimeError(result["error"])
            events.on_phase_change("exploitation", 1, "Focused specialists finished")
            events.on_phase_change("reporting", 0, "Writing focused results")
            _display_focused_results(target, result, params, output_dir)
            events.on_phase_change("reporting", 1, "Focused results written")
            for finding in (result or {}).get("findings", []):
                events.on_finding(finding.get("type", "Finding"), finding.get("details", finding.get("url", target)),
                                  finding.get("severity", "info"), param=finding.get("parameter"),
                                  payload=finding.get("payload"), url=finding.get("url"))
            return
        phase = options.get("phase", "all")
        if phase in {"hunter", "all"}:
            from bugtrace.core.team import TeamOrchestrator
            from bugtrace.__main__ import _check_and_resume_scan
            resume = await _check_and_resume_scan(target, None, options.get("resume", False))
            orchestrator = TeamOrchestrator(
                target, resume=resume, max_depth=options.get("max_depth", settings.MAX_DEPTH),
                max_urls=options.get("max_urls", settings.MAX_URLS),
                use_vertical_agents=True, output_dir=output_dir, url_list=options.get("url_list"),
                auth=options.get("auth_data"),
                custom_headers=options.get("custom_headers"),
                api_handoff=options.get("handoff"),
                api_inventory=(__import__("bugtrace.services.handoff_policy", fromlist=["inventory_from_handoff"]).inventory_from_handoff(options["handoff"]) if options.get("handoff") else None),
            )
            events.emit("started", scan_id=orchestrator.scan_id)
            await orchestrator.start()
        if phase in {"manager", "all"}:
            from bugtrace.__main__ import _run_auditor_phase
            events.on_phase_change("validation", 0, "Auditing scan findings")
            await _run_auditor_phase(target, None, options.get("scan_id"), orchestrator,
                                     output_dir, options.get("continuous", False), options.get("custom_headers"))
            events.on_phase_change("validation", 1, "Auditor finished")

    async def control():
        nonlocal stopped
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                command = "stop"  # Parent exited; don't leave an orphaned scan.
            else:
                try:
                    command = json.loads(line).get("command")
                except (ValueError, AttributeError):
                    continue
            if command == "stop":
                stopped = True
                dashboard.stop_requested = True
                if orchestrator:
                    orchestrator._stop_event.set()
                    ctx = getattr(orchestrator, "_scan_context", None)
                    if ctx:
                        ctx.request_stop()
                if pipeline:
                    pipeline.cancel()
                return
            if command in {"pause", "resume"}:
                ok = False
                if orchestrator:
                    method = orchestrator.pause_pipeline if command == "pause" else orchestrator.resume_pipeline
                    ok = await method()
                if ok:
                    events.emit("state", state="paused" if command == "pause" else "running")
                    if command == "pause":
                        events.on_log("INFO", "Pause requested; in-flight work finishes at the next checkpoint.")
                else:
                    events.on_log("WARNING", f"Cannot {command} before the scan context is ready.")

    async def telemetry():
        last_payload = 0
        last_agents = {}
        last_state = None
        while True:
            await asyncio.sleep(0.2)
            # Older specialists still write telemetry to the dashboard model.
            # The shared model is passive: it has no renderer, input or background thread.
            with dashboard._lock:
                payload_count = dashboard.payloads_tested
                payload = dict(dashboard.payload_history[-1]) if dashboard.payload_history else None
                agents = {name: dict(stats) for name, stats in dashboard.specialist_metrics.items()}
                rate = dashboard.payload_rate
                discovered, analyzed = dashboard.urls_discovered, dashboard.urls_analyzed
            if payload_count != last_payload and payload:
                last_payload = payload_count
                events.on_payload_tested(payload["payload"], payload["status"], payload.get("agent", ""))
            for name, stats in agents.items():
                if stats != last_agents.get(name):
                    events.on_agent_update(name, stats.get("status", "idle"), stats.get("queue", 0),
                                           stats.get("processed", 0), stats.get("vulns", 0))
            last_agents = agents
            events.on_metrics(req_rate=rate, urls_discovered=discovered, urls_analyzed=analyzed)
            ctx = getattr(orchestrator, "_scan_context", None)
            state = getattr(ctx, "status", None)
            if state in {"paused", "running"} and state != last_state:
                last_state = state
                events.emit("state", state=state)

    initial = "exploitation" if any(options.get("focused", {}).values()) else "validation" if options.get("phase") == "manager" else "reconnaissance"
    events.on_phase_change(initial, 0, "Initializing scanner")
    pipeline = asyncio.create_task(run_pipeline())
    controls = asyncio.create_task(control())
    metrics = asyncio.create_task(telemetry())
    status, code = "complete", 0
    try:
        await pipeline
    except asyncio.CancelledError:
        status, code = "stopped", 0
    except Exception as exc:
        status, code = "failed", 1
        events.on_log("ERROR", f"{type(exc).__name__}: {exc}")
    finally:
        controls.cancel()
        metrics.cancel()
        await asyncio.gather(controls, metrics, return_exceptions=True)
        if orchestrator:
            from bugtrace.schemas.db_models import ScanStatus
            if stopped or status == "failed":
                try:
                    orchestrator.db.update_scan_status(orchestrator.scan_id, ScanStatus.STOPPED if stopped else ScanStatus.FAILED)
                except Exception as exc:
                    events.on_log("WARNING", f"Could not persist scan status: {exc}")
            try:
                await asyncio.wait_for(orchestrator._shutdown_specialist_workers(), 2)
            except Exception as exc:
                events.on_log("WARNING", f"Worker cleanup: {exc}")
            orchestrator._unsubscribe_events()
        try:
            from bugtrace.tools.visual.browser import browser_manager
            await asyncio.wait_for(browser_manager.stop(), 2)
        except Exception:
            pass
        from bugtrace.__main__ import _save_qlearning_data
        _save_qlearning_data()
        conductor.set_ui_callback(None)
        events.emit("finished", state=status, total_findings=max(events.findings, events.total_findings),
                    duration=time.monotonic() - started)
    return code


def main() -> None:
    import os
    events = ScanEvents(sys.stdout)
    try:
        options = json.loads(sys.stdin.readline())
        sys.stdout = LogStream(events)
        sys.stderr = LogStream(events, "ERROR")
        # asyncio.run waits for a blocked stdin executor on exit; close the process
        # after async resources have been cleaned up instead.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        code = loop.run_until_complete(execute(sys.argv[1], options, events))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
    except BaseException as exc:
        events.on_log("ERROR", f"Scanner startup failed: {exc}")
        events.emit("finished", state="failed", total_findings=events.findings, duration=0)
        code = 1
    events.output.flush()
    os._exit(code)


if __name__ == "__main__":
    main()
