"""Interactive scan workspace with an isolated scanner and bounded UI updates."""
from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from rich.text import Text
from textual import work
from textual.app import App
from textual.binding import Binding
from textual.widgets import Button, DataTable, Input, ListView, Select, Static, TabbedContent
from textual.worker import Worker

from .messages import AgentUpdate, LogEntry, MetricsUpdate, NewFinding, PayloadTested, PipelineProgress, ScanComplete
from .runtime import EventBuffer, ScanProcess
from .screens.main import MainScreen
from .screens.modals import FindingDetailsModal
from .screens.modals.help import WorkspaceHelpModal
from .screens.modals.provider import ProviderModal
from .screens.modals.auth import AuthModal
from .auth_config import auth_label
from .provider_config import provider_presets
from .widgets.command_input import CommandInput
from .widgets.findings_table import FindingsTable
from .widgets.log_inspector import LogInspector
from .widgets.pipeline import PipelineStatus
from .widgets.timeline import ScanTimeline, TimelineEntry


class BugTraceApp(App):
    CSS_PATH = Path(__file__).parent / "styles.tcss"
    TITLE = "BugTraceAI"
    SUB_TITLE = "Scan workspace"
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+s", "start_scan", "Start", priority=True),
        Binding("ctrl+x", "stop_scan", "Stop", priority=True),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "view('pipeline-view')", "Pipeline"),
        Binding("f3", "view('findings-view')", "Findings"),
        Binding("f4", "view('agents-view')", "Agents"),
        Binding("f5", "view('overview')", "Timeline"),
        Binding("f6", "view('logs-view')", "Logs"),
        Binding("f7", "configure_provider", "Provider"),
        Binding("f8", "configure_auth", "Auth"),
        Binding("ctrl+e", "export_findings", "Export"),
        Binding("escape", "unfocus", "Unfocus", show=False),
        Binding(":", "focus_command", "Command", show=False),
    ]

    def __init__(self, target=None, demo_mode=False, scan_options=None, process_factory=ScanProcess, **kwargs):
        super().__init__(**kwargs)
        self.target = target or ("https://demo.example" if demo_mode else None)
        self.demo_mode = demo_mode
        self.scan_options = {**(scan_options or {}), "phase": "all"}
        self.scan_options.pop("focused", None)
        from bugtrace.core.config import settings
        self.provider = settings.PROVIDER
        self._provider_keys = {}
        self._auth_yaml_path = ""
        self.process_factory = process_factory
        self.main_screen = MainScreen(demo_mode=demo_mode)
        self.scan_worker: Worker | None = None
        self.scan_process: ScanProcess | None = None
        self.scan_state = "demo" if demo_mode else "idle"
        self.report_path: str | None = None
        self._events = EventBuffer()
        self._scan_start_time = None
        self._total_findings = 0
        self._tui_quitting = False
        self._terminal_event = False
        self._finished_event = None
        self._owned_lock = False
        self._last_notification = 0.0

    async def on_mount(self) -> None:
        await self.push_screen(self.main_screen)
        self.set_interval(0.1, self._flush_events)
        self.set_interval(1, self._update_status)
        self._set_state(self.scan_state)
        if self.target and not self.demo_mode:
            self.call_after_refresh(self.action_start_scan)

    @property
    def is_scan_running(self) -> bool:
        return self.scan_state in {"starting", "running", "paused", "stopping"}

    @property
    def is_shutting_down(self) -> bool:
        return self._tui_quitting

    def _set_state(self, state: str) -> None:
        previous = self.scan_state
        self.scan_state = state
        self.main_screen.query_one(PipelineStatus).set_scan_state(state)
        self._update_status()
        if not self.main_screen.query_one("#command-input", CommandInput).value:
            self.main_screen.query_one("#command-hints", Static).update(self.main_screen.command_hint())
        self.main_screen.query_one("#start-btn", Button).disabled = self.is_scan_running or self.demo_mode
        self.main_screen.query_one("#stop-btn", Button).disabled = not self.is_scan_running or state == "stopping"
        self.main_screen.query_one("#pause-btn", Button).disabled = state not in {"running", "paused"}
        self.main_screen.query_one("#pause-btn", Button).label = "Resume" if state == "paused" else "Pause"
        self.main_screen.query_one("#target-input", Input).disabled = self.is_scan_running or self.demo_mode
        self._update_crawl_controls()
        self.main_screen.query_one("#provider-btn", Button).disabled = self.is_scan_running or self.demo_mode
        self.main_screen.query_one("#auth-btn", Button).disabled = self.is_scan_running or self.demo_mode
        if previous != state:
            self.main_screen.query_one("#timeline", ScanTimeline).add_event(
                {"running": "Scanner running", "paused": "Scan paused", "stopping": "Stopping scan",
                 "complete": "Scan complete", "stopped": "Scan stopped", "failed": "Scan failed"}.get(state, state.capitalize()),
                {"paused": "Resume when you're ready. Findings remain available.",
                 "complete": f"{self._total_findings} findings. Open Findings or use /export to save the evidence.",
                 "stopped": "Captured findings remain available.", "failed": "Open Logs to inspect the error."}.get(state, ""),
                category="warning" if state == "failed" else "session")

    def _update_status(self) -> None:
        if not self.is_mounted or not self.main_screen.query("#scan-status"):
            return
        elapsed = int(time.monotonic() - self._scan_start_time) if self._scan_start_time else 0
        mins, secs = divmod(elapsed, 60)
        colors = {"running": "#2ECC71", "paused": "#FFC107", "failed": "#FF3131", "stopping": "#FFC107", "demo": "#FF7F50"}
        line = Text(f"● {self.scan_state.lower()}", style=colors.get(self.scan_state, "#FF7F50"))
        line.append(f"  ·  {self._total_findings} sample findings" if self.demo_mode else
                    f"  ·  {mins:02}:{secs:02}  ·  {self._total_findings} findings", style="#B0A8C0")
        if self.report_path:
            line.append(f"   Report: {self.report_path}", style="dim")
        self.main_screen.query_one("#scan-status", Static).update(line)

    def _acquire_scan_lock(self) -> bool:
        from bugtrace.core.config import settings
        preset = provider_presets().get(self.provider, {})
        key_env = preset.get("api_key_env")
        if key_env:
            import os
            if not (self._provider_keys.get(key_env) or os.environ.get(key_env) or getattr(settings, key_env, None)):
                raise ValueError(f"Open Provider (F7) and configure an API key for {self.provider} before starting a scan.")
        from bugtrace.core.instance_lock import check_existing_instance, write_lock_file
        existing = check_existing_instance()
        if existing:
            self.notify(f"Another scan is active (PID {existing[0]}). Stop it before starting a new scan.", severity="error")
            return False
        self._owned_lock = write_lock_file(f"bugtrace tui {self.target}")
        if not self._owned_lock:
            self.notify("Cannot acquire the scan lock. Check the logs directory permissions.", severity="error")
        return self._owned_lock

    def _release_scan_lock(self) -> None:
        if self._owned_lock:
            from bugtrace.core.instance_lock import remove_lock_file
            remove_lock_file()
            self._owned_lock = False

    def _update_crawl_controls(self) -> None:
        for selector in ("#max-depth", "#max-urls"):
            self.main_screen.query_one(selector, Input).disabled = self.is_scan_running or self.demo_mode

    def action_start_scan(self) -> None:
        if isinstance(self.screen, (AuthModal, ProviderModal)):
            self.notify("Apply or cancel the setup dialog before starting a scan.", severity="warning")
            return
        if self.demo_mode:
            self.notify("Demo workspace. Open bugtrace tui to run a real scan.")
            return
        if self.is_scan_running:
            self.notify("A scan is already running.", severity="warning")
            return
        target_input = self.main_screen.query_one("#target-input", Input)
        target = target_input.value.strip()
        try:
            parsed = urlsplit(target)
            valid = parsed.scheme in {"http", "https"} and parsed.hostname and parsed.port != 0
        except ValueError:
            valid = False
        if not valid or any(char.isspace() for char in target):
            self.notify("Enter a valid http:// or https:// target URL.", severity="warning")
            target_input.focus()
            return
        options = {**self.scan_options, "phase": "all", "provider": self.provider}
        for key, selector, label, maximum in (("max_depth", "#max-depth", "Depth", 10),
                                             ("max_urls", "#max-urls", "Max URLs", 5000)):
            field = self.main_screen.query_one(selector, Input)
            try:
                value = int(field.value)
                if not 1 <= value <= maximum:
                    raise ValueError
            except ValueError:
                self.notify(f"{label} must be a whole number between 1 and {maximum}.", severity="warning")
                field.focus()
                return
            options[key] = value
        self.target = target
        try:
            if not self._acquire_scan_lock():
                return
        except Exception as exc:
            self.notify(f"Scan configuration error: {exc}", severity="error", timeout=10)
            return
        self._events = EventBuffer()
        self._terminal_event = False
        self._finished_event = None
        self._total_findings = 0
        self._scan_start_time = time.monotonic()
        self.report_path = None
        self.main_screen.query_one("#findings-table", FindingsTable).reset_findings()
        self.main_screen.query_one("#finding-filter", Input).value = ""
        self.main_screen.query_one("#severity-filter", Select).value = "all"
        self.main_screen.query_one("#swarm", DataTable).clear()
        self.main_screen.agent_rows.clear()
        self.main_screen.reset_activity(target)
        self.main_screen.query_one("#log-inspector", LogInspector).clear()
        self.main_screen.query_one("#findings-count", Static).update("No findings yet — results appear as agents report them.")
        pipeline = self.main_screen.query_one("#pipeline", PipelineStatus)
        pipeline.reset()
        pipeline.observe_phase("reconnaissance", 0, "Starting scanner…")
        self.scan_process = self.process_factory(target, options)
        self.scan_process.environment = dict(self._provider_keys)
        self._set_state("starting")
        self.action_view("pipeline-view")
        self.scan_worker = self.run_scan()

    @work(exclusive=True, group="scan", exit_on_error=False)
    async def run_scan(self) -> None:
        process = self.scan_process
        final_state = "failed"
        try:
            code = await process.run(self._events.add)
            while self._events.important and self.main_screen.is_mounted and not self._tui_quitting:
                self._flush_events()
            if self.main_screen.is_mounted and not self._tui_quitting:
                self._flush_events()
            final_state = self._finished_event["state"] if self._finished_event else "failed"
            if process.stop_requested:
                final_state = "stopped"
            if not self._terminal_event and not self._tui_quitting:
                if final_state == "failed":
                    self._log("ERROR", f"Scanner exited without a completion event (exit {code}).")
        except asyncio.CancelledError:
            await process.stop()
            raise
        except Exception as exc:
            self._log("ERROR", f"Cannot run scanner: {exc}")
        finally:
            await process.stop(requested=False)
            self._release_scan_lock()
            if not self._tui_quitting:
                self._set_state(final_state)
                pipeline = self.main_screen.query_one("#pipeline", PipelineStatus)
                pipeline.phase = final_state
                pipeline.status_msg = {
                    "complete": "Scan finished. Browse findings or export the results.",
                    "stopped": "Scan stopped. Captured findings remain available.",
                    "failed": "Scan failed. Open Logs for details.",
                }.get(final_state, final_state)
                if final_state == "complete":
                    pipeline.progress = 100
                self.notify(f"Scan {final_state}: {self._total_findings} findings",
                            severity="error" if final_state == "failed" else "information")

    def _flush_events(self) -> None:
        if self._tui_quitting or not self.main_screen.query("#pipeline"):
            return
        for event in self._events.drain():
            kind = event.get("event")
            if kind == "log":
                self._log(event.get("level", "INFO"), event.get("message", ""))
            elif kind == "phase":
                self.on_pipeline_progress(PipelineProgress(event["phase"], event["progress"], event.get("status", ""), event.get("observed_at")))
            elif kind == "agent":
                self.on_agent_update(AgentUpdate(event["agent"], event["status"], event.get("queue", 0), event.get("processed", 0), event.get("vulns", 0)))
            elif kind == "finding":
                self._add_finding(event)
            elif kind == "metrics":
                self.on_metrics_update(MetricsUpdate(**{key: event[key] for key in
                    ("cpu", "ram", "req_rate", "urls_discovered", "urls_analyzed") if key in event}))
            elif kind == "payload":
                self.on_payload_tested(PayloadTested(event["payload"], event["result"], event["agent"]))
            elif kind == "report":
                self.report_path = event["path"]
            elif kind == "started":
                self._set_state("running")
            elif kind == "state" and self.scan_state != "stopping":
                self._set_state(event["state"])
            elif kind == "finished":
                self._terminal_event = True
                self._finished_event = event

    def _log(self, level: str, message: str) -> None:
        self.main_screen.query_one("#log-inspector", LogInspector).log(str(message), level=str(level))
        if level.upper() in {"WARNING", "ERROR", "SUCCESS"}:
            self.main_screen.query_one("#timeline", ScanTimeline).add_event(
                level.capitalize(), str(message)[:500], category="warning" if level.upper() in {"WARNING", "ERROR"} else "event")

    async def action_stop_scan(self) -> None:
        if self.scan_process and self.is_scan_running and self.scan_state != "stopping":
            self._set_state("stopping")
            await self.scan_process.stop()

    async def action_pause_scan(self) -> None:
        if self.scan_process and self.scan_state in {"running", "paused"}:
            await self.scan_process.send("resume" if self.scan_state == "paused" else "pause")

    async def action_quit(self) -> None:
        if self._tui_quitting:
            return
        self._tui_quitting = True
        await self.action_stop_scan()
        self.exit()

    async def on_unmount(self) -> None:
        if self.scan_process:
            await self.scan_process.stop()
        self._release_scan_lock()

    def action_view(self, pane: str) -> None:
        self.main_screen.query_one("#workspace-tabs", TabbedContent).active = pane
        if pane == "findings-view":
            self.main_screen.query_one("#findings-table").focus()
        elif pane == "logs-view":
            self.main_screen.query_one("#log-filter").focus()
        elif pane == "agents-view":
            self.main_screen.query_one("#pipeline-agents").focus()
        elif pane == "pipeline-view":
            self.main_screen.refresh_pipeline()
            table = self.main_screen.query_one("#phase-table", DataTable)
            pipeline = self.main_screen.query_one(PipelineStatus)
            table.move_cursor(row=table.get_row_index(pipeline.selected_phase or pipeline.last_phase))
            self.main_screen.query_one("#pipeline-flow").focus()
        elif pane == "overview":
            self.main_screen.query_one("#timeline").focus()

    def action_focus_command(self) -> None:
        self.main_screen.query_one("#command-input").focus()

    def action_select_pipeline_phase(self, phase):
        pipeline = self.main_screen.query_one(PipelineStatus)
        if phase in pipeline.stages:
            pipeline.selected_phase = phase
            self.action_view("pipeline-view")
            table = self.main_screen.query_one("#phase-table", DataTable)
            table.move_cursor(row=table.get_row_index(phase))

    def action_inspect_pipeline_agent(self, key):
        if key in self.main_screen.query_one(PipelineStatus).agents:
            self.action_view("logs-view")
            self.main_screen.query_one("#log-filter", Input).value = key

    def action_unfocus(self) -> None:
        self.screen.set_focus(None)

    def action_show_help(self) -> None:
        if not isinstance(self.screen, WorkspaceHelpModal):
            self.push_screen(WorkspaceHelpModal())

    def action_configure_provider(self) -> None:
        if self.is_scan_running or self.demo_mode:
            self.notify("Configure the provider before starting a real scan.", severity="warning")
            return
        self.push_screen(ProviderModal(self.provider, self._provider_keys), self._apply_provider)

    def _apply_provider(self, result) -> None:
        if result is None:
            return
        self.provider = result["provider"]
        if result["key"]:
            self._provider_keys[result["key_env"]] = result["key"]
        self.main_screen.query_one("#provider-btn", Button).label = f"Provider · {self.provider}"
        self.notify("Provider ready for the next scan.")

    def action_configure_auth(self) -> None:
        if self.is_scan_running or self.demo_mode:
            self.notify("Configure target authentication before starting a real scan.", severity="warning")
            return
        if not isinstance(self.screen, AuthModal):
            self.push_screen(AuthModal(self.scan_options, self._auth_yaml_path), self._apply_auth)

    def _apply_auth(self, result) -> None:
        if result is None:
            return
        for key in ("auth_data", "custom_headers"):
            if result[key] is None:
                self.scan_options.pop(key, None)
            else:
                self.scan_options[key] = result[key]
        self._auth_yaml_path = result["yaml_path"]
        self.main_screen.query_one("#auth-btn", Button).label = auth_label(self.scan_options)
        self.notify("Target authentication updated for the next scan.")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {"provider-btn": self.action_configure_provider, "auth-btn": self.action_configure_auth,
                   "start-btn": self.action_start_scan, "stop-btn": self.action_stop_scan,
                   "pause-btn": self.action_pause_scan, "export-btn": self.action_export_findings,
                   "replay-btn": self.main_screen.replay_demo}
        action = actions.get(event.button.id)
        if action:
            result = action()
            if asyncio.iscoroutine(result):
                await result

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target-input":
            self.action_start_scan()

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._tui_quitting or not self.main_screen.query("#command-hints"):
            return
        if event.input.id == "finding-filter":
            self._filter_findings()
        elif event.input.id == "command-input":
            matches = event.input.command_matches()
            hint = "  ·  ".join(matches[:5]) + ("  ·  → complete" if matches else "")
            self.main_screen.query_one("#command-hints", Static).update(
                hint or self.main_screen.command_hint())

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "severity-filter":
            self._filter_findings()

    def _filter_findings(self) -> None:
        if not self.main_screen.query("#findings-table"):
            return
        self.main_screen.query_one("#findings-table", FindingsTable).filter_findings(
            self.main_screen.query_one("#finding-filter", Input).value,
            str(self.main_screen.query_one("#severity-filter", Select).value))

    def on_agent_update(self, message: AgentUpdate) -> None:
        self.main_screen.update_agent(message.agent_name, message.status, message.queue, message.processed, message.vulns)

    def on_pipeline_progress(self, message: PipelineProgress) -> None:
        pipeline = self.main_screen.query_one("#pipeline", PipelineStatus)
        pipeline.observe_phase(message.phase, message.progress, message.status_msg, message.observed_at)
        self.main_screen.record_phase(message.phase, message.status_msg)
        self.main_screen.refresh_pipeline()
        self.sub_title = f"{message.phase.upper()} · {pipeline.progress:.0f}%"
        if self.scan_state == "starting":
            self._set_state("running")

    def _add_finding(self, event: dict) -> None:
        table = self.main_screen.query_one("#findings-table", FindingsTable)
        finding = table.add_finding(**{key: event.get(key) for key in
            ("finding_type", "details", "severity", "param", "payload", "url", "request", "response_excerpt")})
        self.main_screen.query_one("#timeline", ScanTimeline).add_event(
            f"Evidence added · {finding.severity.lower()} · {finding.finding_type}",
            category="evidence", finding_id=finding.id)
        self._total_findings = len(table.findings)
        counts = Counter(f.severity for f in table.findings)
        self.main_screen.query_one("#findings-count", Static).update(Text(
            "   ".join(f"{label} {counts[severity]}" for severity, label in
                       (("CRITICAL", "CRIT"), ("HIGH", "HIGH"), ("MEDIUM", "MED"), ("LOW", "LOW"), ("INFO", "INFO")))))
        self._update_status()
        now = time.monotonic()
        if not self.demo_mode and str(event.get("severity", "")).lower() in {"high", "critical"} and now - self._last_notification > 1:
            self._last_notification = now
            self.notify(f"{event['severity'].upper()}: {event['finding_type']}", severity="warning")

    def on_new_finding(self, message: NewFinding) -> None:
        self._add_finding({key: getattr(message, key) for key in ("finding_type", "details", "severity", "param", "payload")})

    def on_payload_tested(self, message: PayloadTested) -> None:
        from .widgets.payload_feed import PayloadFeed
        self.main_screen.query_one("#payload-feed", PayloadFeed).add_payload(
            message.payload, message.agent, status={"success": "confirmed", "fail": "failed"}.get(message.result, message.result))

    def on_log_entry(self, message: LogEntry) -> None:
        self._log(message.level, message.message)

    def on_metrics_update(self, message: MetricsUpdate) -> None:
        pipeline = self.main_screen.query_one("#pipeline", PipelineStatus)
        pipeline.urls_total = max(pipeline.urls_total, message.urls_discovered)
        pipeline.urls_analyzed = max(pipeline.urls_analyzed, message.urls_analyzed)
        from .widgets.activity import ActivityGraph
        self.main_screen.query_one("#activity", ActivityGraph).req_rate = message.req_rate

    def on_scan_complete(self, message: ScanComplete) -> None:
        self._events.add({"event": "finished", "state": "complete", "total_findings": message.total_findings})

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if isinstance(event.data_table, FindingsTable):
            finding = event.data_table.get_finding(event.row_key.value)
            if finding:
                self.push_screen(FindingDetailsModal(finding))
        elif event.data_table.id == "swarm":
            self.action_view("logs-view")
            self.main_screen.query_one("#log-filter", Input).value = str(event.row_key.value)
        elif event.data_table.id == "phase-table":
            self.action_select_pipeline_phase(event.row_key.value)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "timeline" and isinstance(event.item, TimelineEntry) and event.item.finding_id:
            finding = self.main_screen.query_one(FindingsTable).get_finding(event.item.finding_id)
            if finding:
                self.push_screen(FindingDetailsModal(finding))

    async def on_command_input_command_submitted(self, message: CommandInput.CommandSubmitted) -> None:
        parts = message.command.strip().split(maxsplit=1)
        if not parts:
            return
        raw = message.command.strip()
        if not raw.startswith("/"):
            self.notify("Use the SCAN TARGET field above for URLs. Type / for commands.", severity="warning")
            if not self.is_scan_running and not self.demo_mode:
                self.main_screen.query_one("#target-input", Input).focus()
            return
        command, args = parts[0].lower().lstrip("/"), parts[1] if len(parts) > 1 else ""
        if command == "start":
            if args:
                self.notify("Set the URL in SCAN TARGET above, then use /start.", severity="warning")
                return
            self.action_start_scan()
        elif command == "provider":
            self.action_configure_provider()
        elif command == "auth":
            self.action_configure_auth()
        elif command == "stop":
            await self.action_stop_scan()
        elif command in {"pause", "resume"}:
            if (command == "pause" and self.scan_state == "running") or (command == "resume" and self.scan_state == "paused"):
                await self.action_pause_scan()
            else:
                self.notify(f"Cannot {command} while {self.scan_state}.", severity="warning")
        elif command in {"help", "?", ""}:
            self.action_show_help()
        elif command in {"filter", "show"}:
            self.action_view("logs-view")
            self.main_screen.query_one("#log-filter", Input).value = args
        elif command == "clear":
            self.main_screen.query_one("#log-inspector", LogInspector).clear()
        elif command == "export":
            self.action_export_findings(args or None)
        elif command in {"activity", "timeline", "findings", "agents", "logs", "pipeline"}:
            self.action_view({"activity": "overview", "timeline": "overview", "findings": "findings-view", "agents": "agents-view", "logs": "logs-view", "pipeline": "pipeline-view"}[command])
            if command == "findings" and args:
                self.main_screen.query_one("#finding-filter", Input).value = args
        else:
            self.notify(f"Unknown command: {command}. F1 shows help.", severity="warning")

    def action_export_findings(self, output: str | None = None) -> None:
        table = self.main_screen.query_one("#findings-table", FindingsTable)
        path = Path(output).expanduser() if output else Path(self.report_path or "reports/tui") / f"findings_{time.time_ns()}.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as handle:
                json.dump({"target": self.target, "demo": self.demo_mode,
                           "findings": [asdict(finding) for finding in table.findings]}, handle, indent=2, ensure_ascii=False)
            self._log("INFO", f"Exported {len(table.findings)} findings to {path.resolve()}")
            self.notify(f"Exported to {path.resolve()}", timeout=8)
        except (OSError, ValueError) as exc:
            self.notify(f"Export failed: {exc}", severity="error")
