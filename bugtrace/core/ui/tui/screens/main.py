"""A quiet scan transcript with findings, telemetry, and logs on demand."""
from urllib.parse import urlsplit
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Collapsible, DataTable, Input, Select, Static, TabbedContent, TabPane

from bugtrace import __version__
from .. import theme
from ..auth_config import auth_label

from ..widgets.activity import ActivityGraph
from ..widgets.command_input import CommandInput
from ..widgets.findings_table import FindingsTable
from ..widgets.log_inspector import LogInspector
from ..widgets.metrics import SystemMetrics
from ..widgets.mission import AgentCards, MissionStats, PhaseMap
from ..widgets.payload_feed import PayloadFeed
from ..widgets.pipeline import PHASES, PipelineStatus
from ..widgets.timeline import ScanTimeline


class MainScreen(Screen):
    def __init__(self, demo_mode=False, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = demo_mode
        self.agent_rows = set()
        self.agent_states = {}
        self._last_phase = ""
        self.pipeline = PipelineStatus(id="pipeline")

    def compose(self) -> ComposeResult:
        from bugtrace.core.config import settings

        yield Static(self.brand_text(), id="brand")
        with Vertical(id="scan-setup"):
            yield Static("SCAN TARGET", id="scan-setup-title")
            with Horizontal(id="scan-controls"):
                yield Input(value=self.app.target or "", placeholder="https://example.com", id="target-input", compact=True)
                yield Button("Start", id="start-btn", variant="success", compact=True)
                yield Button("Pause", id="pause-btn", compact=True)
                yield Button("Stop", id="stop-btn", compact=True)
            with Horizontal(id="scan-options"):
                with Horizontal(id="crawl-options"):
                    yield Static("Depth", id="depth-label", classes="scan-label")
                    yield Input(value=str(self.app.scan_options.get("max_depth", settings.MAX_DEPTH)),
                                type="integer", id="max-depth", compact=True,
                                tooltip="Crawl depth · 1–10 levels")
                    yield Static("Max URLs", id="urls-label", classes="scan-label")
                    yield Input(value=str(self.app.scan_options.get("max_urls", settings.MAX_URLS)),
                                type="integer", id="max-urls", compact=True,
                                tooltip="Maximum unique URLs · 1–5000")
                with Horizontal(id="scan-integrations"):
                    yield Button(f"Provider · {self.app.provider}", id="provider-btn", compact=True,
                                 tooltip="F7 · LLM provider and API key")
                    yield Button(auth_label(self.app.scan_options), id="auth-btn", compact=True,
                                 tooltip="F8 · Target token or authentication YAML")
        yield self.pipeline
        with TabbedContent(id="workspace-tabs", initial="pipeline-view"):
            with TabPane("Pipeline  F2", id="pipeline-view"):
                with VerticalScroll(id="pipeline-scroll"):
                    yield Static("SCAN OVERVIEW", classes="view-title")
                    yield Static("Follow the six stages. Select a phase to inspect its progress and elapsed time.", classes="view-subtitle")
                    yield MissionStats(self.pipeline, id="mission-stats")
                    with Horizontal(id="mission-heading"):
                        yield Static("PIPELINE  ·  ← → choose a phase", id="mission-title", classes="section-label")
                        if self.demo_mode:
                            yield Button("↻ Replay", id="replay-btn", compact=True)
                    yield PhaseMap(self.pipeline, id="pipeline-flow")
                    yield Static(id="phase-detail")
                    yield Static("PHASE TIMINGS", classes="section-label")
                    yield DataTable(id="phase-table", cursor_type="row")
            with TabPane("Findings  F3", id="findings-view"):
                yield Static("EVIDENCE LIBRARY", classes="view-title")
                yield Static("Search, inspect and export the vulnerabilities reported by the scanner.", classes="view-subtitle")
                yield Static("No findings yet — results appear as agents report them.", id="findings-count")
                with Horizontal(id="finding-tools"):
                    yield Input(placeholder="Search type, URL, parameter or evidence…", id="finding-filter", compact=True)
                    yield Select([(s.title(), s) for s in ("all", "critical", "high", "medium", "low", "info")],
                                 allow_blank=False, value="all", id="severity-filter", compact=True)
                    yield Button("Export", id="export-btn", compact=True)
                yield FindingsTable(id="findings-table")
                yield Static("Enter: evidence · click a heading to sort · Ctrl+E: export all findings", classes="view-hint")
            with TabPane("Agents  F4", id="agents-view"):
                with VerticalScroll(id="overview-scroll"):
                    yield Static("SPECIALIST WORKSPACE", classes="view-title")
                    yield Static("Who is working, what is queued and what each specialist found. Open a card for its logs.", classes="view-subtitle")
                    yield Static("SPECIALISTS", id="specialist-heading", classes="section-label")
                    yield AgentCards(self.pipeline, id="pipeline-agents")
                    with Collapsible(title="Detailed counters", collapsed=True, id="agent-counters"):
                        yield DataTable(id="swarm", cursor_type="row", zebra_stripes=False)
                    with Collapsible(title="Runtime & recent payloads", collapsed=True, id="runtime-details"):
                        with Horizontal(id="telemetry-row"):
                            yield ActivityGraph(id="activity")
                            yield SystemMetrics(id="metrics")
                        yield Static("Recent payloads", classes="section-label")
                        yield PayloadFeed(id="payload-feed")
            with TabPane("Timeline  F5", id="overview"):
                yield Static("Scan journal", id="workspace-title")
                yield Static("Milestones, state changes and alerts — the story of this scan.", id="workspace-hint")
                yield ScanTimeline(id="timeline")
            with TabPane("Logs  F6", id="logs-view"):
                yield Static("ENGINE LOGS", classes="view-title")
                yield Static("Raw engine output. Filter by agent, level or message to investigate a problem.", classes="view-subtitle")
                yield LogInspector(id="log-inspector")
        yield Static(self.command_hint(), id="command-hints", markup=False)
        yield CommandInput(id="command-input")
        yield Static(id="scan-status", markup=False)
        yield Static("F1 help  ·  Tab focus  ·  Ctrl+S start  ·  Ctrl+X stop  ·  Ctrl+E export  ·  Ctrl+Q quit", id="key-hints")

    def brand_text(self, width=114):
        result = Text("◈ ", style=theme.ACCENT)
        result.append("BugTrace", style=f"bold {theme.TEXT}")
        result.append("AI", style=f"bold {theme.ACCENT}")
        result.append(f"  {__version__}", style=theme.MUTED)
        state = "demo" if self.demo_mode else self.app.scan_state
        color = theme.WARNING if state in {"demo", "paused", "stopping"} else theme.ERROR if state == "failed" else theme.ACCENT
        badge = Text(f" {state.upper()} ", style=f"bold {color} on {theme.PANEL}")
        try:
            host = urlsplit(self.app.target or "").hostname or "choose a target"
        except ValueError:
            host = "choose a target"
        target = Text(host, style=theme.SECONDARY)
        target.truncate(max(0, width - result.cell_len - badge.cell_len - 4), overflow="ellipsis")
        result.append(" " * max(2, width - result.cell_len - target.cell_len - badge.cell_len - 2))
        result.append(target)
        result.append("  ")
        result.append(badge)
        return result

    def command_hint(self):
        if self.demo_mode:
            return "Demo · inspect a phase or agent · Replay restarts the preview"
        if self.app.scan_state == "paused":
            return "COMMANDS · Scan paused · /resume · /stop · /findings · /export"
        if self.app.scan_state == "stopping":
            return "COMMANDS · Stopping scan · /findings · /logs"
        if self.app.is_scan_running:
            return "COMMANDS · Scan active · /pause · /stop · /findings · /export"
        return "COMMANDS · Type / for suggestions · F1 for help"

    @staticmethod
    def section_heading(title, hint, width):
        text = Text(title, style=f"bold {theme.TEXT}")
        text.append(f"  {hint}  ", style=theme.MUTED)
        text.append("─" * max(0, width - text.cell_len), style=theme.BORDER)
        return text

    def on_mount(self) -> None:
        self.query_one("#swarm", DataTable).add_columns("Agent", "Status", "Queue", "Processed", "Findings")
        table = self.query_one("#phase-table", DataTable)
        for label, width in (("Phase", 10), ("State", 14), ("Progress", 8), ("Elapsed", 7)):
            table.add_column(label, width=width)
        for spec in PHASES:
            table.add_row(spec.label, "Pending", "—", "—", key=spec.key)
        self.query_one(PipelineStatus).reset()
        self.set_interval(1, self.refresh_pipeline)
        self.query_one("#timeline", ScanTimeline).add_event(
            "Ready when you are", "Enter a target above, choose crawl limits and press Start.\nUse / to discover commands, or switch views with F2–F6.", category="session")
        if self.demo_mode:
            self.enable_demo_mode()
            self.set_interval(1, self.advance_demo_pipeline)
            self.query_one(PhaseMap).focus()
        else:
            self.query_one("#target-input", Input).focus()
        self.refresh_pipeline()

    def on_resize(self, event) -> None:
        self.set_class(event.size.width < 100, "compact")
        self.set_class(event.size.height < 30, "short")
        self.query_one("#brand", Static).update(self.brand_text(event.size.width - (2 if event.size.width < 100 else 6)))
        tabs = self.query_one(TabbedContent)
        for pane, label, key in (("pipeline-view", "Pipeline", "F2"), ("findings-view", "Findings", "F3"),
                                 ("agents-view", "Agents", "F4"), ("overview", "Timeline", "F5"), ("logs-view", "Logs", "F6")):
            tabs.get_tab(pane).label = label if event.size.width < 100 else f"{label}  {key}"
        self.query_one("#key-hints", Static).update(
            "F1 help  ·  ^S start  ·  ^X stop  ·  ^E export  ·  ^Q quit" if event.size.width < 100 else
            "F1 help  ·  Tab focus  ·  Ctrl+S start  ·  Ctrl+X stop  ·  Ctrl+E export  ·  Ctrl+Q quit")

    def update_agent(self, agent, status, queue=0, processed=0, vulns=0):
        # Old specialists use XSSAgent/xss_agent while the conductor uses xss.
        key = agent.lower().removesuffix("_agent").removesuffix("agent").strip("_")
        table = self.query_one("#swarm", DataTable)
        self.query_one(PipelineStatus).update_agent(agent, status, queue, processed, vulns)
        color = {"running": "#2ECC71", "active": "#2ECC71", "error": "#FF3131", "done": "#FF7F50", "complete": "#FF7F50", "waiting": "#FFC107"}.get(status.lower(), "dim")
        cells = (Text(agent), Text(status.upper(), style=color), str(queue), str(processed), str(vulns))
        if key in self.agent_rows:
            for column, cell in zip(table.columns, cells):
                table.update_cell(key, column, cell)
        else:
            self.agent_rows.add(key)
            table.add_row(*cells, key=key)
        if self.agent_states.get(key) != status.lower():
            self.agent_states[key] = status.lower()
            self.query_one("#timeline", ScanTimeline).add_event(
                f"{agent} · {status.lower()}", f"{processed} processed · {queue} queued · {vulns} findings", category="agent")

    def record_phase(self, phase, status):
        if phase.lower() != self._last_phase:
            self._last_phase = phase.lower()
            label = next((spec.label for spec in PHASES if spec.key == phase.lower()), phase.capitalize())
            self.query_one("#timeline", ScanTimeline).add_event(label, status, category="phase")

    def reset_activity(self, target):
        self.agent_states.clear()
        self._last_phase = ""
        self.query_one("#workspace-title", Static).update("Scan journal")
        timeline = self.query_one("#timeline", ScanTimeline)
        timeline.reset()
        timeline.add_event("Scan requested", target, category="session")

    def refresh_pipeline(self):
        brand = self.query_one("#brand", Static)
        brand.update(self.brand_text(brand.size.width or 114))
        for widget_id, title, hint in (("mission-title", "PIPELINE", "← → inspect"),
                                      ("specialist-heading", "SPECIALISTS", "click a card for logs")):
            heading = self.query_one(f"#{widget_id}", Static)
            heading.update(self.section_heading(title, hint, heading.size.width))
        pipeline = self.query_one(PipelineStatus)
        table = self.query_one("#phase-table", DataTable)
        for spec in PHASES:
            stage = pipeline.stages[spec.key]
            icon, label, color = pipeline.state_style(stage)
            seconds = int(stage.seconds(pipeline.clock()))
            cells = (spec.label, Text(f"{icon} {label}", style=color),
                     f"{stage.progress:.0f}%" if stage.progress else "—",
                     f"{seconds // 60:02}:{seconds % 60:02}" if stage.started is not None or stage.elapsed else "—")
            for column, value in zip(table.columns, cells):
                table.update_cell(spec.key, column, value)
        for widget_id in ("pipeline-flow", "mission-stats", "pipeline-agents"):
            self.query_one(f"#{widget_id}").refresh(layout=True)
        self.query_one("#phase-detail", Static).update(pipeline.detail_text(compact=True))

    def replay_demo(self):
        if not self.demo_mode:
            return
        from ..runtime import EventBuffer
        self.app._events = EventBuffer()
        self.pipeline.reset()
        self.query_one(AgentCards).cursor = 0
        self.query_one(FindingsTable).reset_findings()
        self.query_one("#finding-filter", Input).value = ""
        self.query_one("#severity-filter", Select).value = "all"
        self.query_one("#swarm", DataTable).clear()
        self.agent_rows.clear()
        self.query_one(LogInspector).clear()
        self.enable_demo_mode()
        self.refresh_pipeline()

    def enable_demo_mode(self):
        for widget_id in ("pipeline", "activity", "metrics", "payload-feed"):
            self.query_one(f"#{widget_id}").demo_mode = True
        pipeline = self.query_one("#pipeline", PipelineStatus)
        for spec in PHASES[:3]:
            pipeline.observe_phase(spec.key, 1, f"{spec.label} finished")
        for spec, seconds in zip(PHASES[:3], (14, 32, 8)):
            pipeline.stages[spec.key].elapsed = seconds
        pipeline.observe_phase("exploitation", 0.35, "Specialists are testing the discovered parameters")
        pipeline.set_scan_state("demo")
        pipeline.urls_total, pipeline.urls_analyzed = 100, 62
        pipeline.status_msg = "Specialists are testing the discovered parameters"
        self.reset_activity(self.app.target)
        self.record_phase("Discovery", "Mapped 100 endpoints. Handing parameters to the specialist agents.")
        for agent, status, queue, processed, vulns in (
            ("XSSAgent", "running", 8, 42, 1), ("SQLiAgent", "running", 3, 21, 1),
            ("SSRF", "complete", 0, 18, 1), ("JWT", "waiting", 2, 0, 0),
            ("LFI", "complete", 0, 34, 0), ("IDOR", "running", 5, 12, 0),
        ):
            self.update_agent(agent, status, queue, processed, vulns)
        for finding in (
            {"finding_type": "SQL injection", "details": "Boolean responses differ for the same login request.", "severity": "critical", "param": "username", "payload": "' OR 1=1--", "url": "https://demo.example/login"},
            {"finding_type": "Reflected XSS", "details": "Search parameter reflected into HTML without encoding.", "severity": "high", "param": "q", "payload": "<script>alert(1)</script>", "url": "https://demo.example/search"},
            {"finding_type": "SSRF", "details": "Image fetch reaches an internal endpoint.", "severity": "medium", "param": "image_url", "payload": "http://localhost/admin", "url": "https://demo.example/image"},
            {"finding_type": "Open redirect", "details": "Redirect accepts an external destination.", "severity": "low", "param": "next", "payload": "//example.org", "url": "https://demo.example/redirect"},
        ):
            self.app._add_finding(finding)
        for level, message in (("INFO", "[XSSAgent] Testing search parameters"), ("SUCCESS", "[XSSAgent] Evidence recorded for reflected XSS"), ("INFO", "[SQLiAgent] Comparing boolean responses"), ("WARNING", "[JWT] Waiting for an authenticated token")):
            self.app._log(level, message)

    def advance_demo_pipeline(self):
        pipeline = self.query_one(PipelineStatus)
        if pipeline.phase not in pipeline.stages:
            return
        spec = next(spec for spec in PHASES if spec.key == pipeline.phase)
        value = min(1, pipeline.progress / 100 + 0.04)
        self.app._events.add({"event": "phase", "phase": spec.key, "progress": value,
                              "status": f"Demo · {spec.description}"})
        if value == 1:
            index = PHASES.index(spec)
            if index < len(PHASES) - 1:
                following = PHASES[index + 1]
                self.app._events.add({"event": "phase", "phase": following.key, "progress": 0,
                                      "status": f"Demo · {following.description}"})
                if spec.key == "exploitation":
                    for key, agent in list(pipeline.agents.items()):
                        self.update_agent(agent["name"], "complete", 0, agent["processed"], agent["vulns"])
            else:
                pipeline.set_scan_state("complete")
                self.app._events.add({"event": "phase", "phase": "complete", "progress": 1,
                                      "status": "Demo complete · all six phases finished"})
                self.query_one("#payload-feed", PayloadFeed).demo_mode = False
