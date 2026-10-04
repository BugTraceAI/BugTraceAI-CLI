"""The six real pipeline phases, observed completions, and live specialist work."""
from dataclasses import dataclass
import time

from rich.style import Style
from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

from .. import theme


@dataclass(frozen=True)
class PhaseSpec:
    key: str
    label: str
    short: str
    owner: str
    description: str


PHASES = (
    PhaseSpec("reconnaissance", "Recon", "Recon", "ReconAgent", "Crawl and discover target endpoints."),
    PhaseSpec("discovery", "Discovery", "Discovery", "DASTySAST", "Analyze discovered URLs and collect candidate findings."),
    PhaseSpec("strategy", "Strategy", "Strategy", "ThinkingAgent", "Deduplicate findings and distribute specialist queues."),
    PhaseSpec("exploitation", "Exploit", "Exploit", "Specialists", "Test candidate findings with parallel specialist agents."),
    PhaseSpec("validation", "Validate", "Validate", "Validator / Auditor", "Review evidence and confirm findings."),
    PhaseSpec("reporting", "Report", "Report", "ReportingAgent", "Generate the scan reports."),
)


@dataclass
class PhaseState:
    state: str = "pending"
    progress: float = 0
    message: str = ""
    started: float | None = None
    elapsed: float = 0

    def seconds(self, now):
        return self.elapsed + (max(0, now - self.started) if self.started is not None else 0)


class PipelineLinks(Static):
    """Clickable text keeps the phase and agent colors in its Rich spans."""

    @property
    def link_style(self):
        return Style()

    @property
    def link_style_hover(self):
        return Style(underline=True, bold=True, bgcolor=theme.ELEVATED)


class PipelineStatus(PipelineLinks):
    phase = reactive("ready")
    progress = reactive(0.0)
    status_msg = reactive("Waiting for a target")
    urls_analyzed = reactive(0)
    urls_total = reactive(0)
    payloads_tested = reactive(0)
    demo_mode = reactive(False)
    STATES = {
        "pending": ("○", "Pending", theme.MUTED),
        "running": ("●", "Running", theme.ACCENT),
        "complete": ("✓", "Complete", theme.SUCCESS),
        "skipped": ("–", "Not used", theme.MUTED),
        "unobserved": ("○", "Not observed", theme.MUTED),
        "stopped": ("■", "Stopped", theme.WARNING),
        "failed": ("!", "Failed", theme.ERROR),
    }
    SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, *args, clock=time.monotonic, **kwargs):
        super().__init__(*args, **kwargs)
        self.clock = clock
        self.stages = {spec.key: PhaseState() for spec in PHASES}
        self.agents = {}
        self.scan_state = "idle"
        self.selected_phase = None
        self.last_phase = "reconnaissance"
        self._frame = 0

    def on_mount(self):
        self.set_interval(0.2, self._tick)

    def _tick(self):
        if self.scan_state in {"running", "starting", "demo"}:
            self._frame = (self._frame + 1) % len(self.SPINNER)
            self.refresh()

    def reset(self, mode="all", focused=False):
        enabled = {"exploitation", "reporting"} if focused else {"validation"} if mode == "manager" else {spec.key for spec in PHASES}
        self.stages = {spec.key: PhaseState(state="pending" if spec.key in enabled else "skipped") for spec in PHASES}
        self.agents.clear()
        self.phase, self.progress, self.status_msg = "ready", 0, "Waiting for a target"
        self.urls_total = self.urls_analyzed = self.payloads_tested = 0
        self.selected_phase = None
        self.last_phase = "exploitation" if focused else "validation" if mode == "manager" else "reconnaissance"
        self.scan_state = "idle"
        self.refresh()

    def observe_phase(self, phase, progress, message="", observed_at=None):
        key = str(phase).lower()
        value = max(0, min(1, float(progress)))
        self.phase, self.progress, self.status_msg = key, value * 100, message
        if key not in self.stages:
            return
        stage = self.stages[key]
        self.last_phase = key
        now = self.clock() if observed_at is None else min(self.clock(), float(observed_at))
        for other_key, other in self.stages.items():
            if other_key != key and other.state == "running":
                other.elapsed, other.started = other.seconds(now), None
                other.state = "unobserved"
        if value < 1:
            if stage.state != "running":
                stage.started = now
            stage.state = "running"
        else:
            stage.elapsed = stage.seconds(now)
            stage.started, stage.state = None, "complete"
        stage.progress, stage.message = value * 100, message
        self.refresh()

    def set_scan_state(self, state):
        self.scan_state = state
        if state in {"complete", "stopped", "failed"}:
            for stage in self.stages.values():
                if stage.state == "running":
                    stage.elapsed, stage.started = stage.seconds(self.clock()), None
                    stage.state = state
                    if state == "complete":
                        stage.progress = 100
                elif stage.state == "pending" and state == "complete":
                    stage.state = "unobserved"
        self.refresh()

    def update_agent(self, name, status, queue=0, processed=0, vulns=0):
        self.agents[theme.agent_key(name)] = {
            "name": name, "status": str(status).lower(), "queue": queue, "processed": processed, "vulns": vulns,
        }
        self.refresh()

    def state_style(self, stage):
        icon, label, color = self.STATES[stage.state]
        if stage.state == "running":
            if self.scan_state == "paused":
                return "Ⅱ", "Paused", theme.WARNING
            if self.scan_state == "stopping":
                return "■", "Stopping", theme.WARNING
            icon = self.SPINNER[self._frame]
        return icon, label, color

    def route_text(self, width=None, clickable=True):
        width = width or self.size.width
        compact = width < 85
        result = Text(no_wrap=True, overflow="ellipsis")
        for index, spec in enumerate(PHASES):
            if index:
                result.append(" › " if not compact else " ›", style=theme.MUTED)
            stage = self.stages[spec.key]
            icon, _, color = self.state_style(stage)
            meta = {"@click": f"app.select_pipeline_phase('{spec.key}')"} if clickable else {}
            base = Style(bgcolor=theme.PANEL if stage.state == "running" else None, meta=meta)
            result.append(icon + " ", style=base + Style(color=color))
            result.append(spec.short if compact else spec.label, style=base + Style(
                color=theme.SECONDARY if stage.state == "complete" else color, bold=stage.state == "running"))
        return result

    def agents_text(self, width=None):
        width = width or self.size.width
        result = Text(no_wrap=True, overflow="ellipsis")
        active = [a for a in self.agents.values() if a["status"] in {"running", "active", "testing", "working"}]
        if self.scan_state in {"complete", "stopped", "failed"}:
            active = []
        if not active:
            spec = next((spec for spec in PHASES if spec.key == self.phase), None)
            result.append(spec.owner if spec else "Pipeline", style=theme.SECONDARY)
            result.append("  ·  " + ("waiting" if self.scan_state == "idle" else self.scan_state), style=theme.MUTED)
            return result
        result.append("├─ ", style=theme.MUTED)
        shown = active[:max(1, min(6, (width - 10) // 14))]
        for index, agent in enumerate(shown):
            if index:
                result.append("  ", style=theme.MUTED)
            key = theme.agent_key(agent["name"])
            color = theme.AGENT_COLORS.get(key, theme.ACCENT)
            result.append(str(agent["name"]).removesuffix("Agent"), style=Style(color=color, meta={"@click": f"app.inspect_pipeline_agent('{key}')"}))
            result.append(f" {agent['queue']}q", style=theme.MUTED)
        if len(active) > len(shown):
            result.append(f"  +{len(active) - len(shown)}", style=theme.MUTED)
        return result

    def detail_text(self, key=None, compact=False):
        key = key or self.selected_phase or (self.phase if self.phase in self.stages else self.last_phase)
        spec = next((spec for spec in PHASES if spec.key == key), PHASES[0])
        stage = self.stages[spec.key]
        icon, label, color = self.state_style(stage)
        if compact:
            result = Text(f"{icon} {spec.label} · {label} · {spec.owner}\n", style=color)
            result.append(stage.message or spec.description, style=theme.SECONDARY)
            return result
        result = Text(f"{icon} {spec.label} · {label}\n", style=color)
        result.append(spec.description + "\n", style=theme.TEXT)
        result.append(f"Component: {spec.owner}\n", style=theme.SECONDARY)
        if stage.message:
            result.append(stage.message + "\n", style=theme.SECONDARY)
        if spec.key == "exploitation" and self.agents:
            for agent in self.agents.values():
                result.append(f"  {agent['name']} · {agent['status']} · {agent['queue']} queued · {agent['processed']} processed · {agent['vulns']} findings\n", style=theme.SECONDARY)
        return result

    def render(self):
        result = self.route_text()
        result.append("\n")
        result.append(self.agents_text())
        result.append("\n")
        stage = self.stages.get(self.phase if self.phase in self.stages else self.last_phase)
        if stage:
            _, label, color = self.state_style(stage)
            if self.scan_state in {"complete", "stopped", "failed"}:
                _, label, color = self.STATES[self.scan_state]
            completed = sum(s.state == "complete" for s in self.stages.values())
            enabled = sum(s.state != "skipped" for s in self.stages.values())
            compact = self.size.width < 85
            percentage = (f"  ·  {'' if compact else 'phase '}{self.progress:.0f}%"
                          if self.progress and self.phase in self.stages else "")
            result.append(f"{label}{percentage}  ·  {completed}/{enabled} {'phases' if compact else 'stages complete'}", style=color)
            if self.urls_total:
                result.append(f"  ·  URLs {self.urls_analyzed}/{self.urls_total}", style=theme.SECONDARY)
        else:
            result.append("Click a phase to inspect it · F6 pipeline", style=theme.MUTED)
        result.no_wrap = True
        result.overflow = "ellipsis"
        return result
