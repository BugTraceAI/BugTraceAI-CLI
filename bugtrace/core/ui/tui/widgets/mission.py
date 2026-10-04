"""Interactive phase nodes and specialist cards, backed by observed scan data."""
from collections import Counter
import math

from rich.style import Style
from rich.text import Text
from textual.binding import Binding
from textual.geometry import Region
from textual.reactive import reactive

from .. import theme
from .pipeline import PHASES, PipelineLinks, PipelineStatus


ACTIVE = {"running", "active", "testing", "working"}
TERMINAL = {"complete", "stopped", "failed"}


def fit(text, width):
    text = text.copy() if isinstance(text, Text) else Text(str(text))
    text.truncate(max(0, width), overflow="ellipsis")
    text.pad_right(max(0, width - text.cell_len))
    return text


def meter(value, width, color, frame=None):
    width = max(1, width)
    if frame is not None:
        position = frame % width
        result = Text("━" * position, style=theme.ELEVATED)
        result.append("●", style=color)
        result.append("━" * (width - position - 1), style=theme.ELEVATED)
        return result
    filled = min(width, max(0, math.floor(float(value) * width)))
    result = Text("━" * filled, style=color)
    result.append("━" * (width - filled), style=theme.ELEVATED)
    return result


def join_cards(cards, separator="  ", connector=False, connector_colors=()):
    result = Text(no_wrap=True, overflow="ellipsis")
    for line in range(len(cards[0])):
        if line:
            result.append("\n")
        for index, card in enumerate(cards):
            if index:
                color = connector_colors[index - 1] if connector_colors else theme.BORDER
                result.append(" ─›" if connector and line == 2 else separator, style=color)
            result.append(card[line])
    return result


class PhaseMap(PipelineLinks, can_focus=True):
    BINDINGS = [
        Binding("left,up", "move(-1)", "Previous phase", show=False),
        Binding("right,down", "move(1)", "Next phase", show=False),
        Binding("enter,space", "inspect", "Inspect phase", show=False),
    ]

    def __init__(self, pipeline: PipelineStatus, **kwargs):
        super().__init__(**kwargs)
        self.pipeline = pipeline

    def on_mount(self):
        self.set_interval(0.2, self.refresh)

    def action_move(self, delta):
        key = self.pipeline.selected_phase or self.pipeline.last_phase
        index = next((i for i, spec in enumerate(PHASES) if spec.key == key), 0)
        self.pipeline.selected_phase = PHASES[max(0, min(len(PHASES) - 1, index + delta))].key
        self.screen.refresh_pipeline()

    def action_inspect(self):
        self.app.action_select_pipeline_phase(self.pipeline.selected_phase or self.pipeline.last_phase)

    def render(self):
        width = self.size.width or 114
        short = self.screen.has_class("short")
        columns = 6 if width >= 84 else 3
        card_width = max(6, (width - 3 * (columns - 1)) // columns)
        inside = card_width - 2
        cards = []
        for index, spec in enumerate(PHASES):
            stage = self.pipeline.stages[spec.key]
            icon, state_label, color = self.pipeline.state_style(stage)
            selected = self.has_focus and (self.pipeline.selected_phase or self.pipeline.last_phase) == spec.key
            background = theme.PANEL if selected or stage.state == "running" else theme.BACKGROUND
            border = color if stage.state in {"running", "failed", "stopped"} else theme.SECONDARY if selected else theme.BORDER
            base = Style(color=border, bgcolor=background, meta={"@click": f"app.select_pipeline_phase('{spec.key}')"})
            active = stage.state == "running"
            left, right = "│", "│"
            top, bottom, edge = ("╭", "╮"), ("╰", "╯"), "─"
            title = f" {index + 1:02} "
            title = edge + title + edge * (inside - 5) if inside >= 5 else title
            label = spec.label
            label_line = Text(left, style=base)
            if inside >= len(label) + 4:
                caption = Text(icon + " ", style=color)
                caption.append(label, style=Style(color=color if active else theme.SECONDARY, bold=active))
                caption.pad_left((inside - caption.cell_len) // 2)
            else:
                caption = Text(label.center(inside), style=Style(color=color if active else theme.SECONDARY, bold=active))
            label_line.append(fit(caption, inside))
            label_line.append(right)
            if stage.state in {"skipped", "unobserved"}:
                progress = fit("not used" if stage.state == "skipped" else "unknown", inside)
            elif not short and inside >= 10 and stage.progress:
                progress = Text(" ")
                progress.append(meter(stage.progress / 100, inside - 7, color))
                progress.append(f" {stage.progress:3.0f}% ", style=theme.TEXT if active else theme.SECONDARY)
            else:
                frame = self.pipeline._frame if active and not stage.progress and self.pipeline.scan_state not in {"paused", "stopping"} else None
                progress = meter(stage.progress / 100, inside, color, frame)
            progress_line = Text(left, style=base)
            progress_line.append(progress)
            progress_line.append(right)
            lines = [Text(top[0] + title + top[1], style=base), label_line, progress_line]
            if not short:
                elapsed = int(stage.seconds(self.pipeline.clock()))
                clock = f"{elapsed // 60:02}:{elapsed % 60:02}" if stage.started is not None or stage.elapsed else "—"
                status = {"Running": "live", "Complete": "done", "Pending": "next"}.get(state_label, state_label.lower())
                caption = f"{clock} · {status}" if clock != "—" else status
                if len(caption) > inside:
                    caption = clock if clock != "—" else status
                clock_line = Text(left, style=base)
                clock_line.append(fit(Text(caption.center(inside), style=theme.SECONDARY if active else theme.MUTED), inside))
                clock_line.append(right)
                lines.append(clock_line)
            lines.append(Text(bottom[0] + edge * inside + bottom[1], style=base))
            cards.append(lines)
        result = Text(no_wrap=True, overflow="ellipsis")
        for start in range(0, len(cards), columns):
            if start:
                result.append("\n  ↳ continuing\n", style=theme.MUTED)
            link_colors = [theme.ACCENT if self.pipeline.stages[PHASES[i].key].state == "running"
                           else theme.SUCCESS if self.pipeline.stages[PHASES[i - 1].key].state == "complete"
                           else theme.BORDER for i in range(start + 1, min(start + columns, len(PHASES)))]
            result.append(join_cards(cards[start:start + columns], separator="   ", connector=True, connector_colors=link_colors))
        return result


class MissionStats(PipelineLinks):
    def __init__(self, pipeline: PipelineStatus, **kwargs):
        super().__init__(**kwargs)
        self.pipeline = pipeline

    def render(self):
        from .findings_table import FindingsTable
        findings = self.screen.query_one(FindingsTable).findings
        severities = Counter(f.severity for f in findings)
        active = sum(a["status"] in ACTIVE for a in self.pipeline.agents.values()) if self.pipeline.scan_state not in TERMINAL else 0
        queue = sum(a["queue"] for a in self.pipeline.agents.values())
        width = max(12, ((self.size.width or 114) - 4) // 3)
        metrics = (
            ("ENDPOINTS", f"{self.pipeline.urls_analyzed:02} / {self.pipeline.urls_total:02}", "URLs analyzed / discovered", theme.ACCENT, "app.view('agents-view')"),
            ("SPECIALISTS", f"{active:02} active", f"{queue} queued · {len(self.pipeline.agents)} reporting", "#4dd2ff", "app.view('agents-view')"),
            ("FINDINGS", f"{len(findings):02} captured", f"CRIT {severities['CRITICAL']}  ·  HIGH {severities['HIGH']}", theme.ERROR if severities['CRITICAL'] + severities['HIGH'] else theme.SECONDARY, "app.view('findings-view')"),
        )
        cards = []
        for title, value, subtitle, color, action in metrics:
            base = Style(bgcolor=theme.PANEL, meta={"@click": action})
            card = []
            for text, style in ((title, theme.SECONDARY), (value, f"bold {theme.TEXT}"), (subtitle, theme.MUTED)):
                line = Text("▎ ", style=base + Style(color=color))
                line.append(fit(Text(text, style=style), width - 3))
                line.append(" ")
                card.append(line)
            cards.append(card)
        return join_cards(cards)


class AgentCards(PipelineLinks, can_focus=True):
    BINDINGS = [
        Binding("left", "move(-1)", "Previous agent", show=False),
        Binding("right", "move(1)", "Next agent", show=False),
        Binding("up", "row(-1)", "Previous row", show=False),
        Binding("down", "row(1)", "Next row", show=False),
        Binding("enter,space", "inspect", "Agent logs", show=False),
    ]
    cursor = reactive(0)

    def __init__(self, pipeline: PipelineStatus, **kwargs):
        super().__init__(**kwargs)
        self.pipeline = pipeline

    @property
    def columns(self):
        return 3 if self.size.width >= 85 else 2 if self.size.width >= 48 else 1

    def on_mount(self):
        self.set_interval(0.5, self.refresh)

    def on_resize(self):
        self.refresh(layout=True)

    def action_move(self, delta):
        self.cursor = max(0, min(len(self.pipeline.agents) - 1, self.cursor + delta))
        # Reveal the selected row within the enclosing vertical scroll view.
        self.parent.scroll_to_region(Region(self.virtual_region.x, self.virtual_region.y + (self.cursor // self.columns) * 5,
                                          self.size.width, 4), animate=False)

    def action_row(self, delta):
        self.action_move(delta * self.columns)

    def action_inspect(self):
        keys = list(self.pipeline.agents)
        if keys:
            self.app.action_inspect_pipeline_agent(keys[min(self.cursor, len(keys) - 1)])

    def render(self):
        if not self.pipeline.agents:
            return Text("Specialist cards appear as agents report work.\nQueue and processed counts come from the scanner.", style=theme.MUTED)
        width = max(16, ((self.size.width or 114) - 2 * (self.columns - 1)) // self.columns)
        inside = width - 2
        cards = []
        for index, (key, agent) in enumerate(self.pipeline.agents.items()):
            color = theme.AGENT_COLORS.get(key, theme.ACCENT)
            selected = self.has_focus and index == min(self.cursor, len(self.pipeline.agents) - 1)
            active = agent["status"] in ACTIVE
            base = Style(color=color if selected else theme.BORDER,
                         bgcolor=theme.ELEVATED if selected else theme.PANEL if active else theme.PANEL_QUIET,
                         meta={"@click": f"app.inspect_pipeline_agent('{key}')"})
            status = {"active": "running", "complete": "done", "working": "running"}.get(agent["status"], agent["status"])
            icon = self.pipeline.SPINNER[self.pipeline._frame] if active else "✓" if status == "done" else "!" if status in {"error", "failed"} else "○"
            status_color = color if active else theme.SUCCESS if status == "done" else theme.ERROR if status in {"error", "failed"} else theme.MUTED
            if active and self.pipeline.scan_state in TERMINAL:
                status, icon, status_color = "last " + status, "·", theme.MUTED
            elif active and self.pipeline.scan_state == "paused":
                status, icon, status_color = "paused", "Ⅱ", theme.WARNING
            name = str(agent["name"]).removesuffix("Agent").removesuffix("_agent")
            header = Text(f" {name} ", style=f"bold {color}")
            status_text = Text(icon, style=status_color)
            status_text.append(f" {status} ", style=theme.SECONDARY if active else theme.MUTED)
            header.append(" " * max(1, inside - header.cell_len - status_text.cell_len))
            header.append(status_text)
            lines = [Text("╭", style=base)]
            lines[0].append(fit(header, inside))
            lines[0].append("╮")
            counts = Text("│", style=base)
            counts.append(fit(Text(f" {agent['processed']} done · {agent['queue']} queued", style=theme.TEXT if active else theme.SECONDARY), inside))
            counts.append("│")
            work = Text("│", style=base)
            work.append(" ")
            total = agent["processed"] + agent["queue"]
            work.append(meter(agent["processed"] / total if total else 0, max(1, inside - 10), color))
            work.append(fit(Text(f" {agent['vulns']} {'hit' if agent['vulns'] == 1 else 'hits'}", style=theme.WARNING if agent["vulns"] else theme.MUTED), 9))
            work.append("│")
            lines.extend((counts, work, Text("╰" + "─" * inside + "╯", style=base)))
            cards.append(lines)
        result = Text(no_wrap=True, overflow="ellipsis")
        for start in range(0, len(cards), self.columns):
            if start:
                result.append("\n\n")
            result.append(join_cards(cards[start:start + self.columns]))
        return result
