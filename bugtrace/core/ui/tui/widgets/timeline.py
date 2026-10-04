"""A bounded, keyboard-accessible transcript of meaningful scan events."""
from collections import deque
from datetime import datetime

from rich.text import Text
from textual.app import ComposeResult
from textual.widgets import ListItem, ListView, Static


class TimelineEntry(ListItem):
    def __init__(self, title, body="", *, category="event", finding_id=None):
        super().__init__(classes=f"timeline-entry {category}")
        self.finding_id = finding_id
        self.heading = Text(title, style="bold")
        self.heading.append(f"  {datetime.now():%H:%M:%S}", style="dim")
        self.body = Text("\n".join(str(body).splitlines()[:5])[:1000])

    def compose(self) -> ComposeResult:
        yield Static(self.heading, classes="entry-heading")
        if self.body.plain:
            yield Static(self.body, classes="entry-body")
        if self.finding_id:
            yield Static("Enter or click to inspect evidence →", classes="entry-action")


class ScanTimeline(ListView):
    """Batch DOM updates and follow new events only while at the bottom.

    This transcript is a recent activity window. All findings remain in the
    findings explorer and JSON export, including entries aged out here.
    """
    MAX_ENTRIES = 120

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._pending = deque(maxlen=self.MAX_ENTRIES)
        self._entries = deque()
        self._reset_requested = False
        self._flushing = False
        self._follow_revision = 0

    def on_mount(self):
        self.set_interval(0.1, self._flush_pending)

    def add_event(self, title, body="", **kwargs):
        self._pending.append(TimelineEntry(title, body, **kwargs))

    def reset(self):
        self._pending.clear()
        self._reset_requested = True

    def watch_index(self, old_index, new_index):
        if not self._flushing:
            self._follow_revision += 1
        super().watch_index(old_index, new_index)

    def on_key(self, event):
        if event.key in {"up", "down", "home", "end", "pageup", "pagedown"}:
            self._follow_revision += 1

    def on_mouse_scroll_up(self, event):
        self._follow_revision += 1

    def _follow_new_events(self, revision):
        # A delayed layout callback must not undo navigation since the batch.
        if revision == self._follow_revision:
            self.scroll_end(animate=False)

    async def _flush_pending(self):
        if self._flushing:
            return
        self._flushing = True
        try:
            if self._reset_requested:
                self._reset_requested = False
                await self.clear()
                self._entries.clear()
            if not self._pending:
                return
            follow = self.scroll_y >= self.max_scroll_y - 1
            revision = self._follow_revision
            batch = [self._pending.popleft() for _ in range(min(24, len(self._pending)))]
            overflow = max(0, len(self._entries) + len(batch) - self.MAX_ENTRIES)
            selected = self.index
            for _ in range(overflow):
                await self._entries.popleft().remove()
            await self.extend(batch)
            self._entries.extend(batch)
            if overflow and selected is not None:
                self.index = max(0, selected - overflow)
            if follow:
                self.call_after_refresh(self._follow_new_events, revision)
        finally:
            self._flushing = False
