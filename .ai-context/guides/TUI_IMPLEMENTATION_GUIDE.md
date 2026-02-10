# BugTraceAI TUI Implementation Guide

## Table of Contents
- [Getting Started](#getting-started)
- [Creating New Widgets](#creating-new-widgets)
- [Message Integration](#message-integration)
- [Testing Strategies](#testing-strategies)
- [Performance Optimization](#performance-optimization)
- [Common Patterns](#common-patterns)
- [Troubleshooting](#troubleshooting)
- [Migration Guide](#migration-guide)

---

## Getting Started

### Prerequisites

```bash
# Install Textual
pip install textual[dev]

# Install development tools
pip install textual-dev  # For CSS live reload
```

### Project Structure

```
bugtrace/core/ui/tui/
├── app.py                    # Main BugTraceApp class
├── styles.tcss               # Global stylesheet
├── messages.py               # Message definitions
├── workers.py                # Background workers, logging
├── utils.py                  # Utility functions
├── screens/
│   ├── __init__.py
│   ├── main.py              # MainScreen (dashboard)
│   ├── loader.py            # LoaderScreen (startup)
│   └── modals/
│       ├── __init__.py
│       └── finding_details.py  # Finding details modal
└── widgets/
    ├── __init__.py
    ├── header.py            # Header widget
    ├── footer.py            # Footer widget
    ├── pipeline.py          # Pipeline status
    ├── activity.py          # Activity graph
    ├── metrics.py           # System metrics
    ├── swarm.py             # Agent swarm
    ├── payload_feed.py      # Payload feed
    ├── findings.py          # Findings summary (legacy)
    ├── findings_table.py    # Interactive findings table
    ├── log_panel.py         # Log panel (legacy)
    ├── log_inspector.py     # Log inspector with filters
    └── command_input.py     # Command input bar
```

### Running the TUI

#### Standalone Mode
```bash
# Start TUI with target
python -m bugtrace.core.ui.tui.app --target https://example.com

# Start in demo mode (no scan)
python -m bugtrace.core.ui.tui.app --demo
```

#### Integrated Mode
```python
from bugtrace.core.ui.tui.app import BugTraceApp

# Create and run app
app = BugTraceApp(target="https://example.com")
app.run()

# Demo mode
app = BugTraceApp(demo_mode=True)
app.run()
```

---

## Creating New Widgets

### Step 1: Create Widget File

Create a new file in `bugtrace/core/ui/tui/widgets/`:

```python
# widgets/my_widget.py
"""MyWidget - A custom widget for BugTraceAI TUI."""

from textual.widgets import Static
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text


class MyWidget(Static):
    """Custom widget description.

    This widget displays [describe what it shows].

    Attributes:
        value: The current value to display.
        status: The current status (idle, active, error).
        demo_mode: When True, generates demo data.
    """

    # Define reactive attributes
    value = reactive(0)
    status = reactive("idle")
    demo_mode = reactive(False)

    # Define default CSS (optional - can be in styles.tcss instead)
    DEFAULT_CSS = """
    MyWidget {
        height: auto;
        border: round $primary;
        padding: 1;
    }
    """

    def __init__(self, *args, **kwargs):
        """Initialize the widget."""
        super().__init__(*args, **kwargs)
        # Initialize internal state
        self._data_history = []

    def on_mount(self) -> None:
        """Called when widget is mounted to screen.

        Set up timers, load initial data, etc.
        """
        # Update every second
        self.set_interval(1.0, self._update_tick)

    def _update_tick(self) -> None:
        """Called every interval to update widget."""
        if self.demo_mode:
            self._generate_demo_data()
        self.refresh()

    def _generate_demo_data(self) -> None:
        """Generate demo data for testing."""
        import random
        self.value = random.randint(0, 100)
        self.status = random.choice(["idle", "active", "error"])

    def watch_value(self, old_value: int, new_value: int) -> None:
        """Called when value changes.

        Args:
            old_value: Previous value.
            new_value: New value.
        """
        self.log(f"Value changed: {old_value} → {new_value}")
        # Add to history
        self._data_history.append(new_value)
        if len(self._data_history) > 100:
            self._data_history.pop(0)

    def render(self) -> Panel:
        """Render the widget.

        Returns:
            Rich renderable (usually a Panel).
        """
        # Build content
        content = Text()
        content.append(f"Value: {self.value}\n")
        content.append(f"Status: {self.status}", style=self._get_status_color())

        # Return Panel
        return Panel(
            content,
            title="My Widget",
            border_style=self._get_border_color(),
        )

    def _get_status_color(self) -> str:
        """Get color for current status."""
        colors = {
            "idle": "dim",
            "active": "green",
            "error": "red",
        }
        return colors.get(self.status, "white")

    def _get_border_color(self) -> str:
        """Get border color based on status."""
        if self.status == "error":
            return "red"
        elif self.status == "active":
            return "green"
        else:
            return "bright_cyan"

    def action_reset(self) -> None:
        """Reset the widget (action handler for keybindings)."""
        self.value = 0
        self.status = "idle"
        self._data_history.clear()
```

### Step 2: Export Widget

Add to `widgets/__init__.py`:

```python
from .my_widget import MyWidget

__all__ = [
    "MyWidget",
    # ... other widgets
]
```

### Step 3: Add to Screen

Modify `screens/main.py`:

```python
from bugtrace.core.ui.tui.widgets.my_widget import MyWidget

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        # ... existing widgets ...
        yield MyWidget(id="my-widget")
```

### Step 4: Add Styles (Optional)

Add to `styles.tcss`:

```tcss
/* My Widget Styles */
#my-widget {
    height: 10;
    width: 1fr;
    border: round $primary;
    padding: 0 1;
    margin-bottom: 1;
}

MyWidget .status-active {
    color: $success;
    text-style: bold;
}

MyWidget .status-error {
    color: $error;
}
```

### Step 5: Test Widget

```python
# test_my_widget.py
from textual.app import App
from bugtrace.core.ui.tui.widgets.my_widget import MyWidget

class TestApp(App):
    def compose(self):
        yield MyWidget(id="test-widget")

    def on_mount(self):
        # Enable demo mode
        widget = self.query_one("#test-widget", MyWidget)
        widget.demo_mode = True

if __name__ == "__main__":
    TestApp().run()
```

---

## Message Integration

### Creating a New Message Type

#### Step 1: Define Message

Add to `messages.py`:

```python
class MyCustomMessage(Message):
    """Sent when [describe event].

    Attributes:
        data: The data to pass.
        timestamp: When the event occurred.
    """

    def __init__(self, data: str, timestamp: float) -> None:
        super().__init__()
        self.data = data
        self.timestamp = timestamp
```

#### Step 2: Post Message from Pipeline

In your agent or conductor code:

```python
from bugtrace.core.ui.tui.messages import MyCustomMessage
import time

# Get app instance (via UICallback or conductor)
if self.ui_callback:
    self.ui_callback.post_message(
        MyCustomMessage(
            data="Important event occurred",
            timestamp=time.time()
        )
    )
```

#### Step 3: Handle Message in App

Add handler to `app.py`:

```python
class BugTraceApp(App):
    # ... existing code ...

    def on_my_custom_message(self, message: MyCustomMessage) -> None:
        """Handle custom message.

        Args:
            message: The custom message.
        """
        # Log it
        self.log(f"Custom message received: {message.data}")

        # Update widget
        try:
            widget = self.query_one("#my-widget", MyWidget)
            widget.status = "active"
            widget.value = int(message.timestamp)
        except Exception:
            pass  # Widget not mounted yet
```

### UICallback Pattern

The `UICallback` class bridges the pipeline and TUI:

```python
# In workers.py
class UICallback:
    """Callback interface for pipeline → TUI communication."""

    def __init__(self, app: BugTraceApp):
        self.app = app

    def on_phase_change(self, phase: str, progress: float, status: str) -> None:
        """Called when pipeline phase changes."""
        self.app.post_message(
            PipelineProgress(phase=phase, progress=progress, status_msg=status)
        )

    def on_finding(self, finding_type: str, severity: str, **kwargs) -> None:
        """Called when vulnerability found."""
        self.app.post_message(
            NewFinding(
                finding_type=finding_type,
                severity=severity,
                details=kwargs.get("details", ""),
                param=kwargs.get("param"),
                payload=kwargs.get("payload"),
            )
        )

    def on_log(self, level: str, message: str) -> None:
        """Called for log messages."""
        self.app.post_message(LogEntry(level=level, message=message))
```

### Registering UICallback

In your conductor or orchestrator:

```python
from bugtrace.core.ui.tui.workers import UICallback

class TeamOrchestrator:
    def __init__(self, target: str, ui_callback: UICallback = None):
        self.ui_callback = ui_callback

    async def start(self):
        # Notify UI of phase change
        if self.ui_callback:
            self.ui_callback.on_phase_change("DISCOVERY", 0.0, "Starting...")

        # ... do work ...

        # Notify of finding
        if self.ui_callback:
            self.ui_callback.on_finding(
                finding_type="XSS",
                severity="HIGH",
                details="Reflected XSS",
                param="q",
                payload="<script>alert(1)</script>",
            )
```

---

## Testing Strategies

### 1. Unit Testing Widgets

```python
# test_my_widget.py
import pytest
from bugtrace.core.ui.tui.widgets.my_widget import MyWidget

def test_widget_initialization():
    """Test widget initializes with defaults."""
    widget = MyWidget()
    assert widget.value == 0
    assert widget.status == "idle"
    assert widget.demo_mode is False

def test_widget_value_change():
    """Test reactive value changes."""
    widget = MyWidget()
    widget.value = 42
    assert widget.value == 42

def test_demo_mode():
    """Test demo mode generates data."""
    widget = MyWidget()
    widget.demo_mode = True
    widget._generate_demo_data()
    assert widget.value >= 0  # Random value generated
```

### 2. Snapshot Testing (Textual)

```python
# test_my_widget_snapshot.py
from textual.app import App
from bugtrace.core.ui.tui.widgets.my_widget import MyWidget

async def test_my_widget_snapshot(snap_compare):
    """Test widget renders correctly."""
    class TestApp(App):
        def compose(self):
            yield MyWidget(id="test")

    app = TestApp()
    async with app.run_test() as pilot:
        # Take snapshot
        assert await snap_compare(app)
```

### 3. Integration Testing

```python
# test_message_flow.py
from textual.app import App
from bugtrace.core.ui.tui.messages import MyCustomMessage
from bugtrace.core.ui.tui.widgets.my_widget import MyWidget

async def test_message_updates_widget():
    """Test message handler updates widget."""
    class TestApp(App):
        def compose(self):
            yield MyWidget(id="test")

        def on_my_custom_message(self, message: MyCustomMessage):
            widget = self.query_one("#test", MyWidget)
            widget.status = "active"

    app = TestApp()
    async with app.run_test() as pilot:
        widget = app.query_one("#test", MyWidget)
        assert widget.status == "idle"

        # Post message
        app.post_message(MyCustomMessage(data="test", timestamp=123))

        # Wait for processing
        await pilot.pause()

        # Check widget updated
        assert widget.status == "active"
```

### 4. Demo Mode Testing

```bash
# Manual testing in demo mode
python -m bugtrace.core.ui.tui.app --demo

# Or in code
app = BugTraceApp(demo_mode=True)
app.run()
```

### 5. Live Reloading (Development)

```bash
# Start app with Textual devtools
textual console

# In another terminal, run app
textual run --dev bugtrace/core/ui/tui/app.py
```

---

## Performance Optimization

### 1. Lazy Rendering

Only render what's visible:

```python
class LargeListWidget(Static):
    """Widget with many items."""

    def __init__(self):
        super().__init__()
        self._items = []  # Could be 10,000+ items
        self._visible_start = 0
        self._visible_count = 50

    def render(self) -> RenderableType:
        # Only render visible slice
        visible_items = self._items[
            self._visible_start:self._visible_start + self._visible_count
        ]
        return Panel("\n".join(visible_items))
```

### 2. Debouncing High-Frequency Updates

```python
class MetricsWidget(Static):
    """Widget updated frequently."""

    def __init__(self):
        super().__init__()
        self._pending_update = False
        self._last_value = 0

    def update_value(self, value: float) -> None:
        """Debounced update."""
        self._last_value = value

        if not self._pending_update:
            self._pending_update = True
            self.set_timer(0.5, self._apply_update)

    def _apply_update(self) -> None:
        """Apply batched update."""
        self.value = self._last_value
        self._pending_update = False
```

### 3. Conditional Rendering

```python
class ConditionalWidget(Static):
    def render(self) -> RenderableType:
        # Skip rendering if not visible
        if not self.is_mounted or not self.visible:
            return ""

        # Skip rendering if no data
        if not self._data:
            return Panel("No data", style="dim")

        # Normal rendering
        return self._render_data()
```

### 4. Async Workers

Use workers for heavy computation:

```python
from textual import work

class HeavyWidget(Static):
    @work(thread=True)
    async def compute_heavy_data(self) -> str:
        """Compute in background thread."""
        # Heavy computation here
        result = some_heavy_function()
        return result

    def on_mount(self) -> None:
        # Start worker
        self.compute_heavy_data()

    def on_worker_state_changed(self, event):
        """Handle worker completion."""
        if event.state == "success":
            self.data = event.worker.result
```

### 5. Memory Management

```python
class LogWidget(Static):
    """Widget that accumulates data."""

    MAX_LOGS = 1000

    def __init__(self):
        super().__init__()
        self._logs = []

    def add_log(self, message: str) -> None:
        """Add log with automatic pruning."""
        self._logs.append(message)

        # Keep only recent logs
        if len(self._logs) > self.MAX_LOGS:
            self._logs = self._logs[-self.MAX_LOGS:]
```

---

## Common Patterns

### Pattern 1: Status Indicator

```python
class StatusIndicator(Static):
    """Reusable status indicator widget."""

    status = reactive("idle")

    STATUS_ICONS = {
        "idle": ("○", "dim"),
        "active": ("●", "green"),
        "success": ("✓", "bright_green"),
        "error": ("✗", "red"),
        "warning": ("⚠", "yellow"),
    }

    def render(self) -> Text:
        icon, color = self.STATUS_ICONS.get(self.status, ("?", "white"))
        return Text(f"{icon} {self.status.title()}", style=color)
```

### Pattern 2: Progress Bar

```python
class ProgressBar(Static):
    """Reusable progress bar."""

    progress = reactive(0.0)  # 0.0 to 1.0

    def render(self) -> RenderableType:
        width = 20
        filled = int(width * self.progress)
        bar = "█" * filled + "░" * (width - filled)

        # Color based on progress
        if self.progress >= 1.0:
            color = "green"
        elif self.progress >= 0.5:
            color = "yellow"
        else:
            color = "cyan"

        return Text(f"[{bar}] {int(self.progress * 100)}%", style=color)
```

### Pattern 3: Filterable List

```python
class FilterableList(Static):
    """List with text filter."""

    filter_text = reactive("")

    def __init__(self):
        super().__init__()
        self._all_items = []

    def add_item(self, item: str) -> None:
        self._all_items.append(item)

    def _get_filtered_items(self) -> List[str]:
        if not self.filter_text:
            return self._all_items

        # Case-insensitive filter
        filter_lower = self.filter_text.lower()
        return [item for item in self._all_items if filter_lower in item.lower()]

    def render(self) -> Panel:
        items = self._get_filtered_items()
        content = "\n".join(items) if items else "No matches"
        return Panel(content, title=f"Items ({len(items)})")
```

### Pattern 4: Collapsible Section

```python
class CollapsibleSection(Static):
    """Section that can be collapsed."""

    expanded = reactive(True)

    def __init__(self, title: str, content: str):
        super().__init__()
        self.title = title
        self.content = content

    def render(self) -> Panel:
        icon = "▼" if self.expanded else "▶"
        title = f"{icon} {self.title}"

        if self.expanded:
            return Panel(self.content, title=title)
        else:
            return Panel("", title=title, height=3)

    def action_toggle(self) -> None:
        """Toggle expanded state."""
        self.expanded = not self.expanded
```

### Pattern 5: Notification Queue

```python
class NotificationQueue(Static):
    """Shows recent notifications."""

    def __init__(self):
        super().__init__()
        self._notifications = []
        self._max_notifications = 5

    def notify(self, message: str, severity: str = "info") -> None:
        """Add notification."""
        self._notifications.append((message, severity))

        # Keep only recent
        if len(self._notifications) > self._max_notifications:
            self._notifications.pop(0)

        # Auto-remove after 5s
        self.set_timer(5.0, lambda: self._remove_notification(message))

    def _remove_notification(self, message: str) -> None:
        self._notifications = [
            (msg, sev) for msg, sev in self._notifications if msg != message
        ]

    def render(self) -> RenderableType:
        if not self._notifications:
            return ""

        lines = []
        for message, severity in self._notifications:
            color = {"info": "blue", "warning": "yellow", "error": "red"}.get(
                severity, "white"
            )
            lines.append(f"[{color}]{message}[/{color}]")

        return Panel("\n".join(lines), title="Notifications")
```

---

## Troubleshooting

### Issue: Widget Not Updating

**Symptom**: Changed reactive attribute but UI doesn't update.

**Solutions**:
1. Check if widget is mounted:
   ```python
   if not self.is_mounted:
       return
   ```

2. Force refresh if needed:
   ```python
   self.value = 42
   self.refresh()
   ```

3. Check watch method:
   ```python
   def watch_value(self, old_value, new_value):
       self.log(f"Value changed: {old_value} → {new_value}")
       self.refresh()  # Explicit refresh
   ```

### Issue: Message Not Received

**Symptom**: Posted message but handler not called.

**Solutions**:
1. Check handler method name matches message:
   ```python
   # Message class
   class MyMessage(Message): ...

   # Handler (must be lowercase with underscores)
   def on_my_message(self, message: MyMessage): ...
   ```

2. Check message is posted to correct target:
   ```python
   # Post to app
   self.app.post_message(MyMessage())

   # Post to specific widget
   widget.post_message(MyMessage())
   ```

3. Add debug logging:
   ```python
   def on_my_message(self, message: MyMessage):
       self.log(f"Received: {message}")  # Should appear in textual console
   ```

### Issue: Performance Degradation

**Symptom**: TUI becomes slow or laggy.

**Solutions**:
1. Check update frequency:
   ```python
   # Too frequent
   self.set_interval(0.01, self._update)  # 100 updates/sec

   # Better
   self.set_interval(0.5, self._update)   # 2 updates/sec
   ```

2. Profile with Textual devtools:
   ```bash
   textual console
   # Watch for excessive updates
   ```

3. Implement debouncing (see Performance Optimization section)

### Issue: Layout Broken

**Symptom**: Widgets overlapping or not positioning correctly.

**Solutions**:
1. Check TCSS syntax:
   ```tcss
   /* Wrong */
   #my-widget
       height: 10

   /* Correct */
   #my-widget {
       height: 10;
   }
   ```

2. Verify container layout:
   ```python
   # Horizontal container
   with Horizontal():
       yield Widget1()
       yield Widget2()

   # Vertical container (default)
   with Vertical():
       yield Widget1()
       yield Widget2()
   ```

3. Check for conflicting styles:
   ```tcss
   /* Remove fixed heights if using fr units */
   #my-widget {
       height: 1fr;  /* Flexible */
       /* height: 10; */  /* Don't mix with fr */
   }
   ```

### Issue: Colors Not Showing

**Symptom**: Colors appear as text instead of rendering.

**Solutions**:
1. Use Rich markup correctly:
   ```python
   # Wrong
   text = "[red]Error"  # Literal string

   # Correct
   from rich.text import Text
   text = Text("Error", style="red")

   # Or use markup=True
   from rich.console import Console
   console = Console()
   console.print("[red]Error[/]", markup=True)
   ```

2. Check terminal supports colors:
   ```bash
   echo $TERM  # Should be xterm-256color or similar
   ```

### Issue: Widget Not Found

**Symptom**: `query_one()` raises exception.

**Solutions**:
1. Wrap in try-except:
   ```python
   try:
       widget = self.query_one("#my-widget", MyWidget)
   except Exception as e:
       self.log(f"Widget not found: {e}")
       return
   ```

2. Check widget is in current screen:
   ```python
   # Check if screen has widget
   widgets = self.screen.query(MyWidget)
   if widgets:
       widget = widgets.first()
   ```

3. Wait for mount:
   ```python
   async def on_mount(self):
       await self.query_one("#my-widget").wait_until_mounted()
   ```

---

## Migration Guide

### From Rich Dashboard to Textual TUI

#### 1. Convert Rich Panels to Widgets

**Before (Rich)**:
```python
from rich.panel import Panel
from rich.live import Live

panel = Panel("Content", title="My Panel")
with Live(panel, refresh_per_second=1) as live:
    while True:
        live.update(panel)
```

**After (Textual)**:
```python
from textual.widgets import Static
from rich.panel import Panel

class MyWidget(Static):
    def render(self) -> Panel:
        return Panel("Content", title="My Panel")
```

#### 2. Convert Layout to TCSS

**Before (Rich Layout)**:
```python
from rich.layout import Layout

layout = Layout()
layout.split_row(
    Layout(name="left", ratio=1),
    Layout(name="right", ratio=2),
)
```

**After (Textual)**:
```tcss
.row {
    layout: horizontal;
}

.left {
    width: 1fr;
}

.right {
    width: 2fr;
}
```

#### 3. Convert Polling to Reactive

**Before (Rich)**:
```python
status = "idle"

while True:
    panel = Panel(f"Status: {status}")
    live.update(panel)
    time.sleep(1)
```

**After (Textual)**:
```python
class MyWidget(Static):
    status = reactive("idle")

    def render(self):
        return Panel(f"Status: {self.status}")
```

---

## Next Steps

1. **Read the Design Guide**: [TUI_DESIGN_GUIDE.md](TUI_DESIGN_GUIDE.md)
2. **See Visual Examples**: [TUI_VISUAL_EXAMPLES.md](TUI_VISUAL_EXAMPLES.md)
3. **Join Textual Discord**: [textual.textualize.io](https://textual.textualize.io/)
4. **Check Textual Docs**: [textual.textualize.io/guide](https://textual.textualize.io/guide/)

---

**Last Updated**: 2026-02-05
**Version**: 1.0.0
**Maintainer**: BugTraceAI Team
