# BugTraceAI TUI Design Guide

## Table of Contents
- [Introduction](#introduction)
- [Design System](#design-system)
  - [Color Palette](#color-palette)
  - [Typography](#typography)
  - [Spacing & Layout](#spacing--layout)
  - [Borders & Shapes](#borders--shapes)
- [Architecture](#architecture)
  - [Application Structure](#application-structure)
  - [Message System](#message-system)
  - [Reactive Pattern](#reactive-pattern)
- [Components (Widgets)](#components-widgets)
- [Layouts](#layouts)
- [Interaction Patterns](#interaction-patterns)
- [Style Guidelines](#style-guidelines)
- [Best Practices](#best-practices)

---

## Introduction

BugTraceAI features a modern Terminal User Interface (TUI) built with **Textual**, a powerful Python framework for building reactive, terminal-based applications. The TUI provides real-time monitoring and control of security scans with a responsive, event-driven architecture.

### Technology Stack
- **Framework**: [Textual](https://textual.textualize.io/) v0.63+
- **Rendering**: Rich (via Textual)
- **Layout**: CSS Grid + Flexbox (TCSS)
- **Styling**: Textual CSS (`.tcss` files)
- **Architecture**: Event-driven message passing

### Key Features
- Real-time dashboard with live updates
- Interactive widgets with keyboard navigation
- ChatOps command interface
- Dark theme optimized for terminal use
- Responsive layout system
- Demo mode for testing

---

## Design System

### Color Palette

The TUI uses a dark color scheme inspired by the Catppuccin Mocha palette, optimized for terminal readability.

#### TCSS Variables

```tcss
/* Surface colors */
$surface: #1e1e2e          /* Main background */
$surface-light: #313244    /* Elevated surfaces (header, footer) */

/* Brand colors */
$primary: #89b4fa          /* Primary actions, borders */
$primary-dark: #7aa2f7     /* Hover states, secondary emphasis */
$secondary: #cba6f7        /* Secondary actions */

/* Semantic colors */
$success: #a6e3a1          /* Success states, confirmations */
$warning: #f9e2af          /* Warnings, cautions */
$error: #f38ba8            /* Errors, critical issues */

/* Text colors */
$text: #cdd6f4             /* Primary text */
$muted: #6c7086            /* Secondary text, hints */

/* Logo gradient (red → yellow) */
$gradient-1: #ff5555       /* Bright red */
$gradient-2: #e74c3c       /* Red */
$gradient-3: #f1fa8c       /* Yellow */
$gradient-4: #f1c40f       /* Bright yellow */

/* Severity colors */
$severity-critical: #ff5555
$severity-high: #f38ba8
$severity-medium: #f9e2af
$severity-low: #cdd6f4
$severity-info: #89b4fa
```

#### Color Usage Guidelines

| Color | Usage | Example |
|-------|-------|---------|
| `$primary` | Main borders, key information | Pipeline border, header border |
| `$success` | Positive states, completed phases | Payload success, phase completion |
| `$warning` | Active processes, cautions | Active agents, WAF detection |
| `$error` | Vulnerabilities, errors | Finding borders, error messages |
| `$muted` | Disabled states, hints | Idle agents, placeholder text |

### Typography

#### Text Styles (TCSS)

```tcss
/* Style classes */
.text-primary     { color: $primary; }
.text-success     { color: $success; }
.text-warning     { color: $warning; }
.text-error       { color: $error; }
.text-muted       { color: $muted; }

/* Severity styles */
.text-critical    { color: $severity-critical; text-style: bold; }
.text-high        { color: $severity-high; }
.text-medium      { color: $severity-medium; }
.text-low         { color: $severity-low; }
.text-info        { color: $severity-info; }

/* Panel titles */
.panel-title      { text-style: bold; color: $primary; }
```

#### Rich Text Styles (Python)

```python
from rich.text import Text

# Severity-based styling
severity_styles = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

# Status indicators
status_styles = {
    "ACTIVE": "bright_green",
    "WAITING": "bright_yellow",
    "ERROR": "bright_red",
    "DONE": "bright_cyan",
    "IDLE": "bright_black",
}
```

### Spacing & Layout

#### Grid System

```tcss
/* Fractional units (fr) for responsive layouts */
.full-width    { width: 100%; }
.half          { width: 1fr; }
.third         { width: 1fr; max-width: 33%; }

/* Standard spacing units */
margin: 0      /* No margin */
margin: 1      /* 1 cell margin */
padding: 0 1   /* 0 vertical, 1 horizontal */
```

#### Layout Classes

```tcss
/* Main content area */
.layout-content {
    padding: 0 1;
}

/* Dashboard rows */
.dashboard-row {
    layout: horizontal;
    height: auto;
    min-height: 8;
    margin-bottom: 1;
}

/* Metrics row */
.metrics-row {
    layout: horizontal;
    height: 9;
    margin-bottom: 1;
}
```

### Borders & Shapes

#### Border Styles

```tcss
/* Round borders (default for panels) */
border: round $primary

/* Solid borders (tables, inputs) */
border: solid $error

/* Thick borders (emphasis) */
border: thick $warning
```

#### Box Characters (Rich)

```python
from rich import box

# Available box styles
box.ROUNDED      # Default for panels (smooth corners)
box.SIMPLE       # Clean, minimal
box.DOUBLE       # Emphasis
box.ASCII        # Maximum compatibility
```

---

## Architecture

### Application Structure

```
BugTraceApp (app.py)
├── LoaderScreen (loader.py)
│   ├── Logo
│   └── Spinner
└── MainScreen (main.py)
    ├── Header
    ├── Main Content
    │   ├── PipelineStatus
    │   ├── Dashboard Row 1
    │   │   ├── ActivityGraph
    │   │   ├── SystemMetrics
    │   │   └── AgentSwarm
    │   ├── FindingsTable
    │   └── Dashboard Row 2
    │       ├── PayloadFeed
    │       └── LogInspector
    ├── CommandInput
    └── Footer
```

### Message System

Textual uses a message-passing system for event-driven communication. Messages flow from the scanning pipeline to the app, which routes them to widgets.

#### Message Types

```python
from bugtrace.core.ui.tui.messages import (
    AgentUpdate,       # Agent status changes
    PipelineProgress,  # Phase/progress updates
    NewFinding,        # Vulnerability discovered
    PayloadTested,     # Payload test result
    LogEntry,          # Log message
    MetricsUpdate,     # System metrics
    ScanComplete,      # Scan finished
)
```

#### Message Flow

```
Pipeline/Conductor
    ↓ (post message)
BugTraceApp
    ↓ (on_<message> handler)
Widget Update
    ↓ (reactive attribute changed)
UI Refresh (automatic)
```

#### Example: Posting Messages

```python
# In pipeline/conductor code
from bugtrace.core.ui.tui.messages import NewFinding

# Post finding to TUI
app.post_message(NewFinding(
    finding_type="XSS",
    details="Reflected XSS in search",
    severity="HIGH",
    param="q",
    payload="<script>alert(1)</script>"
))
```

#### Example: Handling Messages

```python
# In BugTraceApp (app.py)
def on_new_finding(self, message: NewFinding) -> None:
    """Handle new vulnerability finding."""
    # Update FindingsTable
    table = self.query_one("#findings-table", FindingsTable)
    table.add_finding(
        finding_type=message.finding_type,
        details=message.details,
        severity=message.severity,
        param=message.param,
        payload=message.payload,
    )

    # Show notification
    self.notify(f"[red][{message.severity}][/] {message.finding_type}")
```

### Reactive Pattern

Textual widgets use reactive attributes that automatically trigger UI updates when changed.

#### Defining Reactive Attributes

```python
from textual.reactive import reactive
from textual.widgets import Static

class MyWidget(Static):
    # Reactive attributes
    status = reactive("idle")
    progress = reactive(0.0)
    count = reactive(0)

    def watch_status(self, old_value: str, new_value: str) -> None:
        """Called when status changes."""
        self.log(f"Status changed: {old_value} → {new_value}")
        self.refresh()  # Trigger re-render
```

#### Updating Reactive Attributes

```python
# From within the widget
self.status = "active"
self.progress = 0.5
self.count += 1

# From parent/app
widget = self.query_one("#my-widget", MyWidget)
widget.status = "complete"
```

---

## Components (Widgets)

### PipelineStatus

**Purpose**: Displays the current scan phase with progress visualization.

**Location**: `bugtrace/core/ui/tui/widgets/pipeline.py`

**Visual**: `[✓]RECON → [✓]DISCOVER → [▶]ANALYZE → [○]EXPLOIT → [○]REPORT [67%]`

#### Reactive Attributes

```python
phase = reactive("INITIALIZING")      # Current phase name
progress = reactive(0.0)              # Progress % (0-100)
status_msg = reactive("Starting...")  # Status message
urls_analyzed = reactive(0)           # URLs analyzed count
urls_total = reactive(0)              # Total URLs
payloads_tested = reactive(0)         # Payloads tested count
demo_mode = reactive(False)           # Demo mode flag
```

#### Phases

```python
PHASES = [
    ("RECON", ["recon", "init", "warm"]),
    ("DISCOVER", ["discover", "spider", "crawl"]),
    ("ANALYZE", ["analy", "dast", "hunt"]),
    ("EXPLOIT", ["exploit", "attack", "specialist"]),
    ("REPORT", ["report", "complete", "done"]),
]
```

#### Status Icons

- `✅` Completed phase (green)
- `▶` Current phase (yellow bold)
- `○` Future phase (dim)
- `→` Phase separator

#### Usage

```python
# Update pipeline from message handler
pipeline = self.query_one("#pipeline", PipelineStatus)
pipeline.phase = "ANALYZE"
pipeline.progress = 67.0
pipeline.status_msg = "Analyzing reflection contexts..."
```

---

### AgentSwarm

**Purpose**: Displays specialist agent status with queue depth and findings.

**Location**: `bugtrace/core/ui/tui/widgets/swarm.py`

**Visual**:
```
🟢 XSS [Queue: 5 | Processed: 23 | Vulns: 2]
⚪ SQLi [Idle]
🔴 SSRF [Error]
```

#### Reactive Attributes

```python
agents: reactive[Dict[str, Dict[str, Any]]] = reactive({})
current_agent = reactive("")
demo_mode = reactive(False)
```

#### Agent State Schema

```python
{
    "xss": {
        "status": "ACTIVE",    # IDLE, ACTIVE, WAITING, ERROR, DONE
        "queue": 5,            # Items in queue
        "processed": 23,       # Items processed
        "vulns": 2,            # Vulnerabilities found
    },
    ...
}
```

#### Status Icons

```python
STATUS_ICONS = {
    "IDLE": ("○", "bright_black"),
    "ACTIVE": ("●", "bright_green"),
    "WAITING": ("●", "bright_yellow"),
    "ERROR": ("✗", "bright_red"),
    "DONE": ("✓", "bright_cyan"),
}
```

#### Agent Display Names

```python
AGENT_DISPLAY = {
    "sqli": "SQLi",
    "xss": "XSS",
    "csti": "CSTI",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "idor": "IDOR",
    "lfi": "LFI",
    "rce": "RCE",
    "openredirect": "Redirect",
}
```

#### Usage

```python
swarm = self.query_one("#swarm", AgentSwarm)
swarm.update_agent(
    "xss",
    status="ACTIVE",
    queue=5,
    processed=23,
    vulns=2,
)
```

---

### FindingsTable

**Purpose**: Interactive table for displaying vulnerabilities with sorting and selection.

**Location**: `bugtrace/core/ui/tui/widgets/findings_table.py`

**Visual**:
```
┌─────────────────────────────────────────────────┐
│ Severity │ Type │ Parameter │ Time     │ Status │
├──────────┼──────┼───────────┼──────────┼────────┤
│ CRITICAL │ SQLi │ username  │ 14:23:15 │ new    │
│ HIGH     │ XSS  │ q         │ 14:23:42 │ new    │
└─────────────────────────────────────────────────┘
```

#### Features
- **Cursor navigation**: Arrow keys to move between rows
- **Row selection**: Enter to open finding details modal
- **Severity coloring**: Color-coded severity levels
- **Zebra stripes**: Alternating row backgrounds for readability

#### Finding Schema

```python
@dataclass
class Finding:
    id: str                        # Unique identifier
    severity: str                  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    finding_type: str              # XSS, SQLi, SSRF, etc.
    param: Optional[str]           # Vulnerable parameter
    payload: Optional[str]         # Exploit payload
    request: Optional[str]         # Full request (future)
    response_excerpt: Optional[str] # Response excerpt (future)
    time: str                      # Timestamp (HH:MM:SS)
    status: str                    # new, reviewed, false_positive
```

#### Severity Styling

```python
severity_styles = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}
```

#### Usage

```python
table = self.query_one("#findings-table", FindingsTable)
table.add_finding(
    finding_type="XSS",
    details="Reflected XSS in search",
    severity="HIGH",
    param="q",
    payload="<script>alert(1)</script>",
)
```

---

### ActivityGraph

**Purpose**: Real-time graph of request rate over time.

**Location**: `bugtrace/core/ui/tui/widgets/activity.py`

#### Reactive Attributes

```python
req_rate = reactive(0.0)      # Current requests/sec
peak_rate = reactive(0.0)     # Peak requests/sec
demo_mode = reactive(False)
```

#### Visual Elements
- Sparkline graph showing request rate history
- Current rate display
- Peak rate indicator

---

### SystemMetrics

**Purpose**: Displays CPU and RAM usage.

**Location**: `bugtrace/core/ui/tui/widgets/metrics.py`

#### Reactive Attributes

```python
cpu_usage = reactive(0.0)     # CPU % (0-100)
ram_usage = reactive(0.0)     # RAM % (0-100)
demo_mode = reactive(False)
```

#### Visual Elements
- Progress bars for CPU and RAM
- Color-coded thresholds:
  - Green: 0-60%
  - Yellow: 60-80%
  - Red: 80-100%

---

### PayloadFeed

**Purpose**: Live feed of tested payloads with results.

**Location**: `bugtrace/core/ui/tui/widgets/payload_feed.py`

#### Payload Status

```python
status_map = {
    "confirmed": "✓",  # Green
    "failed": "✗",     # Red
    "blocked": "⚠",    # Yellow
    "testing": "○",    # Dim
}
```

#### Usage

```python
feed = self.query_one("#payload-feed", PayloadFeed)
feed.add_payload(
    payload="<script>alert(1)</script>",
    agent="XSS",
    status="confirmed",
)
```

---

### LogInspector

**Purpose**: Filterable log viewer with level-based coloring.

**Location**: `bugtrace/core/ui/tui/widgets/log_inspector.py`

#### Features
- Real-time log streaming
- Filter by text (regex supported)
- Level-based coloring
- Auto-scroll (with pause on scroll-up)

#### Log Levels

```python
level_styles = {
    "DEBUG": "dim",
    "INFO": "bright_blue",
    "WARNING": "yellow",
    "ERROR": "red",
    "SUCCESS": "green",
}
```

#### Usage

```python
inspector = self.query_one("#log-inspector", LogInspector)
inspector.log("[XSSAgent] Testing payload...", level="INFO")
inspector.log("[XSSAgent] XSS confirmed!", level="SUCCESS")
```

---

### CommandInput

**Purpose**: ChatOps-style command input bar.

**Location**: `bugtrace/core/ui/tui/widgets/command_input.py`

#### Available Commands

```python
COMMANDS = {
    "/stop": "Stop the current scan",
    "/pause": "Pause scan execution",
    "/resume": "Resume paused scan",
    "/help": "Show this help message",
    "/filter <text>": "Filter logs by text",
    "/show <agent>": "Show logs for specific agent",
    "/clear": "Clear log panel",
    "/export": "Export findings to file",
}
```

#### Usage

1. Press `:` to focus command input
2. Type command (autocomplete shows suggestions)
3. Press Enter to execute
4. Press Escape to cancel

---

## Layouts

### Main Dashboard Layout

```tcss
#main-content {
    layout: vertical;
    height: 1fr;
    width: 100%;
    padding: 0 1;
}

/* Pipeline at top */
#pipeline {
    height: 5;
    border: round $primary;
    margin-bottom: 1;
}

/* Row 1: Activity + Metrics | Swarm */
.dashboard-row {
    layout: horizontal;
    height: auto;
    min-height: 8;
    margin-bottom: 1;
}

.left-panel {
    width: 1fr;
    max-width: 40;
    margin-right: 1;
}

#activity {
    width: 1fr;
    border: round $primary-dark;
}

#metrics {
    width: 1fr;
    border: round $secondary;
}

#swarm {
    width: 2fr;
    border: round $warning;
}

/* Row 2: Findings Table (full width) */
#findings-table {
    height: 12;
    min-height: 8;
    margin: 1 0;
    border: solid $error;
}

/* Row 3: Payload Feed | Log Inspector */
#payload-feed {
    width: 1fr;
    border: round $success;
    margin-right: 1;
}

#log-inspector {
    width: 1fr;
    border: round $primary-dark;
}
```

### Responsive Considerations

```tcss
/* Future: Media queries for small terminals */
@media (width < 100) {
    .dashboard-row {
        layout: vertical;
    }

    .left-panel {
        max-width: 100%;
    }
}
```

---

## Interaction Patterns

### Keyboard Bindings

#### Global Bindings (BugTraceApp)

| Key | Action | Description |
|-----|--------|-------------|
| `q` | Quit | Exit application |
| `d` | Toggle Dark | Toggle dark mode |
| `?` | Help | Show help |
| `s` | Start Scan | Start scan (if target set) |
| `f` | Focus Findings | Focus findings table |
| `l` | Focus Logs | Focus log inspector |
| `:` | Command | Focus command input |
| `Esc` | Unfocus | Remove focus from widget |

#### Screen-Specific Bindings (MainScreen)

| Key | Action | Description |
|-----|--------|-------------|
| `f` | Findings View | Switch to findings view |
| `l` | Logs View | Switch to logs view |
| `s` | Stats View | Show statistics |
| `a` | Agents View | Show agent details |

#### Widget Navigation

| Key | Action |
|-----|--------|
| `Tab` | Next widget |
| `Shift+Tab` | Previous widget |
| `↑↓` | Navigate table rows |
| `Enter` | Select/activate |
| `PgUp/PgDn` | Page up/down in logs |

### Focus Management

```python
# Focus specific widget
self.query_one("#findings-table").focus()

# Remove focus
self.screen.set_focus(None)

# Check if focused
if widget.has_focus:
    # Widget is focused
```

### Modal Dialogs

```python
# Open finding details modal
finding = table.get_finding(row_key)
self.push_screen(FindingDetailsModal(finding))

# Close modal
self.app.pop_screen()
```

---

## Style Guidelines

### Naming Conventions

#### Widget IDs
- Use kebab-case: `#findings-table`, `#log-inspector`
- Descriptive: `#pipeline`, `#swarm`, `#payload-feed`

#### CSS Classes
- Use kebab-case: `.dashboard-row`, `.left-panel`
- Purpose-based: `.hidden-legacy`, `.metrics-row`

#### Python Classes
- Use PascalCase: `PipelineStatus`, `FindingsTable`
- Suffix with widget type: `AgentSwarm`, `LogInspector`

#### Reactive Attributes
- Use snake_case: `req_rate`, `cpu_usage`, `demo_mode`

### Panel Titles

```python
# Use UPPERCASE for major sections
Panel(..., title="[bright_cyan]PROGRESS[/]")

# Use Title Case for subsections
Panel(..., title="Agent Swarm")
```

### Status Messages

```python
# Use sentence case with emoji/icons
"🔍 Analyzing reflection contexts..."
"✓ Scan complete"
"⚠ WAF detected"
```

### Severity Display

```python
# Always UPPERCASE for severity
"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"

# Use brackets in notifications
"[CRITICAL] SQL Injection found"
```

---

## Best Practices

### Performance

#### 1. Use Reactive Sparingly
```python
# Good: Only reactive attributes that trigger UI updates
status = reactive("idle")

# Bad: Reactive for internal state that doesn't affect UI
_internal_counter = reactive(0)  # Should be regular attribute
```

#### 2. Batch Updates
```python
# Good: Update multiple attributes, single render
widget.status = "active"
widget.progress = 50
# Render happens once

# Bad: Calling refresh() after each change
widget.status = "active"
widget.refresh()  # Unnecessary
widget.progress = 50
widget.refresh()  # Unnecessary
```

#### 3. Debounce High-Frequency Updates
```python
# Good: Use intervals for high-frequency data
self.set_interval(0.5, self._update_metrics)

# Bad: Updating on every event (100+ times/sec)
def on_event(self, event):
    self.metrics.update()  # Too frequent
```

### Demo Mode

All widgets should support demo mode for testing without a real scan.

```python
class MyWidget(Static):
    demo_mode = reactive(False)

    def on_mount(self) -> None:
        self.set_interval(1.0, self._demo_tick)

    def _demo_tick(self) -> None:
        if not self.demo_mode:
            return

        # Generate demo data
        self.status = random.choice(["idle", "active", "done"])
        self.refresh()
```

### Error Handling

Wrap widget queries in try-except to handle unmounted widgets.

```python
def on_new_finding(self, message: NewFinding) -> None:
    try:
        table = self.query_one("#findings-table", FindingsTable)
        table.add_finding(...)
    except Exception:
        pass  # Widget may not be mounted yet
```

### Logging

Use structured logging with agent name prefix.

```python
# Good
self.log("[XSSAgent] Testing 42 payloads...")

# Better
self.log(f"[{self.name}] Testing {len(payloads)} payloads...")

# Best (with level)
logger.info(f"[{self.name}] Testing {len(payloads)} payloads...")
```

### Testing

```python
# Enable demo mode for visual testing
app = BugTraceApp(demo_mode=True)
app.run()

# Test individual widget
from textual.app import App

class TestApp(App):
    def compose(self):
        yield MyWidget(id="test-widget")

TestApp().run()
```

---

## Quick Reference

### Common Widget Patterns

#### Create a New Widget

```python
from textual.widgets import Static
from textual.reactive import reactive
from rich.panel import Panel

class MyWidget(Static):
    """Widget description."""

    # Reactive attributes
    value = reactive(0)
    demo_mode = reactive(False)

    def render(self) -> Panel:
        """Render the widget."""
        return Panel(f"Value: {self.value}", title="My Widget")

    def on_mount(self) -> None:
        """Called when widget is mounted."""
        self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        """Update on interval."""
        if self.demo_mode:
            self.value += 1
```

#### Add Widget to Screen

```python
# In screen compose()
def compose(self) -> ComposeResult:
    yield MyWidget(id="my-widget")

# Update from app
widget = self.query_one("#my-widget", MyWidget)
widget.value = 42
```

#### Create a Custom Message

```python
from textual.message import Message

class MyMessage(Message):
    """Custom message description."""

    def __init__(self, value: int) -> None:
        super().__init__()
        self.value = value

# Post message
self.post_message(MyMessage(42))

# Handle message
def on_my_message(self, message: MyMessage) -> None:
    self.log(f"Received: {message.value}")
```

---

## Resources

- [Textual Documentation](https://textual.textualize.io/)
- [Rich Documentation](https://rich.readthedocs.io/)
- [TCSS Reference](https://textual.textualize.io/guide/CSS/)
- [Widget Gallery](https://textual.textualize.io/widget_gallery/)

---

**Last Updated**: 2026-02-05
**Version**: 1.0.0
**Maintainer**: BugTraceAI Team
