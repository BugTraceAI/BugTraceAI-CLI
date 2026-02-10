# BugTraceAI TUI Documentation

Complete documentation for the BugTraceAI Terminal User Interface (TUI).

## Overview

The BugTraceAI TUI is a modern, reactive terminal interface built with **Textual**, providing real-time monitoring and control of security scans. This documentation covers design principles, implementation patterns, and best practices.

## Documentation Structure

### 1. [TUI Design Guide](TUI_DESIGN_GUIDE.md)
**Complete design system reference**

- **Design System**: Colors, typography, spacing, borders
- **Architecture**: Application structure, message system, reactive pattern
- **Components**: Detailed widget documentation with API references
- **Layouts**: Grid system, responsive design
- **Interaction Patterns**: Keyboard bindings, focus management
- **Style Guidelines**: Naming conventions, best practices
- **Quick Reference**: Common patterns and resources

**Best for**: Understanding the design system, component APIs, and architectural patterns.

### 2. [TUI Visual Examples](TUI_VISUAL_EXAMPLES.md)
**Visual patterns and real-world examples**

- **Visual Layout Examples**: Full dashboard layouts with ASCII art
- **Widget Visual States**: State progression diagrams
- **Color Patterns**: Semantic coloring and usage
- **Animation Patterns**: Spinners, progress bars, sparklines
- **Advanced Component Patterns**: Context-aware displays, conditional rendering
- **Real-World Use Cases**: XSS scans, multi-agent scans, WAF detection
- **ASCII Art & Icons Reference**: Complete character reference

**Best for**: Seeing how components look, understanding visual states, and finding ASCII characters.

### 3. [TUI Implementation Guide](TUI_IMPLEMENTATION_GUIDE.md)
**Practical implementation and troubleshooting**

- **Getting Started**: Prerequisites, project structure, running the TUI
- **Creating New Widgets**: Step-by-step widget creation
- **Message Integration**: Creating and handling custom messages
- **Testing Strategies**: Unit tests, snapshots, integration tests
- **Performance Optimization**: Lazy rendering, debouncing, memory management
- **Common Patterns**: Reusable widget patterns
- **Troubleshooting**: Common issues and solutions
- **Migration Guide**: From Rich to Textual

**Best for**: Building new features, solving problems, and optimizing performance.

## Quick Start

### Installation

```bash
# Install Textual
pip install textual[dev]

# Install BugTraceAI
pip install -e .
```

### Running the TUI

```bash
# With target URL
python -m bugtrace.core.ui.tui.app --target https://example.com

# Demo mode (no scan)
python -m bugtrace.core.ui.tui.app --demo
```

### Creating Your First Widget

```python
from textual.widgets import Static
from textual.reactive import reactive
from rich.panel import Panel

class MyWidget(Static):
    value = reactive(0)

    def render(self) -> Panel:
        return Panel(f"Value: {self.value}", title="My Widget")
```

## Key Concepts

### Reactive Pattern

Textual uses reactive attributes that automatically trigger UI updates:

```python
class MyWidget(Static):
    status = reactive("idle")  # Reactive attribute

    def watch_status(self, old_value, new_value):
        """Called when status changes."""
        self.refresh()

# Update triggers automatic re-render
widget.status = "active"
```

### Message System

Event-driven communication via messages:

```python
# Define message
class StatusUpdate(Message):
    def __init__(self, status: str):
        super().__init__()
        self.status = status

# Post message
app.post_message(StatusUpdate("active"))

# Handle message
def on_status_update(self, message: StatusUpdate):
    self.status = message.status
```

### TCSS Styling

CSS-like styling for terminal layouts:

```tcss
#my-widget {
    width: 1fr;
    height: 10;
    border: round $primary;
    padding: 0 1;
}
```

## Architecture Overview

```
BugTraceApp (Textual App)
    ↓
MainScreen (Dashboard)
    ↓
Widgets (Pipeline, Swarm, Findings, etc.)
    ↑
Messages (PipelineProgress, NewFinding, etc.)
    ↑
UICallback (Bridge between pipeline and TUI)
    ↑
TeamOrchestrator / Conductor (Scanning logic)
```

## Widget Gallery

| Widget | Purpose | Location |
|--------|---------|----------|
| **PipelineStatus** | Phase progress visualization | `widgets/pipeline.py` |
| **AgentSwarm** | Specialist agent status | `widgets/swarm.py` |
| **FindingsTable** | Interactive vulnerability table | `widgets/findings_table.py` |
| **ActivityGraph** | Request rate sparkline | `widgets/activity.py` |
| **SystemMetrics** | CPU/RAM monitoring | `widgets/metrics.py` |
| **PayloadFeed** | Live payload test results | `widgets/payload_feed.py` |
| **LogInspector** | Filterable log viewer | `widgets/log_inspector.py` |
| **CommandInput** | ChatOps command bar | `widgets/command_input.py` |

## Common Tasks

### Adding a New Widget

1. Create widget file in `widgets/`
2. Define reactive attributes
3. Implement `render()` method
4. Add to screen composition
5. Add styles to `styles.tcss`

See: [Creating New Widgets](TUI_IMPLEMENTATION_GUIDE.md#creating-new-widgets)

### Creating a Custom Message

1. Define message in `messages.py`
2. Post from pipeline via `UICallback`
3. Handle in `BugTraceApp` with `on_<message>()` method

See: [Message Integration](TUI_IMPLEMENTATION_GUIDE.md#message-integration)

### Styling a Widget

1. Add CSS to `styles.tcss`:
   ```tcss
   #my-widget {
       border: round $primary;
   }
   ```

2. Or inline CSS in widget:
   ```python
   DEFAULT_CSS = """
   MyWidget {
       border: round $primary;
   }
   """
   ```

See: [Style Guidelines](TUI_DESIGN_GUIDE.md#style-guidelines)

### Testing a Widget

```python
from textual.app import App

class TestApp(App):
    def compose(self):
        yield MyWidget(id="test")

TestApp().run()
```

See: [Testing Strategies](TUI_IMPLEMENTATION_GUIDE.md#testing-strategies)

## Design Principles

### 1. Reactive by Default
Use reactive attributes for all UI state. Avoid manual refresh calls.

### 2. Message-Driven Architecture
Use messages for cross-component communication. Avoid direct widget references.

### 3. Demo Mode First
All widgets should support demo mode for development and testing.

### 4. Performance Conscious
- Debounce high-frequency updates
- Lazy render large lists
- Use async workers for heavy operations

### 5. Graceful Degradation
- Handle missing widgets (try-except)
- Provide empty states
- Show loading indicators

## Color Palette Reference

```
Primary:   #89b4fa  (Blue)
Success:   #a6e3a1  (Green)
Warning:   #f9e2af  (Yellow)
Error:     #f38ba8  (Red)
Muted:     #6c7086  (Gray)
Surface:   #1e1e2e  (Dark)
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` | Quit |
| `?` | Help |
| `f` | Focus findings |
| `l` | Focus logs |
| `:` | Command input |
| `Esc` | Unfocus |
| `Tab` | Next widget |

## Resources

### Official Documentation
- [Textual Docs](https://textual.textualize.io/)
- [Rich Docs](https://rich.readthedocs.io/)
- [TCSS Reference](https://textual.textualize.io/guide/CSS/)

### BugTraceAI TUI Guides
- [Design Guide](TUI_DESIGN_GUIDE.md) - Design system and components
- [Visual Examples](TUI_VISUAL_EXAMPLES.md) - Visual patterns and ASCII art
- [Implementation Guide](TUI_IMPLEMENTATION_GUIDE.md) - Building and troubleshooting

### Community
- [Textual Discord](https://discord.gg/Enf6Z3qhVr)
- [Textual GitHub](https://github.com/Textualize/textual)

## Troubleshooting

### Widget not updating?
→ Check if attribute is reactive: `value = reactive(0)`

### Message not received?
→ Check handler name: `def on_my_message(self, message):`

### Layout broken?
→ Verify TCSS syntax and container types

### Performance issues?
→ Implement debouncing and lazy rendering

See: [Troubleshooting Guide](TUI_IMPLEMENTATION_GUIDE.md#troubleshooting)

## Contributing

When adding new widgets or features:

1. Follow the design system guidelines
2. Add demo mode support
3. Write unit tests
4. Update this documentation
5. Add visual examples if applicable

## Version History

- **v1.0.0** (2026-02-05): Initial documentation release
  - Complete design guide
  - Visual examples
  - Implementation guide
  - Architecture overview

## Maintainers

- **BugTraceAI Team**
- For issues: [GitHub Issues](https://github.com/BugTraceAI/BugTraceAI-CLI/issues)

---

**Last Updated**: 2026-02-05
**Documentation Version**: 1.0.0
**TUI Version**: Phase 03 (High-Fidelity Interaction)
