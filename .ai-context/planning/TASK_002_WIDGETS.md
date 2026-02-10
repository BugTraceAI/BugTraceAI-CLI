# Task 002: Widget Migration (Porting Rich)

## 📋 Description
Adapt the existing rendering logic from `bugtrace/core/ui.py` into reusable Textual Widgets. The goal is to reuse the *Visual* logic (Gradient text, Sparklines, Tables) without the *Management* logic (Threads).

## 🛠️ Implementation Steps

### 1. Create Core Widgets (`widgets/`)
Create specific widget files for each major dashboard component:

*   `widgets/metrics.py`: System metrics (CPU/RAM).
*   `widgets/pipeline.py`: The Phase progress bar.
*   `widgets/activity.py`: The request/sec graph.
*   `widgets/swarm.py`: The active agents list.

### 2. Implement the `RichWidget` Pattern
Don't rewrite the rendering code. Wrap it.

**Pattern to use:**
```python
from textual.widgets import Static
from textual.reactive import reactive
from bugtrace.core.ui import SparklineBuffer # Reuse your existing helper

class ActivityGraph(Static):
    # Reactive props automatically trigger a re-render when changed
    req_rate = reactive(0.0)
    
    def on_mount(self):
        self.buffer = SparklineBuffer(60)
        self.set_interval(1.0, self.update_graph) # Internal timer
        
    def update_graph(self):
        # Update logic
        self.refresh()
        
    def render(self):
        # COPY EXISITING LOGIC FROM ui.py: _render_activity_graph
        # Return the 'Text' or 'Panel' object directly
        return self._make_sparkline_panel()
```

### 3. Compose the Main Dashboard
Update `screens/main.py` to use these new widgets instead of placeholders.

```python
    def compose(self) -> ComposeResult:
        yield Header()
        yield PipelineStatus() # New widget
        yield Container(
            ActivityGraph(),
            SystemMetrics(),
            classes="metrics-row"
        )
        yield AgentSwarm()
```

## ⚠️ Critical Note
*   Do **NOT** connect the real scan data yet. Use dummy data or `random` within the widgets to verify the visuals work.
*   Focus purely on: "Does it look like the original?"

## ✅ Acceptance Criteria
- [ ] All 4 main panels (Pipeline, Activity, Metrics, Swarm) are rendered.
- [ ] Visual fidelity is 1:1 with the implementation in `ui.py`.
- [ ] Widgets resize gracefully when terminal size changes.
- [ ] No threading errors or blocking loops.
