# Task 001: Foundation & Project Structure

## 📋 Description
Initialize the Textual application structure, define the CSS grid layout, and set up the main application entry point.

## 📂 File Structure Changes

Create the following directory structure under `bugtrace/core/ui/`:

```text
bugtrace/core/ui/
├── tui/
│   ├── __init__.py
│   ├── app.py          # Main Textual App Class
│   ├── styles.tcss     # The Global Stylesheet
│   ├── screens/        # Screen definitions
│   │   ├── __init__.py
│   │   ├── main.py     # The Dashboard Screen
│   │   └── loader.py   # Initial Loading/Boot Screen
│   └── widgets/        # Reusable Components
│       ├── __init__.py
│       ├── header.py
│       └── footer.py
```

## 🛠️ Implementation Steps

### 1. Define Global Styles (`styles.tcss`)
Create the simplified layout using CSS Grid.

```css
/* proper aesthetics matching current dark theme */
Screen {
    layout: grid;
    grid-size: 1 3;
    grid-rows: 3 1fr 1; /* Header (3), Content (Flex), Footer (1) */
    background: $surface;
}

.layout-header {
    dock: top;
    height: 3;
    border-bottom: solid $primary;
}

.layout-content {
    /* Main area */
}

.layout-footer {
    dock: bottom;
    height: 1;
}
```

### 2. Create the Application Entry Point (`app.py`)
Implement the baseline `BugTraceApp` class.

```python
from textual.app import App, ComposeResult
from .screens.main import MainScreen

class BugTraceApp(App):
    CSS_PATH = "styles.tcss"
    TITLE = "BugTraceAI Reactor"
    
    def on_mount(self) -> None:
        self.push_screen(MainScreen())
```

### 3. Implement Main Screen (`screens/main.py`)
Create the container structure.

```python
from textual.screen import Screen
from textual.containers import Grid
from textual.widgets import Header, Footer, Static

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Grid(
            Static("Dashboard Content Placeholder", classes="box"),
            id="main-grid"
        )
        yield Footer()
```

## ✅ Acceptance Criteria
- [ ] `bugtraceai-cli --tui` (or similar trigger) launches the app.
- [ ] App creates a full-screen terminal UI.
- [ ] Header and Footer are visible.
- [ ] Resizing the terminal automatically adjusts the layout.
- [ ] CTRL+C cleanly exits the app.
