# Task 004: High-Fidelity Interaction

## 📋 Description
Implement the advanced "OpenCode-like" features that Textual enables: Scrollable tables, Modals, and Command Palette.

## 🛠️ Implementation Steps

### 1. Interactive Findings Table
Replace the static list of findings with a `DataTable`.

*   **File:** `widgets/findings.py`
*   **Features:**
    *   Sortable columns (Severity, Type, Param).
    *   Cursor navigation (Keys Up/Down).
    *   `on_data_table_row_selected`: Handler for click/enter.

### 2. Finding Details Modal
Create a pop-over screen for examining a specific vulnerability.

*   **File:** `screens/modals/finding_details.py`
*   **Content:**
    *   Full Request/Response view (scrollable).
    *   Generated Payload details.
    *   "Copy to Clipboard" button.

```python
def on_data_table_row_selected(self, event):
    finding = self.get_finding_by_row(event.row_key)
    self.app.push_screen(FindingDetailsScreen(finding))
```

### 3. Log Inspector with Filter
Replace the raw log dump with a filtered view.

*   Use `Log` widget.
*   Add an `Input` field above it to filter logs by string (e.g., "ERROR", "XSS").

### 4. Command Input (ChatOps)
Add the bottom input bar for controlling the session.

*   **Widget:** `Input(placeholder="Ask BugTrace or run command...", id="cmd-input")`
*   **Logic:**
    *   `/stop`: Gentle stop.
    *   `audit <id>`: Switch audit target.
    *   `show <agent>`: Filter dashboard to specific agent.

## ✅ Acceptance Criteria
- [ ] User can scroll through hundreds of findings without UI clipping.
- [ ] Clicking a finding opens a detailed modal.
- [ ] "Escape" key closes modals.
- [ ] Logs can be filtered in real-time.
- [ ] The experience feels "Native" and polished.
