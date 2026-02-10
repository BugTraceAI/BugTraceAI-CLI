# Task 003: The Async Engine (Wiring)

## 📋 Description
Connect the actual BugTraceAI scanning engine (Pipeline) to the new Textual UI using Asynchronous Workers. This replaces the old thread-based shared-memory model.

## 🛠️ Implementation Steps

### 1. Create the `ScanWorker`
In `bugtrace/core/ui/tui/workers.py`:

This worker runs the legacy `_execute_phases` logic but bridges the communication.

```python
from textual.worker import Worker
from textual.message import Message

class ScanWorker:
    def __init__(self, app, target):
        self.app = app
        self.target = target
        
    async def run(self):
        # This replaces the old asyncio.run(_execute_phases...)
        # It calls the pipeline logic
        await _execute_phases(
            self.target, 
            callback=self.emit_update # Inject a callback to bridge data
        )
    
    def emit_update(self, data_type, payload):
        # Post message back to Main Thread
        self.app.post_message(FilesUpdate(payload))
```

### 2. Define Messages
Define strict data contracts for UI updates.

```python
class AgentUpdate(Message):
    def __init__(self, agent_name, status, payload): ...

class PipelineProgress(Message):
    def __init__(self, phase, percent): ...
    
class NewFinding(Message):
    def __init__(self, finding_obj): ...
```

### 3. Handle Messages in App
In `app.py` or `screens/main.py`:

```python
    def on_agent_update(self, message: AgentUpdate):
        # Find the widget and update its reactive prop
        self.query_one(AgentSwarm).update_agent(message.agent_name, message.status)
        
    def on_new_finding(self, message: NewFinding):
        self.query_one(FindingsTable).add_row(...)
        self.notify(f"Vulnerability Found: {message.finding.type}")
```

### 4. Patch the Core Pipeline
You will need to slightly modify `_execute_phases` and the Orchestrator to accept a `ui_callback` or `message_bus` argument instead of writing directly to the global specific `Dashboard` class.

## ✅ Acceptance Criteria
- [ ] Launching a scan updates the UI in real-time.
- [ ] No "RuntimeWarning: coroutine was never awaited" errors.
- [ ] App remains responsive (commands/clicks work) even while heavy scanning occurs.
- [ ] Graceful shutdown works (Ctrl+C kills both UI and Scan).
