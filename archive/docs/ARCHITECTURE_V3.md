# BugTraceAI Architecture V3: The Phased Pipeline

This document details the refactoring of BugTraceAI from a monolithic scanner into a decoupled, professional penetration testing pipeline.

## 1. Architectural Philosophy

The V3 architecture moves away from immediate validation within discovery agents. Instead, it segments the security engagement into three distinct, asynchronous phases:

1. **Hunter Phase (Discovery)**: Focused on breadth and speed. Identifies attack surfaces and potential vulnerabilities.
2. **Manager Phase (Audit)**: Focused on depth and accuracy. Performs high-fidelity validation of findings using isolated browser environments and AI vision.
3. **Reporter Phase (Output)**: Focused on clarity. Aggregates validated findings and generates professional documentation.

The **Database (`bugtrace.db`)** serves as the central "conveyor belt", decoupling these phases and allowing for scan resumption and parallel processing.

---

## 2. Technical Breakdown

### 2.1 The Hunter Phase (Discovery Manager)

* **Orchestrator**: `TeamOrchestrator`
* **Role**: Acts as the **Hunter Manager**. It coordinates the global attack surface reconnaissance and dispatches specialized agents (`DASTySASTAgent`, `XSSAgent`, `SQLMapAgent`, etc.) to perform broad testing.
* **Behavior**: Crawls target, detects technologies, and runs analysis agents. Its goal is to "suspect everything" and seed the database with candidates.
* **State Management**: Every finding is immediately persisted to the database with a status of `PENDING_VALIDATION`. This decouples the discovery from the slow, high-fidelity verification.
* **Resumption**: Periodically saves its internal state (processed URLs, discovery queue) to the database.

### 2.2 The Manager Phase (Auditor Manager)

* **Orchestrator**: `ValidationEngine`
* **Role**: Acts as the **Auditor Manager**. It is a standalone service that polices the findings produced by the Hunter.
* **Specialist Auditor**: `AgenticValidator`
* **Workflow**:
    1. **DB Review**: Polls for findings marked `PENDING_VALIDATION`.
    2. **Isolated Audit**: Instantiates a fresh, ephemeral browser session for each reproduction attempt.
    3. **Protocol Enforcement (CDP)**: Listens for low-level execution events (Alerts, Console Errors) to confirm payload execution.
    4. **AI Vision Arbitration**: If protocol events are silent, it uses a Vision LLM to analyze the screenshot, acting as a "Senior Pentester" to determine if a manifestation occurred.
* **Status Promotion**: Only after this audit is a finding marked as `VALIDATED_CONFIRMED`. Otherwise, it is relegated to `VALIDATED_FALSE_POSITIVE`.

### 2.3 The Conveyor Belt (Persistence Layer)

* **SQLModel / SQLite**: Managed via `bugtrace/core/database.py`, acting as the permanent source of truth and communication bridge between phases.
* **Finding Status Lifecycle**: `PENDING_VALIDATION` -> `VALIDATED_CONFIRMED` / `VALIDATED_FALSE_POSITIVE` / `ERROR`.
* **Scan Resurrection (`ScanStateTable`)**: The framework now persists the entire orchestrator state (URL queue, processed set, tech profiles) in the database. This allows a scan to be interrupted and resumed with 100% state fidelity by simply re-running the command.
* **Historical Traceability**: Every engagement is assigned a unique `ScanID`, enabling full historical audit trails for compliance.

---

## 3. CLI Usage

The CLI now supports phased execution subcommands:

```bash
# Full engagement: Hunter -> Manager -> Reporter (Recommended)
./bugtraceai-cli all <target_url>

# Hunter phase only: Rapid discovery
./bugtraceai-cli scan <target_url>

# Manager phase only: Audit previous findings
./bugtraceai-cli audit <target_url>
```

### Key Options

* `--continuous`: Prototype mode for running Hunter and Manager in parallel processes.
* `--safe-mode`: Enforces safety defaults.

---

## 4. Benefits of V3 Architecture

1. **Stability**: Browser-heavy validation is isolated. A crash in the browser engine during audit no longer kills the Hunter process.
2. **Accuracy**: Vision-based reasoning significantly reduces false positives by verifying the *effect* of an exploit, not just its presence in a response.
3. **Resilience**: Native database-backed state management means no lost data on network drops or framework errors.
4. **Professionalism**: Documentation distinguishes between "Suspected" and "Confirmed" issues, mirroring professional penetration testing standards.

---

## 5. Implementation Roadmap Status

* [x] Database V3 Schema Implementation
* [x] TeamOrchestrator Decoupling (Discovery Focus)
* [x] ValidationEngine Creation (Manager Role)
* [x] AgenticValidator CDP + Vision Refactor
* [x] Phased CLI Integration
* [x] Scan Resumption Logic
* [x] Verification against Juice Shop (Completed)

---
*Created by Antigravity - Framework Architect*
