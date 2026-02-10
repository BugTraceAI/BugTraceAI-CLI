# Architecture

**Analysis Date:** 2026-02-03

## Pattern Overview

**Overall:** Agent-based distributed scanning system with 6-phase pipeline orchestration

**Key Characteristics:**
- Asynchronous event-driven architecture using asyncio
- Specialist agent pattern for vulnerability detection (XSS, SQLi, IDOR, LFI, etc.)
- Work queue distribution to specialized agent workers
- Multi-layer validation (LLM, visual verification, CDP, OOB callbacks)
- State persistence via SQLite database with fallback to JSON
- Real-time CLI dashboard with Rich console output
- REST API wrapper (FastAPI) for web/programmatic access

## Layers

**Presentation Layer (API):**
- Purpose: REST endpoints and CLI interfaces for user interaction
- Location: `bugtrace/api/main.py`, `bugtrace/__main__.py`
- Contains: Route handlers (scan creation, status, findings, stop), Typer CLI commands
- Depends on: ScanService, ReportService, EventBus
- Used by: Web frontend (BugTraceAI-WEB), CLI consumers, MCP tools

**Service Layer:**
- Purpose: Orchestration and lifecycle management
- Location: `bugtrace/services/scan_service.py`, `bugtrace/services/report_service.py`
- Contains: ScanService (async scan execution control), ReportService (report generation)
- Depends on: TeamOrchestrator, Database, EventBus
- Used by: API routes, CLI handlers

**Orchestration Layer (Pipeline):**
- Purpose: 6-phase state machine and phase transitions
- Location: `bugtrace/core/pipeline.py`, `bugtrace/core/team.py`
- Contains: PipelinePhase enum, PipelineState machine, TeamOrchestrator (phase coordination)
- Depends on: Individual agents, Queue system, Event bus, UI dashboard
- Used by: ScanService to manage scan lifecycle

**Agent Layer:**
- Purpose: Specialized vulnerability detection and exploitation
- Location: `bugtrace/agents/*.py`
- Contains: BaseAgent (abstract), specialist agents (XSSAgent, SQLiAgent, JWTAgent, etc.), consolidation agents
- Depends on: LLM client, external tools, HTTP manager, event bus
- Used by: TeamOrchestrator to execute vulnerability scanning phases

**Core Infrastructure:**
- Purpose: System-level services and utilities
- Location: `bugtrace/core/`
- Contains:
  - `conductor.py`: Validation, anti-hallucination, prompt management
  - `llm_client.py`: Claude API wrapper with streaming and batch inference
  - `database.py`: SQLModel ORM, scan tracking, finding storage
  - `event_bus.py`: Pub/sub system for agent coordination
  - `queue.py`: Specialist work queues with backpressure
  - `http_manager.py`: Connection pooling, rate limiting
  - `state_manager.py`: State persistence (DB-first, file fallback)
  - `config.py`: Settings management with environment overrides
- Depends on: External services (OpenAI, LanceDB), third-party tools
- Used by: All layers above

**External Integration Layer:**
- Purpose: Interface with third-party tools and services
- Location: `bugtrace/tools/`
- Contains:
  - `external.py`: CLI tool wrappers (GoSpider, SQLMap, Nuclei, etc.)
  - `go_bridge.py`: Bridge to Go-based fuzzers (XSS, SQLi, IDOR, LFI, SSRF)
  - `visual/verifier.py`: Vision LLM XSS verification
  - `manipulator/`: HTTP manipulation and WAF evasion
  - `waf/`: Q-Learning WAF fingerprinting and bypass strategy
  - `interactsh.py`: Out-of-band callback verification

## Data Flow

**Full Scan Lifecycle (6 Phases):**

1. **RECONNAISSANCE Phase** (Discovery)
   - CLI: `./bugtraceai-cli scan https://target.com`
   - Input: Target URL
   - Agents: GoSpiderAgent, AssetDiscoveryAgent, APISecurityAgent
   - Output: Discovered URLs, tech stack, API endpoints
   - Event: `url_crawled` emitted for each discovered URL
   - Persistence: Scan record created in database with RUNNING status

2. **DISCOVERY Phase** (DAST Probing)
   - Input: URLs from reconnaissance + static analysis payload sets
   - Agents: DASTySASTAgent (analysis_agent.py)
   - Process: Probes URLs for input parameters, analyzes responses
   - Output: Potential vulnerability findings with classification (xss, sqli, csti, etc.)
   - Event: `url_analyzed` for each analyzed URL; findings added to database
   - Queue: ThinkingConsolidationAgent subscribes to url_analyzed

3. **STRATEGY Phase** (Deduplication & Prioritization)
   - Input: `url_analyzed` events from Discovery
   - Agent: ThinkingConsolidationAgent
   - Process:
     - Deduplicates findings using key: `vuln_type:parameter:url_path`
     - Classifies by vulnerability type using VULN_TYPE_TO_SPECIALIST mapping
     - Prioritizes by exploitation probability
     - Writes deduplicated findings to `reports/specialists/wet/*.json` files
   - Output: Work items queued to specialist queues (xss, sqli, csti, lfi, idor, rce, ssrf, xxe, jwt, header_injection)
   - Events: `work_queued_xss`, `work_queued_sqli`, etc. emitted per queue
   - Persistence: File-based (V3.2 architecture - findings are source of truth)

4. **EXPLOITATION Phase** (Specialist Testing)
   - Input: Work items from specialist queues
   - Agents: XSSAgent, SQLiAgent, CSTIAgent, LFIAgent, IDORAgent, RCEAgent, SSRFAgent, XXEAgent, JWTAgent, HeaderInjectionAgent, PrototypePollutionAgent, OpenRedirectAgent
   - Process (per specialist):
     - Load work item from queue
     - Generate payloads (LLM-driven or template-based)
     - Test via HTTP or Go fuzzer bridge
     - Perform multi-layer validation (LLM analysis, Vision, OOB via Interactsh, CDP)
     - Filter false positives via Conductor validation
   - Output: Confirmed vulnerabilities with proof
   - Event: `vulnerability_detected` for confirmed findings
   - Persistence: Findings written to `reports/specialists/wet/*.json` in specialist subdirectories

5. **VALIDATION Phase** (CDP-based Confirmation)
   - Input: Findings marked PENDING_VALIDATION from exploitation
   - Agent: AgenticValidator
   - Process:
     - Opens Chromium via CDP (headless browser)
     - Re-executes exploitation steps with visual feedback
     - Screenshots payload execution
     - Confirms XSS execution via DOM markers
   - Output: Findings marked VALIDATED or REJECTED
   - Event: `finding_validated` or `finding_rejected`
   - Persistence: Updated finding status in database/files

6. **REPORTING Phase** (Report Generation)
   - Input: All confirmed findings from prior phases
   - Agents: ReportingAgent
   - Process:
     - Aggregates findings across all specialists
     - Generates technical report (Markdown)
     - Generates executive summary
     - Renders HTML report with interactive viewer
     - Attaches screenshots and proof artifacts
   - Output: HTML/JSON/Markdown reports in `reports/domain_timestamp/`
   - Persistence: Reports written to filesystem; scan marked COMPLETED

**State Management:**
- Current phase tracked in `PipelineState` (in-memory)
- Scan progress (0-100%) calculated from phase position and queue depths
- Findings stored in two places:
  - **Files**: `reports/[domain]_[timestamp]/specialists/[vuln_type]/wet/*.json` (source of truth)
  - **Database**: ScanTable, FindingTable (for fast queries, not authoritative)
- On resume: State reloaded from database checkpoint, files scanned for existing findings

## Key Abstractions

**BaseAgent:**
- Purpose: Common interface for all specialized agents
- Examples: `bugtrace/agents/base.py` (abstract), `bugtrace/agents/xss_agent.py` (concrete)
- Pattern: Abstract base class with async `run_loop()` method; event bus subscription support; system prompt loading from YAML frontmatter
- Lifecycle: Constructor → start() → run_loop() (infinite) → stop()

**WorkerPool:**
- Purpose: Concurrent work item processing with max worker limit
- Examples: `bugtrace/agents/worker_pool.py`, used by all specialist agents
- Pattern: Pool of async worker coroutines consuming from a specialist queue; rate limiting via semaphore
- Config: Worker count, batch size, timeout per item

**PipelinePhase / PipelineState:**
- Purpose: Phase machine with transition validation
- Examples: `bugtrace/core/pipeline.py`
- Pattern: Enum + state machine for phase transitions; immutable transition records
- Valid transitions: IDLE → RECONNAISSANCE → DISCOVERY → STRATEGY → EXPLOITATION → VALIDATION → REPORTING → COMPLETE (or PAUSED/ERROR from any phase)

**ScanContext / ScanOptions:**
- Purpose: Encapsulation of scan configuration and runtime state
- Examples: `bugtrace/services/scan_context.py`
- Pattern: Frozen dataclass (immutable scan options), mutable runtime tracking (phase, progress)
- Passed to: TeamOrchestrator, agents, database operations

**QueueItem / SpecialistQueue:**
- Purpose: Work distribution to specialists with backpressure
- Examples: `bugtrace/core/queue.py`
- Pattern: Async queue wrapper with stats (throughput, latency); per-specialist named queues
- Enqueue: From ThinkingConsolidationAgent; Dequeue: By specialist agent workers

**Conductor:**
- Purpose: Validation, prompt management, anti-hallucination
- Examples: `bugtrace/core/conductor.py`
- Pattern: Singleton providing shared context, validation rules, payload libraries
- Used by: Agents for system prompts, finding validation rules

## Entry Points

**CLI Entry Point:**
- Location: `bugtrace/__main__.py`
- Triggers: `./bugtraceai-cli scan <URL>` or other commands
- Responsibilities:
  - Parse command-line arguments via Typer
  - Enforce instance lock (prevent concurrent runs)
  - Route to appropriate pipeline phase (_run_pipeline function)
  - Integrate with dashboard for real-time feedback

**API Entry Point:**
- Location: `bugtrace/api/main.py`
- Triggers: FastAPI server on port 8000
- Endpoints:
  - `POST /api/scans`: Create scan → delegates to ScanService.create_scan()
  - `GET /api/scans/{scan_id}/status`: Query scan progress
  - `GET /api/scans/{scan_id}/findings`: Fetch findings from files/database
  - `POST /api/scans/{scan_id}/stop`: Stop running scan
- Responsibilities: HTTP routing, error handling, CORS, request validation

**Scan Initiation Flow:**
1. User: `scan <URL>`
2. CLI handler calls `_run_pipeline(target, phase="hunter")` in `__main__.py`
3. Async context: Calls `asyncio.run(scan_service.create_scan(options))`
4. ScanService: Creates database record, launches TeamOrchestrator in background
5. TeamOrchestrator: Starts pipeline in `start()` method → executes phases sequentially

## Error Handling

**Strategy:** Graceful degradation with retry logic and fallback mechanisms

**Patterns:**

- **Agent Crashes**: BaseAgent.start() wraps run_loop() in try/except; logs error; marks scan FAILED
- **Tool Failures**: Tools wrapped via `run_tool_safely()` with timeout; returns {"error": ...} on failure
- **HTTP Errors**: http_manager retries with exponential backoff; reports as connection errors in findings
- **Database Errors**: StateManager falls back to file-based state if DB write fails
- **Validation Failures**: Conductor silently rejects (increments rejection counter) without failing scan
- **Queue Backpressure**: Specialist queues reject items if full; items enqueued to fallback processing

**Recovery:**
- Resume flag: `--resume` re-enters scan from last checkpoint
- State reload: Reads database checkpoints and file-based findings
- Phase reset: Can restart from specific phase if needed

## Cross-Cutting Concerns

**Logging:** Custom logger via `bugtrace/utils/logger.py` (loguru wrapper) with correlation IDs for request tracing

**Validation:**
- Multi-layer approach per vulnerability type (LLM, visual, OOB, CDP)
- Conductor validation rules applied before emission
- False positive pattern detection to filter known bypasses

**Authentication:**
- Supports basic auth, JWT tokens, session cookies
- TeamOrchestrator._handle_authentication() for interactive login
- HTTP manager stores creds per connection profile

**Rate Limiting:**
- Global HTTP rate limit via http_manager
- Per-specialist concurrency limits via phase_semaphores
- Per-queue backpressure thresholds

**Observability:**
- Event bus publishes scan events for monitoring
- Dashboard updates in real-time via Rich console
- Batch metrics track phase timing, agent throughput
- LanceDB vector database stores embeddings for payload learning

---

*Architecture analysis: 2026-02-03*
