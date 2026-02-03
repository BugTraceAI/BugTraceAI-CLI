# Codebase Structure

**Analysis Date:** 2026-02-03

## Directory Layout

```
BugTraceAI-CLI/
├── bugtrace/                      # Main package
│   ├── __main__.py                # CLI entry point (Typer app)
│   ├── __init__.py                # Package marker
│   ├── agents/                    # Vulnerability detection agents
│   ├── api/                       # FastAPI REST API
│   ├── core/                      # Core infrastructure & orchestration
│   ├── data/                      # Static payload/resource data
│   ├── memory/                    # LLM memory & payload learning
│   ├── mcp/                       # Model Context Protocol tools
│   ├── payloads/                  # Payload templates and batches
│   ├── reporting/                 # Report generation (HTML/JSON/Markdown)
│   ├── resources/                 # Agent prompt templates
│   ├── schemas/                   # Database models & API request/response schemas
│   ├── services/                  # Service layer (ScanService, ReportService)
│   ├── tools/                     # External tool integrations & wrappers
│   ├── utils/                     # Utilities (logging, safeguards, validators)
│   ├── logs/                      # Runtime logs directory
│   └── skills/                    # Specialized knowledge modules (legacy)
├── tests/                         # Test suite
│   ├── unit/                      # Unit tests
│   ├── integration/               # Integration tests
│   ├── mocks/                     # Mock objects for testing
│   └── manual/                    # Manual/interactive tests
├── protocol/                      # Conductor protocol files (validation rules)
├── reports/                       # Generated scan reports (output directory)
├── data/                          # Persistent data (LanceDB, monitoring state)
├── alembic/                       # Database migrations (Alembic config)
├── scripts/                       # Utility scripts (reporting, debugging)
├── tools/                         # Go-based fuzzer binaries & source
│   ├── go-xss-fuzzer/
│   ├── go-sqlmap-like-fuzzer/
│   ├── go-idor-fuzzer/
│   ├── go-lfi-fuzzer/
│   └── go-ssrf-fuzzer/
├── bin/                           # Executable wrappers and launchers
├── pyproject.toml                 # Package configuration & dependencies
├── alembic.ini                    # Database migration config
└── bugtraceaicli.conf             # Configuration template
```

## Directory Purposes

**bugtrace/agents/:**
- Purpose: Specialized vulnerability detection agents following BaseAgent pattern
- Contains:
  - Core agents: `xss_agent.py`, `sqli_agent.py`, `csti_agent.py`, `lfi_agent.py`, `idor_agent.py`, `rce_agent.py`, `ssrf_agent.py`, `xxe_agent.py`, `jwt_agent.py`, `header_injection_agent.py`, `prototype_pollution_agent.py`, `openredirect_agent.py`
  - Orchestration agents: `thinking_consolidation_agent.py`, `agentic_validator.py`, `analysis_agent.py` (DASTySASTAgent)
  - Reconnaissance agents: `gospider_agent.py`, `asset_discovery_agent.py`, `chain_discovery_agent.py`, `nuclei_agent.py`, `api_security_agent.py`
  - Supporting: `base.py` (BaseAgent abstract), `worker_pool.py` (worker concurrency), `specialist_utils.py` (shared utilities), `reporting.py` (ReportingAgent)
  - System prompts: `system_prompts/` directory with YAML frontmatter agent configs
  - Skills: `skills/vulnerabilities/` specialized knowledge modules
- Key files: `base.py` (abstract interface), `xss_agent.py` (reference implementation), `thinking_consolidation_agent.py` (deduplication)

**bugtrace/api/:**
- Purpose: REST API endpoints and request/response handling
- Contains:
  - `main.py`: FastAPI app, CORS, lifespan, openapi config
  - `routes/`: Endpoint implementations (scans.py for scan CRUD, reports.py for report retrieval)
  - `schemas.py`: Pydantic models for requests/responses
  - `deps.py`: Dependency injection (ScanService, ReportService, EventBus)
  - `exceptions.py`: Custom exception handlers
- Key file: `routes/scans.py` (scan lifecycle endpoints)

**bugtrace/core/:**
- Purpose: Core infrastructure and pipeline orchestration
- Contains:
  - `pipeline.py`: 6-phase state machine (PipelinePhase, PipelineState)
  - `team.py`: TeamOrchestrator (coordinates all agents, phase execution)
  - `conductor.py`: Validation, anti-hallucination, prompt management
  - `llm_client.py`: Claude API wrapper (streaming, batch, rate limiting)
  - `database.py`: SQLModel ORM, scan/finding tables, persistence
  - `event_bus.py`: Pub/sub system for agent coordination (EventType enum, EventBus class)
  - `queue.py`: Specialist work queues with stats (QueueItem, SpecialistQueue, queue_manager)
  - `http_manager.py`: Connection pooling, cookies, auth, rate limiting
  - `state_manager.py`: State persistence (DB-first, JSON fallback)
  - `config.py`: Pydantic settings with environment overrides
  - `ui.py`: Rich dashboard for real-time scan progress
  - `batch_metrics.py`: Phase timing and throughput metrics
  - Supporting: `validator_engine.py`, `phase_semaphores.py`, `instance_lock.py`, `boot.py`
- Key files: `team.py` (orchestration), `pipeline.py` (phase machine), `conductor.py` (validation)

**bugtrace/services/:**
- Purpose: Service layer for scan and report management
- Contains:
  - `scan_service.py`: ScanService (create, status, stop, list scans; concurrency control)
  - `scan_context.py`: ScanContext (runtime state), ScanOptions (frozen config)
  - `report_service.py`: ReportService (report retrieval, generation)
  - `event_bus.py`: Service-layer event bus (separate from core EventBus)
- Key file: `scan_service.py` (lifecycle management, async concurrency)

**bugtrace/tools/:**
- Purpose: Integration with external tools and third-party services
- Contains:
  - `external.py`: Wrappers for CLI tools (GoSpider, SQLMap, Nuclei, etc.)
  - `go_bridge.py`: Bridge to Go-based fuzzers (XSS, SQLi, IDOR, LFI, SSRF)
  - `interactsh.py`: Out-of-band callback server for XSS/RCE validation
  - `manipulation/`: HTTP manipulation, payload encoding, WAF evasion
    - `orchestrator.py`: Coordinates payloads across HTTP methods
    - `controller.py`: Request/response manipulation
    - `specialists/`: Specialist payload handlers (LFI, IDOR, etc.)
  - `visual/`: Vision LLM XSS verification via screenshots
    - `verifier.py`: XSSVerifier (screenshot analysis)
  - `waf/`: Q-Learning WAF bypass strategy
    - `strategy_router.py`: Routes payloads to evasion techniques
    - `fingerprinter.py`: Detects WAF implementation
  - `headless/`: Chromium/Playwright automation for CDP validation
  - `recon/`: Asset discovery helpers
  - `exploitation/`: Payload generation and exploitation logic
- Key files: `external.py` (tool interface), `go_bridge.py` (fuzzer integration), `visual/verifier.py` (vision validation)

**bugtrace/reporting/:**
- Purpose: Report generation in multiple formats
- Contains:
  - `generator.py`: HTMLGenerator (Jinja2 templating), report context models
  - `models.py`: ReportContext (Pydantic model for report data)
  - `standards.py`: CWE/severity mapping, remediation guidance
  - `templates/`: Jinja2 HTML templates for report rendering
- Key file: `generator.py` (HTML generation), `standards.py` (remediation/CWE)

**bugtrace/schemas/:**
- Purpose: Data models for database and API contracts
- Contains:
  - `db_models.py`: SQLModel tables (ScanTable, FindingTable, TargetTable, ScanStateTable)
  - Database enums: ScanStatus, FindingStatus, SeverityLevel
- Key file: `db_models.py` (ORM models)

**bugtrace/utils/:**
- Purpose: Utility functions and helpers
- Contains:
  - `logger.py`: Loguru wrapper with correlation IDs
  - `safeguard.py`: Tool execution wrapper with timeout and error handling
  - `token_scanner.py`: JWT token extraction
  - `aiohttp_patch.py`: Timeout configuration for aiohttp clients
  - `payload_amplifier.py`: Payload mutation and scaling
- Key file: `logger.py` (logging setup), `safeguard.py` (tool execution)

**bugtrace/memory/:**
- Purpose: LLM memory and payload learning
- Contains:
  - `manager.py`: MemoryManager (stores observations, embeddings)
  - `payload_learner.py`: PayloadLearner (extracts successful payloads from responses)
- Uses: LanceDB vector database for similarity search

**bugtrace/data/:**
- Purpose: Static payload and resource data
- Contains:
  - `xss_batches/`: Pre-compiled XSS payload batches (JSON format)
  - Resource files: Tech stack definitions, payload templates
- Key files: XSS payload batch JSON files (loaded by XSSAgent)

**bugtrace/payloads/:**
- Purpose: Payload template storage and management
- Contains: Payload JSON templates organized by vulnerability type
- Format: JSON with placeholders for dynamic substitution

**protocol/:**
- Purpose: Conductor protocol files (validation rules, false positive patterns)
- Contains:
  - `context.md`: Shared context and tech stack info
  - `security-rules.md`: Finding validation rules
  - `payload-library.md`: Approved payloads for testing
  - `validation-checklist.md`: Pre-emission validation steps
  - `false-positive-patterns.md`: Known FP indicators
  - `agent-prompts/`: Agent-specific prompt overrides
- Used by: Conductor for validation and anti-hallucination

**reports/:**
- Purpose: Output directory for generated scan reports
- Structure per scan:
  ```
  reports/
  └── domain_timestamp/
      ├── specialists/              # Per-specialist findings
      │   ├── wet/                  # WET phase (raw findings)
      │   ├── dry/                  # DRY phase (validated findings)
      │   └── xss/, sqli/, etc.     # Specialist subdirectories
      ├── logs/                     # Scan logs
      ├── captures/                 # Screenshots/artifacts
      └── analysis/                 # Analysis outputs
  ```
- Key paths: `specialists/wet/*.json` (source of truth), `*.html` (rendered reports)

**tests/:**
- Purpose: Test suite for components
- Contains:
  - `unit/`: Unit tests for core modules
  - `integration/`: End-to-end scan tests
  - `mocks/`: Mock objects for testing
  - `manual/`: Interactive manual tests
- Key files: Test structure mirrors `bugtrace/` layout

**data/:**
- Purpose: Persistent runtime data
- Contains:
  - `lancedb/`: Vector database for embeddings
  - `monitoring_state/`: WAF strategy persistence

**tools/:**
- Purpose: Go-based fuzzer implementations
- Contains:
  - `go-xss-fuzzer/`: Go fuzzer for XSS detection
  - `go-sqlmap-like-fuzzer/`: Go-based SQLi detection
  - `go-idor-fuzzer/`: Go IDOR detection
  - `go-lfi-fuzzer/`: Go LFI/path traversal detection
  - `go-ssrf-fuzzer/`: Go SSRF detection
- Usage: Compiled binaries called via `go_bridge.py`

## Key File Locations

**Entry Points:**
- `bugtrace/__main__.py`: CLI entry point, command routing
- `bugtrace/api/main.py`: FastAPI app initialization
- `bugtrace/core/team.py`: TeamOrchestrator (scan execution start)

**Configuration:**
- `bugtrace/core/config.py`: Settings management (env vars, defaults)
- `pyproject.toml`: Package metadata, dependencies
- `bugtraceaicli.conf`: Configuration template
- `alembic.ini`: Database migration config

**Core Logic:**
- `bugtrace/core/pipeline.py`: Phase state machine
- `bugtrace/core/team.py`: Orchestrator (phase sequencing, agent launching)
- `bugtrace/agents/thinking_consolidation_agent.py`: Deduplication and work distribution
- `bugtrace/services/scan_service.py`: Scan lifecycle (create, status, stop)

**Testing:**
- `bugtrace/core/database.py`: Database layer (persistence)
- `bugtrace/agents/base.py`: BaseAgent interface
- `bugtrace/core/event_bus.py`: Event coordination
- `bugtrace/core/queue.py`: Work queues

## Naming Conventions

**Files:**
- Agents: `{vuln_type}_agent.py` (e.g., `xss_agent.py`, `sqli_agent.py`)
- Services: `{service_name}_service.py` (e.g., `scan_service.py`)
- Core modules: Single-purpose descriptive names (e.g., `conductor.py`, `event_bus.py`)
- Tools: Directory per tool type (e.g., `tools/headless/`, `tools/waf/`)
- Tests: `test_{module_name}.py` (e.g., `test_xss_agent.py`)

**Directories:**
- Package dirs: lowercase with underscores (e.g., `bugtrace/agents/`)
- Version markers: Numeric (e.g., `v1`, `v2` in file comments)
- Feature subdirs: Hyphenated (e.g., `agent-prompts/`, `vulnerability-rules/`)

**Classes:**
- Agents: `{VulnType}Agent` (e.g., `XSSAgent`, `SQLiAgent`)
- Managers/Services: `{Name}Manager` or `{Name}Service` (e.g., `QueueManager`, `ScanService`)
- Data: `{Name}Table` or `{Name}Context` (e.g., `FindingTable`, `ScanContext`)

**Functions:**
- Async: `async def {action}_{subject}()` (e.g., `async def run_agent_loop()`)
- Sync: `def {verb}_{noun}()` (e.g., `def validate_finding()`)
- Private: Prefixed with `_` (e.g., `_init_agents()`)

**Enums:**
- UPPERCASE (e.g., `PipelinePhase`, `EventType`, `ScanStatus`)

## Where to Add New Code

**New Vulnerability Detection Type:**
1. Create agent: `bugtrace/agents/{vuln_type}_agent.py`
   - Inherit from BaseAgent
   - Implement async `run_loop()` and worker pool consumption
2. System prompt: `bugtrace/agents/system_prompts/{vuln_type}_agent.md` with YAML frontmatter
3. Register in:
   - `bugtrace/core/team.py`: Add to `_init_specialist_agents()`
   - `bugtrace/core/event_bus.py`: Add `WORK_QUEUED_{TYPE}` event
   - `bugtrace/core/queue.py`: Add to SPECIALIST_QUEUES dict
   - `bugtrace/agents/thinking_consolidation_agent.py`: Add to VULN_TYPE_TO_SPECIALIST map
4. Tests: `tests/unit/test_{vuln_type}_agent.py`

**New API Endpoint:**
1. Route handler: `bugtrace/api/routes/{feature}.py`
2. Schema: Add Pydantic model to `bugtrace/api/schemas.py`
3. Register: Import and include router in `bugtrace/api/main.py` → `app.include_router(router)`

**New Infrastructure Service:**
1. Core module: `bugtrace/core/{service_name}.py`
2. Singleton/Manager class with initialization
3. Import and initialize in `bugtrace/core/team.py` or relevant orchestrator
4. Export in module `__init__.py` if needed

**New Utility/Helper:**
1. Location: `bugtrace/utils/{utility_name}.py`
2. Provide public interface (functions or class)
3. Import where needed (avoid circular dependencies)

**New Test:**
1. Unit test: `tests/unit/test_{module}.py`
2. Integration test: `tests/integration/test_{feature}.py`
3. Mock helpers: `tests/mocks/{module}_mocks.py`

## Special Directories

**protocol/:**
- Purpose: Conductor validation rules and shared context
- Generated: No (manually maintained)
- Committed: Yes
- Note: Central source for validation logic, payload libraries, false positive patterns

**reports/:**
- Purpose: Scan output artifacts
- Generated: Yes (created per scan execution)
- Committed: No (in .gitignore)
- Structure: One directory per scan with domain name and timestamp
- Subdirs: `specialists/` (findings), `logs/` (execution logs), `captures/` (screenshots)

**data/:**
- Purpose: Persistent vector database and state
- Generated: Yes (created on first use)
- Committed: No (.gitignore)
- Contains: LanceDB vector index, monitoring state

**logs/:**
- Purpose: Runtime execution logs
- Generated: Yes (loguru appends)
- Committed: No (.gitignore)
- Rotation: Configured in settings

**tools/:**
- Purpose: Go-based executables (compiled once, used by reference)
- Generated: Yes (compiled from Go source via build scripts)
- Committed: Binaries not committed; source in repo
- Build: Via `tools/build_fuzzers.sh`

---

*Structure analysis: 2026-02-03*
