# Changelog

All notable changes to BugTraceAI-CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.2] - 2026-02-02

### Added
- **Expert-Level Deduplication** - Specialist agents now deduplicate findings with intelligent fingerprinting
  - `XXEAgent` - Deduplicates by endpoint (ignores query params)
  - `SQLiAgent` - Smart cookie deduplication (cookies=global, URL params=URL-specific)
  - `XSSAgent` - Deduplicates by URL+param+context
  - `SSRFAgent` - Deduplicates by URL+param
  - Each agent maintains `_emitted_findings` set and checks before emitting `VULNERABILITY_DETECTED` event
  - See [DEDUPLICATION_BUG_ANALYSIS_20260202.md](.ai-context/audits/DEDUPLICATION_BUG_ANALYSIS_20260202.md) for analysis
  - See [EXPERT_DEDUP_TEMPLATE.md](.ai-context/audits/EXPERT_DEDUP_TEMPLATE.md) for implementation pattern
- **Payload Format v3.1** - Revolutionary XML-like format with Base64 encoding for 100% payload integrity
  - New `payload_format.py` utility module with encode/decode functions
  - `.queue` files now use `<QUEUE_ITEM>` XML-like blocks with Base64-encoded JSON
  - `.findings` files use `<FINDING>` blocks for finding details
  - `llm_audit.log` uses `<LLM_CALL>` blocks for LLM interaction auditing
  - Solves JSONL corruption issues with newlines, special chars, and nested quotes
  - See [PAYLOAD_FORMAT_V31.md](.ai-context/technical_specs/PAYLOAD_FORMAT_V31.md) for full specification

### Changed
- `thinking_consolidation_agent.py` - Queue writing now uses XML-like format (lines 533-572)
- `team.py` - Finding details writing uses XML-like format (lines 559-564)
- `llm_client.py` - LLM audit logging uses XML-like format (lines 755-786)

### Fixed
- Payload corruption in queue files when payloads contain newlines or special characters
- JSON parsing errors in specialist agents due to malformed JSONL entries
- Evidence preservation for HTTP responses with binary data

---

## [3.2.0] - 2026-02-02

### Changed
- Increased DAST analysis timeout from 120s to configurable value (default 180s)
- Timeout now applies INSIDE semaphore to ensure ALL URLs get analyzed

### Fixed
- URLs timing out before analysis when concurrency limits are high
- Semaphore wait time incorrectly counted against analysis timeout

---

## [3.1.0] - 2026-01-31

### Added
- Configurable False Positive (FP) threshold in `.conf` file (default 0.3)
- URL prioritization system for smarter crawling order

### Fixed
- FP threshold was hardcoded at 0.5, now configurable via `FP_THRESHOLD` setting
- Multiple scan hang issues resolved with proper agent lifecycle management

---

## [3.0.0] - 2026-01-29

### Added
- **Sequential Pipeline V6** - Strict phase-by-phase execution architecture
  - Phase 1: RECONNAISSANCE (GoSpider + TechStack)
  - Phase 2: DISCOVERY (GoSpider + DASTySAST parallel analysis)
  - Phase 3: STRATEGY (ThinkingConsolidation batch processing)
  - Phase 4: EXPLOITATION (11+ specialist agents)
  - Phase 5: VALIDATION (AgenticValidator with CDP)
  - Phase 6: REPORTING (Multi-format report generation)
- `signal_phase_complete()` coordination between phases
- Batch file processing in Phase 3 (replaces event-driven)
- ThinkingAgent now processes all findings at once after Phase 2 completes

### Changed
- **Breaking:** EventBus replaces Redis message queues
- **Breaking:** Configuration migrated from `.conf` to `.yaml`
- ThinkingAgent no longer subscribes to `URL_ANALYZED` events (Phase 3 batch mode)
- Worker initialization moved from before Phase 1 to Phase 3
- Total phases increased from 5 to 6 (Strategy separated from Discovery)

### Removed
- Event-driven concurrent processing between phases
- Real-time finding routing during Phase 2

---

## [2.1.0] - 2026-01-20

### Added
- **Numbered Reports System** - Sequential DASTySAST reports mapped to `urls.txt` line numbers
  - `dastysast/1.json` → Line 1 of `urls.txt`
  - `dastysast/N.json` → Line N of `urls.txt`
- **Dual Format Reports** - JSON (structured) + Markdown (human-readable)
- **Payload Preservation v2.1.0** - JSON reference system for payloads >200 chars
  - `_report_files` metadata in findings
  - `load_full_payload_from_json()` for specialists

### Fixed
- Payload truncation in queue files for long XSS/SQLi payloads
- Inconsistent report numbering across URLs

---

## [2.0.0] - 2025-12-15

### Added
- HTTPOrchestrator with Connection Lifecycle Tracker
  - Ghost connection detection (connections open >120s)
  - Backpressure when `ghost_count >= 5`
  - Adaptive retry calculator based on host success rate
- Circuit breaker per host (prevents hammering dead endpoints)
- Destination-based pool limits (TARGET: 50, LLM: 5, SERVICE: 10)

### Changed
- All HTTP requests now use centralized `http_orchestrator`
- `register_close()` guaranteed in `finally` block for all requests

### Fixed
- Connection saturation issues when scanning aggressive targets
- File descriptor exhaustion from unclosed HTTP connections

---

## [1.5.0] - 2025-11-20

### Added
- AgenticValidator with Chrome DevTools Protocol (CDP)
  - Multi-context support (up to 5 workers)
  - Vision AI verification (Gemini 2.5 Flash)
  - XSS and CSTI validation only
- Phase-specific semaphores (DISCOVERY: 1, ANALYSIS: 5, EXPLOITATION: 10)

### Changed
- Validation concurrency increased from 1 to 5 (CDP multi-context)
- SQLi validation bypasses FP filter (SQLMap is authoritative)

---

## [1.0.0] - 2025-10-01

### Added
- Initial release with 11+ specialist agents
- XSSAgent with Playwright validation
- SQLiAgent with SQLMap integration
- ReconAgent with subdomain enumeration
- Basic EventBus for agent coordination

---

## Version Numbering

- **Major (X.0.0)** - Breaking changes to architecture or API
- **Minor (x.X.0)** - New features, backwards-compatible
- **Patch (x.x.X)** - Bug fixes, no new features

---

## Roadmap

### v4.0.0 (Q2 2026) - Planned
- GraphQL introspection agent
- Authentication bypass agent (OAuth, JWT, Session)
- WebSocket fuzzing support

### v5.0.0 (Q3 2026) - Planned
- Machine Learning-based WAF bypass
- Knowledge graph with Neo4j
- Community plugin marketplace

See [architecture_future.md](.ai-context/architecture/architecture_future.md) for detailed roadmap.
