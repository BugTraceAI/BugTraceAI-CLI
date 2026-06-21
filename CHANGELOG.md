# Changelog

All notable changes to BugTraceAI-CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.5.7-beta] - 2026-06-15

### Changed
- **Agent Architecture Improvements** - Refined model migration to v2 across all agent slots
  - All specialist agents now use consistent model assignment
  - Improved performance and reliability for concurrent scanning

### Fixed
- Improved model assignment consistency across all vulnerability detection agents

---

## [3.5.6-beta] - 2026-06-08

### Added
- **YAML-based Authentication** - New flexible auth configuration format
  - Support for environment variable substitution in YAML configs
  - Cleaner syntax than previous `.conf` approach
  - `--auth-config` flag for specifying custom YAML auth files
- **TOTP (Time-based One-Time Password) Support** - Level 2 authentication
  - Full TOTP injection into request headers and cookies
  - Compatible with 2FA-protected applications
  - Automatic time-sync validation for TOTP generation
- **Enhanced Documentation** - Updated README and INSTALLATION.md with auth examples

### Changed
- **Version Badge Updated** - Now shows v3.5.7-beta in all references
- Authentication configuration now uses YAML instead of environment variables

### Fixed
- Auth Level 2 TOTP injection now correctly handles time-based validation
- Complete test suite for YAML auth and TOTP flows

---

## [3.5.0-beta] - 2026-05-28

### Added
- **Scan Resumption Feature** - Resume interrupted or paused scans
  - Track `recovery_available` status for each scan
  - Resumable scans maintain context and avoid duplicate analysis
  - Proper state management for `PAUSED` and `CANCELLED` scans
  - Database schema migration for resumption columns on existing SQLite DBs
- **429 Concurrency Limit Handling** - Return proper HTTP 429 when resume hits scan limits
  - Prevents unbounded scan resumption when system is under load

### Changed
- Scan state machine now includes `RESUMED` transition states
- Database migrations auto-applied on startup for backward compatibility

### Fixed
- Detached scan state issues during resume operations
- Timeout propagation for resumable scans
- Recovery tracking for interrupted connections
- Ensure resume API works for recoverable scans only

---

## [3.4.9-beta] - 2026-03-21

### Added
- **URL List and Swagger File Import** - Direct import of test targets
  - Support for `.txt` URL lists (one URL per line)
  - Support for OpenAPI/Swagger JSON imports
  - Automatic endpoint extraction from Swagger definitions
  - Reduces manual target configuration time
- **VERSION File** - Single source of truth for CLI version
  - All version references now pull from `VERSION` file
  - Ensures consistency across API responses and documentation
- **Named Docker Volumes** - Improved MCP service management
  - Consistent named volume usage across docker-compose configs
  - Better persistence and data integrity

### Changed
- Version metadata alignment to 3.4.9-beta across all components
- Docker Compose detection logic improved for edge cases

### Fixed
- Correct execution time reporting in scan summaries
- Named volume consistency for MCP service
- Sanity test failures resolved with improved validation

---

## [3.2.0] - 2026-02-02

### Changed
- **Timeout Configuration** - DAST analysis timeout now configurable (default 180s)
  - Timeout applies INSIDE semaphore to ensure all URLs get analyzed
  - Increased from hardcoded 120s for better coverage

### Fixed
- URLs timing out before analysis when concurrency limits are high
- Semaphore wait time incorrectly counted against analysis timeout

---

## [3.1.2] - 2026-02-02

### Added
- **Expert-Level Deduplication** - Intelligent finding deduplication by vulnerability type
  - `XXEAgent` - Deduplicates by endpoint (ignores query params)
  - `SQLiAgent` - Smart cookie deduplication (cookies=global, URL params=URL-specific)
  - `XSSAgent` - Deduplicates by URL+param+context
  - `SSRFAgent` - Deduplicates by URL+param
  - Each agent maintains `_emitted_findings` set for tracking
- **Payload Format v3.1** - Revolutionary XML-like format with Base64 encoding
  - `.queue` files now use `<QUEUE_ITEM>` XML-like blocks with Base64-encoded JSON
  - `.findings` files use `<FINDING>` blocks for finding details
  - `llm_audit.log` uses `<LLM_CALL>` blocks for LLM interaction auditing
  - Eliminates JSONL corruption issues with newlines and special characters

### Changed
- Queue writing and finding details now use XML-like format
- LLM audit logging improved with structured XML blocks

### Fixed
- Payload corruption when payloads contain newlines or special characters
- JSON parsing errors in specialist agents due to malformed JSONL entries
- Evidence preservation for HTTP responses with binary data

---

## [3.1.0] - 2026-01-31

### Added
- **Configurable False Positive Threshold** - FP filtering now tunable per scan
  - Default 0.3, configurable via `.conf` file
- **URL Prioritization System** - Smarter crawling order for improved efficiency

### Fixed
- FP threshold was hardcoded at 0.5, now fully configurable
- Multiple scan hang issues with proper agent lifecycle management

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
- **EventBus Coordination** - `signal_phase_complete()` for phase synchronization
- **Batch File Processing** - Phase 3 now processes all findings at once (event-driven → batch)

### Changed
- **Breaking:** EventBus replaces Redis message queues
- **Breaking:** Configuration migrated from `.conf` to `.yaml`
- ThinkingAgent no longer subscribes to `URL_ANALYZED` events (Phase 3 batch mode)
- Total phases increased from 5 to 6 (Strategy separated from Discovery)

### Removed
- Event-driven concurrent processing between phases
- Real-time finding routing during Phase 2

---

## [2.1.0] - 2026-01-20

### Added
- **Numbered Reports System** - Sequential DASTySAST reports mapped to `urls.txt` line numbers
  - `dastysast/1.json` → Line 1 of `urls.txt`
- **Dual Format Reports** - JSON (structured) + Markdown (human-readable)
- **Payload Preservation v2.1.0** - JSON reference system for large payloads (>200 chars)

### Changed
- Report structure now includes payload references for better organization

### Fixed
- Large payload handling in JSON reports

---

## [2.0.0] - 2026-01-10

### Added
- **Initial BugTraceAI-CLI Release** - Autonomous security scanning platform
  - Multi-phase reconnaissance and vulnerability discovery
  - 11+ specialist vulnerability agents
  - Real-time WebSocket reporting
  - Docker + Docker Compose deployment
  - RESTful API for scan management

