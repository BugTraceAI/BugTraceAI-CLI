# Changelog

All notable changes to BugTraceAI-CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.7.12-beta] - 2026-07-24

### Changed
- **Model Lab (model-eval) recalibration — quality-dominant, per-slot, discrimination-focused.** A real-scan ground-truth audit showed the old composite was effectively a latency sort whenever the judge rubric saturated (many models tying at 10/10). Recalibrated:
  - **Composite re-weighted** to correctness 0.40 / skepticism 0.30 / compliance 0.15 / performance 0.15 (was performance-heavy at 0.35). Latency is now scored on the **median** (robust to a single slow prompt in a small sample) and reported as a side axis, not the decider. All scoring knobs (weights, gate thresholds, latency stat, diversity weight) are externalized to a `[MODELLAB]` config section, and every run records its `scoring_version` + effective weights so results stay self-describing.
  - **New suites `quick-v3` (9 prompts) / `advanced-v2` (12)** with a re-anchored strict rubric (a correct-and-complete answer scores 7-8, not 10) and a per-prompt `discriminator`, so competent models separate instead of tying. Adds HARD cases built from real FP/FN traps (backslash-parity breakout, CSTI "49" baseline collision), JWT algorithm confusion and a TOCTOU race. Legacy `quick-v2`/`advanced-v1` preserved for comparability.
  - **Per-slot leaderboard** (MUTATION / SKEPTICAL / ANALYSIS / REPORTING) — pick the best model per scanner slot, not one global winner. Adds a REPORTING slot (CVSS + PoC), previously untested.
  - **Experimental MUTATION diversity probe** (opt-in) samples payloads at scan temperature and counts unique breakout-valid ones; the MUTATION slot pick blends judge quality with this diversity — the signal that tracks real-scan recall. Validation (2026-07-24) confirmed a model can top one-shot judge quality yet rank last on diversity, matching the observed real scan.
  - Gate min correctness lowered 7.0 → 6.0 to match the stricter rubric's scale; default `runs` raised to 2 to cut single-sample verdict noise.

## [3.7.11-beta] - 2026-07-24

### Added
- **Reporting/enrichment failover (scoped, provider-agnostic)** - when a PoC or CVSS enrichment LLM call on the active scan provider fails or degrades (circuit-breaker fallback, timeout, saturation), the reporting layer now falls back to a secondary provider **only for that enrichment call** — it never changes the scan's active provider or mixes providers during the scan. Self-contained one-shot call using the fallback provider's own preset (base_url/key/api_format/REPORTING_MODEL); Anthropic (api-key) supported natively. Configurable via `REPORTING_FAILOVER_ENABLED` / `REPORTING_FAILOVER_PROVIDER` (default: enabled → `anthropic`). Prevents empty/un-enriched reports when OpenRouter arrives saturated at reporting time.
- **Richer enrichment provenance + telemetry** - `poc_enrichment_provenance` now distinguishes `llm` (active provider), `llm_<provider>_failover` (recovered via failover), and `deterministic_evidence` (evidence-only fallback). `validated_findings.json` meta gains `reporting_failover_count`, so reporting saturation is visible in the deliverable instead of silently degrading.

## [3.7.10-beta] - 2026-07-24

### Fixed
- **Same RCE counted twice (dedup gap)** - a command injection detected two ways on the same endpoint/param (e.g. output-based `id` labelled "Authenticated RCE" and time-based `sleep 5` labelled "RCE" on `/api/health?cmd=`) produced two CRITICAL findings, because the dedup type-normalizer didn't treat the RCE-family labels as equivalent. The RCE / command-injection family now canonicalizes to a single type; param + path stay in the key so distinct endpoints are never merged.
- **Real IDORs buried in PENDING after a brittle re-test** - the IDOR deep-exploitation re-test rebuilds baseline/exploit from the probe's (often synthetic) `original_value`, so its strict gate can fail to reproduce the differential even for a genuine IDOR that already leaked sensitive data on detection (e.g. `/api/orders` with `user_id=test` → 422 baseline). Such a finding was downgraded to PENDING (effectively hidden). It now routes to MANUAL_REVIEW when the detection carried strong evidence (sensitive-data leakage), surfacing it as a reportable finding for human confirmation instead of auto-confirming. Weak-evidence re-test failures still go to PENDING.

---

## [3.7.9-beta] - 2026-07-23

### Fixed
- **"Findings by Severity" total differed between Markdown and engagement JSON** - the Markdown histogram counted validated + manual_review + pending, but the engagement builder counted only validated, so `engagement_data.json`'s `summary.by_severity` total was lower than `final_report.md` for the same scan. Both now count all three buckets.
- **Manual-review ordering drifted between deliverables** - the Markdown "Needs Manual Review" section listed findings in raw order while the HTML/JSON deliverable sorted them by CVSS; MR-1..MR-n now share the same CVSS sort (validated and pending sections already did).
- **`discovery.url.started` omitted the URL total** - the DAST per-URL event sent only `{index}`, so the WEB rendered "[DAST] Analyzing URL 3/" (garbled) and the graph's per-URL progress regex couldn't match. It now includes `total` (threaded from the discovery pass), giving a proper "i/N".

---

## [3.7.8-beta] - 2026-07-23

### Fixed
- **Pending (POTENTIAL) findings were missing from `validated_findings.json`** - pending findings already appeared in the Markdown and engagement deliverables but were omitted from `validated_findings.json`, so the rich-report path (`report_service._load_rich_findings`) never surfaced them even though `PENDING_VALIDATION`/`PENDING` are reportable statuses. `validated_findings.json` now includes a `pending` array (with count), and the rich-findings extractor reads it — bringing all three deliverables into parity.

---

## [3.7.7-beta] - 2026-07-23

### Fixed
- **Event-loop hang on boolean-blind SQLi (ReDoS sibling)** - the boolean-based SQLi test ran `difflib.SequenceMatcher().ratio()` (O(n·m)) over UNCAPPED response bodies on the asyncio loop thread; a large/hostile page could stall the whole scan (same class as the recent gospider ReDoS: `/health`→000, progress frozen). Inputs are now capped to 50 KB and the diff is offloaded via `asyncio.to_thread`, at both live sites (`agents/sqli/exploitation.py`, `tools/exploitation/sqli.py`).
- **WebSocket event mis-mapping (Swarm Graph / scan console)** - `_map_event_type` mapped any event name merely *containing* `"finding"` to `finding_discovered`, so a `finding_rejected`/`finding_verified` lifecycle event could render as a fresh CONFIRMED CRITICAL. Those now route to a log line; only a genuine new-vuln announcement becomes a finding. Also added `auth` to the dotted-event allowlist so `auth.phase.started` passes through to the `[AUTH]` formatter instead of mis-rendering as `[PHASE] … complete` at phase start.

### Added
- **Model Lab key validation endpoint** - `GET /api/model-eval/test-key` validates an OpenRouter key against OpenRouter's authenticated `/key` endpoint (returns label/credit, consumes no tokens) so the WEB "Test key" button can confirm a key works BEFORE a benchmark. The public `/models` catalog returns 200 even for a bad key, so it can't be used for validation. Accepts the module key (`X-OpenRouter-Key`) or falls back to the CLI provider key; the key stays server-side.

---

## [3.7.6-beta] - 2026-07-23

### Added
- **Model Lab per-request OpenRouter key** - `/api/model-eval` and `/api/model-eval/models` now accept an OpenRouter API key supplied by the caller (request `api_key` field / `X-OpenRouter-Key` header). When present it is used for the benchmark instead of the CLI's configured provider key, so Model Lab (now a standalone WEB module) runs with its own key even if the scanner's active provider isn't OpenRouter. Backward-compatible: without the key, the active provider is used as before.

---

## [3.7.5-beta] - 2026-07-23

### Added
- **Anthropic provider (direct API)** - Anthropic is now a first-class LLM provider using an API key (`x-api-key`, Messages API), selectable via the `anthropic` preset or the WEB Provider tab. A new `api_format` preset field decouples the wire format from the OAuth path, so `generate`, threaded generation, vision and connectivity all route to the Anthropic Messages API when active. Existing OpenRouter/Z.ai behaviour is unchanged.

### Fixed
- **Provider hot-switch** - switching providers at runtime (WEB Provider tab) now re-applies the full provider config via a single source of truth (`_apply_provider_config`), so `api_format` and every other provider-scoped attribute move together instead of leaving a stale wire format. Also stopped a missing provider key from silently falling back to another provider's key.
- **Provider "Test API Key"** - the test endpoint now uses the correct wire format per provider (Anthropic `x-api-key` + Messages API), so a valid Anthropic key no longer reports as invalid.

---

## [3.6.93-beta] - 2026-07-21

### Fixed
- **AuthDiscovery visibility** - verbose events now include the target, bounded URL count, per-URL progress, and final JWT/cookie totals.

---

## [3.6.92-beta] - 2026-07-21

### Added
- **Bounded JavaScript endpoint mining** - GoSpider now mines same-origin scripts for API endpoints with configurable script-count, response-size and timeout limits plus strict same-origin redirect handling, while keeping JavaScript assets out of DAST.

---

## [3.6.91-beta] - 2026-07-21

### Added
- **ModelLab history deletion** - the API can delete one persisted benchmark run without affecting scanner history.

---

## [3.6.90-beta] - 2026-07-21

### Added
- **Integrated ModelLab beta** - BugTraceAI-WEB can compare OpenRouter models through the CLI API, stream live progress, cancel jobs, and keep local benchmark history.
- **Completed-scan metric availability** - API clients can distinguish live detailed metrics from historical scans where those metrics were not persisted.

### Fixed
- **Reporting and validation reliability** - full-scan duration, SQLi quality gates, CDP handoff, finding preservation, and false-positive filtering were hardened across the pipeline.
- **ModelLab validation** - unsupported providers and invalid neutral-judge selections now fail before any benchmark job starts.

### Security
- **Local beta deployment boundary** - the API is intended for a local machine or trusted LAN and must not be exposed directly to the Internet. ModelLab uses the configured provider key and can incur costs.

---

## [3.6.50-beta] - 2026-07-07

### Fixed
- **DOM-scan recon URLs now deduped by endpoint surface** — DOM-scan recon no longer floods the URL budget with near-identical blog/post URLs, so pure DOM-sink pages (e.g. a `location = get("back")` sink) survive the cap and reach the detector in normal crawls.

## [3.6.49-beta] - 2026-07-07

### Fixed
- **Browser-only XSS candidates auto-escalate to L5/L6 at standard depth** — a candidate that only fires in a real browser (DOM execution, not HTTP reflection) is now promoted to the Playwright/CDP escalation levels even at the default analysis depth, instead of being dropped when depth is low.

## [3.6.46-beta – 3.6.48-beta] - 2026-07-06

### Added
- **Decoupled CDP validation stage wired into the scan pipeline** — `_find_chrome` locates the Playwright-bundled Chromium and a fail-safe `AgenticValidator` Phase-5 stage runs on the hard queue, so CDP confirmation is a real pipeline stage rather than dead code.

### Removed
- **Dead `agents/validation/` twin package deleted** — removed the stale duplicate that reintroduced identity-merge / static-stub regressions if adopted.
- **Dead `reporting_mod` twin removed** — abandoned February modularization cleaned up.

## [3.6.38-beta – 3.6.45-beta] - 2026-06-28

### Fixed
- **Reporting output-layer quick-wins (two rounds)** — CONFIRMED findings are no longer silently dropped or degraded: real string-evidence is preserved for SQLi, the HTML evidence panel is populated, the dedup key now includes the URL (distinct endpoints no longer collapse into one, losing findings), and CVSS/severity/impact are made consistent across the report.
- **PoC `curl` only for genuine injection** — a reproduction `curl` is synthesized only for real injection findings (payload / captured request); observation and configuration findings (CORS, headers, rate-limit, vulnerable components) get an evidence pointer instead of a misleading forced `curl`.
- **Consistent finding grouping** — canonical LFI type and grouping of all missing-header findings.
- **False-positive discipline across specialists** — SQLi error-based and mass-assignment now require a differential (not mere reflection); validator-marker / CRLF-reflection / prototype-pollution RCE word-list hardening; API security hardening and DRY refactors.

## [3.6.28-beta – 3.6.31-beta] - 2026-06-27

### Fixed
- **Target URL sanitized** — a pasted leading/trailing space no longer makes recon find 0 URLs and fail the scan.
- **CSTI L5 marker desync fixed** — the browser-validation marker (`1000003*1000003` → `1000006000009`) is used consistently, so client-side CSTI confirms reliably at L5.
- **Report gate for locationless injection** — injection-class "confirmed" findings without a location are routed to `MANUAL_REVIEW`, killing phantom SSRF false positives.

### Added
- **XXE discovery for POST-only XML endpoints** — JS-triggered XML endpoints that GET-based analysis can't see are now discovered and dispatched (blind XXE remains an honest `MANUAL_REVIEW` candidate without OOB egress).

## [3.6.21-beta – 3.6.26-beta] - 2026-06-25

### Fixed
- **Recovered DOM search XSS (V-002)** — reflected-param DOM XSS detection made reliable; added a JSON-reflection false-positive guard and dropped the dead Z.ai failover path.
- **SQLi error-based false positives killed** — confirmation now requires a real SQL error signature, not a bare database-name mention (e.g. an `/api/debug/vulns` cheat-sheet page no longer false-confirms).

### Changed
- **Removed target-specific hardcoded values** — generic stored-XSS write-endpoint discovery via 422 schema inference, generic XXE repro-step derivation, and removal of the last ginandjuice/BugStore-tuned constants (XXE base XML, reattack SSTI wordlist).

## [3.6.1-beta – 3.6.20-beta] - 2026-06-23

### Added
- **LoneWolf agent v2 (expert rewrite)** — persistent `KnowledgeBase` memory (endpoints / params / cookies / tech / notes / tested surfaces) injected into every prompt instead of bare counters, autonomous regex surface mapping, context-aware confirmation, and high-impact confirmation classes (OS command injection and error-based SSTI).
- **OOB Collaborator API** — on-demand interactsh session for manual OOB testing.

### Fixed
- **OOB interactions revived** — decrypt with AES-CTR instead of AES-CFB, reviving dead blind SSRF/XXE/RCE/SSTI/XSS OOB confirmation.
- **Cookie SQLi (V-013)** — injected `Cookie` header now sent via a jar-less isolated session (the pooled aiohttp cookie jar was clobbering it); probe-confirmed cookie SQLi emitted as `VALIDATED_CONFIRMED` with anti-FP re-confirmation for the time-based variant.
- **Vulnerable JS components surfaced (V-030)** — routed into the misconfigurations bucket with the OWASP A06 standard label.
- **OpenRedirect V-005** — payload-URL recovery plus a deterministic canary endpoint probe.
- **searchTerm XSS routing recovered** — plus elimination of L4 double-encode false positives.
- **Real PoC screenshots for confirmed XSS** — decoupled from the L0.5 short-circuit, with a CDP fallback when Playwright can't fire the payload.
- **Deterministic reporting baseline** — findings are never blank when the LLM is unavailable.

## [3.5.10-beta] - 2026-06-21

### Fixed
- **Severity floor applied post-enrichment** — the severity floor is enforced after enrichment so a finding can't be downgraded below its class minimum.

## [3.5.9-beta] - 2026-06-21

### Fixed
- **Auth-recall and precision fixes** across the scanner (authenticated-scan recall is the single biggest lever for detection rate).

## [3.5.8-beta] - 2026-06-18

### Fixed
- **CDP batch validation no longer drops freshly-confirmed findings** (`agentic_validator._batch_process_results`) — validation verdicts are now merged onto the original finding so the downstream `(url, parameter, type)` result map resolves correctly; previously a newly CDP-confirmed XSS/CSTI/SSTI collapsed to the empty key and was overwritten to `VALIDATED_FALSE_POSITIVE`.
- **EventBus token publishing fixed** (`team._scan_for_tokens`, `auth_discovery._emit_discoveries`) — use the real async `emit()` instead of the non-existent `publish()`, which raised `AttributeError` and either aborted the scan (URL-list mode) or silently collapsed crawled URLs to the root (normal mode) whenever recon surfaced a JWT.
- **Per-scan EventBus subscription leak / cross-scan persistence** (`team.start`) — the `VULNERABILITY_DETECTED` handler is now unsubscribed when a scan ends, preventing a later scan's finding from being persisted under a previous scan's id/target on a long-lived API/MCP server.
- **Finding status can now be downgraded** (`database._update_existing_finding` via new pure `_resolve_status`) — explicit validator verdicts (`FALSE_POSITIVE` / `MANUAL_REVIEW`) are honored on update instead of only ever upgrading to `CONFIRMED`, so the SQLite row read by the API/WEB no longer shows rejected findings as confirmed.

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
