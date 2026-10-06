# API, Persistence, and Reporting Contract Map

Read-only map of the API, SQLite, report-artifact, and Repeater boundaries.
No executable source or test file was changed while producing this document.

Date: 2026-07-30

## API Request and Response Contracts

### Scan creation

`bugtrace/api/schemas.py:51-84` defines `CreateScanRequest`. It maps to
`ScanOptions` through `bugtrace/api/routes/scans.py:93-115`.

Required compatibility fields:

- `target_url`, sanitized with whitespace stripping at the API boundary.
- `scan_type`, `scan_depth`, `safe_mode`, `max_depth`, and `max_urls`.
- `resume`, `use_vertical`, `focused_agents`, and `param`.
- `auth_token`, structured `auth`, and optional `url_list`.

The API route creates the scan through `ScanService` with `origin="web"` and
returns immediately while the background task runs.

### Scan status and history

`ScanStatusResponse` at `api/schemas.py:86-106` exposes:

- Numeric `scan_id`, target, typed `ScanStatus`, progress, uptime, and findings
  count.
- Active agent, current phase, origin, scan type, depth, URL limit, provider,
  and enrichment status.

`ScanSummary` at `api/schemas.py:142-164` adds report/recovery availability and
separate detection, confirmed, manual-review, and reportable counts. These
counts must not be collapsed during a refactor.

### Findings and Repeater persistence

`FindingItem` at `api/schemas.py:108-127` is the WEB-facing finding shape. It
requires `finding_id`, `type`, `severity`, `details`, `url`, `validated`, and
typed `FindingStatus`; `payload`, `parameter`, `confidence`, `repro`, and
`http_request` are optional.

`RepeaterFindingCreate` at `api/schemas.py:19-37` requires:

- Non-empty type, URL, summary, raw request, and bounded response status.
- A literal `request_ok=True` rather than a generic boolean.
- Optional source finding id, confidence, parameter, and response excerpt.

The route persists this data through `ScanService.persist_repeater_finding()`
and returns `finding_id`, `created`, `success`, `message`, and optional
`report_refresh`.

## Runtime Ownership Map

### Scan lifecycle

- `ScanService` is the API/MCP lifecycle owner and stores active `ScanContext`
  objects in memory.
- SQLite creates and updates scan rows through `DatabaseManager`.
- `ScanService` launches `TeamOrchestrator` in an asyncio background task.
- Direct CLI execution bypasses `ScanService` and constructs
  `TeamOrchestrator` directly.
- This means CLI and API have different lifecycle owners even though they share
  the same orchestrator.

### Database boundary

`bugtrace/schemas/db_models.py` defines these persistent tables:

- `TargetTable`: unique URL and creation timestamp.
- `ScanTable`: status, progress, origin, report directory, enrichment status,
  scan options, provider, resume metadata, and last error.
- `FindingTable`: scan relation, vulnerability type, severity, details, payload,
  validation status, confidence, screenshot, attack URL, parameter, and
  reproduction command.
- `ScanStateTable`: one JSON state blob per scan for resumption.

`DatabaseManager.get_instance()` points at `settings.BASE_DIR/data/bugtrace.db`
and a LanceDB path under the configured logs directory. The `data/` directory
is expected to be created by install/container entrypoints and is ignored by
Git.

### Source-of-truth split

The code documents two overlapping truths:

- `agents/reporting.py:485-520` says specialist result files are the primary
  source and the database is a process-tracking/resume fallback.
- `services/report_service.py:127-133` loads rich findings from
  `validated_findings.json`, then falls back to DB findings.
- `services/report_service.py:223-248` converts `FindingTable` rows to report
  dictionaries when the artifact path is unavailable.
- API scan status and findings endpoints read from `ScanService` and the DB.

Any migration must preserve the file-first report path and the DB fallback;
deleting either one changes recovery behavior.

## Report Artifact Contract

### Pipeline report directory

The normal pipeline uses one unified per-scan directory, usually shaped as
`reports/{domain}_{timestamp}` and recorded in `ScanTable.report_dir`.

Expected artifacts include:

- `raw_findings.json`.
- `validated_findings.json`.
- `final_report.md`.
- `engagement_data.json` and `engagement_data.js`.
- `report.html`.
- `specialists/wet/*.json` for raw queue observations.
- `specialists/dry/*.json` for deduplicated specialist work.
- `specialists/results/*_results.json` for specialist outputs.
- `captures/` and supporting logs.

### Reporting ingestion precedence

`ReportingAgent._load_specialist_results()` at `agents/reporting.py:541-586`
loads and deduplicates in this order:

1. `specialists/*_report.json`.
2. `specialists/results/*_results.json`.
3. `specialists/wet/*.json` only when the first two sources are empty.
4. Database findings only when no file findings were found.

Result files default missing statuses to `VALIDATED_CONFIRMED`; WET JSON Lines
default missing statuses to `PENDING_VALIDATION`. This distinction is a core
validation contract.

### ReportService output path

`ReportService` also generates API-friendly artifacts under
`settings.REPORT_DIR/scan_{scan_id}`:

- HTML: `report.html` plus `engagement_data.js`.
- JSON: `engagement_data.json`.
- Markdown: directory generated by `MarkdownGenerator`.

The route-level `_find_report_dir()` prefers the DB's `report_dir`, then a
domain/timestamp directory, then `scan_{scan_id}`. This supports both pipeline
and API-generated report layouts, but also creates a multi-root ownership
boundary that must be retained until clients are migrated.

## API Report Routes

`bugtrace/api/routes/reports.py` exposes:

- `GET /api/scans/{scan_id}/report/{format}` for HTML, JSON, or Markdown.
- `GET /api/scans/{scan_id}/files/{filename}` for individual artifacts.
- `GET /api/scans/{scan_id}/report-zip` for report exports.

Individual file access resolves the path and checks that it remains under the
resolved report directory (`reports.py:232-239`). This traversal guard is a
security contract, not a convenience implementation detail.

The ZIP export has a 500 MB cap and excludes transient locks and pending
markers. It must continue to export the complete scan directory, including
specialist results and screenshots.

## Re-enrichment and Incremental Updates

`ScanService` owns atomic updates to `raw_findings.json` and
`validated_findings.json` for Repeater and re-enrichment flows. It also locates
report directories through multiple artifact patterns.

`ReportingAgent` writes safety-checkpoint artifacts before LLM enrichment and
renders the final artifact set even when enrichment times out or is cancelled.
The durable status is `ScanTable.enrichment_status`, with values such as
`full`, `partial`, `none`, and `pending`.

The following must remain consistent across DB, JSON, Markdown, HTML, and API:

- Finding status and `validated` authority flag.
- Severity and confidence.
- CVSS/PoC enrichment status.
- Repeater `repro` and `http_request` evidence.
- Finding and scan counts shown in summaries.

## Risks to Resolve Before Refactoring

1. CLI direct execution and API/MCP execution have different scan lifecycle
   owners.
2. Reporting has file-first and DB-fallback paths with multiple report roots.
3. `specialists/*_report.json`, `specialists/results/*_results.json`, and WET
   JSON Lines use different status defaults and shapes.
4. Repeater writes to canonical artifacts after normal reporting, so later
   reporting must not erase those rows.
5. The API exposes distinct scan WebSocket paths in `api/main.py` and
   `api/routes/websocket.py`: `/ws/scans/{scan_id}` and
   `/api/ws/scans/{scan_id}`. Their envelope, replay, and client ownership must
   be decided before either path is removed.
6. No source change is authorized by this map. The first implementation step,
   if later approved, must be a contract test or adapter with no deletion.
