# XSS Contract Map

Read-only contract map for the first refactor wave. No implementation file was
changed while producing this document.

Date: 2026-07-30

## Import Graph

### Runtime path

- `bugtrace/core/team.py:39` imports `XSSAgent` from `bugtrace.agents.xss`.
- `bugtrace/core/team.py:180` repeats the package import when creating worker
  agents.
- `bugtrace/__main__.py:861` imports the package for focused XSS CLI mode.
- `bugtrace/agents/xss/__init__.py:269` imports `XSSAgent` back from
  `bugtrace.agents.xss_agent`.
- `bugtrace/agents/xss_agent.py:105` imports the package's `coverage` module,
  which creates a circular package relationship.

The package is therefore a facade for the monolith's `XSSAgent` class, not an
independent implementation. The extracted package modules provide helpers,
types, constants, and serialization functions around that class.

### Observed import behavior

The following read-only checks were run from the refactor worktree:

- Package-first import succeeds: `import bugtrace.agents.xss` followed by
  `import bugtrace.agents.xss_agent`.
- Direct monolith-first import fails with an `ImportError` because
  `bugtrace.agents.xss` tries to import `XSSAgent` from a partially initialized
  `bugtrace.agents.xss_agent`.
- `bugtrace.agents.xss.XSSAgent is bugtrace.agents.xss_agent.XSSAgent` is
  `True`.
- `bugtrace.agents.xss.XSSFinding is bugtrace.agents.xss_agent.XSSFinding` is
  `False`.
- The package `XSSFinding` does not declare `http_method`; the monolith
  `XSSFinding` does.

The import order is a compatibility requirement until the class and type
ownership are made canonical.

## Type Contract

### Monolith finding

`bugtrace/agents/xss_agent.py:185-215` defines the class used by the live
`XSSAgent` implementation. Required and enriched fields include:

- `url`, `parameter`, `payload`, `context`.
- `validation_method`, `evidence`, `confidence`.
- `type`, `status`, `validated`.
- `screenshot_path`, `reflection_context`, `surviving_chars`.
- `successful_payloads`, `http_method`.
- `xss_type`, `injection_context_type`, `vulnerable_code_snippet`.
- `server_escaping`, bypass metadata, exploit URLs, verification methods,
  warnings, and reproduction steps.

### Extracted package finding

`bugtrace/agents/xss/types.py:28-99` defines another `XSSFinding` with almost
the same fields and `to_dict()` serialization, but without `http_method`.
`bugtrace/agents/xss/finding_builder.py:121-128` accesses
`finding.http_method`, so the package type cannot safely replace the monolith
type without a compatibility decision and focused tests.

### Finding construction and serialization

- Live construction is in `xss_agent.py:8881-8917`.
- Browser and CDP paths construct the monolith dataclass directly at
  `xss_agent.py:7514-7519` and `:7539-7543`.
- Monolith serialization is `_finding_to_dict` at `xss_agent.py:11391-11471`.
- Extracted pure serialization is `xss/finding_builder.py:93-193`.
- Both serializers emit XSS, status, validation, evidence, reproduction, and
  enriched metadata fields, but they are not proven byte-for-byte equivalent.

## Execution Contracts

### Direct execution

- `XSSAgent.run_loop()` is the main direct entrypoint at
  `xss_agent.py:8427-8484`.
- It performs WAF/Interactsh setup, parameter discovery, escalation, DOM and
  additional vectors, cleanup, and returns a dictionary with `findings`,
  `validated_count`, and `params_tested`.
- `bugtrace/agents/xss_agent.py:11478-11481` defines `run_xss_scan`, but calls
  `agent.run()`. The class and `BaseAgent` expose `run_loop()`/`start()` rather
  than a visible `run()` method. This is an unverified baseline contract risk;
  it must not be silently changed during extraction.

### Queue execution

- `start_queue_consumer()` begins at `xss_agent.py:7587`.
- It reads the `xss` queue, performs WET-to-DRY deduplication, writes the dry
  queue file, exploits the dry list, serializes results, and writes
  `specialists/results/xss_results.json` at `xss_agent.py:7545-7575`.
- Queue results can be monolith `XSSFinding` dataclasses or dictionaries from
  stored-XSS paths. The queue path normalizes both with `asdict()` or direct
  dictionary handling at `xss_agent.py:7630-7633`.
- `stop_queue_consumer()` releases document caches in a `finally` block at
  `xss_agent.py:7678-7698`.

### Validation and emission

- XSS validation overrides `BaseAgent._validate_before_emit` at
  `xss_agent.py:3025-3065`.
- `_emit_xss_finding()` wraps a finding in a full event structure, calls
  `BaseAgent.emit_finding()`, and may emit a second full event when
  `WORKER_POOL_EMIT_EVENTS` is enabled (`xss_agent.py:3067-3092`).
- `BaseAgent.emit_finding()` emits a bare finding dictionary through
  `EventType.VULNERABILITY_DETECTED` (`bugtrace/agents/base.py:270-303`).
- Consumers must therefore be checked for both bare and wrapped event payload
  shapes before any event consolidation.

## Artifact Contracts

- Specialist queue results are written to `specialists/results/xss_results.json`.
- Generic reporting consumes specialist result/dry/wet namespaces; the XSS
  coverage artifact deliberately avoids those namespaces.
- `xss/coverage.py:44` declares schema `xss.coverage/1`.
- Coverage is aggregated per parameter, not per payload, and records probes,
  contexts, levels, skipped levels, exit reason, and confirmation status.
- `XSSAgent._write_xss_coverage()` validates the destination and writes the
  coverage document at `xss_agent.py:6558-6604`.
- Final report artifacts include `raw_findings.json`,
  `validated_findings.json`, and generated report formats owned by the live
  reporting agent. XSS result payloads may be base64-encoded before writing.
- The WEB AI Repeater relies on the top-level `repro` and `http_request` fields
  assembled by the monolith serializer and `_promote_repro()`.

## Consumers and Tests

### Production consumers

- `TeamOrchestrator` uses package import and queue mode.
- Direct focused CLI uses package import and direct `run_loop()`.
- Agentic validation consumes `vulnerability_detected` events.
- Reporting consumes specialist result files, not only event payloads.
- API report routes serve files discovered from the database scan directory.

### Test consumers

- Multiple XSS smoke tests intentionally import the package before the
  monolith to avoid the circular import.
- Queue integration tests import `XSSAgent` and `XSSFinding` from the monolith.
- Context, CSP, dojo, coverage, cache-release, and parity harnesses inspect
  monolith methods and class constants directly.
- `smoke_xss_context.py` passed 110/110 and `smoke_xss_coverage.py` passed
  73/73 on the clean baseline.

## No-Code Conclusions

1. Do not extract or delete `xss_agent.py` yet; it owns the live class, finding
   type, queue lifecycle, event emission, and several serializers.
2. Do not replace `xss.types.XSSFinding` with the monolith type or vice versa
   until field parity and serializer parity are measured.
3. Preserve package-first import order until the circular dependency is removed
   behind an explicit compatibility test.
4. Treat event payload shape, result-file shape, coverage schema, and `repro`
   enrichment as separate contracts.
5. The first implementation wave, when authorized, should establish one type
   owner and adapters while keeping both direct and queue paths green. This
   document does not authorize that implementation work.
