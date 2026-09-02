# SQLi Contract Map

Read-only contract map for the SQLi specialist wave. No production behavior was
changed while producing this document (P5-SQLi-0 freezes baseline contracts).

Date: 2026-07-31

## Layout (already modular)

Unlike XSS at baseline, SQLi is **already package-first**:

| Path | Role |
| --- | --- |
| `bugtrace/agents/sqli_agent.py` | Thin compatibility re-export (~97 LOC) |
| `bugtrace/agents/sqli/__init__.py` | Public facade |
| `bugtrace/agents/sqli/agent.py` | `SQLiAgent` orchestration (~1k LOC) |
| `bugtrace/agents/sqli/types.py` | `SQLiFinding` + constants (owner) |
| `bugtrace/agents/sqli/context.py` | Confidence / prioritization / emit gate |
| `bugtrace/agents/sqli/payloads.py` | URL / payload pure helpers |
| `bugtrace/agents/sqli/validation.py` | Error signatures + `finding_to_dict` |
| `bugtrace/agents/sqli/finding_builders.py` | Pure finding constructors / evidence (P5-SQLi-2) |
| `bugtrace/agents/sqli/dedup.py` | Fingerprint dedup pure |
| `bugtrace/agents/sqli/discovery.py` | I/O discovery |
| `bugtrace/agents/sqli/exploitation.py` | I/O techniques + sqlmap (thin constructors) |
| `bugtrace/agents/sqli/pipeline.py` | Escalation orchestration |
| `bugtrace/agents/sqli/reporting.py` | I/O report write |

## Import graph

- Canonical: `from bugtrace.agents.sqli import SQLiAgent`
- Compatibility: `from bugtrace.agents.sqli_agent import SQLiAgent`
- **Either import order works** (shim imports package; package does not import shim).
- `bugtrace.agents.sqli.SQLiAgent is bugtrace.agents.sqli_agent.SQLiAgent` → `True`
- `SQLiFinding` single owner: `bugtrace.agents.sqli.types` (re-exported by facade + shim)

## Type / serializer contracts

- Finding dataclass fields frozen in golden `sqli_finding_fields_package.json`.
- Serializer: `validation.finding_to_dict` keys frozen in
  `sqli_serializer_keys_package.json`.
- Emit gate: `context.validate_sqli_finding` requires proof keys (error / time /
  data / sqlmap / OOB / quote-parity) — reflection-only must not pass.

## Pure vs effect debt

Declared pure modules still have caveats:

- **P5-SQLi-1:** `parse_infrastructure_cookie_catalog` +
  `default_infrastructure_cookies_path` are pure; `load_infrastructure_cookies`
  is a thin injectable adapter (`data` / `text` / `path`). Module bootstrap
  still loads the packaged JSON once for production defaults.
  `should_test_cookie` accepts optional `cookies`/`prefixes` for hermetic tests.
- **P5-SQLi-3:** time-based, cookie sqlmap/probe, and header error/status constructors also live in `finding_builders`.
- **P5-SQLi-2:** error/boolean/union/sqlmap finding constructors +
  `has_new_db_error_evidence` + `demote_unproven_union` live in
  `finding_builders.py`. `exploitation` re-exports private aliases for
  pipeline compatibility; `_withhold_unproven_union` remains log shell.
- `exploitation.py` and `discovery.py` remain intentional I/O shells for HTTP
  / sqlmap / LLM.
- Live sqlmap / network paths must never enter offline gates.

## Consumers

- Team queue name: `sqli` in `SPECIALIST_QUEUES`.
- Events: same `vulnerability_detected` / validation pipeline as other specialists.
- Reporting: specialist results + shared report formats.

## No-code conclusions

1. Do not reintroduce a monolith SQLi class; package is already the owner.
2. Next pure work: remaining I/O slices in `exploitation` (time-based finding
   construction, header/cookie finding assembly) — not a wholesale re-architecture.
3. Freeze import/type/serializer/proof contracts before any behavior change.
4. Offline gates expand with unit contracts only; no live SQL targets.
