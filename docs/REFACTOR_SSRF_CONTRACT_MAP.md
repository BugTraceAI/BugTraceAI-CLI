# SSRF Contract Map

Read-only + P4-SSRF-0 pure ownership notes for the SSRF specialist wave.

Date: 2026-07-31

## Live owner (authoritative)

| Path | Role |
| --- | --- |
| `bugtrace/agents/ssrf_agent.py` | **Live** `SSRFAgent` — team / CLI / smoke import this |
| `bugtrace/agents/ssrf/detection.py` | **Pure** confirm / status / fingerprint helpers |
| `bugtrace/agents/ssrf/agent.py` | Package shell (subset methods); **not** wired as live owner yet |
| `bugtrace/agents/ssrf/__init__.py` | Re-exports package `agent.SSRFAgent` (≠ live dual) |

### Import graph (live)

- `team/lifecycle_flow.py`, `team/surface_flow.py`, `__main__.py` →
  `from bugtrace.agents.ssrf_agent import SSRFAgent`
- `tests/smoke_confirm.py` → `is_time_based_confirmed` from `ssrf_agent`

### Dual status

**P4-SSRF-2:** dual collapsed. Live and package import paths resolve to the
same class: `bugtrace.agents.ssrf.agent.SSRFAgent`. ``ssrf_agent`` is a thin
re-export. Pure helpers remain in ``ssrf.detection``.

## Pure contracts (P4-SSRF-0)

Owner module: `bugtrace.agents.ssrf.detection`

| Symbol | Contract |
| --- | --- |
| `is_time_based_confirmed(baseline, payload, delay=3, margin=0.6)` | `(payload - baseline) >= delay * margin` |
| `determine_validation_status(res, baseline_elapsed=None)` | Content indicators OR differential time; **no** absolute `elapsed > 3` proof |
| `get_validation_status(evidence)` | Tiers via `ValidationStatus` (OOB/internal/metadata/file → CONFIRMED) |
| `generate_ssrf_fingerprint` | `(SSRF, host, path, param)` — callback domain ignored |
| `fallback_fingerprint_dedup` | Fingerprint-based DRY list |

Live shell methods are thin adapters:

- `_determine_validation_status` → pure `determine_validation_status`
- `_get_validation_status` → pure `get_validation_status`
- `_generate_ssrf_fingerprint` / `_fallback_fingerprint_dedup` → pure owners
- Module-level `is_time_based_confirmed` re-export for smoke_confirm

## Red lines (pentest)

- Reflection-only / absolute latency alone must not confirm SSRF.
- OOB Interactsh callback remains TIER 1 confirmation.
- Dual collapse must not drop `_measure_baseline` differential path.

## Next units

1. **P4-SSRF-1** — bring package agent to live parity (method set + baseline path)
2. **P4-SSRF-2** — thin `ssrf_agent` re-export of package (dual collapse)
3. Optional pure slices (payload builders) after collapse
