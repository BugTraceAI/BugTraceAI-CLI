"""
XSS escalation coverage — NEGATIVE EVIDENCE.

The escalation pipeline returns the same ``None`` for "1300 requests fired, 246 payloads
reflected, nothing executable" and for "this parameter was never tested". Those are opposite
statements about the target and the scanner, and the difference is invisible in the report:
every defect in this subsystem so far had to be found by pulling an unrelated thread.

This module records, per parameter, WHAT WAS ACTUALLY DONE: the probes sent, whether the
marker came back, every reflection context observed, how many payloads reflected, the rung
the pipeline stopped at and WHY it stopped. Every exit of the pipeline — including the
caller's ``except`` path — must produce exactly one record.

DESIGN
------
Pure core, IO at one edge:

    start_coverage() -> with_probe()/with_level()/with_context() -> finish() -> to_record()

``ParamCoverage`` is frozen; every transition returns a NEW value, so a record can never be
half-mutated by an exception mid-pipeline. Only :func:`write_coverage_document` touches disk.

WHAT THIS IS NOT
----------------
It is not a finding, and it must never be mistaken for one. Four generic loaders
(state_manager, validator_engine, scan_service, summary) walk
``specialists/{results,dry,wet}/*.json`` and ingest ANY dict they find as a FINDING, and
``reporting.py`` globs ``specialists/*_report.json``. :func:`resolve_coverage_path` keeps the
artifact out of every one of those namespaces, and refuses to write at the reports ROOT (the
agent's ``report_dir`` defaults there before the team injects the real scan directory).

It is also AGGREGATED, never per payload: one object per parameter, not one per request.
The report ZIP ships every byte under the scan directory to the customer.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA = "xss.coverage/1"

# ── Exit reasons ────────────────────────────────────────────────────────────────────────
# One constant per RETURN of _xss_escalation_pipeline, plus the caller's exception path.
# A record whose exit_reason is "" means the pipeline left through a path nobody labelled —
# that is a bug in the instrumentation, and the offline harness asserts it never happens.
EXIT_NO_RESPONSE = "no_response_at_probe"        # target returned nothing to the char probe
EXIT_NO_REFLECTION = "no_reflection_at_probe"    # responded, marker absent -> not injectable here
EXIT_CONFIRMED = "confirmed"                     # a rung proved execution; see exit_level
EXIT_DEPTH_QUICK = "depth_gate_quick"            # scan depth 'quick' stops after L2
EXIT_DEPTH_NO_BROWSER = "depth_gate_no_browser"  # non-thorough depth, not a browser-only vector
EXIT_FLAGGED_CDP = "flagged_for_cdp"             # handed to the CDP AgenticValidator
EXIT_EXHAUSTED = "levels_exhausted"              # all rungs ran, nothing confirmed
EXIT_EXCEPTION = "exception"                     # raised out of the pipeline

# Exits that mean "the scanner never got far enough to have an opinion". Their
# reflecting-payload count is NOT zero, it is unknown: at these exits the reflecting list is
# empty BY CONSTRUCTION because the rungs that populate it never ran.
_NOT_REACHED_EXITS = frozenset({EXIT_NO_RESPONSE, EXIT_NO_REFLECTION})


# ── Pure core ───────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LevelOutcome:
    """One rung of the escalation ladder, as it actually ran.

    reflected=None means the rung does not measure reflection (L0.5/L1/L5/L6 either confirm
    or they do not); an int means the rung reported that many reflecting payloads.
    """
    level: str
    reflected: Optional[int] = None
    confirmed: bool = False
    note: str = ""


@dataclass(frozen=True)
class ParamCoverage:
    """Everything the pipeline learned about ONE parameter. Immutable."""
    url: str
    parameter: str
    http_method: str = "GET"
    initial_context: str = ""
    final_context: str = ""
    probes: Tuple[str, ...] = ()
    marker_reflected: Optional[bool] = None      # None = the probe rung never answered
    surviving_chars: Optional[str] = None
    contexts: Tuple[str, ...] = ()
    levels: Tuple[LevelOutcome, ...] = ()
    notes: Tuple[str, ...] = ()                  # rungs deliberately NOT run, and why
    exit_reason: str = ""
    exit_level: str = ""
    confirmed: bool = False
    started_at: float = 0.0
    ended_at: Optional[float] = None


def start_coverage(
    url: str,
    parameter: str,
    http_method: str = "GET",
    initial_context: str = "",
    now: Optional[float] = None,
) -> ParamCoverage:
    """Open a record. Called once per parameter, before the first rung."""
    return ParamCoverage(
        url=url,
        parameter=parameter,
        http_method=http_method or "GET",
        initial_context=initial_context or "",
        final_context=initial_context or "",
        started_at=_now(now),
    )


def with_probe(
    cov: ParamCoverage,
    probe: str,
    reflected: Optional[bool],
    surviving_chars: Optional[str] = None,
) -> ParamCoverage:
    """Record a probe string that was actually SENT, and whether its marker came back."""
    probes = cov.probes + (probe,) if probe and probe not in cov.probes else cov.probes
    return replace(
        cov,
        probes=probes,
        marker_reflected=reflected if reflected is not None else cov.marker_reflected,
        surviving_chars=(
            surviving_chars if surviving_chars is not None else cov.surviving_chars
        ),
    )


def with_contexts(cov: ParamCoverage, contexts: Optional[Iterable[str]]) -> ParamCoverage:
    """Union in every context label a rung observed. The SET, never the ranked label alone."""
    merged = set(cov.contexts) | {
        (c or "").strip().lower() for c in (contexts or ()) if (c or "").strip()
    }
    return replace(cov, contexts=tuple(sorted(merged)))


def with_final_context(cov: ParamCoverage, context: Optional[str]) -> ParamCoverage:
    """Track the single ranked label the pipeline is currently driving payload choice with."""
    if not context:
        return cov
    return replace(cov, final_context=context)


def with_level(
    cov: ParamCoverage,
    level: str,
    reflected: Optional[int] = None,
    confirmed: bool = False,
    note: str = "",
) -> ParamCoverage:
    """Append a rung outcome. Append-only: a rung that ran twice appears twice."""
    outcome = LevelOutcome(level=level, reflected=reflected, confirmed=confirmed, note=note)
    return replace(cov, levels=cov.levels + (outcome,), confirmed=cov.confirmed or confirmed)


def with_note(cov: ParamCoverage, note: str) -> ParamCoverage:
    """Record a rung that was deliberately NOT run, and why.

    A skipped rung is negative evidence too: "L3+L4 skipped, 0 reflecting payloads" is a
    different statement from "L3 ran and found nothing", and only one of them is a gap.
    """
    if not note or note in cov.notes:
        return cov
    return replace(cov, notes=cov.notes + (note,))


def finish(
    cov: ParamCoverage,
    exit_reason: str,
    now: Optional[float] = None,
    exit_level: str = "",
) -> ParamCoverage:
    """Close the record at a pipeline exit. exit_level defaults to the last rung that ran."""
    last = cov.levels[-1].level if cov.levels else ""
    return replace(
        cov,
        exit_reason=exit_reason,
        exit_level=exit_level or last,
        ended_at=_now(now),
    )


def reflecting_total(cov: ParamCoverage) -> Optional[int]:
    """Distinct-ish count of payloads that reflected, or None for 'never reached'.

    None is not the same as 0. Before the bombing rungs run, the reflecting list is empty by
    construction — reporting that as "0 of N reflected" would be a claim the scan never made.
    """
    reported = [lv.reflected for lv in cov.levels if lv.reflected is not None]
    if not reported:
        return None
    return sum(reported)


def _level_record(lv: LevelOutcome) -> Dict[str, Any]:
    """Serialise one rung. Keeps reflected=0; drops only what was never measured."""
    out: Dict[str, Any] = {"level": lv.level}
    if lv.reflected is not None:
        out["reflected"] = lv.reflected
    if lv.confirmed:
        out["confirmed"] = True
    if lv.note:
        out["note"] = lv.note
    return out


def to_record(cov: ParamCoverage) -> Dict[str, Any]:
    """Serialise ONE parameter. Pure; aggregated; no payload bodies."""
    total = reflecting_total(cov)
    not_reached = cov.exit_reason in _NOT_REACHED_EXITS
    return {
        "url": cov.url,
        "parameter": cov.parameter,
        "http_method": cov.http_method,
        "probes_sent": list(cov.probes),
        "marker_reflected": cov.marker_reflected,
        "surviving_chars": cov.surviving_chars,
        "initial_context": cov.initial_context,
        "final_context": cov.final_context,
        "contexts_observed": list(cov.contexts),
        "levels_run": [lv.level for lv in cov.levels],
        # NB: reflected=0 is a MEASUREMENT ("this rung fired and nothing came back") and
        # must survive serialisation; only reflected=None ("this rung does not measure
        # reflection") is omitted. A truthiness filter here would silently delete every zero.
        "levels": [
            _level_record(lv) for lv in cov.levels
        ],
        "skipped": list(cov.notes),
        "payloads_reflected": None if not_reached else total,
        "exit_reason": cov.exit_reason,
        "exit_level": cov.exit_level,
        "confirmed": cov.confirmed,
        "duration_s": (
            round(cov.ended_at - cov.started_at, 3)
            if cov.ended_at is not None and cov.started_at else None
        ),
    }


def summarise(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll the per-parameter records up into the numbers a human reads first."""
    by_reason: Dict[str, int] = {}
    by_exit_level: Dict[str, int] = {}
    for r in records:
        by_reason[r.get("exit_reason") or ""] = by_reason.get(r.get("exit_reason") or "", 0) + 1
        lvl = r.get("exit_level") or ""
        by_exit_level[lvl] = by_exit_level.get(lvl, 0) + 1
    return {
        "params_tested": len(records),
        "confirmed": sum(1 for r in records if r.get("confirmed")),
        "reflected_but_unconfirmed": sum(
            1 for r in records
            if not r.get("confirmed") and (r.get("payloads_reflected") or 0) > 0
        ),
        "no_reflection": sum(
            1 for r in records if r.get("exit_reason") == EXIT_NO_REFLECTION
        ),
        "no_response": sum(1 for r in records if r.get("exit_reason") == EXIT_NO_RESPONSE),
        "by_exit_reason": dict(sorted(by_reason.items())),
        "by_exit_level": dict(sorted(by_exit_level.items())),
    }


def build_document(
    coverages: Sequence[ParamCoverage],
    scan_url: str = "",
    max_params: Optional[int] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Assemble the whole artifact.

    ``max_params`` bounds the file size. A cap that silently drops coverage would recreate
    the very blindness this module exists to remove, so the truncation is stated IN the
    document (``truncated``/``params_total``) as well as logged by the caller.
    """
    records = [to_record(c) for c in coverages]
    total = len(records)
    truncated = bool(max_params) and total > int(max_params)
    kept = records[: int(max_params)] if truncated else records
    return {
        "schema": SCHEMA,
        "generated_at": _now(now),
        "scan_url": scan_url,
        "params_total": total,
        "params_recorded": len(kept),
        "truncated": truncated,
        "summary": summarise(kept),
        "parameters": kept,
    }


def resolve_coverage_path(
    report_dir: Optional[Path],
    reports_root: Optional[Path],
    subdir: str,
    filename: str,
) -> Optional[Path]:
    """Decide WHERE the artifact goes — or refuse.

    Returns None (do not write) when:
      * there is no report_dir at all;
      * report_dir IS the reports root — the agent's default before the team injects the real
        scan directory. A stray write there becomes a phantom "latest scan" for summary.py,
        which picks the lexicographically last directory;
      * the configured location would land inside specialists/{results,dry,wet}, which four
        generic loaders ingest as FINDINGS;
      * the filename would match specialists/*_report.json, which reporting.py ingests.
    """
    if not report_dir or not str(subdir) or not str(filename):
        return None
    base = Path(report_dir)
    try:
        base_res = base.resolve()
    except OSError:
        return None
    if reports_root is not None:
        root = Path(reports_root)
        try:
            if base_res == root.resolve():
                return None
        except OSError:
            pass
        # ...and the same refusal by NAME. The agent's default report_dir is the RELATIVE
        # Path("./reports"), which resolves against the process cwd and therefore does NOT
        # compare equal to the absolute reports root whenever the CLI is started from
        # somewhere else. A per-scan directory is always "<target>_<timestamp>"; only the
        # root is ever named after REPORT_DIR_PATH itself.
        if root.name and base_res.name == root.name:
            return None

    rel = Path(str(subdir).strip("/"))
    parts = [p.lower() for p in rel.parts]
    if parts[:1] == ["specialists"] and len(parts) > 1 and parts[1] in ("results", "dry", "wet"):
        return None
    if parts == ["specialists"] and str(filename).endswith("_report.json"):
        return None
    return base / rel / str(filename)


def _now(now: Optional[float] = None) -> float:
    return time.time() if now is None else now


# ── IO edge ─────────────────────────────────────────────────────────────────────────────

def write_coverage_document(path: Path, document: Dict[str, Any]) -> Optional[Path]:
    """Write the artifact. Returns the path written, or None on failure.

    Never raises: coverage is diagnostics, and losing it must not lose the scan.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        return path
    except Exception:
        return None
