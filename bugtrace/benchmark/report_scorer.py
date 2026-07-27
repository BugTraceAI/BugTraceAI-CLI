"""
Benchmark Report Scorer — measures detection recall against a ground-truth manifest.

Scores an EXISTING scan report (no re-scan) by matching its findings to the planted
vulnerabilities in `ground_truth/<target>.json`. Reports per-V-ID hit/miss, recall over
the full set and over the black-box-detectable subset, and per-tier/per-type breakdowns.

This is the cheap, reproducible half of the benchmark: run it on any report dir to turn
"~90% recall" into a concrete, auditable number, and use it as a regression gate after
scanner changes. The expensive half (N live runs for variance) wraps this scorer.

Usage:
    python -m bugtrace.benchmark.report_scorer <report_dir> [--target bugstore] [--json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _norm(s: Any) -> str:
    return str(s or "").lower()


def _finding_fields(f: Dict[str, Any]) -> Dict[str, str]:
    """Pull the searchable fields out of a finding dict (tolerant of schema variation)."""
    # `_source_types` carries the producing specialist's vuln type(s) so a finding whose
    # own `type` is mislabeled (e.g. a JWT-forge exploit reported as "Authenticated RCE")
    # still matches its real V-ID.
    ftype = _norm(" ".join([
        str(f.get("type") or f.get("title") or f.get("vulnerability_type") or f.get("vuln_type") or ""),
        " ".join(f.get("_source_types") or []),
    ]))
    subtype = _norm(f.get("subtype") or f.get("xss_type") or f.get("validation_method"))
    url = _norm(f.get("url") or f.get("attack_url") or f.get("endpoint"))
    param = _norm(f.get("parameter") or f.get("vuln_parameter") or f.get("param"))
    payload = _norm(f.get("payload") or f.get("payload_used"))
    return {"type": ftype, "subtype": subtype, "url": url, "param": param, "payload": payload}


def _matches(vuln: Dict[str, Any], ff: Dict[str, str]) -> bool:
    """True if a finding plausibly corresponds to this ground-truth vuln."""
    type_blob = f"{ff['type']} {ff['subtype']}"
    if not any(m in type_blob for m in vuln.get("match", [])):
        return False
    # Stored-vs-reflected XSS disambiguation
    stored_ctx = f"{ff['subtype']} {ff['url']}"
    if vuln.get("subtype") and not any(s in stored_ctx for s in vuln["subtype"]):
        return False
    if vuln.get("subtype_not") and any(s in stored_ctx for s in vuln["subtype_not"]):
        return False
    # Location/parameter disambiguation: when hints exist, require at least one to hit,
    # so a generic SQLi finding doesn't mark every SQLi V-ID as found.
    loc = vuln.get("loc") or []
    par = vuln.get("param") or []
    if loc or par:
        loc_blob = f"{ff['url']} {ff['param']} {ff['payload']}"
        if not (any(l in loc_blob for l in loc) or any(p in ff["param"] for p in par)):
            return False
    return True


def load_report_findings(report_dir: Path) -> List[Dict[str, Any]]:
    """Collect the UNION of findings the scan produced (validated + manual_review + raw +
    specialist results). Recall counts a vuln as found if it appears anywhere."""
    findings: List[Dict[str, Any]] = []

    def _add_from(obj: Any) -> None:
        if isinstance(obj, dict):
            for key in ("findings", "manual_review"):
                if isinstance(obj.get(key), list):
                    findings.extend(x for x in obj[key] if isinstance(x, dict))
            if "finding" in obj and isinstance(obj["finding"], dict):
                findings.append(obj["finding"])
            if not any(k in obj for k in ("findings", "manual_review", "finding")) and \
               any(k in obj for k in ("type", "vulnerability_type", "vuln_type")):
                findings.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                _add_from(item)

    for name in ("validated_findings.json", "raw_findings.json"):
        p = report_dir / name
        if p.is_file():
            try:
                _add_from(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                pass

    results_dir = report_dir / "specialists" / "results"
    if results_dir.is_dir():
        for jf in results_dir.glob("*.json"):
            try:
                txt = jf.read_text(encoding="utf-8").strip()
                if not txt:
                    continue
                try:
                    data: Any = json.loads(txt)
                except json.JSONDecodeError:
                    data = []
                    for line in txt.splitlines():  # JSON-lines fallback
                        line = line.strip()
                        if line:
                            try:
                                data.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                # The producing specialist's declared vuln type(s) — used to rescue
                # findings whose own `type` is mislabeled (forge-exploit reported as RCE).
                src: List[str] = []
                if isinstance(data, dict):
                    for k in ("vulnerability_type", "agent"):
                        if data.get(k):
                            src.append(str(data[k]))
                    summ = data.get("summary")
                    if isinstance(summ, dict):
                        src += [str(x) for x in (summ.get("vuln_types_found") or [])]
                before = len(findings)
                _add_from(data)
                for f in findings[before:]:
                    if isinstance(f, dict) and src:
                        f.setdefault("_source_types", src)
            except Exception:
                pass

    return findings


def score(findings: List[Dict[str, Any]], ground_truth: Dict[str, Any]) -> Dict[str, Any]:
    vulns = ground_truth.get("vulns", [])
    ff_list = [_finding_fields(f) for f in findings]

    per_vuln: List[Dict[str, Any]] = []
    for v in vulns:
        hit = any(_matches(v, ff) for ff in ff_list)
        per_vuln.append({"id": v["id"], "name": v["name"], "tier": v.get("tier"),
                         "detectable": v.get("detectable", True),
                         "implemented": v.get("implemented", True), "found": hit})

    # Recall is computed only over IMPLEMENTED vulns — a "miss" on a phantom (vuln listed
    # in the reference but not deployed) is not a recall failure; a "hit" on one is a FP.
    real = [v for v in per_vuln if v["implemented"]]
    found = sum(1 for v in real if v["found"])
    det = [v for v in real if v["detectable"]]
    det_found = sum(1 for v in det if v["found"])
    false_positives = [v["id"] for v in per_vuln if not v["implemented"] and v["found"]]

    by_tier: Dict[int, Dict[str, int]] = {}
    for v in real:
        t = v["tier"]
        by_tier.setdefault(t, {"found": 0, "total": 0})
        by_tier[t]["total"] += 1
        by_tier[t]["found"] += 1 if v["found"] else 0

    return {
        "target": ground_truth.get("target"),
        "findings_loaded": len(findings),
        "total_vulns": len(real),
        "found": found,
        "recall": round(found / len(real), 4) if real else 0.0,
        "detectable_total": len(det),
        "detectable_found": det_found,
        "recall_detectable": round(det_found / len(det), 4) if det else 0.0,
        "by_tier": {str(k): by_tier[k] for k in sorted(by_tier)},
        "per_vuln": per_vuln,
        "not_implemented": [v["id"] for v in per_vuln if not v["implemented"]],
        "false_positives": false_positives,
        "missed": [v["id"] for v in real if not v["found"]],
        "missed_detectable": [v["id"] for v in real if not v["found"] and v["detectable"]],
    }


def _load_ground_truth(target: str) -> Dict[str, Any]:
    gt_path = Path(__file__).parent / "ground_truth" / f"{target}.json"
    return json.loads(gt_path.read_text(encoding="utf-8"))


def _print_report(result: Dict[str, Any]) -> None:
    print(f"\n=== Benchmark: {result['target']} ===")
    print(f"findings loaded: {result['findings_loaded']}")
    print(f"RECALL (all):        {result['found']}/{result['total_vulns']}  = {result['recall'] * 100:.1f}%")
    print(f"RECALL (detectable): {result['detectable_found']}/{result['detectable_total']}  = {result['recall_detectable'] * 100:.1f}%")
    print("by tier:", ", ".join(f"T{k}={v['found']}/{v['total']}" for k, v in result["by_tier"].items()))
    print("\nper-vuln:")
    for v in result["per_vuln"]:
        if not v["implemented"]:
            mark, tag = ("⚠️ FP" if v["found"] else "🚫"), " (NOT implemented in target)"
        elif v["found"]:
            mark, tag = "✅", ""
        elif v["detectable"]:
            mark, tag = "❌", ""
        else:
            mark, tag = "➖", " (not black-box detectable)"
        print(f"  {mark} {v['id']} T{v['tier']}  {v['name']}{tag}")
    if result["missed_detectable"]:
        print(f"\nMISSED (detectable): {', '.join(result['missed_detectable'])}")
    if result["false_positives"]:
        print(f"FALSE POSITIVES (claimed but not implemented): {', '.join(result['false_positives'])}")
    if result["not_implemented"]:
        print(f"excluded (not implemented): {', '.join(result['not_implemented'])}")


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Score a scan report against a ground-truth manifest.")
    ap.add_argument("report_dir", help="Path to a report directory (contains validated_findings.json / specialists/)")
    ap.add_argument("--target", default="bugstore", help="Ground-truth manifest name (default: bugstore)")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of the human report")
    args = ap.parse_args(argv)

    report_dir = Path(args.report_dir)
    if not report_dir.is_dir():
        print(f"error: not a directory: {report_dir}", file=sys.stderr)
        return 2

    ground_truth = _load_ground_truth(args.target)
    findings = load_report_findings(report_dir)
    result = score(findings, ground_truth)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
