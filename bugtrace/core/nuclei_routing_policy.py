"""PURE Nuclei misconfig → vuln-type routing (orig team.py / dual peel).

No filesystem I/O in match helpers. Load JSON via ``load_nuclei_routing_config``.
Finding builders and partition are pure; shell only writes results / enqueues.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

from bugtrace.core.package_paths import bugtrace_data_file

_FALLBACK: Dict[str, Any] = {
    "type": "MISSING_SECURITY_HEADER",
    "default_severity": "info",
    "action": "classify",
}


def default_nuclei_routing_path() -> Path:
    """Canonical path to nuclei_type_routing.json under bugtrace/data."""
    return bugtrace_data_file("nuclei_type_routing.json")


def load_nuclei_routing_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load routing JSON; on failure return empty rules + MISSING_SECURITY_HEADER fallback."""
    p = path or default_nuclei_routing_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("routing root must be object")
        data.setdefault("rules", [])
        data.setdefault("fallback", dict(_FALLBACK))
        return data
    except Exception:
        return {"rules": [], "fallback": dict(_FALLBACK)}


def match_nuclei_routing_rule(
    routing_config: Dict[str, Any],
    tags_set: Set[str],
    template_id: str,
) -> Dict[str, Any]:
    """Return first matching rule or fallback (PURE).

    Match: any tag in match_tags OR substring in match_template_id_contains
    OR prefix in match_template_id_starts_with.
    """
    tid = (template_id or "").lower()
    tags = {t.lower() for t in tags_set if t}

    for rule in routing_config.get("rules", []) or []:
        match_tags = {t.lower() for t in (rule.get("match_tags") or []) if t}
        if match_tags & tags:
            return rule

        for pattern in rule.get("match_template_id_contains") or []:
            if pattern and pattern.lower() in tid:
                return rule

        for prefix in rule.get("match_template_id_starts_with") or []:
            if prefix and tid.startswith(prefix.lower()):
                return rule

    return routing_config.get("fallback") or dict(_FALLBACK)


def is_graphql_misconfig(tags: Any, template_id: str) -> bool:
    """Orig special-case: GraphQL introspection → specialist finding, not table rule."""
    tid = (template_id or "").lower()
    if "graphql" in tid:
        return True
    if isinstance(tags, (list, set, tuple, frozenset)):
        return any("graphql" in str(t).lower() for t in tags)
    if isinstance(tags, str):
        return "graphql" in tags.lower()
    return False


def _mc_name(mc: Mapping[str, Any]) -> str:
    return str(mc.get("name") or mc.get("template_id") or "unknown")


def build_graphql_finding(
    mc: Mapping[str, Any],
    *,
    target: str,
    scan_context: str,
) -> Dict[str, Any]:
    """Finding dict for GraphQL introspection (route to specialist path)."""
    tid = mc.get("template_id", _mc_name(mc))
    desc = mc.get("description", _mc_name(mc))
    return {
        "type": "GraphQL Introspection",
        "parameter": tid,
        "url": mc.get("matched_at", target),
        "severity": "High",
        "fp_confidence": 0.95,
        "confidence_score": 0.95,
        "votes": 5,
        "skeptical_score": 9,
        "probe_validated": True,
        "reasoning": desc,
        "description": desc,
        "evidence": f"Nuclei template: {mc.get('template_id', 'unknown')}",
        "_source_file": "nuclei_misconfiguration",
        "_scan_context": scan_context,
    }


def build_nuclei_route_finding(
    mc: Mapping[str, Any],
    *,
    finding_type: str,
    default_severity: str,
    target: str,
    scan_context: str,
) -> Dict[str, Any]:
    """``action=route`` — real vuln candidate for specialist queue."""
    desc = mc.get("description", _mc_name(mc))
    sev_raw = mc.get("severity", default_severity)
    sev = str(sev_raw).capitalize() if sev_raw else str(default_severity).capitalize()
    return {
        "type": finding_type,
        "parameter": mc.get("template_id", _mc_name(mc)),
        "url": mc.get("matched_at", target),
        "severity": sev,
        "fp_confidence": 0.95,
        "confidence_score": 0.95,
        "votes": 5,
        "skeptical_score": 9,
        "probe_validated": True,
        "reasoning": desc,
        "description": desc,
        "evidence": f"Nuclei template: {mc.get('template_id', 'unknown')}",
        "_source_file": "nuclei_misconfiguration",
        "_scan_context": scan_context,
    }


def build_nuclei_classify_finding(
    mc: Mapping[str, Any],
    *,
    finding_type: str,
    default_severity: str,
    target: str = "",
) -> Dict[str, Any]:
    """``action=classify`` — pre-validated misconfig written to results."""
    sev_raw = mc.get("severity", default_severity)
    sev = str(sev_raw).capitalize() if sev_raw else str(default_severity).capitalize()
    return {
        "type": finding_type,
        "parameter": mc.get("template_id", _mc_name(mc)),
        "url": mc.get("matched_at", target) or target,
        "severity": sev,
        "confidence": 0.95,
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "validation_method": "nuclei_template",
        "description": mc.get("description", _mc_name(mc)),
        "evidence": {"nuclei_template": mc.get("template_id", "unknown")},
        "_source_file": "nuclei_misconfiguration",
    }


def partition_nuclei_misconfigs(
    misconfigs: List[Mapping[str, Any]],
    routing_config: Dict[str, Any],
    *,
    target: str,
    scan_context: str,
) -> Dict[str, Any]:
    """Partition misconfigs into pure buckets (no I/O).

    Returns::
        {
          "route": [...],      # append to all_findings / specialist path
          "classify": [...],   # pre-validated results file
          "skipped": int,      # action=skip (e.g. BAC handled elsewhere)
        }
    """
    route: List[Dict[str, Any]] = []
    classify: List[Dict[str, Any]] = []
    skipped = 0

    for mc in misconfigs or []:
        tags = mc.get("tags", []) or []
        template_id = str(mc.get("template_id", "") or "")
        tags_set = set(tags) if not isinstance(tags, set) else tags

        if is_graphql_misconfig(tags, template_id):
            route.append(
                build_graphql_finding(mc, target=target, scan_context=scan_context)
            )
            continue

        rule = match_nuclei_routing_rule(routing_config, set(tags_set), template_id)
        action = rule.get("action", "classify")
        finding_type = rule.get("type", _FALLBACK["type"])
        default_sev = rule.get("default_severity", _FALLBACK["default_severity"])

        if action == "skip":
            skipped += 1
            continue
        if action == "route":
            route.append(
                build_nuclei_route_finding(
                    mc,
                    finding_type=finding_type,
                    default_severity=default_sev,
                    target=target,
                    scan_context=scan_context,
                )
            )
            continue
        # classify (default)
        classify.append(
            build_nuclei_classify_finding(
                mc,
                finding_type=finding_type,
                default_severity=default_sev,
                target=target,
            )
        )

    return {"route": route, "classify": classify, "skipped": skipped}

