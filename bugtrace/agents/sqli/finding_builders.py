"""Pure SQLi finding constructors and evidence helpers.

Extracted from ``exploitation.py`` (P5-SQLi-2) so offline tests can freeze
construction/demotion contracts without HTTP, sqlmap, or LLM I/O.

All functions here are pure relative to network/FS: they only transform
arguments into ``SQLiFinding`` / bool values (or mutate a handed-in finding).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from bugtrace.agents.sqli.context import (
    determine_validation_status,
    sqlmap_type_to_technique,
)
from bugtrace.agents.sqli.payloads import build_exploit_url, generate_repro_steps
from bugtrace.agents.sqli.types import SQLiFinding
from bugtrace.agents.sqli.validation import parse_sqlmap_output

# Evidence string frozen for demoted UNION candidates (report copy contract).
UNPROVEN_UNION_REASON = (
    "A reflection-strip heuristic flagged this candidate, but the database never assembled "
    "the split canary, so query execution is unproven. Reported for manual review rather "
    "than as a confirmed injection."
)


def has_new_db_error_evidence(baseline: Dict, injected: Dict) -> bool:
    """PURE: true only when injection introduces a DB signal absent from baseline."""
    baseline_db = baseline.get("db_type")
    baseline_tables = baseline.get("tables_leaked", [])
    return (
        bool(injected.get("db_type") or injected.get("tables_leaked"))
        and (
            injected.get("db_type") != baseline_db
            or injected.get("tables_leaked", []) != baseline_tables
        )
    )


def create_error_based_finding(
    url: str, param: str, variant: str, error_info: Dict
) -> SQLiFinding:
    """PURE: build finding for error-based SQL injection."""
    exploit_url, exploit_url_encoded = build_exploit_url(url, param, variant)
    curl_cmd = f"curl '{exploit_url_encoded}'"

    return SQLiFinding(
        url=url,
        parameter=param,
        injection_type="error-based",
        technique="error_based",
        working_payload=variant,
        payload_encoded=variant,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        extracted_tables=error_info.get("tables_leaked", []),
        dbms_detected=error_info.get("db_type", "unknown"),
        severity="HIGH",  # DB fingerprint confirmed - upgrade from default MEDIUM
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --technique=E --batch",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=f"sqlmap -u '{url}' -p {param} --batch --dbs --technique=E",
        validated=True,
        status=determine_validation_status("error_based", {
            "sql_error_visible": True,
            "tables_leaked": error_info.get("tables_leaked", [])
        }),
        evidence={
            "sql_error_visible": True,
            **error_info
        },
        reproduction_steps=generate_repro_steps(url, param, variant, curl_cmd)
    )


def create_boolean_finding(
    url: str,
    param: str,
    payload: str,
    diff_ratio: float,
    true_sim: float,
    false_sim: float,
    detected_db_type: Optional[str] = None,
) -> SQLiFinding:
    """PURE: build finding for boolean-based SQL injection."""
    exploit_url, exploit_url_encoded = build_exploit_url(url, param, payload)
    curl_cmd = f"curl '{exploit_url_encoded}'"

    return SQLiFinding(
        url=url,
        parameter=param,
        injection_type="boolean-based",
        technique="boolean_based",
        working_payload=payload,
        payload_encoded=payload,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        dbms_detected=detected_db_type or "unknown",
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --technique=B --batch",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=f"sqlmap -u '{url}' -p {param} --batch --technique=B",
        validated=True,
        status=determine_validation_status("boolean_based", {"diff_ratio": diff_ratio}),
        evidence={
            "diff_ratio": diff_ratio,
            "true_similarity": true_sim,
            "false_similarity": false_sim,
        },
        reproduction_steps=generate_repro_steps(url, param, payload, curl_cmd)
    )


def create_union_finding(
    url: str, param: str, payload: str, cols: int, pos: int
) -> SQLiFinding:
    """PURE: build finding for UNION-based SQL injection."""
    exploit_url, exploit_url_encoded = build_exploit_url(url, param, payload)
    curl_cmd = f"curl '{exploit_url_encoded}'"

    return SQLiFinding(
        url=url,
        parameter=param,
        injection_type="union-based",
        technique="union_based",
        working_payload=payload,
        payload_encoded=payload,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        columns_detected=cols,
        severity="CRITICAL",  # Union-based with data extraction = CRITICAL
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --technique=U --batch",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=f"sqlmap -u '{url}' -p {param} --batch --technique=U",
        validated=True,
        status="VALIDATED_CONFIRMED",
        evidence={
            "data_extracted": True,
            "columns_found": cols,
            "canary_position": pos
        },
        reproduction_steps=generate_repro_steps(url, param, payload, curl_cmd)
    )


def demote_unproven_union(finding: SQLiFinding) -> SQLiFinding:
    """PURE mutator: demote UNION candidate the DB never proved.

    Mutates the handed-in finding in place and returns it. Logging stays in the
    I/O shell (``exploitation._withhold_unproven_union``).
    """
    finding.severity = "MEDIUM"
    finding.status = "PENDING_VALIDATION"
    finding.validated = False
    if finding.evidence is None:
        finding.evidence = {}
    finding.evidence["data_extracted"] = False
    finding.evidence["computed_canary_confirmed"] = False
    finding.evidence["unproven_reason"] = UNPROVEN_UNION_REASON
    return finding


def create_sqlmap_finding(
    url: str, sqlmap_result: Dict, param: str
) -> SQLiFinding:
    """PURE: build finding from a parsed SQLMap result dict (no subprocess)."""
    technique = sqlmap_type_to_technique(sqlmap_result.get("type", ""))
    details = parse_sqlmap_output(sqlmap_result.get("output_snippet", ""))

    dbms = (
        details.get("dbms")
        if details.get("dbms") != "unknown"
        else sqlmap_result.get("dbms", "unknown")
    )
    working_payload = details.get("working_payload") or sqlmap_result.get("payload", "")

    exploit_url, exploit_url_encoded = build_exploit_url(url, param, working_payload)
    curl_cmd = f"curl '{exploit_url_encoded}'"

    tech_letter = technique[0].upper() if technique else "E"

    return SQLiFinding(
        url=url,
        parameter=sqlmap_result.get("parameter", param),
        injection_type=sqlmap_result.get("type", technique),
        technique=technique,
        working_payload=working_payload,
        payload_encoded=working_payload,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        dbms_detected=dbms,
        columns_detected=details.get("columns_count"),
        extracted_databases=details.get("databases", []),
        extracted_tables=details.get("tables", []),
        severity="CRITICAL",  # SQLMap confirmed exploitation = CRITICAL
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --batch --technique={tech_letter}",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=sqlmap_result.get("reproduction_command", ""),
        validated=True,
        status="VALIDATED_CONFIRMED",
        evidence={
            "sqlmap_confirmed": True,
            "db_type": dbms,
            "raw_output": sqlmap_result.get("output_snippet", "")[:1000]
        },
        reproduction_steps=generate_repro_steps(url, param, working_payload, curl_cmd)
    )


def create_time_based_finding(
    url: str,
    param: str,
    payload: str,
    evidence: Dict,
    detected_db_type: Optional[str] = None,
) -> SQLiFinding:
    """PURE: build finding for time-based SQLi after triple verification."""
    exploit_url, exploit_url_encoded = build_exploit_url(url, param, payload)
    curl_cmd = f"curl '{exploit_url_encoded}'"

    return SQLiFinding(
        url=url,
        parameter=param,
        injection_type="time-based",
        technique="time_based",
        working_payload=payload,
        payload_encoded=payload,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        dbms_detected=detected_db_type or "unknown",
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --technique=T --time-sec=5 --batch",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=f"sqlmap -u '{url}' -p {param} --batch --technique=T",
        validated=True,
        status=determine_validation_status("time_based", evidence),
        evidence=evidence,
        reproduction_steps=generate_repro_steps(url, param, payload, curl_cmd),
    )


def create_cookie_sqlmap_finding(
    url: str,
    cookie_name: str,
    finding: Dict,
    sqlmap_result: Dict,
    dbms_detected: str,
) -> SQLiFinding:
    """PURE: cookie SQLi confirmed via sqlmap result dict."""
    return SQLiFinding(
        url=url,
        parameter=f"Cookie: {cookie_name}",
        injection_type=sqlmap_result.get("type", "error_based"),
        technique="cookie_injection",
        working_payload=finding.get("payload", "'"),
        severity="CRITICAL",  # SQLMap confirmed = CRITICAL
        status="VALIDATED_CONFIRMED",
        evidence={
            "sqlmap_confirmed": True,
            "output": sqlmap_result.get("output_snippet", "")[:500],
        },
        dbms_detected=dbms_detected,
        validated=True,
        reproduction_steps=[sqlmap_result.get("reproduction_command", "")],
    )


def create_cookie_probe_finding(
    url: str,
    cookie_name: str,
    finding: Dict,
) -> SQLiFinding:
    """PURE: high-confidence probe cookie candidate (unvalidated)."""
    fd = finding.get("finding_data", {}) or {}
    return SQLiFinding(
        url=url,
        parameter=f"Cookie: {cookie_name}",
        injection_type="error_based",
        technique="cookie_injection",
        working_payload=fd.get("reproduction", finding.get("payload", "'")),
        evidence={
            "probe_detection": fd.get(
                "evidence",
                finding.get("evidence", "Status code differential detected"),
            )
        },
        dbms_detected="Unknown",
        validated=False,
        reproduction_steps=[fd.get("reproduction", "")],
    )


def create_header_error_finding(
    url: str,
    header_name: str,
    payload: str,
    error_info: Dict,
    baseline_error_info: Dict,
) -> SQLiFinding:
    """PURE: header SQLi confirmed by new DB error signal."""
    return SQLiFinding(
        url=url,
        parameter=f"Header: {header_name}",
        injection_type="error_based",
        technique="header_injection",
        working_payload=payload,
        severity="HIGH",  # DB fingerprint in header = HIGH
        status="VALIDATED_CONFIRMED",
        evidence={
            "header": header_name,
            "sql_error_visible": True,
            "baseline_db_type": baseline_error_info.get("db_type"),
            "baseline_tables": baseline_error_info.get("tables_leaked", []),
            **error_info,
        },
        dbms_detected=error_info["db_type"],
        sqlmap_command=(
            f"sqlmap -u '{url}' --level=3 "
            f"--headers='{header_name}: *' --batch"
        ),
        reproduction_steps=[f"curl -H '{header_name}: {payload}' '{url}'"],
    )


def create_header_status_finding(
    url: str,
    header_name: str,
    payload: str,
    baseline_status: int,
    injected_status: int,
) -> SQLiFinding:
    """PURE: header SQLi candidate from 5xx vs healthy baseline status."""
    return SQLiFinding(
        url=url,
        parameter=f"Header: {header_name}",
        injection_type="error_based",
        technique="header_injection",
        working_payload=payload,
        evidence={
            "header": header_name,
            "baseline_status": baseline_status,
            "injected_status": injected_status,
        },
        dbms_detected="Unknown",
        sqlmap_command=(
            f"sqlmap -u '{url}' --level=3 "
            f"--headers='{header_name}: *' --batch"
        ),
        reproduction_steps=[f"curl -H '{header_name}: {payload}' '{url}'"],
    )


def create_oob_finding(
    url: str,
    param: str,
    payload: str,
    db_type: str,
    interaction: Dict,
) -> SQLiFinding:
    """PURE: OOB SQLi after Interactsh callback evidence is already in hand.

    Severity CRITICAL is intentional: DNS/HTTP OOB callback proves exfiltration
    path, not mere reflection.
    """
    exploit_url, exploit_url_encoded = build_exploit_url(url, param, payload)
    curl_cmd = f"curl '{exploit_url_encoded}'"
    return SQLiFinding(
        url=url,
        parameter=param,
        injection_type="out-of-band",
        technique="oob",
        working_payload=payload,
        payload_encoded=payload,
        exploit_url=exploit_url,
        exploit_url_encoded=exploit_url_encoded,
        dbms_detected=db_type,
        severity="CRITICAL",
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --technique=U --batch",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=(
            f"sqlmap -u '{url}' -p {param} --batch --dbs --technique=U"
        ),
        validated=True,
        status="VALIDATED_CONFIRMED",
        evidence={
            "oob_callback_received": True,
            "interaction_data": interaction,
            "db_type": db_type,
        },
        reproduction_steps=generate_repro_steps(url, param, payload, curl_cmd),
    )


def create_json_body_error_finding(
    url: str,
    key: str,
    payload: str,
    error_info: Dict,
    *,
    original_json_body: Dict,
    test_json_body: Dict,
) -> SQLiFinding:
    """PURE: JSON body error-based SQLi after extract_info_from_error signals."""
    import json as _json

    curl_cmd = (
        f"curl -X POST '{url}' -H 'Content-Type: application/json' "
        f"-d '{_json.dumps(test_json_body)}'"
    )
    return SQLiFinding(
        url=url,
        parameter=f"JSON:{key}",
        injection_type="error-based (JSON)",
        technique="error_based",
        working_payload=payload,
        payload_encoded=payload,
        exploit_url=url,
        exploit_url_encoded=url,
        dbms_detected=error_info.get("db_type", "unknown"),
        extracted_tables=error_info.get("tables_leaked", []),
        severity="HIGH",
        sqlmap_command=(
            f"sqlmap -u '{url}' --data='{_json.dumps(original_json_body)}' "
            f"-p '{key}' --technique=E"
        ),
        curl_command=curl_cmd,
        sqlmap_reproduce_command=(
            f"sqlmap -u '{url}' --data='{_json.dumps(test_json_body)}' --technique=E"
        ),
        validated=True,
        status="VALIDATED_CONFIRMED",
        evidence={
            "sql_error_visible": True,
            "method": "POST",
            "content_type": "application/json",
            **error_info,
        },
        reproduction_steps=generate_repro_steps(url, f"JSON:{key}", payload, curl_cmd),
    )


def create_l5_manipulator_finding(
    url: str,
    param: str,
    working_payload: str,
    db_type: str,
) -> SQLiFinding:
    """PURE: L5 ManipulatorOrchestrator confirmation assembly."""
    exploit_url_val, exploit_url_encoded = build_exploit_url(
        url, param, working_payload
    )
    curl_cmd = f"curl '{exploit_url_encoded}'"
    return SQLiFinding(
        url=url,
        parameter=param,
        injection_type="manipulator-confirmed",
        technique="error_based",
        working_payload=working_payload,
        payload_encoded=working_payload,
        exploit_url=exploit_url_val,
        exploit_url_encoded=exploit_url_encoded,
        dbms_detected=db_type,
        severity="CRITICAL",
        sqlmap_command=f"sqlmap -u '{url}' -p {param} --batch",
        curl_command=curl_cmd,
        sqlmap_reproduce_command=f"sqlmap -u '{url}' -p {param} --batch --dbs",
        validated=True,
        status="VALIDATED_CONFIRMED",
        evidence={
            "http_confirmed": True,
            "method": "ManipulatorOrchestrator",
            "level": "L5",
        },
        reproduction_steps=generate_repro_steps(
            url, param, working_payload, curl_cmd
        ),
    )


__all__ = [
    "UNPROVEN_UNION_REASON",
    "has_new_db_error_evidence",
    "create_error_based_finding",
    "create_boolean_finding",
    "create_union_finding",
    "demote_unproven_union",
    "create_sqlmap_finding",
    "create_time_based_finding",
    "create_cookie_sqlmap_finding",
    "create_cookie_probe_finding",
    "create_header_error_finding",
    "create_header_status_finding",
    "create_oob_finding",
    "create_json_body_error_finding",
    "create_l5_manipulator_finding",
]
