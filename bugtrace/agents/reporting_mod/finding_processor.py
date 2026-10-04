"""Finding processor facade — baseline, payload upgrade, quality/dedup.

Public API re-exported for reporting_mod and reporting agent.
"""

from bugtrace.agents.reporting_mod.finding_baseline import (
    _safe_evidence_get,
    _synthesize_description,
    apply_deterministic_baseline,
    categorize_findings,
    has_minimum_evidence,
    _VISUAL_BANNER_JS,
    _VISUAL_BANNER_TEXT,
    _VISUAL_BANNER_TEXT_ESCAPED,
    _PAYLOAD_UPGRADE_MAP,
    _CSTI_UPGRADE_MAP,
)
from bugtrace.agents.reporting_mod.finding_upgrade import (
    upgrade_payload,
    upgrade_finding_payloads,
    _as_text,
    _as_header_map,
    _split_url,
    _rewrite_query_payload,
    _rewrite_url_payload,
    _rewrite_body_payload,
    _render_raw_http,
    _rewrite_raw_http_payload,
    _rewrite_repro_text,
    _sync_repro_with_payload,
)
from bugtrace.agents.reporting_mod.finding_quality import (
    meets_report_quality,
    deduplicate_exact,
    normalize_type_for_dedup,
    normalize_parameter_for_dedup,
    deduplicate_findings,
    count_by_severity,
    event_finding_to_db_format,
    merge_event_findings,
    consolidate_informational,
    build_consolidated_header_finding,
    build_consolidated_api_docs_finding,
    db_build_finding_dict,
    db_enrich_sqli_metadata,
    nuclei_map_severity,
    nuclei_parse_findings,
    nuclei_extract_tech_stack,
    group_findings_by_type,
    present_findings_for_api,
)

__all__ = [
    "apply_deterministic_baseline",
    "categorize_findings",
    "has_minimum_evidence",
    "upgrade_payload",
    "upgrade_finding_payloads",
    "meets_report_quality",
    "deduplicate_findings",
    "count_by_severity",
    "event_finding_to_db_format",
    "merge_event_findings",
    "consolidate_informational",
    "group_findings_by_type",
    "present_findings_for_api",
]
