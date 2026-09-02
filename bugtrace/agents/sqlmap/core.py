"""SQLMap pure helpers facade (split modules under core_*)."""

from bugtrace.agents.sqlmap.core_types import (
    DBType,
    SQLMapConfig,
    SQLiEvidence,
    SAFE_COOKIE_VALUE_PATTERN,
    SAFE_HEADER_NAME_PATTERN,
)
from bugtrace.agents.sqlmap.core_security import (
    validate_cookie_value,
    validate_header,
    validate_post_data,
    strip_ansi_codes,
)
from bugtrace.agents.sqlmap.core_strategy import (
    DBFingerprinter,
    WAFBypassStrategy,
)
from bugtrace.agents.sqlmap.core_command import (
    build_base_command,
    is_likely_base64,
    add_cookies_to_command,
    add_headers_to_command,
    add_tamper_scripts_to_command,
    build_full_command,
    build_reproduction_command,
    build_docker_command,
    build_extraction_command,
)
from bugtrace.agents.sqlmap.core_parse import (
    cache_key,
    parse_sqlmap_output,
    parse_extracted_data,
    process_sqlmap_output,
    check_sqlmap_error_patterns,
    check_critical_errors,
)
from bugtrace.agents.sqlmap.core_evidence import (
    evidence_to_finding,
    build_evidence_description,
    build_evidence_details,
    docker_url,
    extract_post_params,
    inject_probe_payload,
    default_error_patterns,
    default_test_payloads,
)
from bugtrace.agents.sqlmap.core_report import (
    build_report_header,
    build_single_finding_report,
    build_report_findings,
)

__all__ = [
    "DBType", "SQLMapConfig", "SQLiEvidence",
    "SAFE_COOKIE_VALUE_PATTERN", "SAFE_HEADER_NAME_PATTERN",
    "validate_cookie_value", "validate_header", "validate_post_data", "strip_ansi_codes",
    "DBFingerprinter", "WAFBypassStrategy",
    "build_base_command", "is_likely_base64", "add_cookies_to_command",
    "add_headers_to_command", "add_tamper_scripts_to_command",
    "build_full_command", "build_reproduction_command", "build_docker_command",
    "build_extraction_command",
    "cache_key", "parse_sqlmap_output", "parse_extracted_data", "process_sqlmap_output",
    "check_sqlmap_error_patterns", "check_critical_errors",
    "evidence_to_finding", "build_evidence_description", "build_evidence_details",
    "docker_url", "extract_post_params", "inject_probe_payload",
    "default_error_patterns", "default_test_payloads",
    "build_report_header", "build_single_finding_report", "build_report_findings",
]
