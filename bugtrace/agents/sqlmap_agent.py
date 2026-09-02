"""SQLMapAgent — compatibility facade.

Implementation lives in ``bugtrace.agents.sqlmap`` (core + runner + agent).
This module preserves the historical import path used by team flows:

    from bugtrace.agents.sqlmap_agent import SQLMapAgent
"""

from bugtrace.agents.sqlmap import (
    SQLMapAgent,
    EnhancedSQLMapRunner,
    DBType,
    SQLMapConfig,
    SQLiEvidence,
    DBFingerprinter,
    WAFBypassStrategy,
    validate_cookie_value,
    validate_header,
    validate_post_data,
    strip_ansi_codes,
    get_sqlmap_semaphore,
)

__all__ = [
    "SQLMapAgent",
    "EnhancedSQLMapRunner",
    "DBType",
    "SQLMapConfig",
    "SQLiEvidence",
    "DBFingerprinter",
    "WAFBypassStrategy",
    "validate_cookie_value",
    "validate_header",
    "validate_post_data",
    "strip_ansi_codes",
    "get_sqlmap_semaphore",
]
