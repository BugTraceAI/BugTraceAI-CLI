"""
Logging Standards for BugTraceAI CLI
=====================================

This module documents the logging conventions established across phases 6-8
of the v2.1 Code Quality & Security Audit.

Standard Import Pattern
-----------------------
The project uses `get_logger` from `bugtrace.utils.logger` as the STANDARD pattern:

    from bugtrace.utils.logger import get_logger
    logger = get_logger(__name__)

This provides stdlib logging with Rich console output + JSON file handlers.

Note: 24 files currently use `from loguru import logger`. These should be
migrated to `get_logger` over time, but that migration is out of scope for
this documentation. This module only documents log LEVELS and message formats.

Log Level Standards
-------------------
Use the following log levels for consistency across all modules:

DEBUG (logger.debug):
  - Cleanup operations (file cleanup, resource teardown)
  - Security tool expected failures (payloads that are meant to fail during testing)
  - Resource teardown (closing connections, removing temp files)
  - Verbose operational details useful only during development

INFO (logger.info):
  - General operations (scan start, scan complete)
  - Agent lifecycle events (agent created, agent completed)
  - Significant milestones in workflows
  - Normal operational flow checkpoints

WARNING (logger.warning):
  - Database errors (connection failures, query timeouts, integrity errors)
  - Network errors (HTTP timeouts, connection refused, DNS failures)
  - Recoverable failures that need attention but don't stop execution
  - Degraded functionality (fallback to default, missing optional config)

ERROR (logger.error):
  - Unexpected failures (unhandled exceptions, logic errors)
  - Unhandled exceptions (ALWAYS use exc_info=True)
  - Critical operation failures that prevent completing a task
  - Data corruption or integrity issues

CRITICAL (logger.critical):
  - System stability threats (imminent crashes, data loss)
  - Resource exhaustion (out of memory, disk full)
  - Rarely used - most severe failures should use ERROR

Message Format Standards
------------------------
Follow these conventions for log messages:

1. Use f-strings (not % formatting or .format())
   Good: logger.info(f"Starting scan for {url}")
   Bad:  logger.info("Starting scan for %s" % url)

2. Start with action verb
   Good: logger.info(f"Starting scan for {url}")
   Good: logger.warning(f"Failed to connect to {host}")
   Bad:  logger.info(f"Scan for {url}")

3. Include relevant context
   - Agent name where applicable
   - URL or target being scanned
   - Scan ID or correlation ID if available
   - Operation being performed

4. Do NOT include stack traces in message
   - Use exc_info=True for that
   Good: logger.error(f"Failed to parse response from {url}", exc_info=True)
   Bad:  logger.error(f"Failed to parse response: {traceback.format_exc()}")

5. Do NOT prefix with redundant level name
   Good: logger.error(f"Failed to connect to {host}", exc_info=True)
   Bad:  logger.error(f"Error: Failed to connect to {host}")

Exception Handling Patterns
----------------------------
When logging exceptions:

1. For unexpected exceptions:
   try:
       risky_operation()
   except Exception as e:
       logger.error(f"Failed to complete {operation}", exc_info=True)

2. For expected failures (security testing):
   try:
       test_payload(url, payload)
   except ConnectionError as e:
       logger.debug(f"Payload failed as expected: {payload}")

3. For network/database errors:
   try:
       response = requests.get(url, timeout=5)
   except (Timeout, ConnectionError) as e:
       logger.warning(f"Network error connecting to {url}: {e}")

"""

# Event category to log level mapping
LOG_LEVEL_STANDARDS = {
    # DEBUG level events
    "cleanup": "debug",
    "security_tool_expected_failure": "debug",
    "resource_teardown": "debug",
    "verbose_operational_detail": "debug",

    # INFO level events
    "scan_start": "info",
    "scan_complete": "info",
    "agent_lifecycle": "info",
    "workflow_milestone": "info",
    "normal_operation": "info",

    # WARNING level events
    "network_error": "warning",
    "database_error": "warning",
    "recoverable_failure": "warning",
    "degraded_functionality": "warning",

    # ERROR level events
    "unexpected_error": "error",
    "unhandled_exception": "error",
    "critical_operation_failure": "error",
    "data_corruption": "error",

    # CRITICAL level events
    "system_threat": "critical",
    "resource_exhaustion": "critical",
}

# Message format guide as a reference string
MESSAGE_FORMAT_GUIDE = """
Log Message Format Standards:

1. Use f-strings:           logger.info(f"Starting scan for {url}")
2. Action verb first:       logger.warning(f"Failed to connect to {host}")
3. Include context:         logger.error(f"Failed to parse {file} at line {line}")
4. Use exc_info=True:       logger.error(f"Unexpected error", exc_info=True)
5. No redundant prefixes:   logger.error(f"Failed...") NOT logger.error(f"Error: Failed...")
"""
