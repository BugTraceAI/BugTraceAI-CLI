"""
reporting_mod: helper subpackage for the live ReportingAgent.

The live reporting agent is the monolith ``bugtrace/agents/reporting.py``.
This subpackage only exposes helpers it consumes:

    from bugtrace.agents.reporting_mod.finding_processor import upgrade_finding_payloads

Live surface: ``finding_processor`` (+ its deps ``formatters`` and ``types``).

The former modular ``ReportingAgent`` twin (``agent.py`` plus ``report_builder``,
``cvss``, ``file_writer`` and ``screenshot_handler``) was created by the 2026-02-25
"modularization" refactor, never wired into any live caller, and drifted behind the
monolith. It was removed in 3.6.48-beta. No re-export here on purpose: importing this
package must not pull in dead modules.
"""
