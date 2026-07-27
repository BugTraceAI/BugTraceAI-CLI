"""
Chain Discovery Agent Module

Correlates confirmed specialist findings into candidate multi-step attack
chains. NOTE: this agent is currently DISABLED in the orchestrator (team.py)
and does not run during scans. Findings are modelled as graph NODES only — it
does NOT yet add exploitation edges/weights or execute chain steps (steps are
reported as unverified, never as fabricated success). Reviving it is a scoped
feature, not a bugfix.

Modules:
    - core: PURE functions for chain templates, vulnerability conversion,
            node building, Mermaid visualization, report building
    - agent: Thin orchestrator (ChainDiscoveryAgent)

Usage:
    from bugtrace.agents.chain_discovery import ChainDiscoveryAgent
"""

from bugtrace.agents.chain_discovery.core import (
    # Constants
    VULN_TYPE_MAP,
    CRITICAL_TYPES,
    HIGH_TYPES,
    MEDIUM_TYPES,
    SEVERITY_COLORS,
    # Chain templates
    get_critical_chain_templates,
    get_high_severity_chain_templates,
    load_chain_templates,
    # Vulnerability conversion
    infer_severity,
    convert_specialist_finding,
    # Graph operations
    make_vuln_node_id,
    build_node_attributes,
    build_chain_from_template,
    find_matching_templates,
    # Step execution
    step_execute_and_validate,
    step_build_error,
    # Report building
    build_chain_report,
    build_exploit_prompt,
    build_poc_prompt,
    # Visualization
    visualize_graph,
)

from bugtrace.agents.chain_discovery.agent import ChainDiscoveryAgent

__all__ = [
    # Main class
    "ChainDiscoveryAgent",
    # Constants
    "VULN_TYPE_MAP",
    "CRITICAL_TYPES",
    "HIGH_TYPES",
    "MEDIUM_TYPES",
    "SEVERITY_COLORS",
    # Chain templates
    "get_critical_chain_templates",
    "get_high_severity_chain_templates",
    "load_chain_templates",
    # Vulnerability conversion
    "infer_severity",
    "convert_specialist_finding",
    # Graph operations
    "make_vuln_node_id",
    "build_node_attributes",
    "build_chain_from_template",
    "find_matching_templates",
    # Step execution
    "step_execute_and_validate",
    "step_build_error",
    # Report building
    "build_chain_report",
    "build_exploit_prompt",
    "build_poc_prompt",
    # Visualization
    "visualize_graph",
]
