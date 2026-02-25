"""
Chain Discovery Agent Module

Automatically discovers and exploits multi-step vulnerability chains.
Uses NetworkX graph to model exploitation paths.

Modules:
    - core: PURE functions for chain templates, vulnerability conversion,
            graph operations, Mermaid visualization, report building
    - agent: Thin orchestrator (ChainDiscoveryAgent)

Usage:
    from bugtrace.agents.chain_discovery import ChainDiscoveryAgent

For backward compatibility:
    from bugtrace.agents.chain_discovery_agent import ChainDiscoveryAgent
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
