"""
Asset Discovery Agent Module

Comprehensive subdomain and endpoint enumeration for attack surface mapping.

Modules:
    - core: PURE functions for wordlists, CT log processing, Wayback processing,
            cloud bucket patterns, common paths, result aggregation
    - agent: Thin orchestrator (AssetDiscoveryAgent)

Usage:
    from bugtrace.agents.asset_discovery import AssetDiscoveryAgent

For backward compatibility:
    from bugtrace.agents.asset_discovery_agent import AssetDiscoveryAgent
"""

from bugtrace.agents.asset_discovery.core import (
    # Data
    SENSITIVE_KEYWORDS,
    # Wordlists & patterns
    load_subdomain_wordlist,
    get_common_paths,
    generate_bucket_patterns,
    extract_company_name,
    # Processing
    process_ct_certificates,
    process_wayback_results,
    # Aggregation
    aggregate_results,
    # Classification
    is_sensitive_endpoint,
    is_s3_bucket_public,
)

from bugtrace.agents.asset_discovery.agent import AssetDiscoveryAgent

__all__ = [
    # Main class
    "AssetDiscoveryAgent",
    # Data
    "SENSITIVE_KEYWORDS",
    # Wordlists & patterns
    "load_subdomain_wordlist",
    "get_common_paths",
    "generate_bucket_patterns",
    "extract_company_name",
    # Processing
    "process_ct_certificates",
    "process_wayback_results",
    # Aggregation
    "aggregate_results",
    # Classification
    "is_sensitive_endpoint",
    "is_s3_bucket_public",
]
