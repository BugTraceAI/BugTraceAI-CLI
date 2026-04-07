"""
Asset Discovery Core

PURE functions and data for subdomain wordlists, CT log processing,
Wayback processing, cloud bucket patterns, common paths,
and result aggregation.

Extracted from asset_discovery_agent.py for modularity.
"""

from typing import List, Dict, Set, Optional, Any
from urllib.parse import urlparse


# =============================================================================
# SUBDOMAIN WORDLIST
# =============================================================================

def load_subdomain_wordlist() -> List[str]:  # PURE
    """Load common subdomain wordlist (top 500).

    Returns:
        List of subdomain prefixes for DNS enumeration
    """
    # Top 100 most common subdomains for bug bounty
    common = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
        "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
        "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
        "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info",
        "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter",
        "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4",
    ]

    # Add staging/dev variations
    prefixes = ["dev", "staging", "test", "qa", "uat", "pre", "prod"]
    variations = common + [f"{p}-{sub}" for p in prefixes for sub in common[:20]]

    return list(set(variations))[:500]  # Limit to 500 for performance


# =============================================================================
# COMMON PATHS
# =============================================================================

def get_common_paths() -> List[str]:  # PURE
    """Get top 50 common paths for bug bounty endpoint discovery.

    Returns:
        List of path strings to probe
    """
    return [
        "/admin", "/administrator", "/login", "/signin", "/api", "/v1", "/v2",
        "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json", "/docs",
        "/graphql", "/graphiql", "/api/graphql", "/.git", "/.git/config",
        "/.env", "/.env.local", "/.env.production", "/backup", "/backups",
        "/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma", "/admin.php",
        "/config", "/config.php", "/config.json", "/settings", "/debug",
        "/.aws/credentials", "/.docker", "/api/v1", "/api/v2", "/api/docs",
        "/rest/api", "/api-docs", "/actuator", "/health", "/metrics",
        "/status", "/server-status", "/trace", "/dump", "/env",
    ]


# =============================================================================
# CLOUD BUCKET PATTERNS
# =============================================================================

def generate_bucket_patterns(company_name: str) -> List[str]:  # PURE
    """Generate common cloud storage bucket name patterns.

    Args:
        company_name: Company name extracted from domain

    Returns:
        List of bucket name patterns to check
    """
    return [
        company_name,
        f"{company_name}-backup",
        f"{company_name}-backups",
        f"{company_name}-data",
        f"{company_name}-files",
        f"{company_name}-uploads",
        f"{company_name}-assets",
        f"{company_name}-images",
        f"{company_name}-static",
        f"{company_name}-prod",
        f"{company_name}-production",
        f"{company_name}-dev",
        f"{company_name}-staging",
    ]


def extract_company_name(target_domain: str) -> str:  # PURE
    """Extract company name from domain.

    Args:
        target_domain: Full domain string

    Returns:
        Company name (first part of domain)
    """
    return target_domain.split('.')[0]


# =============================================================================
# CT LOG PROCESSING (PURE)
# =============================================================================

def process_ct_certificates(certs: list, target_domain: str) -> Set[str]:  # PURE
    """Process certificate transparency results and extract subdomains.

    Args:
        certs: List of certificate dicts from crt.sh
        target_domain: Target domain for scope filtering

    Returns:
        Set of discovered subdomain strings
    """
    subdomains = set()
    for cert in certs:
        name_value = cert.get("name_value", "")
        # CT logs can have multiple domains per cert
        domains = name_value.split("\n")
        for domain in domains:
            domain = domain.strip()
            # Skip wildcards
            if "*" in domain:
                continue
            # Skip if not our target domain
            if target_domain not in domain:
                continue
            subdomains.add(domain)
    return subdomains


# =============================================================================
# WAYBACK PROCESSING (PURE)
# =============================================================================

def process_wayback_results(data: list) -> Set[str]:  # PURE
    """Process Wayback Machine results and extract historical URLs.

    Args:
        data: Wayback API response (list of rows, first row is header)

    Returns:
        Set of historical URL strings
    """
    endpoints = set()
    # Skip header row
    for row in data[1:]:
        if not row:
            continue
        historical_url = row[0] if isinstance(row, list) else row
        endpoints.add(historical_url)
    return endpoints


# =============================================================================
# RESULT AGGREGATION (PURE)
# =============================================================================

def aggregate_results(
    discovered_subdomains: Set[str],
    discovered_endpoints: Set[str],
    discovered_cloud_buckets: Set[str],
    max_subdomains: int = 50,
) -> Dict[str, Any]:  # PURE
    """Aggregate and limit discovered assets.

    Args:
        discovered_subdomains: Set of discovered subdomains
        discovered_endpoints: Set of discovered endpoints
        discovered_cloud_buckets: Set of discovered cloud buckets
        max_subdomains: Maximum number of subdomains to include

    Returns:
        Aggregated results dict
    """
    limited_subdomains = sorted(discovered_subdomains)[:max_subdomains]

    return {
        "subdomains": limited_subdomains,
        "endpoints": sorted(discovered_endpoints),
        "cloud_buckets": sorted(discovered_cloud_buckets),
        "total_assets": len(limited_subdomains) + len(discovered_endpoints),
        "total_subdomains_found": len(discovered_subdomains),
        "was_limited": len(discovered_subdomains) > max_subdomains,
    }


# =============================================================================
# ENDPOINT CLASSIFICATION (PURE)
# =============================================================================

SENSITIVE_KEYWORDS = [".git", ".env", "swagger", "graphql", "admin", "config", "backup"]


def is_sensitive_endpoint(url: str) -> bool:  # PURE
    """Check if an endpoint URL contains sensitive keywords.

    Args:
        url: Endpoint URL to check

    Returns:
        True if endpoint appears sensitive
    """
    url_lower = url.lower()
    return any(kw in url_lower for kw in SENSITIVE_KEYWORDS)


def is_s3_bucket_public(status_code: int, response_text: str) -> bool:  # PURE
    """Check if S3 bucket is publicly accessible.

    Args:
        status_code: HTTP status code
        response_text: HTTP response body

    Returns:
        True if bucket appears publicly listable
    """
    return status_code == 200 and "<Contents>" in response_text
