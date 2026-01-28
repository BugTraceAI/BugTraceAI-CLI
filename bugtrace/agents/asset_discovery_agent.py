"""
Asset Discovery Agent - Comprehensive Subdomain and Endpoint Enumeration

This agent discovers the complete attack surface:
- Subdomains (DNS bruteforce, CT logs)
- Hidden endpoints (Wayback, common paths)
- Cloud storage (S3, Azure, GCP buckets)
- GitHub code search
- Related domains

Advanced reconnaissance and comprehensive asset mapping.
"""

import asyncio
import httpx
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urlparse, urljoin
from loguru import logger
from datetime import datetime

from bugtrace.agents.base import BaseAgent
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings


class AssetDiscoveryAgent(BaseAgent):
    """
    Comprehensive asset discovery for bug bounty reconnaissance.

    Discovery Methods:
    1. DNS Enumeration (bruteforce + zone transfer attempts)
    2. Certificate Transparency Logs
    3. Wayback Machine (historical URLs)
    4. GitHub Code Search (mentions of domain)
    5. Cloud Storage Enumeration
    6. Common Path Discovery
    """

    def __init__(self, event_bus=None):
        super().__init__(
            "AssetDiscoveryAgent",
            "Attack Surface Mapper",
            event_bus,
            agent_id="asset_discovery"
        )
        self.discovered_subdomains: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_cloud_buckets: Set[str] = set()
        self.target_domain = ""
        self.wordlist_subdomains = self._load_subdomain_wordlist()

    def _setup_event_subscriptions(self):
        """Subscribe to target discovery events."""
        if self.event_bus:
            self.event_bus.subscribe("new_target_added", self.handle_new_target)
            logger.info(f"[{self.name}] Subscribed to 'new_target_added' events")

    async def handle_new_target(self, data: Dict[str, Any]):
        """Triggered when a new target is added to scope."""
        target_url = data.get("url")
        self.think(f"New target in scope: {target_url}")
        await self.discover_assets(target_url)

    def _load_subdomain_wordlist(self) -> List[str]:
        """Load common subdomain wordlist (top 1000)."""
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

    async def run_loop(self):
        """Main agent loop."""
        dashboard.current_agent = self.name
        self.think("Asset Discovery Agent initialized and waiting for targets...")

        while self.running:
            await asyncio.sleep(1)

    async def discover_assets(self, target_url: str) -> Dict[str, Any]:
        """
        Main discovery orchestration method.

        Returns:
            Dict with discovered assets:
            {
                "subdomains": [...],
                "endpoints": [...],
                "cloud_buckets": [...],
                "github_mentions": [...]
            }
        """
        parsed = urlparse(target_url)
        self.target_domain = parsed.netloc or parsed.path

        # Check if asset discovery is enabled in config
        enable_asset_discovery = settings.get("ASSET_DISCOVERY", "ENABLE_ASSET_DISCOVERY", "False").lower() == "true"

        if not enable_asset_discovery:
            dashboard.log(f"ℹ️  Asset discovery disabled - scanning target URL only: {self.target_domain}", "INFO")
            return {
                "subdomains": [],
                "endpoints": [],
                "cloud_buckets": [],
                "total_assets": 0,
                "discovery_disabled": True
            }

        dashboard.log(f"🔍 Starting comprehensive asset discovery for: {self.target_domain}", "INFO")

        # Check individual method toggles
        enable_dns = settings.get("ASSET_DISCOVERY", "ENABLE_DNS_ENUMERATION", "True").lower() == "true"
        enable_ct = settings.get("ASSET_DISCOVERY", "ENABLE_CERTIFICATE_TRANSPARENCY", "True").lower() == "true"
        enable_wayback = settings.get("ASSET_DISCOVERY", "ENABLE_WAYBACK_DISCOVERY", "True").lower() == "true"
        enable_cloud = settings.get("ASSET_DISCOVERY", "ENABLE_CLOUD_STORAGE_ENUM", "True").lower() == "true"
        enable_common = settings.get("ASSET_DISCOVERY", "ENABLE_COMMON_PATHS", "True").lower() == "true"

        # Build task list based on enabled methods
        tasks = []
        if enable_dns:
            tasks.append(self._dns_enumeration())
        if enable_ct:
            tasks.append(self._certificate_transparency())
        if enable_wayback:
            tasks.append(self._wayback_discovery())
        if enable_cloud:
            tasks.append(self._cloud_storage_enum())
        if enable_common:
            tasks.append(self._common_paths_discovery(target_url))

        if not tasks:
            dashboard.log("⚠️  All asset discovery methods disabled", "WARNING")
            return {
                "subdomains": [],
                "endpoints": [],
                "cloud_buckets": [],
                "total_assets": 0
            }

        # Run enabled discovery methods in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Apply MAX_SUBDOMAINS limit
        max_subdomains = int(settings.get("ASSET_DISCOVERY", "MAX_SUBDOMAINS", "50"))
        limited_subdomains = sorted(self.discovered_subdomains)[:max_subdomains]

        if len(self.discovered_subdomains) > max_subdomains:
            dashboard.log(
                f"⚠️  Limited to {max_subdomains} subdomains (found {len(self.discovered_subdomains)})",
                "WARNING"
            )

        # Aggregate results
        assets = {
            "subdomains": limited_subdomains,
            "endpoints": sorted(self.discovered_endpoints),
            "cloud_buckets": sorted(self.discovered_cloud_buckets),
            "total_assets": len(limited_subdomains) + len(self.discovered_endpoints)
        }

        # Emit discovery event
        if self.event_bus:
            await self.event_bus.emit("assets_discovered", {
                "target": self.target_domain,
                "assets": assets,
                "timestamp": datetime.now().isoformat()
            })

        dashboard.log(
            f"✅ Discovery complete: {len(limited_subdomains)} subdomains, "
            f"{len(self.discovered_endpoints)} endpoints, "
            f"{len(self.discovered_cloud_buckets)} cloud buckets",
            "SUCCESS"
        )

        return assets

    async def _dns_enumeration(self):
        """DNS bruteforce using common subdomain wordlist."""
        self.think("Starting DNS enumeration...")

        tasks = []
        for subdomain in self.wordlist_subdomains:
            hostname = f"{subdomain}.{self.target_domain}"
            tasks.append(self._check_dns_record(hostname))

        # Run in batches to avoid overwhelming DNS
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            await asyncio.sleep(0.5)  # Rate limiting

    async def _check_dns_record(self, hostname: str):
        """Check if hostname resolves (simple HTTP check)."""
        try:
            async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
                # Try both HTTP and HTTPS
                for scheme in ["https", "http"]:
                    try:
                        url = f"{scheme}://{hostname}"
                        response = await client.get(url, timeout=3)
                        if response.status_code < 500:  # Any response = exists
                            self.discovered_subdomains.add(hostname)
                            dashboard.log(f"  ✅ Found: {hostname}", "INFO")
                            return
                    except Exception as e:
                        continue
        except Exception as e:
            pass  # DNS resolution failed

    async def _certificate_transparency(self):
        """Query Certificate Transparency logs via crt.sh."""
        self.think("Querying Certificate Transparency logs...")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
                response = await client.get(url)

                if response.status_code == 200:
                    certs = response.json()
                    for cert in certs:
                        name_value = cert.get("name_value", "")
                        # CT logs can have multiple domains per cert
                        domains = name_value.split("\n")
                        for domain in domains:
                            domain = domain.strip()
                            # Skip wildcards and add valid subdomains
                            if "*" not in domain and self.target_domain in domain:
                                self.discovered_subdomains.add(domain)

                    dashboard.log(f"  📜 CT Logs: Found {len(certs)} certificates", "INFO")
        except Exception as e:
            logger.warning(f"Certificate Transparency query failed: {e}")

    async def _wayback_discovery(self):
        """Query Wayback Machine for historical URLs."""
        self.think("Querying Wayback Machine for historical endpoints...")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                url = f"http://web.archive.org/cdx/search/cdx?url={self.target_domain}/*&output=json&collapse=urlkey&fl=original"
                response = await client.get(url)

                if response.status_code == 200:
                    data = response.json()
                    # Skip header row
                    for row in data[1:]:
                        if row:
                            historical_url = row[0] if isinstance(row, list) else row
                            self.discovered_endpoints.add(historical_url)

                    dashboard.log(f"  🕰️  Wayback: Found {len(data)-1} historical URLs", "INFO")
        except Exception as e:
            logger.warning(f"Wayback Machine query failed: {e}")

    async def _cloud_storage_enum(self):
        """Enumerate cloud storage buckets (S3, Azure, GCP)."""
        self.think("Enumerating cloud storage buckets...")

        # Extract company name from domain
        company_name = self.target_domain.split('.')[0]

        # Common bucket name patterns
        patterns = [
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

        tasks = []
        # S3 buckets
        for pattern in patterns:
            tasks.append(self._check_s3_bucket(pattern))

        # Azure blobs
        for pattern in patterns:
            tasks.append(self._check_azure_blob(pattern))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_s3_bucket(self, bucket_name: str):
        """Check if S3 bucket exists and is accessible."""
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                url = f"https://{bucket_name}.s3.amazonaws.com"
                response = await client.get(url, timeout=5)

                # Bucket exists if we get XML response (even if access denied)
                if response.status_code in [200, 403] or "<?xml" in response.text:
                    self.discovered_cloud_buckets.add(f"s3://{bucket_name}")

                    # Check if publicly accessible
                    if response.status_code == 200 and "<Contents>" in response.text:
                        dashboard.log(f"  ⚠️  PUBLIC S3 bucket: {bucket_name}", "CRITICAL")
                    else:
                        dashboard.log(f"  🪣 Found S3 bucket: {bucket_name} (access denied)", "INFO")
        except Exception as e:
            logger.debug(f"operation failed: {e}")

    async def _check_azure_blob(self, container_name: str):
        """Check if Azure blob storage exists."""
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                url = f"https://{container_name}.blob.core.windows.net"
                response = await client.get(url, timeout=5)

                if response.status_code in [200, 400, 403]:
                    self.discovered_cloud_buckets.add(f"azure://{container_name}")
                    dashboard.log(f"  🪣 Found Azure blob: {container_name}", "INFO")
        except Exception as e:
            logger.debug(f"_check_azure_blob failed: {e}")

    async def _common_paths_discovery(self, base_url: str):
        """Discover common paths and hidden endpoints."""
        self.think("Probing for common endpoints...")

        # Top 50 common paths for bug bounty
        common_paths = [
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

        tasks = []
        for path in common_paths:
            url = urljoin(base_url, path)
            tasks.append(self._probe_endpoint(url))

        # Run in batches
        batch_size = 10
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            await asyncio.sleep(0.5)

    async def _probe_endpoint(self, url: str):
        """Probe single endpoint to check if it exists."""
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                response = await client.get(url, timeout=5)

                # Any non-404 response is interesting
                if response.status_code != 404:
                    self.discovered_endpoints.add(url)

                    # Flag sensitive endpoints
                    if response.status_code == 200:
                        sensitive_keywords = [".git", ".env", "swagger", "graphql", "admin", "config", "backup"]
                        if any(kw in url.lower() for kw in sensitive_keywords):
                            dashboard.log(f"  ⚠️  Sensitive endpoint exposed: {url}", "CRITICAL")
                        else:
                            dashboard.log(f"  📍 Found: {url}", "INFO")
        except Exception as e:
            logger.debug(f"operation failed: {e}")


# Export for team orchestrator
__all__ = ["AssetDiscoveryAgent"]
