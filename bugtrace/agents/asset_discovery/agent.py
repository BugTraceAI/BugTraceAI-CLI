"""
Asset Discovery Agent

Thin orchestrator for comprehensive subdomain and endpoint enumeration.
Delegates pure data/logic to core.py, performs I/O (HTTP, DNS) directly.

Extracted from asset_discovery_agent.py for modularity.
"""

import asyncio
import httpx
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urlparse, urljoin
from loguru import logger
from datetime import datetime

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings

from bugtrace.agents.asset_discovery.core import (
    load_subdomain_wordlist,
    get_common_paths,
    generate_bucket_patterns,
    extract_company_name,
    process_ct_certificates,
    process_wayback_results,
    aggregate_results,
    is_sensitive_endpoint,
    is_s3_bucket_public,
)


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
            agent_id="asset_discovery",
        )
        self.discovered_subdomains: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_cloud_buckets: Set[str] = set()
        self.target_domain = ""
        self.wordlist_subdomains = load_subdomain_wordlist()

    # =====================================================================
    # EVENT SUBSCRIPTIONS
    # =====================================================================

    def _setup_event_subscriptions(self):
        """Subscribe to target discovery events."""
        if self.event_bus:
            self.event_bus.subscribe("new_target_added", self.handle_new_target)
            logger.info(f"[{self.name}] Subscribed to 'new_target_added' events")

    async def handle_new_target(self, data: Dict[str, Any]):  # I/O
        """Triggered when a new target is added to scope."""
        target_url = data.get("url")
        self.think(f"New target in scope: {target_url}")
        await self.discover_assets(target_url)

    # =====================================================================
    # RUN LOOP
    # =====================================================================

    async def run_loop(self):  # I/O
        """Main agent loop."""
        from bugtrace.core.ui import dashboard

        dashboard.current_agent = self.name
        self.think("Asset Discovery Agent initialized and waiting for targets...")

        while self.running:
            await asyncio.sleep(1)

    # =====================================================================
    # MAIN DISCOVERY ORCHESTRATION
    # =====================================================================

    async def discover_assets(self, target_url: str) -> Dict[str, Any]:  # I/O
        """Main discovery orchestration method."""
        from bugtrace.core.ui import dashboard

        parsed = urlparse(target_url)
        self.target_domain = parsed.netloc or parsed.path

        # Check if asset discovery is enabled in config
        enable_asset_discovery = settings.get("ASSET_DISCOVERY", "ENABLE_ASSET_DISCOVERY", "False").lower() == "true"

        if not enable_asset_discovery:
            dashboard.log(f"Asset discovery disabled - scanning target URL only: {self.target_domain}", "INFO")
            return {
                "subdomains": [],
                "endpoints": [],
                "cloud_buckets": [],
                "total_assets": 0,
                "discovery_disabled": True,
            }

        dashboard.log(f"Starting comprehensive asset discovery for: {self.target_domain}", "INFO")

        tasks = self._build_discovery_tasks(target_url)
        if not tasks:
            dashboard.log("All asset discovery methods disabled", "WARNING")
            return {"subdomains": [], "endpoints": [], "cloud_buckets": [], "total_assets": 0}

        # Run enabled discovery methods in parallel
        await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate and limit results (PURE)
        max_subdomains = int(settings.get("ASSET_DISCOVERY", "MAX_SUBDOMAINS", "50"))
        assets = aggregate_results(
            self.discovered_subdomains,
            self.discovered_endpoints,
            self.discovered_cloud_buckets,
            max_subdomains=max_subdomains,
        )

        if assets["was_limited"]:
            dashboard.log(
                f"Limited to {max_subdomains} subdomains (found {assets['total_subdomains_found']})",
                "WARNING",
            )

        # Emit discovery event
        if self.event_bus:
            await self.event_bus.emit("assets_discovered", {
                "target": self.target_domain,
                "assets": assets,
                "timestamp": datetime.now().isoformat(),
            })

        dashboard.log(
            f"Discovery complete: {len(assets['subdomains'])} subdomains, "
            f"{len(self.discovered_endpoints)} endpoints, "
            f"{len(self.discovered_cloud_buckets)} cloud buckets",
            "SUCCESS",
        )

        return assets

    def _build_discovery_tasks(self, target_url: str) -> List:
        """Build list of discovery tasks based on enabled methods."""
        enable_dns = settings.get("ASSET_DISCOVERY", "ENABLE_DNS_ENUMERATION", "True").lower() == "true"
        enable_ct = settings.get("ASSET_DISCOVERY", "ENABLE_CERTIFICATE_TRANSPARENCY", "True").lower() == "true"
        enable_wayback = settings.get("ASSET_DISCOVERY", "ENABLE_WAYBACK_DISCOVERY", "True").lower() == "true"
        enable_cloud = settings.get("ASSET_DISCOVERY", "ENABLE_CLOUD_STORAGE_ENUM", "True").lower() == "true"
        enable_common = settings.get("ASSET_DISCOVERY", "ENABLE_COMMON_PATHS", "True").lower() == "true"

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
        return tasks

    # =====================================================================
    # DNS ENUMERATION (I/O)
    # =====================================================================

    async def _dns_enumeration(self):  # I/O
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

    async def _check_dns_record(self, hostname: str):  # I/O
        """Check if hostname resolves (simple HTTP check)."""
        try:
            async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
                for scheme in ["https", "http"]:
                    try:
                        url = f"{scheme}://{hostname}"
                        response = await client.get(url, timeout=3)
                        if response.status_code >= 500:
                            continue
                        # Any response = exists
                        self.discovered_subdomains.add(hostname)
                        from bugtrace.core.ui import dashboard
                        dashboard.log(f"  Found: {hostname}", "INFO")
                        return
                    except Exception:
                        continue
        except Exception:
            pass  # DNS resolution failed

    # =====================================================================
    # CERTIFICATE TRANSPARENCY (I/O)
    # =====================================================================

    async def _certificate_transparency(self):  # I/O
        """Query Certificate Transparency logs via crt.sh."""
        from bugtrace.core.ui import dashboard

        self.think("Querying Certificate Transparency logs...")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
                response = await client.get(url)

                if response.status_code != 200:
                    return

                certs = response.json()
                # Process certificates (PURE)
                new_subdomains = process_ct_certificates(certs, self.target_domain)
                self.discovered_subdomains.update(new_subdomains)
                dashboard.log(f"  CT Logs: Found {len(certs)} certificates", "INFO")
        except Exception as e:
            logger.warning(f"Certificate Transparency query failed: {e}")

    # =====================================================================
    # WAYBACK MACHINE (I/O)
    # =====================================================================

    async def _wayback_discovery(self):  # I/O
        """Query Wayback Machine for historical URLs."""
        from bugtrace.core.ui import dashboard

        self.think("Querying Wayback Machine for historical endpoints...")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                url = f"http://web.archive.org/cdx/search/cdx?url={self.target_domain}/*&output=json&collapse=urlkey&fl=original"
                response = await client.get(url)

                if response.status_code != 200:
                    return

                data = response.json()
                # Process results (PURE)
                new_endpoints = process_wayback_results(data)
                self.discovered_endpoints.update(new_endpoints)
                dashboard.log(f"  Wayback: Found {len(data)-1} historical URLs", "INFO")
        except Exception as e:
            logger.warning(f"Wayback Machine query failed: {e}")

    # =====================================================================
    # CLOUD STORAGE ENUMERATION (I/O)
    # =====================================================================

    async def _cloud_storage_enum(self):  # I/O
        """Enumerate cloud storage buckets (S3, Azure, GCP)."""
        self.think("Enumerating cloud storage buckets...")

        company_name = extract_company_name(self.target_domain)
        patterns = generate_bucket_patterns(company_name)

        tasks = []
        # S3 buckets
        for pattern in patterns:
            tasks.append(self._check_s3_bucket(pattern))
        # Azure blobs
        for pattern in patterns:
            tasks.append(self._check_azure_blob(pattern))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_s3_bucket(self, bucket_name: str):  # I/O
        """Check if S3 bucket exists and is accessible."""
        from bugtrace.core.ui import dashboard

        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                url = f"https://{bucket_name}.s3.amazonaws.com"
                response = await client.get(url, timeout=5)

                if response.status_code not in [200, 403] and "<?xml" not in response.text:
                    return

                self.discovered_cloud_buckets.add(f"s3://{bucket_name}")

                # Check if publicly accessible (PURE)
                if is_s3_bucket_public(response.status_code, response.text):
                    dashboard.log(f"  PUBLIC S3 bucket: {bucket_name}", "CRITICAL")
                else:
                    dashboard.log(f"  Found S3 bucket: {bucket_name} (access denied)", "INFO")
        except Exception as e:
            logger.debug(f"operation failed: {e}")

    async def _check_azure_blob(self, container_name: str):  # I/O
        """Check if Azure blob storage exists."""
        from bugtrace.core.ui import dashboard

        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                url = f"https://{container_name}.blob.core.windows.net"
                response = await client.get(url, timeout=5)

                if response.status_code in [200, 400, 403]:
                    self.discovered_cloud_buckets.add(f"azure://{container_name}")
                    dashboard.log(f"  Found Azure blob: {container_name}", "INFO")
        except Exception as e:
            logger.debug(f"_check_azure_blob failed: {e}")

    # =====================================================================
    # COMMON PATHS DISCOVERY (I/O)
    # =====================================================================

    async def _common_paths_discovery(self, base_url: str):  # I/O
        """Discover common paths and hidden endpoints."""
        self.think("Probing for common endpoints...")

        common_paths = get_common_paths()

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

    async def _probe_endpoint(self, url: str):  # I/O
        """Probe single endpoint to check if it exists."""
        from bugtrace.core.ui import dashboard

        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                response = await client.get(url, timeout=5)

                if response.status_code == 404:
                    return

                self.discovered_endpoints.add(url)

                # Only check sensitive keywords for 200 responses
                if response.status_code == 200 and is_sensitive_endpoint(url):
                    dashboard.log(f"  Sensitive endpoint exposed: {url}", "CRITICAL")
                elif response.status_code == 200:
                    dashboard.log(f"  Found: {url}", "INFO")
        except Exception as e:
            logger.debug(f"operation failed: {e}")
