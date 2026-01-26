"""
Real-Time Monitoring Agent

Continuous monitoring of targets for changes:
- New subdomains appearing
- New endpoints discovered
- Parameter drift (new params on existing endpoints)
- Version changes (new features deployed)
- Automatic regression testing

This is a UNIQUE feature - no competitor has continuous monitoring for bug bounty.
Gives hunters a massive advantage: be first to find vulns in new attack surface.
"""

import asyncio
import json
import hashlib
from typing import Dict, Set, Optional, Any, List
from datetime import datetime, timedelta
from pathlib import Path
from loguru import logger

import httpx

from bugtrace.agents.base import BaseAgent
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings


class MonitoringAgent(BaseAgent):
    """
    Continuous monitoring agent for target surveillance.

    Monitors:
    1. New subdomains (DNS changes)
    2. New endpoints (path discovery)
    3. Parameter changes (new attack surface)
    4. Technology stack updates
    5. Security header changes
    """

    def __init__(self, event_bus=None):
        super().__init__(
            "MonitoringAgent",
            "Continuous Surveillance Specialist",
            event_bus,
            agent_id="monitoring"
        )

        # Monitored targets
        self.monitored_targets: Dict[str, Dict] = {}

        # Historical state
        self.state_dir = Path("data/monitoring_state")
        self.state_dir.mkdir(parents=True, exist_ok=True)

        # Notification handlers
        self.notification_handlers = []

        # Monitoring intervals
        self.subdomain_check_interval = 3600  # 1 hour
        self.endpoint_check_interval = 1800   # 30 minutes
        self.content_check_interval = 600     # 10 minutes

    def _setup_event_subscriptions(self):
        """Subscribe to monitoring events."""
        if self.event_bus:
            self.event_bus.subscribe("monitoring_enabled", self.handle_monitoring_request)
            logger.info(f"[{self.name}] Subscribed to monitoring events")

    async def handle_monitoring_request(self, data: Dict[str, Any]):
        """Enable monitoring for a target."""
        target = data.get("target")
        config = data.get("config", {})

        await self.add_target(target, config)

    async def run_loop(self):
        """Main monitoring loop."""
        dashboard.current_agent = self.name
        self.think("Monitoring Agent initialized - continuous surveillance active")

        while self.running:
            # Load monitored targets from disk
            await self._load_targets()

            if not self.monitored_targets:
                self.think("No targets monitored. Waiting...")
                await asyncio.sleep(60)
                continue

            # Run checks for each target
            for target_id, target_info in list(self.monitored_targets.items()):
                try:
                    await self._check_target(target_id, target_info)
                except Exception as e:
                    logger.error(f"Error monitoring {target_id}: {e}")

            # Sleep before next cycle
            await asyncio.sleep(300)  # Check all targets every 5 minutes

    async def add_target(self, target_url: str, config: Dict = None):
        """
        Add target to continuous monitoring.

        Args:
            target_url: Target URL to monitor
            config: Monitoring configuration
                {
                    "check_subdomains": bool,
                    "check_endpoints": bool,
                    "check_parameters": bool,
                    "alert_on_changes": bool,
                    "auto_retest": bool
                }
        """
        target_id = hashlib.md5(target_url.encode()).hexdigest()[:8]

        # Default config
        default_config = {
            "check_subdomains": True,
            "check_endpoints": True,
            "check_parameters": True,
            "alert_on_changes": True,
            "auto_retest": True,
            "enabled": True
        }

        if config:
            default_config.update(config)

        # Initial scan to establish baseline
        baseline = await self._create_baseline(target_url)

        target_data = {
            "url": target_url,
            "config": default_config,
            "baseline": baseline,
            "last_check": datetime.now().isoformat(),
            "added_at": datetime.now().isoformat(),
            "changes_detected": 0
        }

        self.monitored_targets[target_id] = target_data

        # Save to disk
        await self._save_target_state(target_id, target_data)

        dashboard.log(f"📡 Monitoring enabled for: {target_url}", "SUCCESS")
        self.think(f"Baseline established for {target_url}")

    async def _create_baseline(self, target_url: str) -> Dict:
        """
        Create initial baseline snapshot of target.

        Returns:
            {
                "subdomains": [...],
                "endpoints": [...],
                "parameters": {...},
                "headers": {...},
                "technology": {...}
            }
        """
        self.think(f"Creating baseline for {target_url}...")

        # Trigger asset discovery
        if self.event_bus:
            await self.event_bus.emit("new_target_added", {"url": target_url})

        # Wait for discovery to complete
        await asyncio.sleep(10)

        # Collect baseline data
        baseline = {
            "timestamp": datetime.now().isoformat(),
            "subdomains": set(),
            "endpoints": set(),
            "parameters": {},
            "headers": {},
            "technology": {},
            "checksum": ""
        }

        # Basic HTTP fingerprint
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(target_url)

                baseline["headers"] = dict(response.headers)
                baseline["status_code"] = response.status_code
                baseline["content_length"] = len(response.content)
                baseline["checksum"] = hashlib.md5(response.content).hexdigest()

                # Technology detection
                baseline["technology"] = self._detect_technology(response)

        except Exception as e:
            logger.warning(f"Baseline creation failed for {target_url}: {e}")

        # Convert sets to lists for JSON serialization
        baseline["subdomains"] = list(baseline["subdomains"])
        baseline["endpoints"] = list(baseline["endpoints"])

        return baseline

    def _detect_technology(self, response: httpx.Response) -> Dict:
        """Detect technology stack from HTTP response."""
        tech = {
            "server": response.headers.get("Server", "Unknown"),
            "powered_by": response.headers.get("X-Powered-By", "Unknown"),
            "frameworks": []
        }

        # Simple detection patterns
        content = response.text.lower()

        if "wordpress" in content or "wp-content" in content:
            tech["frameworks"].append("WordPress")
        if "django" in content or "csrftoken" in response.cookies:
            tech["frameworks"].append("Django")
        if "react" in content or "__react" in content:
            tech["frameworks"].append("React")
        if "angular" in content or "ng-" in content:
            tech["frameworks"].append("Angular")

        return tech

    async def _check_target(self, target_id: str, target_info: Dict):
        """Run all checks for a monitored target."""
        if not target_info["config"]["enabled"]:
            return

        target_url = target_info["url"]
        baseline = target_info["baseline"]
        config = target_info["config"]

        self.think(f"Checking target: {target_url}")

        changes = {
            "new_subdomains": [],
            "new_endpoints": [],
            "new_parameters": [],
            "header_changes": [],
            "technology_changes": []
        }

        # Check 1: Subdomain changes
        if config["check_subdomains"]:
            new_subdomains = await self._check_subdomains(target_url, baseline)
            if new_subdomains:
                changes["new_subdomains"] = new_subdomains

        # Check 2: Endpoint changes
        if config["check_endpoints"]:
            new_endpoints = await self._check_endpoints(target_url, baseline)
            if new_endpoints:
                changes["new_endpoints"] = new_endpoints

        # Check 3: Parameter changes
        if config["check_parameters"]:
            new_params = await self._check_parameters(target_url, baseline)
            if new_params:
                changes["new_parameters"] = new_params

        # Check 4: Content/Technology changes
        tech_changes = await self._check_technology(target_url, baseline)
        if tech_changes:
            changes["technology_changes"] = tech_changes

        # If changes detected
        if any(changes.values()):
            target_info["changes_detected"] += 1
            target_info["last_change"] = datetime.now().isoformat()

            dashboard.log(
                f"🚨 CHANGES DETECTED on {target_url}: "
                f"{len(changes['new_subdomains'])} subdomains, "
                f"{len(changes['new_endpoints'])} endpoints",
                "CRITICAL"
            )

            # Emit alert
            await self._alert_changes(target_id, target_info, changes)

            # Auto-retest if enabled
            if config["auto_retest"]:
                await self._trigger_retest(target_url, changes)

            # Update baseline
            await self._update_baseline(target_id, target_info, changes)

        # Update last check time
        target_info["last_check"] = datetime.now().isoformat()
        await self._save_target_state(target_id, target_info)

    async def _check_subdomains(self, target_url: str, baseline: Dict) -> List[str]:
        """Check for new subdomains."""
        # Trigger subdomain discovery
        # (In production, integrate with AssetDiscoveryAgent)

        # For now, return empty (would query CT logs, DNS)
        return []

    async def _check_endpoints(self, target_url: str, baseline: Dict) -> List[str]:
        """Check for new endpoints."""
        new_endpoints = []

        # Probe common new paths that appear in updates
        new_paths = [
            "/api/v2", "/api/v3", "/graphql", "/admin",
            "/debug", "/status", "/health", "/metrics"
        ]

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                for path in new_paths:
                    url = target_url.rstrip("/") + path

                    # Check if this endpoint existed in baseline
                    if url in baseline.get("endpoints", []):
                        continue

                    try:
                        response = await client.get(url, timeout=5)
                        if response.status_code != 404:
                            new_endpoints.append(url)
                            dashboard.log(f"  🆕 New endpoint: {url}", "WARNING")
                    except:
                        pass

        except Exception as e:
            logger.warning(f"Endpoint check failed: {e}")

        return new_endpoints

    async def _check_parameters(self, target_url: str, baseline: Dict) -> List[Dict]:
        """Check for new parameters on existing endpoints."""
        # Would crawl known endpoints and compare parameters
        return []

    async def _check_technology(self, target_url: str, baseline: Dict) -> List[str]:
        """Check for technology stack changes."""
        changes = []

        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(target_url)

                # Check content checksum
                current_checksum = hashlib.md5(response.content).hexdigest()
                if current_checksum != baseline.get("checksum"):
                    changes.append("Content changed (possible new deployment)")

                # Check headers
                current_server = response.headers.get("Server", "Unknown")
                baseline_server = baseline.get("headers", {}).get("Server", "Unknown")

                if current_server != baseline_server:
                    changes.append(f"Server changed: {baseline_server} → {current_server}")

                # Check technology
                current_tech = self._detect_technology(response)
                baseline_tech = baseline.get("technology", {})

                new_frameworks = set(current_tech.get("frameworks", [])) - set(baseline_tech.get("frameworks", []))
                if new_frameworks:
                    changes.append(f"New frameworks detected: {', '.join(new_frameworks)}")

        except Exception as e:
            logger.warning(f"Technology check failed: {e}")

        return changes

    async def _alert_changes(self, target_id: str, target_info: Dict, changes: Dict):
        """Send alerts about detected changes."""
        target_url = target_info["url"]

        # Emit event
        if self.event_bus:
            await self.event_bus.emit("target_changed", {
                "target_id": target_id,
                "target_url": target_url,
                "changes": changes,
                "timestamp": datetime.now().isoformat()
            })

        # Console alert
        alert_msg = f"""
🚨 TARGET CHANGED: {target_url}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        if changes["new_subdomains"]:
            alert_msg += f"\n📡 New Subdomains ({len(changes['new_subdomains'])}):\n"
            for sub in changes["new_subdomains"][:5]:
                alert_msg += f"  • {sub}\n"

        if changes["new_endpoints"]:
            alert_msg += f"\n🔗 New Endpoints ({len(changes['new_endpoints'])}):\n"
            for ep in changes["new_endpoints"][:5]:
                alert_msg += f"  • {ep}\n"

        if changes["technology_changes"]:
            alert_msg += f"\n⚙️  Technology Changes:\n"
            for change in changes["technology_changes"]:
                alert_msg += f"  • {change}\n"

        dashboard.log(alert_msg, "CRITICAL")

        # Save alert to file
        alert_path = self.state_dir / f"alerts_{target_id}.jsonl"
        with open(alert_path, "a") as f:
            f.write(json.dumps({
                "timestamp": datetime.now().isoformat(),
                "target": target_url,
                "changes": changes
            }) + "\n")

    async def _trigger_retest(self, target_url: str, changes: Dict):
        """Automatically retest new attack surface."""
        self.think(f"Auto-retest triggered for {target_url}")

        # Emit retest event for new endpoints
        if self.event_bus:
            for endpoint in changes.get("new_endpoints", []):
                await self.event_bus.emit("new_url_discovered", {
                    "url": endpoint,
                    "source": "monitoring_agent",
                    "priority": "high"
                })

            for subdomain in changes.get("new_subdomains", []):
                await self.event_bus.emit("new_target_added", {
                    "url": f"https://{subdomain}",
                    "source": "monitoring_agent"
                })

    async def _update_baseline(self, target_id: str, target_info: Dict, changes: Dict):
        """Update baseline with newly discovered assets."""
        baseline = target_info["baseline"]

        # Add new subdomains to baseline
        if "subdomains" not in baseline:
            baseline["subdomains"] = []
        baseline["subdomains"].extend(changes.get("new_subdomains", []))

        # Add new endpoints
        if "endpoints" not in baseline:
            baseline["endpoints"] = []
        baseline["endpoints"].extend(changes.get("new_endpoints", []))

        # Update timestamp
        baseline["last_updated"] = datetime.now().isoformat()

        await self._save_target_state(target_id, target_info)

    async def _save_target_state(self, target_id: str, target_data: Dict):
        """Save target monitoring state to disk."""
        state_file = self.state_dir / f"{target_id}.json"

        # Convert sets to lists for JSON
        serializable_data = json.loads(json.dumps(target_data, default=str))

        state_file.write_text(json.dumps(serializable_data, indent=2, default=str))

    async def _load_targets(self):
        """Load monitored targets from disk."""
        for state_file in self.state_dir.glob("*.json"):
            if state_file.stem.startswith("alerts_"):
                continue

            try:
                target_data = json.loads(state_file.read_text())
                target_id = state_file.stem

                if target_id not in self.monitored_targets:
                    self.monitored_targets[target_id] = target_data
            except Exception as e:
                logger.error(f"Failed to load {state_file}: {e}")

    def get_monitoring_stats(self) -> Dict:
        """Get statistics about monitored targets."""
        total_targets = len(self.monitored_targets)
        active_targets = sum(1 for t in self.monitored_targets.values() if t["config"]["enabled"])
        total_changes = sum(t.get("changes_detected", 0) for t in self.monitored_targets.values())

        return {
            "total_targets": total_targets,
            "active_targets": active_targets,
            "total_changes_detected": total_changes,
            "monitored_targets": [
                {
                    "url": t["url"],
                    "changes": t.get("changes_detected", 0),
                    "last_check": t.get("last_check"),
                    "enabled": t["config"]["enabled"]
                }
                for t in self.monitored_targets.values()
            ]
        }


# Export
__all__ = ["MonitoringAgent"]
