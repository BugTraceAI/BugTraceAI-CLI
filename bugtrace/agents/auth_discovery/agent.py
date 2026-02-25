"""
Auth Discovery Agent — Thin Orchestrator.

Inherits from BaseAgent and delegates all logic to pure (core.py) and
I/O (scanning.py) modules. This class owns only:
- Agent lifecycle (init, run, run_loop)
- State wiring (target, report_dir, urls_to_scan)
- Discovery result storage and artifact generation
"""

import json
from typing import Dict, List, Any
from pathlib import Path
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.ui import dashboard

from bugtrace.agents.auth_discovery.core import (
    format_jwt_finding,
    format_cookie_finding,
    build_markdown_report,
)
from bugtrace.agents.auth_discovery.scanning import (
    scan_url,
    attempt_auto_registration,
)


class AuthDiscoveryAgent(BaseAgent):
    """
    Authentication Artifact Discovery Agent.

    Discovers JWTs and cookies from web applications for subsequent exploitation.
    """

    def __init__(
        self,
        target: str,
        report_dir: Path,
        urls_to_scan: List[str] = None,
    ):
        super().__init__(
            "AuthDiscoveryAgent",
            "Authentication Discovery Specialist",
            agent_id="auth_discovery_agent",
        )
        self.target = target
        self.report_dir = Path(report_dir)
        self.urls_to_scan = urls_to_scan or [target]

        # Discovery results
        self.discovered_jwts: List[Dict] = []
        self.discovered_cookies: List[Dict] = []

    async def run_loop(self):
        """Standard run loop for BaseAgent contract."""
        return await self.run()

    async def run(self) -> Dict[str, Any]:
        """Main execution entry point."""
        dashboard.current_agent = self.name
        dashboard.log(
            f"[{self.name}] Starting authentication artifact discovery...", "INFO"
        )

        # Scan URLs (limit to top 5 for performance)
        scan_limit = min(5, len(self.urls_to_scan))
        urls_to_check = self.urls_to_scan[:scan_limit]

        logger.info(f"[{self.name}] Scanning {len(urls_to_check)} URLs for auth artifacts")

        for idx, url in enumerate(urls_to_check, 1):
            logger.info(f"[{self.name}] [{idx}/{len(urls_to_check)}] Scanning {url}")
            try:
                new_jwts, new_cookies = await scan_url(
                    url, self.discovered_jwts, self.discovered_cookies
                )
                self.discovered_jwts.extend(new_jwts)
                self.discovered_cookies.extend(new_cookies)
            except Exception as e:
                logger.error(f"[{self.name}] Failed to scan {url}: {e}")

        # Auto-registration to obtain JWTs when passive scan finds nothing
        if not self.discovered_jwts:
            new_jwts = await attempt_auto_registration(
                self.urls_to_scan, self.discovered_jwts
            )
            self.discovered_jwts.extend(new_jwts)
            if new_jwts:
                dashboard.log(
                    f"[{self.name}] JWT obtained via auto-registration", "SUCCESS"
                )

        # Save discoveries to disk
        self._save_discoveries()

        dashboard.log(
            f"[{self.name}] Discovery complete: {len(self.discovered_jwts)} JWTs, "
            f"{len(self.discovered_cookies)} cookies",
            "SUCCESS",
        )

        return {
            "jwts": self.discovered_jwts,
            "cookies": self.discovered_cookies,
        }

    # ============================================================================
    # FINDING FORMAT & EMISSION
    # ============================================================================

    def _emit_discoveries(self):
        """Emit findings to event bus for orchestrator routing."""
        for jwt_info in self.discovered_jwts:
            finding = format_jwt_finding(jwt_info, self.name)
            event_bus.emit(EventType.VULNERABILITY_DETECTED, finding)
            event_bus.publish("auth_token_found", {
                "token": jwt_info["token"],
                "url": jwt_info["url"],
                "location": jwt_info["source"],
            })
            logger.debug(f"[{self.name}] Emitted JWT finding: {jwt_info['source']}")

        for cookie_info in self.discovered_cookies:
            finding = format_cookie_finding(cookie_info, self.name)
            event_bus.emit(EventType.VULNERABILITY_DETECTED, finding)
            logger.debug(f"[{self.name}] Emitted cookie finding: {cookie_info['name']}")

    # ============================================================================
    # ARTIFACT GENERATION
    # ============================================================================

    def _save_discoveries(self):
        """Save discoveries to JSON and Markdown artifacts."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._save_jwts_json()
        self._save_cookies_json()
        self._save_markdown_report()
        logger.info(f"[{self.name}] Artifacts saved to {self.report_dir}")

    def _save_jwts_json(self):
        """Save discovered JWTs to JSON file."""
        jwt_file = self.report_dir / "jwts_discovered.json"
        from datetime import datetime
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_jwts": len(self.discovered_jwts),
            "jwts": self.discovered_jwts,
        }
        with open(jwt_file, "w") as f:
            json.dump(data, f, indent=2)

    def _save_cookies_json(self):
        """Save discovered cookies to JSON file."""
        cookie_file = self.report_dir / "cookies_discovered.json"
        from datetime import datetime
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_cookies": len(self.discovered_cookies),
            "cookies": self.discovered_cookies,
        }
        with open(cookie_file, "w") as f:
            json.dump(data, f, indent=2)

    def _save_markdown_report(self):
        """Generate human-readable Markdown report."""
        md_file = self.report_dir / "auth_discovery.md"
        content = build_markdown_report(
            self.target,
            self.name,
            self.discovered_jwts,
            self.discovered_cookies,
        )
        with open(md_file, "w") as f:
            f.write(content)
