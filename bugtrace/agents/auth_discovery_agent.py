"""
AuthDiscoveryAgent - Authentication Artifact Discovery

Discovers JWTs and session cookies from multiple sources:
- HTTP headers (Authorization, X-Auth-Token, etc.)
- Cookies (JWT cookies + session cookies)
- Web storage (localStorage, sessionStorage)
- HTML content (inline scripts, data attributes)
- JavaScript files (external .js files)

Phase: RECONNAISSANCE (Phase 1)
Execution: After GoSpiderAgent, before DAST analysis
"""

import asyncio
import json
import base64
import hashlib
import re
from typing import List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.tools.visual.browser import browser_manager
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings


class AuthDiscoveryAgent(BaseAgent):
    """
    Authentication Artifact Discovery Agent.

    Discovers JWTs and cookies from web applications for subsequent exploitation.
    """

    def __init__(self, target: str, report_dir: Path, urls_to_scan: List[str] = None):
        super().__init__(
            "AuthDiscoveryAgent",
            "Authentication Discovery Specialist",
            agent_id="auth_discovery_agent"
        )
        self.target = target
        self.report_dir = Path(report_dir)
        self.urls_to_scan = urls_to_scan or [target]

        # Discovery results
        self.discovered_jwts: List[Dict] = []
        self.discovered_cookies: List[Dict] = []

        # JWT regex pattern
        self.jwt_pattern = re.compile(
            r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)'
        )

    async def run_loop(self):
        """Standard run loop for BaseAgent contract."""
        return await self.run()

    async def run(self) -> Dict[str, Any]:
        """Main execution entry point."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting authentication artifact discovery...", "INFO")

        # Scan URLs (limit to top 5 for performance)
        scan_limit = min(5, len(self.urls_to_scan))
        urls_to_check = self.urls_to_scan[:scan_limit]

        logger.info(f"[{self.name}] Scanning {len(urls_to_check)} URLs for auth artifacts")

        for idx, url in enumerate(urls_to_check, 1):
            logger.info(f"[{self.name}] [{idx}/{len(urls_to_check)}] Scanning {url}")
            try:
                await self._scan_url(url)
            except Exception as e:
                logger.error(f"[{self.name}] Failed to scan {url}: {e}")

        # Save discoveries to disk
        self._save_discoveries()

        # NOTE: Findings are NOT emitted here anymore (2026-02-04)
        # Phase 3 (ThinkingAgent) reads the JSON files and processes them in batch
        # This avoids duplicate findings and maintains consistent batch processing
        # self._emit_discoveries()

        dashboard.log(
            f"[{self.name}] Discovery complete: {len(self.discovered_jwts)} JWTs, "
            f"{len(self.discovered_cookies)} cookies",
            "SUCCESS"
        )

        return {
            "jwts": self.discovered_jwts,
            "cookies": self.discovered_cookies
        }

    # ============================================================================
    # MAIN SCANNER
    # ============================================================================

    async def _scan_url(self, url: str):
        """Scan a single URL for authentication artifacts."""
        async with browser_manager.get_page() as page:
            # Storage for intercepted tokens
            intercepted_tokens = []

            # Setup request interceptor for headers
            async def handle_request(request):
                # Extract from Authorization header
                auth_header = request.headers.get("authorization", "")
                if "Bearer " in auth_header:
                    token = auth_header.split("Bearer ")[1].strip()
                    if self._is_jwt(token):
                        intercepted_tokens.append({
                            "token": token,
                            "source": "http_header_authorization",
                            "url": url,
                            "context": "request"
                        })

                # Check other auth headers
                for header_name in ["x-auth-token", "x-access-token", "token"]:
                    header_value = request.headers.get(header_name, "")
                    if header_value and self._is_jwt(header_value):
                        intercepted_tokens.append({
                            "token": header_value,
                            "source": f"http_header_{header_name}",
                            "url": url,
                            "context": "request"
                        })

            page.on("request", handle_request)

            # Navigate to URL
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
            except Exception as e:
                logger.warning(f"[{self.name}] Navigation timeout/error for {url}: {e}")
                # Continue with partial extraction

            # Extract from all sources
            await asyncio.gather(
                self._extract_from_cookies(page, url),
                self._extract_from_storage(page, url),
                self._extract_from_html(page, url),
                self._extract_from_javascript(page, url),
                return_exceptions=True
            )

            # Add intercepted tokens
            for token_info in intercepted_tokens:
                if not self._is_duplicate_jwt(token_info["token"]):
                    self.discovered_jwts.append(token_info)
                    logger.info(f"[{self.name}] JWT found in {token_info['source']}")

    # ============================================================================
    # EXTRACTION METHODS
    # ============================================================================

    async def _extract_from_cookies(self, page, url: str):
        """Extract both JWT cookies and session cookies."""
        try:
            cookies = await page.context.cookies()

            for cookie in cookies:
                cookie_value = cookie.get("value", "")
                cookie_name = cookie.get("name", "")

                # Check if cookie value is a JWT
                if self._is_jwt(cookie_value):
                    if not self._is_duplicate_jwt(cookie_value):
                        self.discovered_jwts.append({
                            "token": cookie_value,
                            "source": "cookie",
                            "cookie_name": cookie_name,
                            "url": url,
                            "context": "cookie_jar",
                            "metadata": {
                                "domain": cookie.get("domain"),
                                "path": cookie.get("path"),
                                "secure": cookie.get("secure", False),
                                "httpOnly": cookie.get("httpOnly", False),
                                "sameSite": cookie.get("sameSite", "None")
                            }
                        })
                        logger.info(f"[{self.name}] JWT cookie found: {cookie_name}")

                # Non-JWT session cookies
                elif self._is_session_cookie(cookie_name):
                    if not self._is_duplicate_cookie(cookie_name, cookie_value):
                        self.discovered_cookies.append({
                            "name": cookie_name,
                            "value": cookie_value,
                            "source": "cookie_jar",
                            "url": url,
                            "metadata": {
                                "domain": cookie.get("domain"),
                                "path": cookie.get("path"),
                                "secure": cookie.get("secure", False),
                                "httpOnly": cookie.get("httpOnly", False),
                                "sameSite": cookie.get("sameSite", "None")
                            }
                        })
                        logger.info(f"[{self.name}] Session cookie found: {cookie_name}")

        except Exception as e:
            logger.debug(f"[{self.name}] Cookie extraction failed: {e}")

    async def _extract_from_storage(self, page, url: str):
        """Extract JWTs from localStorage and sessionStorage."""
        try:
            storage_data = await page.evaluate("""
                () => {
                    const local = {};
                    const session = {};

                    try {
                        // Extract from localStorage
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            local[key] = localStorage.getItem(key);
                        }
                    } catch (e) {}

                    try {
                        // Extract from sessionStorage
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            session[key] = sessionStorage.getItem(key);
                        }
                    } catch (e) {}

                    return { local, session };
                }
            """)

            # Check localStorage
            for key, value in storage_data.get("local", {}).items():
                if value and self._is_jwt(value):
                    if not self._is_duplicate_jwt(value):
                        self.discovered_jwts.append({
                            "token": value,
                            "source": "localStorage",
                            "storage_key": key,
                            "url": url,
                            "context": "client_storage"
                        })
                        logger.info(f"[{self.name}] JWT in localStorage: {key}")

            # Check sessionStorage
            for key, value in storage_data.get("session", {}).items():
                if value and self._is_jwt(value):
                    if not self._is_duplicate_jwt(value):
                        self.discovered_jwts.append({
                            "token": value,
                            "source": "sessionStorage",
                            "storage_key": key,
                            "url": url,
                            "context": "client_storage"
                        })
                        logger.info(f"[{self.name}] JWT in sessionStorage: {key}")

        except Exception as e:
            logger.debug(f"[{self.name}] Storage extraction failed: {e}")

    async def _extract_from_html(self, page, url: str):
        """Extract JWTs from HTML content."""
        try:
            html = await page.content()

            # Scan for JWTs with regex
            for match in self.jwt_pattern.finditer(html):
                token = match.group(1)
                if self._is_jwt(token) and not self._is_duplicate_jwt(token):
                    # Determine context
                    context = self._find_jwt_context_in_html(html, token)

                    self.discovered_jwts.append({
                        "token": token,
                        "source": "html_content",
                        "url": url,
                        "context": context,
                        "extraction_method": "regex_scan"
                    })
                    logger.info(f"[{self.name}] JWT in HTML: {context}")

        except Exception as e:
            logger.debug(f"[{self.name}] HTML extraction failed: {e}")

    async def _extract_from_javascript(self, page, url: str):
        """Extract JWTs from loaded JavaScript files."""
        try:
            # Get all script sources
            script_urls = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script[src]'))
                               .map(s => s.src)
                               .filter(src => src && src.startsWith('http'));
                }
            """)

            # Limit to first 10 scripts for performance
            for script_url in script_urls[:10]:
                try:
                    async with orchestrator.session(DestinationType.TARGET) as session:
                        async with session.get(script_url, timeout=10) as resp:
                            if resp.status == 200:
                                js_content = await resp.text()

                                # Scan for JWTs
                                for match in self.jwt_pattern.finditer(js_content):
                                    token = match.group(1)
                                    if self._is_jwt(token) and not self._is_duplicate_jwt(token):
                                        self.discovered_jwts.append({
                                            "token": token,
                                            "source": "javascript_file",
                                            "script_url": script_url,
                                            "page_url": url,
                                            "context": "external_script"
                                        })
                                        logger.info(f"[{self.name}] JWT in JS file: {script_url}")

                except Exception as e:
                    logger.debug(f"Failed to scan JS file {script_url}: {e}")

        except Exception as e:
            logger.debug(f"[{self.name}] JavaScript extraction failed: {e}")

    # ============================================================================
    # HELPER METHODS
    # ============================================================================

    def _is_jwt(self, token: str) -> bool:
        """Validate JWT format (3 parts, base64)."""
        if not token or not isinstance(token, str):
            return False

        parts = token.split('.')
        if len(parts) != 3:
            return False

        # Check that first two parts are non-empty and look like base64
        if len(parts[0]) < 4 or len(parts[1]) < 4:
            return False

        return True

    def _is_session_cookie(self, name: str) -> bool:
        """Detect session cookies by name patterns."""
        if not name:
            return False

        session_patterns = [
            "session", "sessid", "phpsessid", "jsessionid",
            "asp.net_sessionid", "connect.sid", "_session",
            "sid", "csrf", "xsrf", "sessionid"
        ]

        name_lower = name.lower()
        return any(pattern in name_lower for pattern in session_patterns)

    def _decode_jwt_parts(self, token: str) -> Dict:
        """Decode JWT header and payload for metadata."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}

            # Decode header
            header_data = self._base64_decode(parts[0])
            header = json.loads(header_data) if header_data else {}

            # Decode payload
            payload_data = self._base64_decode(parts[1])
            payload = json.loads(payload_data) if payload_data else {}

            # Check signature presence
            signature_present = bool(parts[2])

            return {
                "header": header,
                "payload": payload,
                "signature_present": signature_present
            }

        except Exception as e:
            logger.debug(f"JWT decode failed: {e}")
            return {}

    def _base64_decode(self, data: str) -> str:
        """Base64Url decode helper."""
        try:
            # Add padding if needed
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)

            return base64.urlsafe_b64decode(data).decode('utf-8')
        except Exception:
            return ""

    def _find_jwt_context_in_html(self, html: str, token: str) -> str:
        """Determine where in HTML the JWT appears."""
        # Find the line containing the token
        for line in html.split('\n'):
            if token in line:
                # Determine context
                line_lower = line.lower()
                if '<script' in line_lower or '</script>' in line_lower:
                    return "inline_script"
                elif 'data-' in line:
                    return "data_attribute"
                elif 'value=' in line:
                    return "input_value"
                else:
                    return "html_text"
        return "unknown"

    def _is_duplicate_jwt(self, token: str) -> bool:
        """Check if JWT already discovered."""
        return any(jwt["token"] == token for jwt in self.discovered_jwts)

    def _is_duplicate_cookie(self, name: str, value: str) -> bool:
        """Check if cookie already discovered."""
        return any(
            c["name"] == name and c["value"] == value
            for c in self.discovered_cookies
        )

    # ============================================================================
    # FINDING FORMAT & EMISSION
    # ============================================================================

    def _format_jwt_finding(self, jwt_info: Dict) -> Dict:
        """Format JWT info as a standard finding."""
        # Decode JWT for metadata
        decoded = self._decode_jwt_parts(jwt_info["token"])

        return {
            "type": "JWT_DISCOVERED",
            "url": jwt_info["url"],
            "token": jwt_info["token"],
            "source": jwt_info["source"],
            "parameter": jwt_info.get("storage_key", jwt_info.get("cookie_name", "N/A")),
            "context": jwt_info.get("context", "unknown"),
            "severity": "INFO",
            "agent": self.name,
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "header": decoded.get("header", {}),
                "payload_preview": decoded.get("payload", {}),
                "signature_present": decoded.get("signature_present", False)
            }
        }

    def _format_cookie_finding(self, cookie_info: Dict) -> Dict:
        """Format cookie info as a standard finding."""
        return {
            "type": "SESSION_COOKIE_DISCOVERED",
            "url": cookie_info["url"],
            "cookie_name": cookie_info["name"],
            "cookie_value": cookie_info["value"],
            "source": cookie_info["source"],
            "severity": "INFO",
            "agent": self.name,
            "timestamp": datetime.now().isoformat(),
            "metadata": cookie_info.get("metadata", {})
        }

    def _emit_discoveries(self):
        """Emit findings to event bus for orchestrator routing."""
        # Emit JWT findings
        for jwt_info in self.discovered_jwts:
            finding = self._format_jwt_finding(jwt_info)

            # Emit to event bus (ThinkingAgent will route to JWT queue)
            event_bus.emit(EventType.VULNERABILITY_DETECTED, finding)

            # Also emit legacy event for backward compatibility
            event_bus.publish("auth_token_found", {
                "token": jwt_info["token"],
                "url": jwt_info["url"],
                "location": jwt_info["source"]
            })

            logger.debug(f"[{self.name}] Emitted JWT finding: {jwt_info['source']}")

        # Emit cookie findings
        for cookie_info in self.discovered_cookies:
            finding = self._format_cookie_finding(cookie_info)

            # Emit to event bus
            event_bus.emit(EventType.VULNERABILITY_DETECTED, finding)

            logger.debug(f"[{self.name}] Emitted cookie finding: {cookie_info['name']}")

    # ============================================================================
    # ARTIFACT GENERATION
    # ============================================================================

    def _save_discoveries(self):
        """Save discoveries to JSON and Markdown artifacts."""
        # Ensure report directory exists
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # Save JWTs
        self._save_jwts_json()

        # Save cookies
        self._save_cookies_json()

        # Save markdown report
        self._save_markdown_report()

        logger.info(f"[{self.name}] Artifacts saved to {self.report_dir}")

    def _save_jwts_json(self):
        """Save discovered JWTs to JSON file."""
        jwt_file = self.report_dir / "jwts_discovered.json"

        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_jwts": len(self.discovered_jwts),
            "jwts": self.discovered_jwts
        }

        with open(jwt_file, "w") as f:
            json.dump(data, f, indent=2)

    def _save_cookies_json(self):
        """Save discovered cookies to JSON file."""
        cookie_file = self.report_dir / "cookies_discovered.json"

        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_cookies": len(self.discovered_cookies),
            "cookies": self.discovered_cookies
        }

        with open(cookie_file, "w") as f:
            json.dump(data, f, indent=2)

    def _save_markdown_report(self):
        """Generate human-readable Markdown report."""
        md_file = self.report_dir / "auth_discovery.md"

        lines = []
        lines.append("# Authentication Discovery Report\n")
        lines.append(f"**Target**: {self.target}  ")
        lines.append(f"**Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append(f"**Agent**: {self.name}\n")
        lines.append("---\n")

        # Summary
        lines.append("## Summary\n")
        lines.append(f"- **JWTs Discovered**: {len(self.discovered_jwts)}")
        lines.append(f"- **Session Cookies Discovered**: {len(self.discovered_cookies)}\n")
        lines.append("---\n")

        # JWT Findings
        if self.discovered_jwts:
            lines.append("## JWT Findings\n")
            for idx, jwt_info in enumerate(self.discovered_jwts, 1):
                decoded = self._decode_jwt_parts(jwt_info["token"])
                header = decoded.get("header", {})
                payload = decoded.get("payload", {})

                lines.append(f"### {idx}. JWT in {jwt_info['source']}\n")
                lines.append(f"- **URL**: {jwt_info['url']}")
                lines.append(f"- **Source**: {jwt_info['source']}")
                if "storage_key" in jwt_info:
                    lines.append(f"- **Storage Key**: {jwt_info['storage_key']}")
                if "cookie_name" in jwt_info:
                    lines.append(f"- **Cookie Name**: {jwt_info['cookie_name']}")

                if header:
                    lines.append(f"- **Algorithm**: {header.get('alg', 'unknown')}")

                if payload:
                    lines.append("- **Payload Preview**:")
                    lines.append("  ```json")
                    lines.append(f"  {json.dumps(payload, indent=2)}")
                    lines.append("  ```")

                lines.append("")
        else:
            lines.append("## JWT Findings\n")
            lines.append("No JWTs discovered.\n")

        lines.append("---\n")

        # Cookie Findings
        if self.discovered_cookies:
            lines.append("## Session Cookie Findings\n")
            for idx, cookie_info in enumerate(self.discovered_cookies, 1):
                metadata = cookie_info.get("metadata", {})

                lines.append(f"### {idx}. {cookie_info['name']}\n")
                lines.append(f"- **Value**: {cookie_info['value'][:20]}... (truncated)")
                lines.append(f"- **URL**: {cookie_info['url']}")
                lines.append(f"- **Domain**: {metadata.get('domain', 'N/A')}")
                lines.append(f"- **Secure**: {metadata.get('secure', False)}")
                lines.append(f"- **HttpOnly**: {metadata.get('httpOnly', False)}")
                lines.append(f"- **SameSite**: {metadata.get('sameSite', 'None')}")

                # Security warnings
                if not metadata.get('secure'):
                    lines.append("  - ⚠️ **WARNING**: Cookie not marked as Secure")
                if not metadata.get('httpOnly'):
                    lines.append("  - ⚠️ **WARNING**: Cookie not marked as HttpOnly")

                lines.append("")
        else:
            lines.append("## Session Cookie Findings\n")
            lines.append("No session cookies discovered.\n")

        lines.append("---\n")

        # Next Steps
        lines.append("## Next Steps\n")
        if self.discovered_jwts:
            lines.append("**JWTs** will be analyzed by **JWTAgent** for:")
            lines.append("- 'none' algorithm bypass")
            lines.append("- Weak secret bruteforce")
            lines.append("- Key confusion attacks (RS256 → HS256)\n")

        if self.discovered_cookies:
            lines.append("**Session cookies** will be tested by **IDORAgent** for:")
            lines.append("- Session fixation")
            lines.append("- Predictable session IDs")
            lines.append("- Authorization bypass\n")

        # Write to file
        with open(md_file, "w") as f:
            f.write("\n".join(lines))
