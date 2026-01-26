# Security Tools - Audit Fix Tasks

## Feature Overview
External security tools and integrations:
- **Interactsh**: Out-of-band callback detection
- **Docker Containers**: Go-based IDOR detection, JWT tools
- **External Validators**: SQLMap, Nuclei, etc.
- **Payload Encoders**: WAF bypass encoding techniques

---

## 🔴 CRITICAL Tasks (3)

### TASK-104: Fix SSL/TLS Verification Disabled in Interactsh
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/interactsh.py:198`
**Issue**: `verify=False` disables certificate validation
**Impact**: MITM attacks on OOB callbacks

**Current Code**:
```python
# Line 198
async with httpx.AsyncClient(verify=False) as client:
    response = await client.get(f"https://{server}/poll?id={correlation_id}")
```

**Proposed Fix**:
```python
async with httpx.AsyncClient(verify=True) as client:
    response = await client.get(f"https://{server}/poll?id={correlation_id}")
```

**Priority**: P0 - Fix immediately

---

### TASK-105: Fix Unsafe Temp File Handling
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/external.py:273-292`
**Issue**: `delete=False` leaves payloads on disk, TOCTOU race
**Impact**: Payload file recovery, timing attacks

**Current Code**:
```python
# Lines 273-292
with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
    json.dump(payload, f)
    temp_file = f.name

# File remains on disk!
result = await run_tool(temp_file)
# File still there, can be recovered
```

**Proposed Fix**:
```python
# Option 1: Use delete=True (auto cleanup)
with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix='.json') as f:
    json.dump(payload, f)
    f.flush()  # Ensure written
    result = await run_tool(f.name)
    # Auto-deleted when context exits

# Option 2: Manual secure deletion
import os

temp_file = None
try:
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(payload, f)
        temp_file = f.name

    result = await run_tool(temp_file)

finally:
    if temp_file and os.path.exists(temp_file):
        # Secure deletion
        with open(temp_file, 'wb') as f:
            f.write(os.urandom(os.path.getsize(temp_file)))
        os.remove(temp_file)

# Option 3: Use secure deletion library
from secure_delete import secure_delete

try:
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        json.dump(payload, f)
        temp_file = f.name

    result = await run_tool(temp_file)

finally:
    if temp_file:
        secure_delete.secure_random_delete(temp_file)
```

**Priority**: P0 - Fix immediately

---

### TASK-106: Fix Unvalidated JSON Deserialization
**Severity**: 🔴 CRITICAL
**File**: `bugtrace/tools/external.py:295,352,402,457`
**Issue**: JSON from Docker containers parsed without validation
**Impact**: DoS via large structures, potential code execution

**Current Code**:
```python
# Lines 295, 352, 402, 457
result = json.loads(output)  # No validation!
```

**Proposed Fix**:
```python
import json
from jsonschema import validate, ValidationError

# Define expected schema
RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean"},
        "data": {"type": "object"},
        "error": {"type": ["string", "null"]}
    },
    "required": ["success"]
}

def parse_tool_output(output, max_size=1_000_000):
    """Parse and validate tool output."""
    # Check size
    if len(output) > max_size:
        raise ValueError(f"Output too large: {len(output)} bytes")

    try:
        data = json.loads(output)

        # Validate structure
        validate(instance=data, schema=RESULT_SCHEMA)

        return data

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        raise

    except ValidationError as e:
        logger.error(f"Invalid schema: {e}")
        raise

# Usage
result = parse_tool_output(stdout.decode())
```

**Additional Security**:
```python
# Limit JSON parsing depth and size
import json

class SafeJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        self.max_depth = kwargs.pop('max_depth', 10)
        self.current_depth = 0
        super().__init__(*args, **kwargs)

    def decode(self, s):
        obj = super().decode(s)
        self._check_depth(obj, 0)
        return obj

    def _check_depth(self, obj, depth):
        if depth > self.max_depth:
            raise ValueError(f"JSON depth exceeds {self.max_depth}")

        if isinstance(obj, dict):
            for value in obj.values():
                self._check_depth(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._check_depth(item, depth + 1)

# Usage
decoder = SafeJSONDecoder(max_depth=10)
result = decoder.decode(output)
```

**Priority**: P0 - Fix immediately

---

## 🟠 HIGH Priority Tasks (4)

### TASK-107: Add Interactsh Server URL Validation
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/interactsh.py:54-80,196`
**Issue**: Server parameter accepts arbitrary domains
**Impact**: OOB redirection to attacker-controlled server

**Current Code**:
```python
# No validation on server URL
async def poll(self, server, correlation_id):
    url = f"https://{server}/poll?id={correlation_id}"
```

**Proposed Fix**:
```python
# Whitelist allowed Interactsh servers
ALLOWED_INTERACTSH_SERVERS = {
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "interact.sh"
}

def validate_interactsh_server(server):
    """Validate Interactsh server domain."""
    # Remove protocol if present
    server = server.replace("https://", "").replace("http://", "")

    # Extract domain
    domain = server.split('/')[0].split(':')[0]

    # Check whitelist
    if domain not in ALLOWED_INTERACTSH_SERVERS:
        raise ValueError(f"Untrusted Interactsh server: {domain}")

    return domain

# Usage
server = validate_interactsh_server(settings.INTERACTSH_SERVER)
```

**Priority**: P1 - Fix within 1 week

---

### TASK-108: Add Docker Container Resource Limits
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/external.py`
**Issue**: Docker containers run without resource limits

**Proposed Fix**:
```python
import docker

client = docker.from_env()

container = client.containers.run(
    image="bugtrace/idor-detector",
    command=["analyze", input_file],
    detach=True,
    mem_limit="512m",  # 512MB memory limit
    cpu_quota=50000,   # 50% of one CPU
    pids_limit=100,    # Max 100 processes
    security_opt=["no-new-privileges"],
    read_only=True,    # Read-only root filesystem
    tmpfs={'/tmp': 'size=100m'},  # Writable temp dir
    remove=True,       # Auto-remove after stop
    network_disabled=False  # Allow network for API calls
)
```

**Priority**: P1 - Fix within 1 week

---

### TASK-109: Add Docker Container Timeout
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/external.py`
**Issue**: Containers can run indefinitely

**Proposed Fix**:
```python
async def run_docker_with_timeout(image, command, timeout=300):
    """Run Docker container with timeout."""
    container = None
    try:
        container = client.containers.run(
            image=image,
            command=command,
            detach=True,
            remove=False
        )

        # Wait with timeout
        result = container.wait(timeout=timeout)

        # Get logs
        stdout = container.logs(stdout=True, stderr=False)
        stderr = container.logs(stdout=False, stderr=True)

        return result, stdout, stderr

    except docker.errors.ReadTimeout:
        logger.error(f"Container timeout after {timeout}s")
        if container:
            container.kill()
        raise

    finally:
        if container:
            try:
                container.remove()
            except Exception as e:
                logger.error(f"Failed to remove container: {e}")
```

**Priority**: P1 - Fix within 1 week

---

### TASK-110: Add Interactsh Polling Timeout
**Severity**: 🟠 HIGH
**File**: `bugtrace/tools/interactsh.py`
**Issue**: Polling can continue indefinitely

**Proposed Fix**:
```python
async def poll_with_timeout(self, correlation_id, timeout=300, interval=10):
    """Poll Interactsh with timeout."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = await self._poll_once(correlation_id)
            if response:
                return response

            await asyncio.sleep(interval)

        except Exception as e:
            logger.error(f"Polling error: {e}")
            await asyncio.sleep(interval)

    logger.warning(f"Interactsh polling timeout after {timeout}s")
    return None
```

**Priority**: P1 - Fix within 2 weeks

---

## 🟡 MEDIUM Priority Tasks (4)

### TASK-111: Add Docker Image Verification
**Severity**: 🟡 MEDIUM
**Issue**: Docker images not verified before use

**Proposed Fix**:
```python
def verify_docker_image(image_name):
    """Verify Docker image signature."""
    # Check image exists
    try:
        client.images.get(image_name)
    except docker.errors.ImageNotFound:
        logger.error(f"Image not found: {image_name}")
        return False

    # Verify digest
    image = client.images.get(image_name)
    expected_digest = settings.TRUSTED_IMAGE_DIGESTS.get(image_name)

    if expected_digest and image.id != expected_digest:
        logger.error(f"Image digest mismatch: {image_name}")
        return False

    return True
```

**Priority**: P2 - Fix before release

---

### TASK-112: Add Interactsh Correlation ID Validation
**Severity**: 🟡 MEDIUM
**Issue**: Correlation IDs not validated

**Proposed Fix**:
```python
import re
import uuid

def generate_correlation_id():
    """Generate secure correlation ID."""
    return str(uuid.uuid4())

def validate_correlation_id(correlation_id):
    """Validate correlation ID format."""
    if not re.match(r'^[a-f0-9\-]{36}$', correlation_id):
        raise ValueError(f"Invalid correlation ID: {correlation_id}")
    return correlation_id
```

**Priority**: P2 - Fix before release

---

### TASK-113: Add Tool Output Sanitization
**Severity**: 🟡 MEDIUM
**Issue**: Tool output may contain ANSI codes

**Priority**: P2 - Fix before release

---

### TASK-114: Add Docker Network Isolation
**Severity**: 🟡 MEDIUM
**Issue**: Containers can access host network

**Priority**: P2 - Fix before release

---

## 🟢 LOW Priority Tasks (3)

### TASK-115: Add Tool Version Tracking
**Severity**: 🟢 LOW
**Issue**: No tracking of external tool versions

**Priority**: P4 - Technical debt

---

### TASK-116: Add Tool Metrics
**Severity**: 🟢 LOW
**Issue**: No metrics on tool usage/failures

**Priority**: P4 - Technical debt

---

### TASK-117: Add Unit Tests for External Tools
**Severity**: 🟢 LOW
**Issue**: Limited test coverage

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 14
- 🔴 Critical: 3 (SSL, temp files, JSON deserialization)
- 🟠 High: 4 (Validation, timeouts, resource limits)
- 🟡 Medium: 4 (Image verification, sanitization)
- 🟢 Low: 3 (Technical debt)

**Estimated Effort**: 1-2 weeks for P0-P1 tasks
